use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisStore};
use futures_util::StreamExt as _;

use super::*;
use crate::execution::{Engine, Limits};
use crate::follow::Clock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Item {
    Metadata,
    Row,
    Checkpoint,
    Health,
    Error,
    InitialError {
        store: [u8; 16],
        epoch: u64,
        revision: u64,
        operation: Operation,
        failure: Failure,
    },
    Complete,
}

struct Authority {
    valid: AtomicBool,
    changes: watch::Sender<u64>,
}

impl Authority {
    fn revoke(&self) {
        self.valid.store(false, Ordering::SeqCst);
        self.changes.send_replace(1);
    }
}

struct TestClock {
    changes: watch::Sender<u64>,
    reads: AtomicUsize,
}

impl Clock for TestClock {
    fn now_ns(&self) -> Result<u64> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(*self.changes.borrow())
    }
    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

struct Encoder {
    authority: Arc<Authority>,
    fail: bool,
}

impl Encoder {
    fn encode(item: Item, memory: &mut MemoryReservation) -> std::result::Result<Item, Failure> {
        memory
            .try_resize(8)
            .map_err(|source| Failure::native(&source))?;
        Ok(item)
    }
}

impl Consumer for Encoder {
    type Item = Item;
    type Error = Failure;

    fn authorize(&self) -> std::result::Result<(), Failure> {
        if self.authority.valid.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(Failure::Denied)
        }
    }
    fn changes(&self) -> watch::Receiver<u64> {
        self.authority.changes.subscribe()
    }
    fn expires(&self) -> Instant {
        Instant::now() + Duration::from_secs(60)
    }
    fn expired(&self) -> Failure {
        Failure::Denied
    }
    fn code(&self, failure: Failure) -> Failure {
        failure
    }
    fn rows(&self, _: &Update) -> usize {
        1
    }
    fn encode(
        &mut self,
        action: Action<'_>,
        _: &Update,
        memory: &mut MemoryReservation,
    ) -> std::result::Result<Item, Failure> {
        let item = match action {
            Action::Metadata => Item::Metadata,
            Action::Row(_) => Item::Row,
            Action::Checkpoint => Item::Checkpoint,
            Action::Health(_) => Item::Health,
            Action::Error { .. } => Item::Error,
            Action::Complete { .. } => Item::Complete,
        };
        let item = Self::encode(item, memory)?;
        if self.fail && item == Item::Metadata {
            Err(Failure::EvaluationFailed)
        } else {
            Ok(item)
        }
    }
    fn complete_after_checkpoint(&self, _: &Update) -> bool {
        false
    }

    fn initial_error(
        &mut self,
        failure: Failure,
        cause: &Error,
        snapshot: &ArrowSnapshot,
        operation: Operation,
        memory: &mut MemoryReservation,
    ) -> std::result::Result<Item, Failure> {
        assert_eq!(failure, Failure::from(cause));
        let meta = &snapshot.page.extraction.meta;
        Self::encode(
            Item::InitialError {
                store: *meta.store_uuid.as_bytes(),
                epoch: meta.recovery_epoch,
                revision: meta.commit_revision,
                operation,
                failure,
            },
            memory,
        )
    }
    fn deadline_completes(&self) -> bool {
        false
    }
}

struct Fixture {
    engine: Arc<Engine>,
    authority: Arc<Authority>,
    clock: Arc<TestClock>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(AnalysisStore::open(directory.path().join("data")).unwrap());
        let engine = Engine::new(
            store,
            Limits {
                input_capacity: Some(128 * 1024 * 1024),
                output_capacity: Some(16 * 1024 * 1024),
                extract_timeout: Some(Duration::from_secs(5)),
                evaluate_timeout: Some(Duration::from_secs(5)),
                global_streams: Some(16),
                tenant_streams: Some(4),
                ..Default::default()
            },
        )
        .unwrap();
        Self {
            engine,
            authority: Arc::new(Authority {
                valid: AtomicBool::new(true),
                changes: watch::channel(0).0,
            }),
            clock: Arc::new(TestClock {
                changes: watch::channel(1_000_000_000).0,
                reads: AtomicUsize::new(0),
            }),
            _directory: directory,
        }
    }

    async fn delivery(&self, timeout: Duration, follow: bool, fail: bool) -> Delivery<Encoder> {
        let inner = self
            .engine
            .subscribe(
                "SELECT 1 AS value",
                Vec::new(),
                AnalysisSelectionV1::tenant([1; 16]),
                Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap()),
                b"delivery authority",
                None,
                self.clock.clone(),
                follow,
            )
            .await
            .unwrap();
        Delivery::new(
            inner,
            Encoder {
                authority: Arc::clone(&self.authority),
                fail,
            },
            None,
            timeout,
            None,
        )
        .unwrap()
    }
}

async fn next(delivery: &mut Delivery<Encoder>) -> std::result::Result<Item, Failure> {
    tokio::time::timeout(Duration::from_secs(8), delivery.next())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn phases_and_conversion_lifetime() {
    let fixture = Fixture::new();
    let mut delivery = fixture
        .delivery(Duration::from_secs(10), false, false)
        .await;
    let capacity = fixture
        .engine
        .limits()
        .output_capacity
        .expect("configured output capacity");
    assert_eq!(next(&mut delivery).await, Ok(Item::Metadata));
    assert!(delivery.holds_output());
    assert_eq!(delivery.frame_bytes(), 8);
    assert!(fixture.engine.memory().reserve_output(capacity).is_err());
    assert_eq!(next(&mut delivery).await, Ok(Item::Row));
    assert_eq!(next(&mut delivery).await, Ok(Item::Checkpoint));
    assert!(!delivery.holds_output());
    assert_eq!(next(&mut delivery).await, Ok(Item::Complete));
    assert!(fixture.engine.memory().reserve_output(capacity).is_err());
    assert!(delivery.next().await.is_none());
    assert!(fixture.engine.memory().reserve_output(capacity).is_ok());
}

#[tokio::test]
async fn initial_failure_keeps_receipt(
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use araphor_data::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1};
    use datafusion::arrow::datatypes::DataType;
    use datafusion::logical_expr::{col, create_udf, LogicalPlanBuilder, Volatility};

    let fixture = Fixture::new();
    let before = fixture.engine.store().meta()?;
    let store = Arc::clone(fixture.engine.store());
    let fail = create_udf(
        "fail_after_capture",
        vec![DataType::Utf8],
        DataType::Int64,
        Volatility::Volatile,
        Arc::new(move |_| {
            store
                .commit_context(&AnalysisContextVersionV1 {
                    key: AnalysisContextKeyV1 {
                        tenant_id: [1; 16],
                        owner_id: "fixture".into(),
                        entity_key: vec![1],
                        lifetime_key: vec![1],
                        owner_revision: 1,
                    },
                    valid_from_utc_ns: None,
                    valid_until_utc_ns: None,
                    sensitivity: ContextSensitivityV1::Tenant,
                    body: vec![1],
                })
                .map_err(|source| DataFusionError::External(Box::new(source)))?;
            Err(DataFusionError::Execution(
                "fixture evaluation failure".into(),
            ))
        }),
    );
    let (plan, sources) = fixture
        .engine
        .prepare("SELECT relation FROM catalog LIMIT 1", Vec::new())
        .await?;
    let plan = LogicalPlanBuilder::from(plan)
        .project(vec![fail.call(vec![col("relation")]).alias("value")])?
        .build()?;
    let inner = fixture
        .engine
        .session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            1_000_000_000,
        )?
        .subscribe(plan, sources, b"initial failure", false)?;
    let mut delivery = Delivery::new(
        inner,
        Encoder {
            authority: Arc::clone(&fixture.authority),
            fail: false,
        },
        None,
        Duration::from_secs(10),
        None,
    )?;
    assert_eq!(
        next(&mut delivery).await,
        Ok(Item::InitialError {
            store: *before.store_uuid.as_bytes(),
            epoch: before.recovery_epoch,
            revision: before.commit_revision,
            operation: Operation::Replace,
            failure: Failure::EvaluationFailed,
        })
    );
    assert!(fixture.engine.store().meta()?.commit_revision > before.commit_revision);
    assert_eq!(delivery.frame_bytes(), 8);
    let input = fixture
        .engine
        .limits()
        .input_capacity
        .ok_or("configured input capacity")?;
    let output = fixture
        .engine
        .limits()
        .output_capacity
        .ok_or("configured output capacity")?;
    assert!(fixture.engine.memory().reserve_input(input).is_ok());
    assert!(fixture.engine.memory().reserve_output(output).is_err());
    assert_eq!(next(&mut delivery).await, Err(Failure::EvaluationFailed));
    assert!(delivery.next().await.is_none());
    assert!(fixture.engine.memory().reserve_output(output).is_ok());
    let mut recovered = fixture
        .delivery(Duration::from_secs(10), false, false)
        .await;
    for item in [Item::Metadata, Item::Row, Item::Checkpoint, Item::Complete] {
        assert_eq!(next(&mut recovered).await, Ok(item));
    }
    assert!(recovered.next().await.is_none());
    Ok(())
}

#[tokio::test]
async fn package_checkpoint_releases_capacity(
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use araphor_analysis_sdk as sdk;
    use araphor_discovery_definition::{Definition, Program, Source};
    use araphor_package::{
        PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1,
    };

    let capacity = 64 * 1024;
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let engine = Engine::new(
        Arc::clone(&store),
        Limits {
            output_bytes: capacity,
            output_capacity: Some(capacity),
            ..Default::default()
        },
    )?;
    let mut model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![sdk::Port::new(
            "data",
            sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
        )],
    );
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    model.limits.max_bytes = (capacity / 4) as u64;
    store.install_package_image(
        [1; 16],
        &PackageBundleV1 {
            schema_version: 1,
            root: PackageRefV1 {
                package_id: "runtime-fixture".into(),
                revision: "1".into(),
            },
            artifacts: vec![PackageArtifactV1 {
                descriptor: sdk::Package::new("runtime-fixture", "1", vec![model]),
                implementations: vec![PackageImplementationV1::Wasm {
                    exports: vec!["evaluate".into()],
                    artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
                }],
                fixtures: Vec::new(),
            }],
        },
        || Ok(()),
    )?;
    let control = AnalysisReadControl::default();
    let definition = Definition {
        name: "package-delivery".into(),
        description: String::new(),
        labels: Default::default(),
        program: Program::Sql {
            source: Source::Inline {
                inline: r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => 'echo',
                amount => (SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) FROM context_versions))"#
                    .into(),
            },
        },
    };
    let prepared = engine
        .prepare_definition([1; 16], &definition, Arc::new(control.within(None)?))
        .await?;
    let session = engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &control,
        1_000_000_000,
    )?;
    let permit = Arc::new(engine.reserve_evaluation([1; 16])?);
    let mut state = session.state()?;
    state.config_mut().set_extension(Arc::clone(&permit));
    drop(session.physical(&prepared.plan, &state).await?);
    drop((state, permit));
    assert!(engine.guest_cached(araphor_analysis_builtins::components::RUNTIME)?);
    drop(engine.reserve_evaluation([1; 16])?);
    drop(engine.memory().reserve_output(capacity)?);
    let clock = Arc::new(TestClock {
        changes: watch::channel(1_000_000_000).0,
        reads: AtomicUsize::new(0),
    });
    let subscription = Subscription::new(
        session,
        Arc::new(prepared.plan),
        prepared.sources,
        b"package delivery",
        None,
        clock,
        true,
    )?;
    let mut delivery = Delivery::new(
        subscription,
        Encoder {
            authority: Arc::new(Authority {
                valid: AtomicBool::new(true),
                changes: watch::channel(0).0,
            }),
            fail: false,
        },
        None,
        Duration::from_secs(30),
        None,
    )?;
    for item in [Item::Metadata, Item::Row, Item::Checkpoint] {
        assert_eq!(next(&mut delivery).await, Ok(item));
    }
    drop(
        engine
            .memory()
            .reserve_output(capacity - delivery.frame_bytes())?,
    );
    store.commit_context(&araphor_data::AnalysisContextVersionV1 {
        key: araphor_data::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "delivery".into(),
            entity_key: vec![1],
            lifetime_key: vec![1],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: araphor_data::ContextSensitivityV1::Tenant,
        body: vec![1],
    })?;
    for item in [Item::Row, Item::Checkpoint] {
        assert_eq!(next(&mut delivery).await, Ok(item));
    }
    drop(
        engine
            .memory()
            .reserve_output(capacity - delivery.frame_bytes())?,
    );
    Ok(())
}

#[tokio::test]
async fn failed_conversion_releases_immediately() {
    let fixture = Fixture::new();
    let mut delivery = fixture.delivery(Duration::from_secs(10), true, true).await;
    assert_eq!(next(&mut delivery).await, Err(Failure::EvaluationFailed));
    assert_eq!(delivery.frame_bytes(), 0);
    assert!(fixture
        .engine
        .memory()
        .reserve_output(
            fixture
                .engine
                .limits()
                .output_capacity
                .expect("configured output capacity")
        )
        .is_ok());
    assert!(delivery.next().await.is_none());
}

#[tokio::test]
async fn idle_demand_releases_producer() {
    let fixture = Fixture::new();
    let mut delivery = fixture
        .delivery(Duration::from_millis(10), true, false)
        .await;
    assert_eq!(fixture.clock.reads.load(Ordering::SeqCst), 0);
    assert_eq!(Arc::strong_count(&fixture.clock), 2);
    let held: Vec<_> = (0..3)
        .map(|_| fixture.engine.reserve_stream([1; 16]).unwrap())
        .collect();
    assert!(fixture.engine.reserve_stream([1; 16]).is_err());
    assert_eq!(next(&mut delivery).await, Ok(Item::Metadata));
    let reads = fixture.clock.reads.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(next(&mut delivery).await, Err(Failure::OutputTimeout));
    assert_eq!(fixture.clock.reads.load(Ordering::SeqCst), reads);
    assert_eq!(Arc::strong_count(&fixture.clock), 1);
    assert!(fixture.engine.reserve_stream([1; 16]).is_ok());
    assert_eq!(delivery.frame_bytes(), 0);
    assert!(delivery.next().await.is_none());
    drop(held);
}

#[tokio::test]
async fn native_wait_is_not_output_idle() {
    let fixture = Fixture::new();
    let mut delivery = fixture
        .delivery(Duration::from_millis(10), true, false)
        .await;
    for item in [Item::Metadata, Item::Row, Item::Checkpoint] {
        assert_eq!(next(&mut delivery).await, Ok(item));
    }
    let pending = delivery.next();
    futures_util::pin_mut!(pending);
    assert!(futures_util::poll!(&mut pending).is_pending());
    tokio::time::sleep(Duration::from_millis(30)).await;
    fixture.clock.changes.send_replace(2_000_000_000);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(8), pending)
            .await
            .unwrap()
            .unwrap(),
        Ok(Item::Health)
    );
}

#[tokio::test]
async fn authority_interrupts_native_wait() {
    let fixture = Fixture::new();
    let mut delivery = fixture.delivery(Duration::from_secs(10), true, false).await;
    for item in [Item::Metadata, Item::Row, Item::Checkpoint] {
        assert_eq!(next(&mut delivery).await, Ok(item));
    }
    let pending = delivery.next();
    futures_util::pin_mut!(pending);
    assert!(futures_util::poll!(&mut pending).is_pending());
    fixture.authority.revoke();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap(),
        Err(Failure::Denied)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn authority_interrupts_read_check() {
    let fixture = Fixture::new();
    let mut delivery = fixture.delivery(Duration::from_secs(10), true, false).await;
    assert_eq!(next(&mut delivery).await, Ok(Item::Metadata));
    let parked = Arc::new(tokio::sync::Notify::new());
    let checking = Arc::clone(&parked);
    delivery.checking = Some(Box::pin(async move {
        checking.notify_one();
        futures_util::future::pending().await
    }));
    let pending = tokio::spawn(async move {
        let result = delivery.next().await;
        (result, delivery)
    });
    tokio::time::timeout(Duration::from_secs(1), parked.notified())
        .await
        .unwrap();
    fixture.authority.revoke();
    let (result, mut delivery) = tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, Some(Err(Failure::Denied)));
    assert_eq!(Arc::strong_count(&fixture.clock), 1);
    assert_eq!(delivery.frame_bytes(), 0);
    assert!(fixture
        .engine
        .memory()
        .reserve_output(
            fixture
                .engine
                .limits()
                .output_capacity
                .expect("configured output capacity")
        )
        .is_ok());
    assert!(delivery.next().await.is_none());
}
