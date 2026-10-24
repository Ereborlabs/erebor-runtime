use std::collections::BTreeMap;

use tokio::sync::watch;

use araphor_analysis_sdk as sdk;
use araphor_data::analysis::{PackageCommitV1, PackageKeyV1, PackageRevisionV1};
use araphor_data::{
    AnalysisSelectionV1, AnalysisStore, ClockDependency, EvidenceIntakeIdentityV1, EvidenceRecord,
    PackageArtifactV1, PackageImplementationV1, PackageReadinessV1, PackageRefV1, SqlModelV1,
    ValidatedEvidenceBatchV1,
};
use prost::Message as _;

use super::*;
use crate::execution::Limits;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const NOW: u64 = 1_700_000_000_000_000_000;

struct TestClock {
    now: std::sync::atomic::AtomicU64,
    reads: std::sync::atomic::AtomicUsize,
    on_read: std::sync::Mutex<Option<(usize, tokio::sync::oneshot::Sender<()>)>>,
    changes: watch::Sender<u64>,
}

impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            now: std::sync::atomic::AtomicU64::new(NOW),
            reads: std::sync::atomic::AtomicUsize::new(0),
            on_read: std::sync::Mutex::new(None),
            changes: watch::channel(NOW).0,
        })
    }

    fn set(&self, now: u64) {
        self.now.store(now, std::sync::atomic::Ordering::SeqCst);
        self.changes.send_replace(now);
    }

    fn after_reads(&self, count: usize) -> tokio::sync::oneshot::Receiver<()> {
        let (send, receive) = tokio::sync::oneshot::channel();
        let target = self.reads.load(std::sync::atomic::Ordering::SeqCst) + count;
        *self.on_read.lock().unwrap() = Some((target, send));
        receive
    }
}

impl Clock for TestClock {
    fn now_ns(&self) -> Result<u64> {
        let read = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if let Some((_, send)) = self
            .on_read
            .lock()
            .unwrap()
            .take_if(|(target, _)| *target == read)
        {
            let _sent = send.send(());
        }
        Ok(self.now.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

struct Fixture {
    store: Arc<AnalysisStore>,
    engine: Arc<Engine>,
    inputs: Arc<Inputs>,
    model: sdk::Model,
    active: PackageActivationV1,
    source: EvidenceIntakeIdentityV1,
    clock: Arc<TestClock>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(input_clock: bool) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let engine = Engine::new(
            Arc::clone(&store),
            Limits {
                input_capacity: Some(128 * 1024 * 1024),
                output_capacity: Some(16 * 1024 * 1024),
                tenant_evaluations: Some(1),
                ..Default::default()
            },
        )?;
        let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
        let mut model = sdk::Model::new(
            "model",
            Vec::new(),
            vec![sdk::Port::new("result", schema.clone())],
        );
        model.input_mode = sdk::InputMode::Resolved;
        model.inputs = vec![sdk::InputPort {
            port: sdk::Port::new("counted", schema),
            source: sdk::InputSource::Query(
                "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM events".into(),
            ),
        }];
        if input_clock {
            model.inputs.push(sdk::InputPort {
                port: sdk::Port::new(
                    "time",
                    sdk::Schema::new(vec![sdk::Field::new(
                        "value",
                        sdk::DataType::Timestamp(sdk::TimeUnit::Nanosecond, Some("UTC".into())),
                        false,
                    )]),
                ),
                source: sdk::InputSource::Query("SELECT now() AS value".into()),
            });
        }
        let source = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "live-input".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        Self::event_into(&store, &source, 1)?;
        let active = Self::install(&store, &source, &model, "live-input")?;
        let inputs = Arc::new(Inputs::admit(&engine, &model)?);
        Ok(Self {
            store,
            engine,
            inputs,
            model,
            active,
            source,
            clock: TestClock::new(),
            _directory: directory,
        })
    }

    fn install(
        store: &AnalysisStore,
        source: &EvidenceIntakeIdentityV1,
        model: &sdk::Model,
        package: &str,
    ) -> TestResult<PackageActivationV1> {
        let descriptor = sdk::Package::new(package, "v1", vec![model.clone()]);
        let artifact = PackageArtifactV1 {
            descriptor: descriptor.clone(),
            implementations: vec![PackageImplementationV1::Sql {
                export: model.name.clone(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([(
                        "result".into(),
                        "SELECT 1::BIGINT UNSIGNED AS value".into(),
                    )]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        };
        store.install_package(
            &[PackageRevisionV1 {
                tenant_id: [1; 16],
                package_id: descriptor.id.clone(),
                revision: descriptor.revision.clone(),
                descriptor: serde_json::to_vec(&descriptor)?,
                artifact: artifact.encode()?,
                dependencies: model
                    .dependencies()
                    .map(|(_, output)| (output.package.clone(), output.revision.clone()))
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .map(
                        |(package_id, revision)| araphor_data::analysis::PackageRevisionRefV1 {
                            package_id,
                            revision,
                        },
                    )
                    .collect(),
            }],
            || Ok(()),
        )?;
        let installed = InstalledContext {
            grant: PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::new([1; 16], vec![source.clone()]),
                expires_utc_ns: None,
                authorization_id: None,
            },
            root: PackageRefV1 {
                package_id: descriptor.id.clone(),
                revision: descriptor.revision.clone(),
            },
            parameters: None,
            readiness: PackageReadinessV1::Ready,
            status_checkpoint: 0,
            prepared: true,
            clock: ClockDependency::None,
        };
        Ok(store.activate_package(
            &PackageActivationV1 {
                key: PackageKeyV1 {
                    tenant_id: [1; 16],
                    scope_id: "scope".into(),
                    package_id: descriptor.id,
                    export: model.name.clone(),
                },
                revision: descriptor.revision,
                generation: 0,
                checkpoint_revision: 0,
                result_id: None,
                grant_id: "fixture".into(),
                metadata: serde_json::to_vec(&installed)?,
                active: true,
            },
            None,
            None,
            || Ok(()),
        )?)
    }

    fn event_into(
        store: &AnalysisStore,
        source: &EvidenceIntakeIdentityV1,
        cursor: u64,
    ) -> araphor_data::Result<()> {
        let payload = EvidenceRecord {
            operation: 7,
            ..Default::default()
        }
        .encode_to_vec();
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
        store.accept_validated_batch(
            source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: NOW - 1,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        Ok(())
    }

    fn watch(&self, model_clock: bool) -> Result<InputOperation> {
        self.inputs.watch(
            Arc::clone(&self.engine),
            self.active.clone(),
            self.clock.clone(),
            model_clock,
        )
    }

    fn commit(
        &self,
        operation: &InputOperation,
        input: &InputSet,
        id: &str,
        time: u64,
    ) -> TestResult<PackageResultRefV1> {
        Ok(self
            .store
            .commit_package(&self.commit_input(operation, input, id, time)?, || Ok(()))?)
    }

    fn commit_input(
        &self,
        operation: &InputOperation,
        input: &InputSet,
        id: &str,
        time: u64,
    ) -> TestResult<PackageCommitV1> {
        let data = sdk::Dataset {
            name: "result".into(),
            batches: vec![sdk::RecordBatch::try_new(
                Arc::new(self.model.outputs[0].schema.clone()),
                vec![Arc::new(sdk::arrow_array::UInt64Array::from(vec![1]))],
            )?],
        };
        Ok(PackageCommitV1 {
            activation: operation.activation().clone(),
            expected_checkpoint_revision: operation.activation().checkpoint_revision,
            window_id: "window".into(),
            result_id: id.into(),
            request: b"request".to_vec(),
            metadata: serde_json::to_vec(&ResultContext::new(id, time, &input.inputs))?,
            datasets: serde_json::to_vec(&sdk::wire::Output {
                datasets: vec![sdk::wire::Dataset::encode(
                    &data,
                    &self.model.outputs[0].schema,
                )?],
                ..Default::default()
            })?,
            checkpoint: Vec::new(),
            dependencies: input.dependencies().cloned().collect(),
            source_revisions: input.source_revisions(),
            witnesses: input.witnesses().cloned().collect(),
            context_refs: input.contexts().cloned().collect(),
            created_utc_ns: operation.now(),
        })
    }
}

fn count(input: &InputSet) -> u64 {
    input.inputs[0].data.batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<sdk::arrow_array::UInt64Array>()
        .unwrap()
        .value(0)
}

async fn next(operation: &mut InputOperation) -> TestResult<Arc<InputSet>> {
    Ok(
        tokio::time::timeout(Duration::from_secs(5), operation.next())
            .await??
            .ok_or("operation ended")?,
    )
}

#[tokio::test]
async fn commit_quiet_source_change() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let first = next(&mut operation).await?;
    assert_eq!(count(&first), 1);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    let receipt = fixture.commit(&operation, &first, "first", operation.now())?;
    operation.complete(&receipt).await?;
    let pending = operation.next();
    tokio::pin!(pending);
    tokio::select! {
        value = &mut pending => panic!("quiet input returned: {}", value?.is_some()),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    Fixture::event_into(&fixture.store, &fixture.source, 2)?;
    let changed = tokio::time::timeout(Duration::from_secs(5), pending)
        .await??
        .ok_or("source update")?;
    assert_eq!(count(&changed), 2);
    Ok(())
}

#[tokio::test]
async fn busy_retains_cut_stage() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let first = next(&mut operation).await?;
    assert!(Arc::ptr_eq(first.memory(), operation.memory()));
    assert!(!Arc::ptr_eq(first.memory(), fixture.engine.memory()));
    operation.control = Arc::new(operation.control.stage(Some(Duration::from_nanos(1)))?);
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert!(operation.control.check().is_err());
    operation.retry();
    let retried = next(&mut operation).await?;
    assert!(Arc::ptr_eq(&first, &retried));
    assert!(Arc::ptr_eq(retried.memory(), operation.memory()));
    assert_eq!(operation.now(), NOW);
    first.check(&fixture.engine, operation.control())?;
    let mut session = fixture.engine.session(
        operation.grant.selection.clone(),
        operation.control(),
        operation.now(),
    )?;
    first.register(&mut session)?;
    Ok(())
}

#[tokio::test]
async fn global_notice_invalidates_cut() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let first = next(&mut operation).await?;
    let mut other = fixture.source.clone();
    other.tenant_id = [9; 16];
    Fixture::event_into(&fixture.store, &other, 1)?;
    operation.retry();
    let second = next(&mut operation).await?;
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(first.inputs[0].revision, second.inputs[0].revision);
    assert!(
        second
            .snapshot
            .as_ref()
            .unwrap()
            .page
            .extraction
            .meta
            .commit_revision
            > first
                .snapshot
                .as_ref()
                .unwrap()
                .page
                .extraction
                .meta
                .commit_revision
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_commit_rearms_capture() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let store = Arc::clone(&fixture.store);
    let source = fixture.source.clone();
    operation
        .control()
        .on_read_step(move || Fixture::event_into(&store, &source, 2))?;
    let captured = next(&mut operation).await?;
    assert_eq!(count(&captured), 2);
    assert_eq!(
        captured.snapshot.as_ref().unwrap().page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        2
    );
    Ok(())
}

#[tokio::test]
async fn clocks_select_input_recapture() -> TestResult {
    for input_clock in [false, true] {
        let fixture = Fixture::new(input_clock)?;
        let mut operation = fixture.watch(true)?;
        let first = next(&mut operation).await?;
        let receipt = fixture.commit(&operation, &first, "tick-first", operation.now())?;
        operation.complete(&receipt).await?;
        fixture.clock.set(NOW + 500_000_000);
        let second = next(&mut operation).await?;
        assert!(Arc::ptr_eq(second.memory(), operation.memory()));
        assert_eq!(Arc::ptr_eq(&first, &second), !input_clock);
        assert_eq!(operation.now(), NOW + 500_000_000);
        assert_eq!(
            second.now,
            if input_clock { NOW + 500_000_000 } else { NOW }
        );
    }
    Ok(())
}

#[tokio::test]
async fn stable_clock_recaptures_quietly() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    fixture.model.inputs[1].source = sdk::InputSource::Query(
        "SELECT date_bin(INTERVAL '1 day', now(), TIMESTAMP '1970-01-01 00:00:00') AS value".into(),
    );
    fixture.active = Fixture::install(
        &fixture.store,
        &fixture.source,
        &fixture.model,
        "stable-input-clock",
    )?;
    fixture.inputs = Arc::new(Inputs::admit(&fixture.engine, &fixture.model)?);
    assert!(fixture.inputs.input_clock());
    let mut operation = fixture.watch(false)?;
    let first = next(&mut operation).await?;
    let receipt = fixture.commit(&operation, &first, "stable-clock-first", operation.now())?;
    operation.complete(&receipt).await?;
    let control = Arc::clone(operation.control());
    let pending = operation.next();
    tokio::pin!(pending);
    for offset in [1, 2] {
        let (captured, observed) = tokio::sync::oneshot::channel();
        control.on_read_step(move || {
            let _sent = captured.send(());
            Ok(())
        })?;
        fixture.clock.set(NOW + offset * 500_000_000);
        tokio::select! {
            result = &mut pending => {
                result?;
                return Err("stable input clock returned a backend offer".into());
            }
            result = tokio::time::timeout(Duration::from_secs(5), observed) => { result??; }
        }
        tokio::select! {
            result = &mut pending => {
                result?;
                return Err("stable captured values returned a backend offer".into());
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    Fixture::event_into(&fixture.store, &fixture.source, 2)?;
    let changed = tokio::time::timeout(Duration::from_secs(5), pending)
        .await??
        .ok_or("changed input")?;
    assert_eq!(count(&changed), 2);
    assert_eq!(changed.inputs[1].revision, first.inputs[1].revision);
    Ok(())
}

#[tokio::test]
async fn completion_renews_stage() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let input = next(&mut operation).await?;
    operation.control = Arc::new(operation.control.stage(Some(Duration::from_nanos(1)))?);
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert!(operation.control.check().is_err());
    let receipt = fixture.commit(
        &operation,
        &input,
        "after-capture-deadline",
        operation.now(),
    )?;
    operation.complete(&receipt).await?;
    assert_eq!(
        operation.activation().result_id.as_deref(),
        Some("after-capture-deadline")
    );
    assert_eq!(
        operation.activation().checkpoint_revision,
        receipt.commit_revision
    );
    operation.control.check()?;
    Ok(())
}

#[tokio::test]
async fn completion_requires_matching_receipt() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let input = next(&mut operation).await?;
    assert!(operation
        .complete(&PackageResultRefV1 {
            result_id: "forged".into(),
            commit_revision: 99
        })
        .await
        .is_err());
    assert_eq!(operation.activation(), &fixture.active);
    let receipt = fixture.commit(&operation, &input, "actual", operation.now())?;
    let wrong = PackageResultRefV1 {
        commit_revision: receipt.commit_revision + 1,
        ..receipt.clone()
    };
    assert!(operation.complete(&wrong).await.is_err());
    operation.active.generation += 1;
    assert!(operation.complete(&receipt).await.is_err());
    operation.active.generation -= 1;
    operation.complete(&receipt).await?;
    assert_eq!(operation.activation().result_id.as_deref(), Some("actual"));
    assert!(!operation.offered);
    Ok(())
}

#[tokio::test]
async fn completion_checks_time_generation() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let input = next(&mut operation).await?;
    let receipt = fixture.commit(&operation, &input, "wrong-time", operation.now() + 1)?;
    assert!(operation.complete(&receipt).await.is_err());
    assert_eq!(operation.activation(), &fixture.active);
    operation.retry();
    assert!(operation.next().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn restart_skips_input_capacity() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let input = next(&mut operation).await?;
    let receipt = fixture.commit(&operation, &input, "before-crash", operation.now())?;
    drop(operation);
    drop(input);
    let active = fixture
        .store
        .package_activation(&fixture.active.key)?
        .ok_or("active head")?;
    let held = fixture.engine.memory().reserve_input(
        fixture
            .engine
            .limits()
            .input_capacity
            .expect("configured input capacity"),
    )?;
    let mut restarted = fixture.inputs.watch(
        Arc::clone(&fixture.engine),
        active,
        fixture.clock.clone(),
        false,
    )?;
    let pending = restarted.next();
    tokio::pin!(pending);
    tokio::select! {
        value = &mut pending => panic!("current restart returned: {}", value?.is_some()),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    let control = fixture
        .store
        .package_activation(&fixture.active.key)?
        .ok_or("committed activation")?;
    assert_eq!(control.checkpoint_revision, receipt.commit_revision);
    drop(held);
    Ok(())
}

#[tokio::test]
async fn fresh_cut_suppresses_unchanged() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let input = next(&mut operation).await?;
    let receipt = fixture.commit(&operation, &input, "unchanged", operation.now())?;
    operation.complete(&receipt).await?;
    let mut other = fixture.source.clone();
    other.tenant_id = [9; 16];
    Fixture::event_into(&fixture.store, &other, 1)?;
    let pending = operation.next();
    tokio::pin!(pending);
    tokio::select! {
        value = &mut pending => panic!("unchanged input returned: {}", value?.is_some()),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    Fixture::event_into(&fixture.store, &fixture.source, 2)?;
    let changed = tokio::time::timeout(Duration::from_secs(5), pending)
        .await??
        .ok_or("changed input")?;
    assert_eq!(count(&changed), 2);
    Ok(())
}

#[tokio::test]
async fn raw_recapture_renews_lease() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let first = next(&mut operation).await?;
    let expiry = first
        .witnesses()
        .map(|witness| witness.expires_utc_ns)
        .min()
        .ok_or("live witness")?;
    fixture.clock.set(expiry);
    operation.retry();
    let expired = next(&mut operation).await?;
    assert!(!Arc::ptr_eq(&first, &expired));
    assert_eq!(count(&expired), count(&first));
    assert_eq!(expired.witnesses().count(), 1);
    assert_eq!(
        expired.witnesses().next().unwrap().expires_utc_ns,
        expired.now + 7 * 24 * 60 * 60 * 1_000_000_000
    );
    assert_eq!(expired.inputs[0].coverage, first.inputs[0].coverage);
    Ok(())
}

#[tokio::test]
async fn expired_capture_keeps_unknown() -> TestResult {
    let mut fixture = Fixture::new(false)?;
    let mut upstream = fixture.model.clone();
    upstream.inputs.clear();
    let active = Fixture::install(
        &fixture.store,
        &fixture.source,
        &upstream,
        "expired-upstream",
    )?;
    let definition = Arc::new(Inputs::admit(&fixture.engine, &upstream)?);
    let mut operation = definition.watch(
        Arc::clone(&fixture.engine),
        active,
        fixture.clock.clone(),
        false,
    )?;
    let input = next(&mut operation).await?;
    let mut commit = fixture.commit_input(&operation, &input, "expired-output", NOW - 100)?;
    commit.created_utc_ns = NOW - 100;
    commit.witnesses = vec![araphor_data::AnalysisWitnessV1 {
        identity: fixture.source.clone().into(),
        cursor: 1,
        expires_utc_ns: NOW - 1,
    }];
    let receipt = fixture.store.commit_package(&commit, || Ok(()))?;
    drop(operation);
    drop(input);
    fixture.model.inputs[0].source =
        sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "expired-upstream".into(),
            revision: "v1".into(),
            export: upstream.name,
            output: "result".into(),
        }));
    fixture.active = Fixture::install(
        &fixture.store,
        &fixture.source,
        &fixture.model,
        "expired-input",
    )?;
    fixture.inputs = Arc::new(Inputs::admit(&fixture.engine, &fixture.model)?);
    let mut operation = fixture.watch(false)?;
    let expired = next(&mut operation).await?;
    assert_eq!(count(&expired), 1);
    assert_eq!(expired.dependencies().collect::<Vec<_>>(), vec![&receipt]);
    assert_eq!(
        expired.snapshot.as_ref().unwrap().witnesses[0].expires_utc_ns,
        NOW - 1
    );
    assert_eq!(expired.witnesses().count(), 0);
    assert_eq!(
        expired.inputs[0].coverage.state,
        sdk::CoverageState::Unknown
    );
    assert!(expired.inputs[0]
        .coverage
        .limits
        .iter()
        .any(|limit| limit == "source evidence retention expired"));
    Ok(())
}

#[tokio::test]
async fn quiet_cancel_expiry_release() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let input = next(&mut operation).await?;
    let expiry = input
        .snapshot
        .as_ref()
        .unwrap()
        .witnesses
        .iter()
        .map(|witness| witness.expires_utc_ns)
        .min()
        .ok_or("raw witness")?;
    fixture.clock.set(expiry);
    operation.changed().await?;
    assert!(!operation.valid(expiry).await?);
    operation.pending = None;
    drop(input);
    operation.witness = u64::MAX;
    operation.progress.clear();
    operation.progress.begin()?;
    let control = Arc::clone(operation.control());
    {
        let waiting = operation.changed();
        tokio::pin!(waiting);
        tokio::select! {
            result = &mut waiting => panic!("quiet wait ended early: {}", result.is_ok()),
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
        control.cancel()?;
        assert_eq!(
            crate::Failure::from(
                &tokio::time::timeout(Duration::from_secs(1), waiting)
                    .await?
                    .unwrap_err()
            ),
            crate::Failure::Cancelled
        );
    }
    drop(operation);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    drop(
        fixture.engine.memory().reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .expect("configured input capacity"),
        )?,
    );
    Ok(())
}

#[tokio::test]
async fn drop_retains_input_capacity() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let input = next(&mut operation).await?;
    let parent = Arc::clone(operation.control());
    drop(operation);
    let error = crate::Error::from(parent.check().unwrap_err());
    assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .expect("configured input capacity")
        )
        .is_err());
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    {
        let mut session = fixture.engine.session_on(
            input.snapshot.as_ref().unwrap().selection.clone(),
            &control,
            input.now,
            Arc::clone(input.memory()),
        )?;
        input.register(&mut session)?;
    }
    drop(input);
    drop(
        fixture.engine.memory().reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .expect("configured input capacity"),
        )?,
    );
    Ok(())
}

#[tokio::test]
async fn idle_clock_waits_for_data() -> TestResult {
    for clocked in [false, true] {
        let fixture = Fixture::new(clocked)?;
        let mut operation = fixture.watch(true)?;
        let first = next(&mut operation).await?;
        let receipt = fixture.commit(&operation, &first, "idle-first", operation.now())?;
        operation.complete(&receipt).await?;
        let control = Arc::clone(operation.control());
        // Wait for the operation, validation, and idle clock reads.
        let idle = fixture.clock.after_reads(3);
        let pending = operation.next();
        tokio::pin!(pending);
        tokio::select! {
            value = &mut pending => panic!("completion repeated an offer: {}", value?.is_some()),
            ready = tokio::time::timeout(Duration::from_secs(5), idle) => { ready??; }
        }
        let clock_reads = fixture
            .clock
            .reads
            .load(std::sync::atomic::Ordering::SeqCst);
        fixture
            .clock
            .now
            .store(NOW + 650_000_123, std::sync::atomic::Ordering::SeqCst);
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&reads);
        control.on_read_step(move || {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })?;
        tokio::select! {
            value = &mut pending => panic!("idle clock repeated an offer: {}", value?.is_some()),
            _ = tokio::time::sleep(Duration::from_millis(650)) => {}
        }
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            fixture
                .clock
                .reads
                .load(std::sync::atomic::Ordering::SeqCst),
            clock_reads
        );
        Fixture::event_into(&fixture.store, &fixture.source, 2)?;
        let second = tokio::time::timeout(Duration::from_secs(5), pending)
            .await??
            .ok_or("source update")?;
        assert_eq!(count(&second), 2);
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    Ok(())
}

#[tokio::test]
async fn source_deadline_fires_once() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let first = next(&mut operation).await?;
    let time = operation.now();
    operation.progress.captured(
        first
            .snapshot
            .as_ref()
            .ok_or("snapshot")?
            .page
            .extraction
            .meta
            .commit_revision,
        Some(NOW - 3),
    );
    operation.changed().await?;
    assert!(operation.clock_changed);
    operation.witness = NOW - 2;
    tokio::time::timeout(Duration::from_secs(1), operation.changed()).await??;
    {
        let changed = operation.changed();
        tokio::pin!(changed);
        tokio::select! {
            value = &mut changed => panic!("source deadline repeated: {}", value.is_ok()),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    operation.retry();
    let retried = next(&mut operation).await?;
    assert!(Arc::ptr_eq(&first, &retried));
    assert_eq!(operation.now(), time);
    Ok(())
}

#[tokio::test]
async fn window_expires_without_commit() -> TestResult {
    let mut fixture = Fixture::new(false)?;
    fixture.model.inputs[0].source = sdk::InputSource::Query(
        "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM events WHERE received_at >= now() - INTERVAL '2 seconds'".into(),
    );
    fixture.active = Fixture::install(
        &fixture.store,
        &fixture.source,
        &fixture.model,
        "window-input",
    )?;
    fixture.inputs = Arc::new(Inputs::admit(&fixture.engine, &fixture.model)?);
    let mut operation = fixture.watch(false)?;
    let first = next(&mut operation).await?;
    assert_eq!(count(&first), 1);
    let expiry = first.expiry.ok_or("window expiry")?;
    assert_eq!(expiry, (NOW - 1) / 1000 * 1000 + 2_000_000_000 + 1000);
    let receipt = fixture.commit(&operation, &first, "window-first", operation.now())?;
    operation.complete(&receipt).await?;
    fixture.clock.set(expiry);
    let second = next(&mut operation).await?;
    assert_eq!(count(&second), 0);
    assert_eq!(second.now, expiry);
    assert_eq!(second.expiry, None);
    Ok(())
}

#[tokio::test]
async fn idle_stage_renews_on_event() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(false)?;
    let first = next(&mut operation).await?;
    let receipt = fixture.commit(&operation, &first, "idle-stage", operation.now())?;
    operation.complete(&receipt).await?;
    operation.control = Arc::new(operation.control.stage(Some(Duration::from_millis(10)))?);
    let control = Arc::clone(operation.control());
    let pending = operation.next();
    tokio::pin!(pending);
    tokio::select! {
        value = &mut pending => panic!("idle stage returned: {}", value?.is_some()),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    assert!(control.check().is_err());
    Fixture::event_into(&fixture.store, &fixture.source, 2)?;
    let second = tokio::time::timeout(Duration::from_secs(5), pending)
        .await??
        .ok_or("source update")?;
    assert_eq!(count(&second), 2);
    second.check(
        &fixture.engine,
        &AnalysisReadControl::with_timeout(Duration::from_secs(1))?,
    )?;
    Ok(())
}

#[tokio::test]
async fn capture_preserves_clock_notice() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(true)?;
    let clock = Arc::clone(&fixture.clock);
    operation.control().on_read_step(move || {
        clock.set(NOW + 123);
        Ok(())
    })?;
    let first = next(&mut operation).await?;
    let time = operation.now();
    assert_eq!(time, NOW);
    operation.changed().await?;
    assert!(operation.clock_changed);
    let retried = next(&mut operation).await?;
    assert!(Arc::ptr_eq(&first, &retried));
    assert_eq!(operation.now(), time);
    let receipt = fixture.commit(&operation, &first, "clock-captured", time)?;
    operation.complete(&receipt).await?;
    let second = next(&mut operation).await?;
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(second.now, time);
    assert_eq!(operation.now(), NOW + 123);
    Ok(())
}

struct ClosedClock;

impl Clock for ClosedClock {
    fn now_ns(&self) -> Result<u64> {
        Ok(NOW)
    }
    fn changes(&self) -> watch::Receiver<u64> {
        watch::channel(0).1
    }
}

#[tokio::test]
async fn closed_clock_ends_wait() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.inputs.watch(
        Arc::clone(&fixture.engine),
        fixture.active.clone(),
        Arc::new(ClosedClock),
        false,
    )?;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), operation.changed())
            .await?
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn clock_demand_survives_busy() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut operation = fixture.watch(true)?;
    let first = next(&mut operation).await?;
    let receipt = fixture.commit(&operation, &first, "before-busy", operation.now())?;
    operation.complete(&receipt).await?;
    let active = operation.activation().clone();
    drop(operation);
    let mut restarted = fixture.inputs.watch(
        Arc::clone(&fixture.engine),
        active,
        fixture.clock.clone(),
        true,
    )?;
    fixture.clock.set(NOW + 123);
    let held = fixture.engine.reserve_evaluation([1; 16])?;
    let failure = tokio::time::timeout(Duration::from_secs(5), restarted.next())
        .await?
        .err()
        .ok_or("input capacity was not busy")?;
    assert_eq!(crate::Failure::from(&failure), crate::Failure::Busy);
    assert!(restarted.clock_changed);
    drop(held);
    restarted.retry();
    let second = next(&mut restarted).await?;
    assert_eq!(count(&second), 1);
    assert_eq!(restarted.now(), NOW + 123);
    assert_eq!(second.inputs[0].revision, first.inputs[0].revision);
    Ok(())
}

#[test]
fn stage_uses_grant_deadline() -> TestResult {
    let mut grant = PackageGrantV1 {
        principal: "fixture".into(),
        revision: 1,
        selection: AnalysisSelectionV1::tenant([1; 16]),
        expires_utc_ns: None,
        authorization_id: None,
    };
    let unbounded = InputOperation::stage(&grant, NOW, None)?;
    assert_eq!(unbounded.remaining()?, None);
    grant.expires_utc_ns = Some(NOW + 75_000_000_000);
    let bounded = InputOperation::stage(&grant, NOW, None)?;
    assert!(bounded.remaining()?.ok_or("grant deadline absent")? > Duration::from_secs(30));
    let parent = AnalysisReadControl::with_timeout(Duration::from_secs(1))?;
    let child = InputOperation::stage(&grant, NOW, Some(&parent))?;
    assert!(child.remaining()?.ok_or("grant deadline absent")? > Duration::from_secs(30));
    grant.expires_utc_ns = None;
    let child = InputOperation::stage(&grant, NOW, Some(&parent))?;
    assert_eq!(child.remaining()?, None);
    parent.cancel()?;
    assert!(child.check().is_err());
    assert!(InputOperation::stage(&grant, NOW, Some(&parent))?
        .check()
        .is_err());
    grant.expires_utc_ns = Some(NOW);
    assert!(matches!(
        InputOperation::stage(&grant, NOW, None),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: PackageErrorCodeV1::Denied,
                ..
            }
        })
    ));
    Ok(())
}
