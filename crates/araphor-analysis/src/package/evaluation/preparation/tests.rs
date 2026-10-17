use araphor_analysis_sdk as sdk;
use std::sync::Arc;
use std::time::Duration;

use crate::package::tests::{bundle, Fixture, TestResult};
use crate::package::PackageImplementationV1;
use crate::Engine;

use super::*;

const START: u64 = 946_684_800_000_000_000;
const EXPIRY: &str = "SELECT CASE WHEN CURRENT_TIMESTAMP < TIMESTAMP '2000-01-01 00:00:00.5' THEN 1::BIGINT UNSIGNED ELSE 0::BIGINT UNSIGNED END AS count";
const NOTIFICATION_COUNT: &str =
    "SELECT COUNT(*)::BIGINT UNSIGNED AS count FROM notifications WHERE NOT overdue";

fn notification_deadline(fixture: &Fixture, period: u64) -> TestResult<crate::NotificationRouter> {
    use crate::{
        ContextSensitivityV1, NotificationAuthorization, NotificationGrantV1,
        NotificationOperationV1, NotificationPolicyV1, NotificationPrincipalV1,
        NotificationPriorityV1, NotificationRouter, UnconfirmedNotificationConcernV1,
    };

    struct Authority;
    impl NotificationAuthorization for Authority {
        fn check(&self, grant: &NotificationGrantV1, _now: u64) -> araphor_data::Result<()> {
            grant.validate()
        }
    }

    let router = NotificationRouter::new(fixture.store.clone(), std::sync::Arc::new(Authority))?;
    let mut grant = NotificationGrantV1 {
        tenant_id: [1; 16],
        principal_id: [9; 16],
        principal: NotificationPrincipalV1::Human,
        authorization_revision: 1,
        routes: vec!["deadline".into()],
        operations: vec![
            NotificationOperationV1::Configure,
            NotificationOperationV1::SubmitConcern,
        ],
        max_sensitivity: ContextSensitivityV1::Tenant,
        expires_utc_ns: u64::MAX,
    };
    router.configure(
        &grant,
        NotificationPolicyV1 {
            tenant_id: [1; 16],
            route_id: "deadline".into(),
            revision: 1,
            package_ids: vec!["model-concern".into()],
            minimum_priority: NotificationPriorityV1::Info,
            acknowledgement_ns: period,
            retry_limit: 1,
            retry_delay_ns: 1,
            escalation_route_id: "deadline".into(),
            max_sensitivity: ContextSensitivityV1::Tenant,
            allow_concerns: true,
        },
        START - 1,
    )?;
    grant.principal = NotificationPrincipalV1::Agent;
    let state = router.submit_concern(
        &grant,
        "deadline",
        UnconfirmedNotificationConcernV1 {
            concern_id: [7; 16],
            model_label: "clock".into(),
            summary: "Review this concern".into(),
            context: Vec::new(),
            sensitivity: ContextSensitivityV1::Tenant,
            suggested_priority: NotificationPriorityV1::Info,
        },
        START,
    )?;
    assert_eq!(state.deadline_utc_ns, Some(START + period));
    Ok(router)
}

struct Clock {
    now: std::sync::atomic::AtomicU64,
    changes: tokio::sync::watch::Sender<u64>,
}

impl Clock {
    fn new(now: u64) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            now: std::sync::atomic::AtomicU64::new(now),
            changes: tokio::sync::watch::channel(now).0,
        })
    }

    fn set(&self, now: u64) {
        self.now.store(now, std::sync::atomic::Ordering::Release);
        self.changes.send_replace(now);
    }
}

impl araphor_query::follow::Clock for Clock {
    fn now_ns(&self) -> araphor_query::Result<u64> {
        Ok(self.now.load(std::sync::atomic::Ordering::Acquire))
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

#[tokio::test]
async fn automatic_clock_ticks() -> TestResult {
    for source in [None, Some(EXPIRY), Some(NOTIFICATION_COUNT)] {
        let fixture = Fixture::new()?;
        let period = AnalysisPackageOwner::RECONCILE_INTERVAL.as_nanos() as u64;
        let _router = if source == Some(NOTIFICATION_COUNT) {
            Some(notification_deadline(&fixture, period)?)
        } else {
            None
        };
        let mut package = bundle("1", EXPIRY);
        if let Some(sql) = source {
            let artifact = &mut package.artifacts[0];
            let mut port = artifact.descriptor.exports[0].outputs[0].clone();
            port.name = "source".into();
            artifact.descriptor.exports[0].inputs.push(sdk::InputPort {
                port,
                source: sdk::InputSource::Query(sql.into()),
            });
            let PackageImplementationV1::Sql { program, .. } = &mut artifact.implementations[0]
            else {
                return Err("SQL implementation".into());
            };
            program
                .outputs
                .insert("rows".into(), "SELECT count FROM source".into());
        }
        fixture.install(package.clone(), None).await?;
        let package =
            InstalledBundle::new(&fixture.owner.query, package, fixture.owner.query.memory())?;
        let active = fixture.store.package_activation_page(None)?.remove(0);
        let context: InstalledContext = AnalysisPackageOwner::decode(&active.metadata)?;
        assert_eq!(
            context.clock,
            if source.is_some() {
                ClockDependency::Inputs
            } else {
                ClockDependency::Model
            },
            "source: {source:?}"
        );
        let (_, _, admitted) =
            package.export(&active.key.package_id, &active.revision, &active.key.export)?;
        let clock = Clock::new(START + 123);
        let mut operation = admitted.inputs.watch(
            fixture.owner.query.clone(),
            active,
            clock.clone(),
            admitted.model_clock(),
        )?;
        assert!(!Arc::ptr_eq(
            operation.memory(),
            fixture.owner.query.memory()
        ));
        let memory = Arc::clone(operation.memory());
        let control = Arc::clone(operation.control());
        let mut active = operation.activation().clone();
        let (offers, mut arrivals) = tokio::sync::mpsc::channel(1);
        let (receipts, mut commits) = tokio::sync::mpsc::channel::<(
            crate::analysis::PackageResultRefV1,
            tokio::sync::oneshot::Sender<crate::analysis::PackageActivationV1>,
        )>(1);
        let driver = tokio::spawn(async move {
            while let Some(inputs) = operation.next().await? {
                offers
                    .send((
                        inputs,
                        operation.activation().clone(),
                        operation.now(),
                        Arc::clone(operation.control()),
                    ))
                    .await
                    .map_err(|_| {
                        crate::PackageErrorCodeV1::Incomplete.error("clock offer receiver")
                    })?;
                let Some((receipt, ack)) = commits.recv().await else {
                    break;
                };
                operation.complete(&receipt).await?;
                let _sent = ack.send(operation.activation().clone());
            }
            Ok::<_, crate::Error>(())
        });
        let result = async {
            for (offset, expected) in [(0, 1), (1, 0), (2, 0), (3, 0)] {
                let now = START + period * offset + 123;
                clock.set(now);
                if source.is_some() && offset >= 2 {
                    let meta = fixture.store.meta()?;
                    let heads = fixture.store.package_results(&active.key)?;
                    assert!(
                        tokio::time::timeout(Duration::from_millis(100), arrivals.recv())
                            .await
                            .is_err(),
                        "source: {source:?}, offset: {offset}"
                    );
                    assert_eq!(fixture.store.meta()?, meta);
                    assert_eq!(fixture.store.package_results(&active.key)?, heads);
                    assert_eq!(
                        fixture.store.package_activation(&active.key)?.as_ref(),
                        Some(&active)
                    );
                    continue;
                }
                let (inputs, selected, now, stage) =
                    tokio::time::timeout(Duration::from_secs(30), arrivals.recv())
                        .await?
                        .ok_or("clock input offer")?;
                assert_eq!(selected, active);
                assert!(Arc::ptr_eq(inputs.memory(), &memory));
                let run = crate::model::ModelRun::prepared(
                    &fixture.owner.query,
                    [1; 16],
                    &stage,
                    Arc::clone(&inputs),
                )?;
                assert!(Arc::ptr_eq(&run.memory, &memory));
                drop(run);
                let tick = START + period * offset;
                assert_eq!(now, tick);
                let request = RunPreparation {
                    inputs: Some(&inputs),
                    id: "tick",
                    rebuild: false,
                    now,
                };
                let context: InstalledContext = AnalysisPackageOwner::decode(&selected.metadata)?;
                let prepared = fixture
                    .owner
                    .prepare_model(&selected, &context, &package, request, Action::Run, &stage)?
                    .ok_or("clock evaluation")?;
                assert_eq!(prepared.created_utc_ns, tick);
                let metadata: ResultContext = AnalysisPackageOwner::decode(&prepared.metadata)?;
                assert_eq!(metadata.context.time_utc_ns, tick as i64);
                let output: sdk::wire::Output = AnalysisPackageOwner::decode(&prepared.datasets)?;
                assert_eq!(
                    crate::AnalysisPackageOwner::output_rows(&output)?["rows"],
                    serde_json::json!([{"count":expected}])
                );
                let committed = fixture.store.commit_package(&prepared, || stage.check())?;
                let (ack, acknowledged) = tokio::sync::oneshot::channel();
                receipts
                    .send((committed.clone(), ack))
                    .await
                    .map_err(|_| "clock commit receiver")?;
                active = acknowledged.await?;
                let stored = fixture.result(&committed.result_id)?;
                let saved: ResultContext = AnalysisPackageOwner::decode(&stored.commit.metadata)?;
                assert_eq!(saved.context.time_utc_ns, tick as i64);
                clock.set(tick + period - 1);
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), arrivals.recv())
                        .await
                        .is_err()
                );
                assert_eq!(
                    fixture.store.package_activation(&active.key)?.as_ref(),
                    Some(&active)
                );
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;
        drop(receipts);
        control.cancel()?;
        let stopped = driver.await?;
        result?;
        match stopped {
            Err(error)
                if erebor_runtime_error::ErrorExt::status_code(&error)
                    == erebor_runtime_error::StatusCode::Cancelled => {}
            Err(error) => return Err(error.into()),
            Ok(()) => return Err("clock actor ended without cancellation".into()),
        }
        let active = fixture.store.package_activation_page(None)?.remove(0);
        fixture.owner.inspect(
            &fixture.grant,
            "test",
            &active.key.package_id,
            Some(&package),
            &AnalysisReadControl::with_timeout(Duration::from_secs(30))?,
        )?;
        let stored = fixture.result(active.result_id.as_deref().ok_or("active result")?)?;
        assert_eq!(stored.stale, source.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn unchanged_model_stays_current() -> TestResult {
    let fixture = Fixture::new()?;
    let package = bundle("1", "SELECT 3::BIGINT UNSIGNED AS count");
    fixture.install(package.clone(), None).await?;
    let package =
        InstalledBundle::new(&fixture.owner.query, package, fixture.owner.query.memory())?;
    let active = fixture.store.package_activation_page(None)?.remove(0);
    let (_, _, admitted) =
        package.export(&active.key.package_id, &active.revision, &active.key.export)?;
    let mut operation = admitted.inputs.watch(
        fixture.owner.query.clone(),
        active.clone(),
        Clock::new(START),
        false,
    )?;
    let parent = Arc::clone(operation.control());
    let pending = operation.next();
    tokio::pin!(pending);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut pending)
            .await
            .is_err()
    );
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let context: InstalledContext = AnalysisPackageOwner::decode(&active.metadata)?;
    let manual = fixture
        .owner
        .prepare_model(
            &active,
            &context,
            &package,
            RunPreparation {
                inputs: None,
                id: "manual",
                rebuild: false,
                now: START + 123,
            },
            Action::Run,
            &control,
        )?
        .ok_or("manual")?;
    let metadata: ResultContext = AnalysisPackageOwner::decode(&manual.metadata)?;
    assert_eq!(metadata.context.time_utc_ns, (START + 123) as i64);
    parent.cancel()?;
    assert!(matches!(
        pending.await,
        Err(araphor_query::Error::Data {
            source: araphor_data::Error::AnalysisReadCancelled { .. },
        })
    ));
    Ok(())
}

#[tokio::test]
async fn unchanged_input_skips_extraction() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = bundle("1", "SELECT count FROM source");
    let artifact = &mut package.artifacts[0];
    let mut port = artifact.descriptor.exports[0].outputs[0].clone();
    port.name = "source".into();
    artifact.descriptor.exports[0].inputs.push(sdk::InputPort {
        port,
        source: sdk::InputSource::Query(
            "SELECT COUNT(*)::BIGINT UNSIGNED AS count FROM context_versions".into(),
        ),
    });
    fixture.install(package.clone(), None).await?;
    let package =
        InstalledBundle::new(&fixture.owner.query, package, fixture.owner.query.memory())?;
    let owner = AnalysisPackageOwner::new(
        Engine::new(
            fixture.store.clone(),
            crate::Limits {
                input_bytes: 1,
                input_capacity: 1,
                ..Default::default()
            },
        )?,
        fixture.authority.clone(),
    )?;
    let active = fixture.store.package_activation_page(None)?.remove(0);
    let (_, _, admitted) =
        package.export(&active.key.package_id, &active.revision, &active.key.export)?;
    let mut operation =
        admitted
            .inputs
            .watch(owner.query.clone(), active, Clock::new(START), false)?;
    let pending = operation.next();
    tokio::pin!(pending);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut pending)
            .await
            .is_err()
    );
    fixture
        .store
        .commit_context(&crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "input-notice".into(),
                entity_key: vec![1],
                lifetime_key: vec![1],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: b"{}".to_vec(),
        })?;
    assert!(tokio::time::timeout(Duration::from_secs(30), &mut pending)
        .await?
        .is_err());
    Ok(())
}
