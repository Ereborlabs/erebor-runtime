use std::time::Duration;

use crate::package::tests::{bundle, Fixture, TestResult};
use crate::package::{PackageImplementationV1, PackageOutputV1};

use super::*;

const START: u64 = 946_684_800_000_000_000;
const EXPIRY: &str = "SELECT CASE WHEN CURRENT_TIMESTAMP < TIMESTAMP '2000-01-01 00:00:00.5' THEN 1::UBIGINT ELSE 0::UBIGINT END AS count";
const NOTIFICATION_COUNT: &str =
    "SELECT COUNT(*)::UBIGINT AS count FROM notifications WHERE NOT overdue";

fn notification_deadline(fixture: &Fixture, period: u64) -> TestResult<crate::NotificationRouter> {
    use crate::{
        ContextSensitivityV1, NotificationAuthorization, NotificationGrantV1,
        NotificationOperationV1, NotificationPolicyV1, NotificationPrincipalV1,
        NotificationPriorityV1, NotificationRouter, UnconfirmedNotificationConcernV1,
    };

    struct Authority;
    impl NotificationAuthorization for Authority {
        fn check(&self, grant: &NotificationGrantV1, _now: u64) -> Result<()> {
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
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        for (offset, expected) in [(0, 1), (1, 0), (2, 0), (3, 0)] {
            let now = START + period * offset + 123;
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
            assert!(!fixture
                .owner
                .inputs_current(&active, context.clock, now, false, &control)?);
            let prior = if source.is_some() && offset >= 2 {
                Some((
                    fixture.store.meta()?,
                    fixture.store.package_results(&active.key)?,
                ))
            } else {
                None
            };
            let request = RunPreparation {
                id: "tick",
                rebuild: false,
                automatic: true,
                now,
            };
            let prepared = fixture
                .owner
                .prepare_at(&active, &package, request, &control)?;
            if let Some((meta, heads)) = prior {
                assert!(prepared.is_none(), "source: {source:?}, offset: {offset}");
                assert_eq!(fixture.store.meta()?, meta);
                assert_eq!(fixture.store.package_results(&active.key)?, heads);
                assert_eq!(
                    fixture.store.package_activation(&active.key)?.as_ref(),
                    Some(&active)
                );
                continue;
            }
            let prepared = prepared.ok_or("clock evaluation")?;
            let tick = AnalysisPackageOwner::clock_tick(now);
            assert_eq!(prepared.created_utc_ns, tick);
            let metadata: ResultContext = AnalysisPackageOwner::decode(&prepared.metadata)?;
            assert_eq!(metadata.context.time_utc_ns, tick as i64);
            let output: PackageOutputV1 = AnalysisPackageOwner::decode(&prepared.datasets)?;
            assert_eq!(
                output.json_rows()?["rows"],
                serde_json::json!([{"count":expected}])
            );
            let committed = fixture
                .store
                .commit_package(&prepared, || control.check())?;
            let stored = fixture
                .store
                .package_result([1; 16], &committed.result_id)?
                .ok_or("committed result")?;
            let saved: ResultContext = AnalysisPackageOwner::decode(&stored.metadata)?;
            assert_eq!(saved.context.time_utc_ns, tick as i64);
            let active = fixture.store.package_activation_page(None)?.remove(0);
            let repeated = RunPreparation {
                id: "same-tick",
                rebuild: false,
                automatic: true,
                now: tick + period - 1,
            };
            assert!(fixture
                .owner
                .prepare_at(&active, &package, repeated, &control)?
                .is_none());
            assert_eq!(
                fixture.store.package_activation(&active.key)?.as_ref(),
                Some(&active)
            );
        }
        let active = fixture.store.package_activation_page(None)?.remove(0);
        fixture.owner.refresh(
            &active,
            &package.artifacts[0].descriptor.exports[0],
            &fixture.grant,
            &control,
        )?;
        let stored = fixture
            .store
            .package_result([1; 16], active.result_id.as_deref().ok_or("active result")?)?
            .ok_or("stored result")?;
        assert_eq!(stored.stale, source.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn unchanged_model_stays_current() -> TestResult {
    let fixture = Fixture::new()?;
    let package = bundle("1", "SELECT 3::UBIGINT AS count");
    fixture.install(package.clone(), None).await?;
    let active = fixture.store.package_activation_page(None)?.remove(0);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let request = RunPreparation {
        id: "tick",
        rebuild: false,
        automatic: true,
        now: START,
    };
    assert!(fixture
        .owner
        .prepare_at(&active, &package, request, &control)?
        .is_none());
    let request = RunPreparation {
        id: "manual",
        rebuild: false,
        automatic: false,
        now: START + 123,
    };
    let manual = fixture
        .owner
        .prepare_at(&active, &package, request, &control)?
        .ok_or("manual")?;
    let metadata: ResultContext = AnalysisPackageOwner::decode(&manual.metadata)?;
    assert_eq!(metadata.context.time_utc_ns, (START + 123) as i64);
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
            "SELECT COUNT(*)::UBIGINT AS count FROM context_versions".into(),
        ),
    });
    fixture.install(package.clone(), None).await?;
    let owner = AnalysisPackageOwner::new(
        fixture.store.clone(),
        std::sync::Arc::new(QueryOwner::new(
            fixture.store.clone(),
            crate::QueryLimits {
                input_bytes: 1,
                input_capacity: 1,
                ..Default::default()
            },
        )?),
        fixture.authority.clone(),
    )?;
    let active = fixture.store.package_activation_page(None)?.remove(0);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    assert!(owner
        .prepare_at(
            &active,
            &package,
            RunPreparation {
                id: "unchanged",
                rebuild: false,
                automatic: true,
                now: START,
            },
            &control
        )?
        .is_none());
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
    assert!(owner
        .prepare_at(
            &active,
            &package,
            RunPreparation {
                id: "changed",
                rebuild: false,
                automatic: true,
                now: START,
            },
            &control
        )
        .is_err());
    Ok(())
}
