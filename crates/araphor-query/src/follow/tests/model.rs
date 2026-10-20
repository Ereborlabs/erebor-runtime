use araphor_analysis_sdk as sdk;
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_package::{
    PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1, SqlModelV1,
};

use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn model_notification_deadlines() -> TestResult {
    for source in [
        sdk::InputSource::Table(sdk::TableRef::Named("notifications".into())),
        sdk::InputSource::Query("SELECT notification_revision FROM notifications WHERE overdue".into()),
        sdk::InputSource::Query("WITH unused AS (SELECT notification_revision FROM notifications) SELECT CAST(1 AS BIGINT UNSIGNED) AS notification_revision".into()),
    ] {
        let fixture = Fixture::new(Limits::default());
        fixture.notification(100);
        let scalar = |name| sdk::Schema::new(vec![sdk::Field::new(name, sdk::DataType::UInt64, false)]);
        let mut model = sdk::Model::new("count", Vec::new(), vec![sdk::Port::new("result", scalar("value"))]);
        model.input_mode = sdk::InputMode::Resolved;
        model.inputs = vec![sdk::InputPort { port: sdk::Port::new("notices", scalar("notification_revision")), source }];
        let image = PackageBundleV1 {
            schema_version: 1,
            root: PackageRefV1 { package_id: "clock-model".into(), revision: "1".into() },
            artifacts: vec![PackageArtifactV1 {
                descriptor: sdk::Package::new("clock-model", "1", vec![model]),
                implementations: vec![PackageImplementationV1::Sql { export: "count".into(), program: SqlModelV1 {
                    outputs: BTreeMap::from([("result".into(), "SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into())]),
                    ..Default::default()
                }}],
                fixtures: Vec::new(),
            }],
        };
        fixture.store.install_package_image(fixture.source.tenant_id, &image, || Ok(()))?;
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(20))?;
        let prepared = fixture.engine.prepare_definition(fixture.source.tenant_id, &Definition {
            name: "notification-clock".into(), description: "Select the notification deadline.".into(), labels: BTreeMap::new(),
            program: Program::Sql { source: Source::Inline { inline: r#"SELECT * FROM "clock-model"."1".count()"#.into() } },
        }, Arc::new(control.within(None)?)).await?;
        assert!(prepared.sources().contains_key("notifications"));
        assert_eq!(Window::clocks(&prepared.plan)?, 0);
        let clock = TestClock::new(99);
        let session = fixture.engine.session(AnalysisSelectionV1::tenant(fixture.source.tenant_id), &control, 0)?;
        let mut subscription = Subscription::new(session, Arc::new(prepared.plan.clone()), prepared.sources().clone(), b"model notification clock", None, clock.clone(), true)?;
        let first = next(&mut subscription).await;
        assert_eq!(first.operation, Operation::Replace);
        assert_eq!(values(&first, 0), [ScalarValue::UInt64(Some(7))]);
        assert_eq!(first.snapshot.next_change, Some(100));
        assert_eq!(first.calls.len(), 1);
        let call = first.calls.values().next().ok_or("initial model call")?;
        assert_eq!(call.evaluation().context.time_utc_ns, 99);
        let before = fixture.store.meta()?;
        clock.set(100);
        let overdue = next(&mut subscription).await;
        assert!(overdue.clock_changed);
        assert_eq!(overdue.evaluated_utc_ns, 100);
        assert_eq!(overdue.snapshot.next_change, None);
        assert!(overdue.batches.is_none());
        assert_eq!(overdue.calls.len(), 1);
        let changed = overdue.calls.values().next().ok_or("deadline model call")?;
        assert_eq!(changed.evaluation().context.time_utc_ns, 100);
        assert!(!Arc::ptr_eq(call, changed));
        assert_eq!(fixture.store.meta()?, before);
        control.check()?;
        subscription.cancel_and_join().await?;
    }
    Ok(())
}
