use std::time::Duration;

use crate::package::tests::{bundle, Fixture, TestResult};
use crate::package::{PackageImplementationV1, PackageOutputV1};

use super::*;

const START: u64 = 946_684_800_000_000_000;
const EXPIRY: &str = "SELECT CASE WHEN CURRENT_TIMESTAMP < TIMESTAMP '2000-01-01 00:00:00.5' THEN 1::UBIGINT ELSE 0::UBIGINT END AS count";

#[tokio::test]
async fn automatic_clock_ticks() -> TestResult {
    for source_clock in [false, true] {
        let fixture = Fixture::new()?;
        let mut package = bundle("1", EXPIRY);
        if source_clock {
            let artifact = &mut package.artifacts[0];
            let mut port = artifact.descriptor.exports[0].outputs[0].clone();
            port.name = "source".into();
            artifact.descriptor.exports[0].inputs.push(sdk::InputPort {
                port,
                source: sdk::InputSource::Sql(EXPIRY.into()),
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
        let period = AnalysisPackageOwner::RECONCILE_INTERVAL.as_nanos() as u64;
        for (now, expected) in [(START + 123, 1), (START + period + 123, 0)] {
            let active = fixture.store.package_activation_page(None)?.remove(0);
            let request = RunPreparation {
                id: "tick",
                rebuild: false,
                automatic: true,
                now,
            };
            let prepared = fixture
                .owner
                .prepare_at(&active, &package, request, &control)?
                .ok_or("clock evaluation")?;
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
        if !source_clock {
            let active = fixture.store.package_activation_page(None)?.remove(0);
            let artifact = &package.artifacts[0];
            fixture.owner.refresh(
                &active,
                artifact,
                &artifact.descriptor.exports[0],
                &fixture.grant,
                &control,
            )?;
            let stored = fixture
                .store
                .package_result([1; 16], active.result_id.as_deref().ok_or("active result")?)?
                .ok_or("stored result")?;
            assert!(stored.stale);
        }
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
