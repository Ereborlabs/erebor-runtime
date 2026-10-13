use std::os::unix::process::ExitStatusExt as _;
use std::process::Command;

use super::super::wasm::checkpoint::{bundle, run};
use super::*;

fn assert_output(fixture: &Fixture, response: &PackageResponseV1, value: u64) -> TestResult {
    let receipt = &response.exports[0].results[0];
    assert_eq!(receipt.target, "native");
    assert!(receipt.artifact.is_some());
    let output = fixture.owner.read_output(
        &fixture.grant,
        "test",
        "runtime-fixture",
        "accumulate",
        &receipt.result_id,
    )?;
    assert_eq!(
        output.json_rows()?["data"],
        serde_json::json!([{"value": value}])
    );
    let checkpoint = output.checkpoint.ok_or("checkpoint absent")?;
    assert_eq!(checkpoint.version, 1);
    assert_eq!(
        PackageOutputV1 {
            datasets: checkpoint.datasets,
            ..Default::default()
        }
        .json_rows()?["state"],
        serde_json::json!([{"value": value}])
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_host_fault_restart() -> TestResult {
    if let Some(root) = std::env::var_os("ARAPHOR_NATIVE_HOST_ROOT") {
        let fixture = Fixture::open(PathBuf::from(root))?;
        let before = fixture
            .owner
            .activations([1; 16], "test", "runtime-fixture")?
            .pop()
            .ok_or("activation absent")?;
        let result_id = before.result_id.as_ref().ok_or("prior result absent")?;
        let stored = fixture
            .store
            .package_result([1; 16], result_id)?
            .ok_or("prior output absent")?;
        let mut next = bundle()?;
        next.root.revision = "2".into();
        next.artifacts[0].descriptor.revision = "2".into();
        let result = fixture
            .execute(PackageRequestV1::Update {
                scope_id: "test".into(),
                bundle: native(next)?,
            })
            .await;
        if std::env::var("ARAPHOR_NATIVE_FIXTURE_FAULT")? == "abort" {
            return Err("native abort returned to the host".into());
        }
        assert!(matches!(
            result,
            Err(crate::Error::PackageNative {
                code: PackageErrorCodeV1::Incomplete,
                ..
            })
        ));
        assert_eq!(
            fixture.store.package_activation(&before.key)?,
            Some(before.clone())
        );
        let retained = fixture
            .store
            .package_result([1; 16], result_id)?
            .ok_or("retained output absent")?;
        assert_eq!(retained.datasets, stored.datasets);
        assert_eq!(retained.checkpoint, stored.checkpoint);
        assert_eq!(retained.metadata, stored.metadata);
        assert_eq!(fixture.owner.operations.available_permits(), 4);
        let recovered = fixture.execute(run("after-panic")).await?;
        assert_output(&fixture, &recovered, 9)?;
        return Ok(());
    }

    let directory = tempfile::tempdir()?;
    let root = directory.path().to_path_buf();
    let fixture = Fixture::open(root.clone())?;
    fixture.install(native(bundle()?)?, None).await?;
    let initial = fixture.execute(run("before-fault")).await?;
    assert_output(&fixture, &initial, 6)?;
    let initial_id = initial.exports[0].results[0].result_id.clone();
    let stored_initial = fixture
        .store
        .package_result([1; 16], &initial_id)?
        .ok_or("initial output absent")?;
    drop(fixture);

    for mode in ["panic", "abort"] {
        let fixture = Fixture::open(root.clone())?;
        let before = fixture
            .owner
            .activations([1; 16], "test", "runtime-fixture")?
            .pop()
            .ok_or("activation absent")?;
        let before_id = before.result_id.as_ref().ok_or("prior result absent")?;
        let stored = fixture
            .store
            .package_result([1; 16], before_id)?
            .ok_or("prior output absent")?;
        drop(fixture);
        let marker = directory.path().join(mode);
        let status = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "package::tests::native::restart::native_host_fault_restart",
                "--ignored",
                "--nocapture",
            ])
            .env("ARAPHOR_NATIVE_HOST_ROOT", &root)
            .env("ARAPHOR_NATIVE_FIXTURE_FAULT", mode)
            .env("ARAPHOR_NATIVE_FIXTURE_MARKER", &marker)
            .status()?;
        assert_eq!(std::fs::read_to_string(marker)?, mode);
        if mode == "panic" {
            assert!(status.success(), "panic host status: {status}");
        } else {
            assert_eq!(
                status.signal(),
                Some(rustix::process::Signal::ABORT.as_raw())
            );
        }
        let fixture = Fixture::open(root.clone())?;
        let retained = fixture
            .store
            .package_result([1; 16], before_id)?
            .ok_or("prior output absent after host restart")?;
        assert_eq!(retained.datasets, stored.datasets);
        assert_eq!(retained.checkpoint, stored.checkpoint);
        assert_eq!(retained.metadata, stored.metadata);
        assert_eq!(retained.commit_revision, stored.commit_revision);
        let original = fixture
            .store
            .package_result([1; 16], &initial_id)?
            .ok_or("initial output absent after host restart")?;
        assert_eq!(original.datasets, stored_initial.datasets);
        assert_eq!(original.checkpoint, stored_initial.checkpoint);
        assert_eq!(original.metadata, stored_initial.metadata);
        let replay = fixture.execute(run("before-fault")).await?;
        assert_eq!(replay.exports[0].results[0].result_id, initial_id);
        assert_output(&fixture, &replay, 6)?;
        if mode == "panic" {
            let replay = fixture.execute(run("after-panic")).await?;
            assert_output(&fixture, &replay, 9)?;
        } else {
            assert_eq!(fixture.store.package_activation(&before.key)?, Some(before));
            let recovered = fixture.execute(run("after-abort")).await?;
            assert_output(&fixture, &recovered, 12)?;
        }
        assert_eq!(fixture.owner.operations.available_permits(), 4);
    }
    Ok(())
}
