use std::fs;

use super::{test_support, NativeProcessFixture};

#[test]
fn leader_first_fixture_keeps_the_worker_until_release() -> crate::Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| {
        super::invalid_state(format!("create leader-first test directory: {error}"))
    })?;
    let ready = temporary.path().join("ready");
    let release = temporary.path().join("release");
    let runner = test_support::runner();
    let mut fixture =
        NativeProcessFixture::start_with_leader_first_exit(&runner.repo_root, &ready, &release)?;

    fixture.release_root()?;
    let tid = runner.wait_for("leader-first unit worker", &ready, || {
        fixture.reported_tid(&ready)
    })?;
    assert_ne!(tid, fixture.outer_pid());

    fs::write(&release, b"release\n").map_err(|error| {
        super::invalid_state(format!("release leader-first unit worker: {error}"))
    })?;
    fixture.wait_for_successful_exit()
}
