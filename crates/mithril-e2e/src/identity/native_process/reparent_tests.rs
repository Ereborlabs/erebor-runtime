use std::fs;
use std::path::PathBuf;

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

#[test]
fn native_process_fixture_reparents_double_fork_child_before_exec() -> crate::Result<()> {
    let runner = test_support::runner();
    let mut fixture = NativeProcessFixture::start_double_forking()?;
    let outer_pid = fixture.outer_pid();

    fixture.release_root()?;
    let outer_children_path = PathBuf::from(format!("/proc/{outer_pid}/task/{outer_pid}/children"));
    let intermediate_pid = runner.wait_for(
        "double-fork intermediate creation",
        &outer_children_path,
        || fixture.intermediate_pid(),
    )?;
    fixture.open_intermediate_pidfd(intermediate_pid)?;
    let intermediate_children_path = PathBuf::from(format!(
        "/proc/{intermediate_pid}/task/{intermediate_pid}/children"
    ));
    let native_pid = runner.wait_for(
        "double-fork native child creation",
        &intermediate_children_path,
        || fixture.intermediate_native_child_pid(intermediate_pid),
    )?;
    fixture.open_native_pidfd(native_pid)?;
    fixture.wait_for_stopped_native_child(native_pid)?;
    assert_eq!(parent_pid(native_pid)?, Some(intermediate_pid));

    fixture.release_intermediate_exit()?;
    runner.wait_for(
        "double-fork intermediate exit",
        &intermediate_children_path,
        || {
            fixture
                .intermediate_exited(intermediate_pid)
                .map(|exited| exited.then_some(()))
        },
    )?;
    assert!(PathBuf::from(format!("/proc/{outer_pid}")).exists());
    fixture.release_exec(native_pid)?;
    let status_path = PathBuf::from(format!("/proc/{native_pid}/status"));
    runner.wait_for("double-fork native child reparenting", &status_path, || {
        Ok(parent_pid(native_pid)?.filter(|parent_pid| *parent_pid != intermediate_pid))
    })?;
    fixture.wait_for_executable(native_pid, "sleep", "double-fork native child exec")
}

fn parent_pid(pid: u32) -> crate::Result<Option<u32>> {
    let path = PathBuf::from(format!("/proc/{pid}/status"));
    let status = fs::read_to_string(&path)
        .map_err(|error| super::invalid_state(format!("read {}: {error}", path.display())))?;
    Ok(status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:")?.split_whitespace().next())
        .and_then(|value| value.parse().ok()))
}
