use std::fs;
use std::path::PathBuf;

use super::{test_support, NativeProcessFixture};

#[test]
fn native_process_fixture_executes_non_leader_thread() -> crate::Result<()> {
    let repo_root = test_support::runner().repo_root;
    let temporary = tempfile::tempdir().map_err(|error| {
        super::invalid_state(format!("create non-leader thread test directory: {error}"))
    })?;
    let ready = temporary.path().join("non-leader-thread-ready");
    let mut fixture = NativeProcessFixture::start_with_non_leader_exec(&repo_root, &ready)?;
    let outer_pid = fixture.outer_pid();

    fs::write(&ready, b"")
        .map_err(|error| super::invalid_state(format!("write {}: {error}", ready.display())))?;
    assert_eq!(fixture.non_leader_thread_tid(&ready)?, None);
    fs::remove_file(&ready)
        .map_err(|error| super::invalid_state(format!("remove {}: {error}", ready.display())))?;

    fixture.release_root()?;
    let thread_tid = fixture.wait_for_reported_tid(&ready, "non-leader Python thread creation")?;
    assert_ne!(thread_tid, outer_pid);
    assert!(PathBuf::from(format!("/proc/{outer_pid}/task/{thread_tid}")).is_dir());

    fixture.release_non_leader_exec()?;
    fixture.wait_for_executable(outer_pid, "sleep", "non-leader Python thread exec")
}

#[test]
fn native_process_fixture_races_two_thread_execs() -> crate::Result<()> {
    let repo_root = test_support::runner().repo_root;
    let temporary = tempfile::tempdir().map_err(|error| {
        super::invalid_state(format!("create concurrent thread test directory: {error}"))
    })?;
    let ready = temporary.path().join("concurrent-thread-ready");
    let mut fixture = NativeProcessFixture::start_with_concurrent_thread_exec(&repo_root, &ready)?;
    let outer_pid = fixture.outer_pid();

    fixture.release_root()?;
    let [first_thread_tid, second_thread_tid] =
        fixture.wait_for_concurrent_thread_tids(&ready, "concurrent Python thread creation")?;
    assert_ne!(first_thread_tid, outer_pid);
    assert_ne!(second_thread_tid, outer_pid);
    assert_ne!(first_thread_tid, second_thread_tid);
    assert!(PathBuf::from(format!("/proc/{outer_pid}/task/{first_thread_tid}")).is_dir());
    assert!(PathBuf::from(format!("/proc/{outer_pid}/task/{second_thread_tid}")).is_dir());

    fixture.release_concurrent_thread_exec()?;
    fixture.wait_for_executable(outer_pid, "sleep", "concurrent Python thread exec")
}
