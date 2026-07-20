use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
};

use crate::{
    ActiveSessionSignalKind, DaemonFailureMode, RunnerCapabilityDocument, SessionRunnerKind,
};

use super::{
    process_start_time, DockerContainerExpectation, DockerContainerInspection,
    RecoveredLinuxSession,
};

fn linux_capability() -> Result<RunnerCapabilityDocument, Box<dyn std::error::Error>> {
    Ok(RunnerCapabilityDocument::new(
        SessionRunnerKind::LinuxHost,
        "test-linux",
        "1",
        "linux",
        "x86_64",
        true,
        true,
        BTreeSet::from([String::from("stdout"), String::from("stderr")]),
        BTreeSet::from([ActiveSessionSignalKind::Kill]),
        false,
        true,
        BTreeSet::from([DaemonFailureMode::Terminate]),
        BTreeMap::new(),
    )?)
}

#[test]
fn linux_recovery_rejects_a_reused_pid_with_the_wrong_start_time(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("/usr/bin/sleep").arg("5").spawn()?;
    let start = process_start_time(child.id()).ok_or("child start time was unavailable")?;
    let identity = format!(
        "linux:pid={}:start={};helper_pid=1;helper_start=1",
        child.id(),
        start.saturating_add(1)
    );
    let recovered = RecoveredLinuxSession::new(&identity, linux_capability()?);
    let _kill = child.kill();
    let _status = child.wait();
    assert!(recovered.is_err());
    Ok(())
}

#[test]
fn linux_recovery_rejects_a_live_workload_without_the_exact_saved_helper(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("/usr/bin/sleep").arg("5").spawn()?;
    let workload_start =
        process_start_time(child.id()).ok_or("child start time was unavailable")?;
    let helper_pid = std::process::id();
    let helper_start = process_start_time(helper_pid).ok_or("helper start time was unavailable")?;
    let identity = format!(
        "linux:pid={}:start={workload_start};helper_pid={helper_pid};helper_start={}",
        child.id(),
        helper_start.saturating_add(1),
    );
    let recovered = RecoveredLinuxSession::new(&identity, linux_capability()?);
    let _kill = child.kill();
    let _status = child.wait();
    assert!(recovered.is_err());
    Ok(())
}

#[test]
fn docker_recovery_requires_exact_container_image_user_and_session_label(
) -> Result<(), Box<dyn std::error::Error>> {
    let container_id = "a".repeat(64);
    let image_id = format!("sha256:{}", "b".repeat(64));
    let source = serde_json::json!({
        "Id": container_id,
        "Image": image_id,
        "Config": {
            "User": "1001:1002",
            "WorkingDir": "/workspace",
            "Entrypoint": ["/bin/sh"],
            "Cmd": ["-c", "sleep 10"],
            "Labels": {"dev.erebor.session_id": "session-one"}
        },
        "State": {"Running": true, "ExitCode": 0},
        "HostConfig": {
            "CgroupParent": "erebor-session-session-one.slice",
            "ReadonlyRootfs": true,
            "NetworkMode": "none",
            "SecurityOpt": ["no-new-privileges"],
            "CapDrop": ["ALL"],
            "GroupAdd": null,
            "Ulimits": [
                {"Name": "nofile", "Soft": 1024, "Hard": 1024},
                {"Name": "nproc", "Soft": 512, "Hard": 512},
                {"Name": "core", "Soft": 0, "Hard": 0}
            ]
        },
        "Mounts": [{
            "Source": "/run/erebor/session/workspace",
            "Destination": "/workspace",
            "RW": true
        }]
    });
    let observed: DockerContainerInspection = serde_json::from_value(source)?;

    let expected = DockerContainerExpectation {
        container_id: "a".repeat(64),
        image_id: image_id.clone(),
        session_id: String::from("session-one"),
        user: String::from("1001:1002"),
        cgroup_parent: String::from("erebor-session-session-one.slice"),
        workspace: Path::new("/run/erebor/session/workspace").to_path_buf(),
        command: vec![
            String::from("/bin/sh"),
            String::from("-c"),
            String::from("sleep 10"),
        ],
        groups: Vec::new(),
        maximum_open_files: 1024,
        maximum_processes: 512,
        maximum_core_bytes: 0,
    };
    assert!(observed.matches(&expected));

    let mut mismatched = expected.clone();
    mismatched.container_id = "c".repeat(64);
    assert!(!observed.matches(&mismatched));

    let mut mismatched = expected.clone();
    mismatched.image_id = format!("sha256:{}", "c".repeat(64));
    assert!(!observed.matches(&mismatched));

    let mut mismatched = expected.clone();
    mismatched.session_id = String::from("session-two");
    assert!(!observed.matches(&mismatched));

    let mut mismatched = expected.clone();
    mismatched.user = String::from("0:0");
    assert!(!observed.matches(&mismatched));

    let mut mismatched = expected;
    mismatched.cgroup_parent = String::from("other.slice");
    assert!(!observed.matches(&mismatched));
    Ok(())
}
