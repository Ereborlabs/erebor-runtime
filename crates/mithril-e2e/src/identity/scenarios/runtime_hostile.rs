use std::{env, fs, path::PathBuf, process::Command, time::Duration};

use mithril_node::OciBaseSpecOwner;

use crate::platform::{platform_test, Platform, TestResult, PROCESS_FIXTURES};
use crate::process::ProcessFixture;

#[platform_test(runc)]
#[lifecycle = runtime_gate]
fn hostile_runtime_never_starts<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-hostile")?;
    let runc = PathBuf::from(env::var_os("MITHRIL_TEST_RUNC").ok_or("runc is not supplied")?);
    let hook = PathBuf::from(env::var_os("MITHRIL_TEST_OCI_HOOK").ok_or("hook is not supplied")?);
    let bundle = env.work().join("bundle");
    let state = env.work().join("state");
    let markers = env.work().join("markers");
    for name in [
        "usr", "lib", "lib64", "proc", "dev", "fixtures", "result", "host",
    ] {
        fs::create_dir_all(bundle.join("rootfs").join(name))?;
    }
    fs::create_dir(&state)?;
    fs::create_dir(&markers)?;
    let group = PathBuf::from(env::var_os("MITHRIL_TEST_CGROUP").ok_or("cgroup is not supplied")?);
    let fixtures = env.source().join(PROCESS_FIXTURES);
    let mut input = include_str!("../../../fixtures/process/runtime_hostile.json").to_owned();
    for (key, path) in [
        ("MITHRIL_FIXTURES", fixtures.as_path()),
        ("MITHRIL_WORK", markers.as_path()),
        ("MITHRIL_CGROUP", group.strip_prefix("/sys/fs/cgroup")?),
    ] {
        input = input.replace(key, path.to_str().ok_or("OCI input path is not UTF-8")?);
    }
    let mut spec: serde_json::Value = serde_json::from_str(&input)?;
    let id = crate::DigestV1::of(b"hostile").to_hex();
    spec["annotations"]["io.kubernetes.cri.container-id"] = id.clone().into();
    let manifest = env
        .source()
        .join("crates/mithril-e2e/fixtures/convergence/direct-runc-recovery-v1.json");
    let socket = env.work().join("absent-runtime.sock");
    assert!(!socket.try_exists()?);
    let config = OciBaseSpecOwner::build(
        &serde_json::to_vec(&spec)?,
        &hook,
        &manifest,
        &socket,
        100,
        2,
        "info",
    )?;
    fs::write(bundle.join("config.json"), config)?;

    let mut command = Command::new(&runc);
    command
        .arg("--root")
        .arg(&state)
        .args(["run", "--bundle"])
        .arg(&bundle)
        .arg(&id);
    let mut actor = ProcessFixture::spawn(&mut command, &bundle)?;
    actor.set_group(&group);
    let status = actor
        .wait_exit("hostile runtime admission", Duration::from_secs(5))
        .map_err(|error| format!("{error}; stderr: {:?}", actor.stderr()))?;
    let stderr = actor.stderr()?;
    let stdout = actor.stdout(status)?;
    actor.stop()?;
    assert!(
        !status.success(),
        "hostile actor started: {status}; {stderr}"
    );
    assert!(
        stderr.contains("decision=DENY_HOSTILE"),
        "{status}; {stderr}"
    );
    assert!(stdout.is_empty(), "unexpected actor output: {stdout:?}");
    assert!(!markers.join("started").try_exists()?, "the actor ran");
    assert!(
        !markers.join("hostile").try_exists()?,
        "the actor read the host file"
    );
    let runtime = Command::new(&runc)
        .arg("--root")
        .arg(&state)
        .args(["list", "--format", "json"])
        .output()?;
    assert!(runtime.status.success(), "{:?}", runtime);
    assert!(runtime.stderr.is_empty(), "{runtime:?}");
    let containers: Option<Vec<serde_json::Value>> = serde_json::from_slice(&runtime.stdout)?;
    assert!(
        containers.as_ref().is_none_or(Vec::is_empty),
        "runtime containers remain: {containers:?}"
    );
    assert!(!state.join(&id).try_exists()?, "runtime state remains");
    env.stop()?;
    assert!(!group.try_exists()?, "actor cgroup remains: {group:?}");
    Ok(())
}
