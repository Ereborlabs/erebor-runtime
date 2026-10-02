use std::{env, process::Command, time::Duration};

use crate::physical::oci_bundle::OciBundle;
use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(runc)]
#[lifecycle = runtime_gate]
fn inert_sandbox_can_start<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-sandbox")?;
    let bundle = OciBundle::new(&env, "cri-sandbox")?;
    let manifest = bundle.manifest(include_str!(
        "../../../fixtures/convergence/direct-runc-recovery-v1.json"
    ))?;
    let mut actor = bundle.spawn(
        include_str!("../../../fixtures/process/runtime_sandbox.json"),
        &manifest,
    )?;
    let status = actor
        .wait_exit("inert sandbox start", Duration::from_secs(5))
        .map_err(|error| format!("{error}; stderr: {:?}", actor.stderr()))?;
    let stderr = actor.stderr()?;
    let stdout = actor.stdout(status)?;
    actor.stop()?;
    assert!(status.success(), "{status}; {stderr}");
    assert_eq!(stdout, b"CRI_SANDBOX_ALLOWED", "{status}; {stderr}");

    let hook = env::var_os("MITHRIL_TEST_OCI_HOOK").ok_or("hook is not supplied")?;
    let socket = bundle.bundle.join("absent-runtime.sock");
    assert!(!socket.try_exists()?);
    let mut command = Command::new(hook);
    command
        .args(["run", "--stage", "stage-runtime-facts", "--socket"])
        .arg(&socket)
        .arg("--recovery-manifest")
        .arg(&manifest)
        .args(["--timeout-ms", "100"])
        .env("RUST_LOG", "info");
    let mut probe = ProcessFixture::spawn(&mut command, &bundle.bundle)?;
    probe.send(&serde_json::to_vec(&serde_json::json!({
        "id": bundle.id, "pid": 1, "bundle": bundle.bundle, "annotations": {}
    }))?)?;
    probe.close();
    let status = probe
        .wait_exit("sandbox decision log", Duration::from_secs(5))
        .map_err(|error| format!("{error}; stderr: {:?}", probe.stderr()))?;
    let stderr = probe.stderr()?;
    let stdout = probe.stdout(status)?;
    probe.stop()?;
    assert!(status.success(), "{status}; {stderr}");
    assert!(stdout.is_empty(), "unexpected hook output: {stdout:?}");
    assert!(stderr.contains("decision=ALLOW_CRI_SANDBOX"), "{stderr}");

    let containers = bundle.containers()?;
    assert!(
        containers.is_empty(),
        "runtime containers remain: {containers:?}"
    );
    assert!(
        !bundle.state.join(&bundle.id).try_exists()?,
        "runtime state remains"
    );
    env.stop()?;
    assert!(
        !bundle.group.try_exists()?,
        "actor cgroup remains: {:?}",
        bundle.group
    );
    Ok(())
}
