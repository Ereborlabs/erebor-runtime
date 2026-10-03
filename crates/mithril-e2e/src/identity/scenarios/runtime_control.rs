use std::{env, fs, os::unix::fs::PermissionsExt as _, process::Command, time::Duration};

use crate::physical::oci_bundle::OciBundle;
use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(runc)]
#[lifecycle = runtime_gate]
fn control_recovery_can_start<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-control")?;
    let bundle = OciBundle::new(&env, "control-recovery")?;
    fs::set_permissions(&bundle.markers, fs::Permissions::from_mode(0o777))?;
    let input = include_str!("../../../fixtures/process/runtime_recovery_manifest.json");
    let manifest = bundle.manifest(input)?;
    let entry: serde_json::Value = serde_json::from_str(input)?;
    let args = entry["controlEntries"][0]["args"]
        .as_array()
        .ok_or("Control recovery argv is missing")?;
    let mut spec: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/process/runtime_control.json"
    ))?;
    spec["process"]["args"] = serde_json::Value::Array(args.clone());
    assert!(!bundle.markers.join("control").try_exists()?);
    let mut actor = bundle.spawn(&serde_json::to_string(&spec)?, &manifest)?;
    let status = actor
        .wait_exit("Control recovery start", Duration::from_secs(5))
        .map_err(|error| format!("{error}; stderr: {:?}", actor.stderr()))?;
    let stderr = actor.stderr()?;
    let stdout = actor.stdout(status)?;
    actor.stop()?;
    assert!(status.success(), "{status}; {stderr}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&stdout)?,
        spec["process"]["args"]
    );
    assert_eq!(
        fs::read_to_string(bundle.markers.join("control"))?,
        "CONTROL_RECOVERY_ALLOWED"
    );

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
        .wait_exit("Control recovery decision", Duration::from_secs(5))
        .map_err(|error| format!("{error}; stderr: {:?}", probe.stderr()))?;
    let stderr = probe.stderr()?;
    let stdout = probe.stdout(status)?;
    probe.stop()?;
    assert!(status.success(), "{status}; {stderr}");
    assert!(stdout.is_empty(), "unexpected hook output: {stdout:?}");
    assert!(stderr.contains("decision=ALLOW_EXACT_RECOVERY"), "{stderr}");

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
    for path in [
        &bundle.bundle,
        &bundle.state,
        &bundle.markers,
        &bundle.group,
    ] {
        assert!(!path.try_exists()?, "runtime test path remains: {path:?}");
    }
    Ok(())
}

#[platform_test(runc)]
#[lifecycle = runtime_gate]
fn changed_control_never_starts<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-control-changed")?;
    let bundle = OciBundle::new(&env, "changed-control")?;
    fs::set_permissions(&bundle.markers, fs::Permissions::from_mode(0o777))?;
    let input = include_str!("../../../fixtures/process/runtime_recovery_manifest.json");
    let manifest = bundle.manifest(input)?;
    let entry: serde_json::Value = serde_json::from_str(input)?;
    let args = entry["controlEntries"][0]["args"]
        .as_array()
        .ok_or("Control recovery argv is missing")?;
    let mut spec: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/process/runtime_control.json"
    ))?;
    spec["process"]["args"] = serde_json::Value::Array(args.clone());
    spec["process"]["capabilities"]["effective"] = serde_json::json!(["CAP_SYS_ADMIN"]);
    assert!(!bundle.markers.join("control").try_exists()?);
    let mut actor = bundle.spawn(&serde_json::to_string(&spec)?, &manifest)?;
    let status = actor
        .wait_exit("changed Control admission", Duration::from_secs(5))
        .map_err(|error| format!("{error}; stderr: {:?}", actor.stderr()))?;
    let stderr = actor.stderr()?;
    let stdout = actor.stdout(status)?;
    actor.stop()?;
    assert!(!status.success(), "{status}; {stderr}");
    assert!(
        stderr.contains("decision=DENY_NODE_UNAVAILABLE"),
        "{status}; {stderr}"
    );
    assert!(
        !stderr.contains("decision=ALLOW_EXACT_RECOVERY"),
        "{stderr}"
    );
    assert!(stdout.is_empty(), "unexpected actor output: {stdout:?}");
    assert!(
        !bundle.markers.join("control").try_exists()?,
        "the changed Control actor ran"
    );
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
    for path in [
        &bundle.bundle,
        &bundle.state,
        &bundle.markers,
        &bundle.group,
    ] {
        assert!(!path.try_exists()?, "runtime test path remains: {path:?}");
    }
    Ok(())
}
