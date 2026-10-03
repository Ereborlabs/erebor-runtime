use std::{fs, time::Duration};

use crate::physical::oci_bundle::OciBundle;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(runc)]
#[lifecycle = runtime_gate]
fn changed_recovery_never_starts<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-recovery-changed")?;
    let bundle = OciBundle::new(&env, "changed-recovery")?;
    for name in ["host-hook", "host-containerd"] {
        fs::create_dir(bundle.markers.join(name))?;
    }
    let manifest = bundle.manifest(include_str!(
        "../../../fixtures/process/runtime_recovery_manifest.json"
    ))?;
    let mut spec: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/process/runtime_recovery.json"
    ))?;
    spec["process"]["args"] =
        serde_json::json!(["/owner", "/result/changed-recovery", "CHANGED_RECOVERY_RAN"]);
    spec["mounts"]
        .as_array_mut()
        .ok_or("OCI mounts are missing")?
        .retain(|mount| {
            mount["destination"] != "/host-hook-bin" && mount["destination"] != "/host-containerd"
        });
    assert!(!bundle.markers.join("changed-recovery").try_exists()?);
    let mut actor = bundle.spawn(&serde_json::to_string(&spec)?, &manifest)?;
    let status = actor
        .wait_exit("changed recovery admission", Duration::from_secs(5))
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
        !bundle.markers.join("changed-recovery").try_exists()?,
        "the changed recovery actor ran"
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
