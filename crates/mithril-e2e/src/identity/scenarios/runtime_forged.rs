use std::time::Duration;

use crate::physical::oci_bundle::OciBundle;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(runc)]
#[lifecycle = runtime_gate]
fn forged_sandbox_never_starts<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-forged")?;
    let bundle = OciBundle::new(&env, "forged-cri-sandbox")?;
    let manifest = env
        .source()
        .join("crates/mithril-e2e/fixtures/convergence/direct-runc-recovery-v1.json");
    let mut spec: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/process/runtime_sandbox.json"
    ))?;
    spec["process"]["args"] =
        serde_json::json!(["/usr/bin/python3", "/fixtures/runtime_pause.py", "/result"]);
    spec["mounts"]
        .as_array_mut()
        .ok_or("OCI mounts are missing")?
        .push(serde_json::json!({
            "destination": "/result", "type": "bind", "source": "MITHRIL_WORK",
            "options": ["rbind", "rw"]
        }));
    let mut actor = bundle.spawn(&serde_json::to_string(&spec)?, &manifest)?;
    let status = actor
        .wait_exit("forged sandbox admission", Duration::from_secs(5))
        .map_err(|error| format!("{error}; stderr: {:?}", actor.stderr()))?;
    let stderr = actor.stderr()?;
    let stdout = actor.stdout(status)?;
    actor.stop()?;
    assert!(
        !status.success(),
        "forged sandbox started: {status}; {stderr}"
    );
    assert!(
        stderr.contains("decision=DENY_NODE_UNAVAILABLE"),
        "{status}; {stderr}"
    );
    assert!(!stderr.contains("decision=ALLOW_CRI_SANDBOX"), "{stderr}");
    assert!(stdout.is_empty(), "unexpected actor output: {stdout:?}");
    assert!(
        !bundle.markers.join("started").try_exists()?,
        "the forged actor ran"
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
    assert!(
        !bundle.group.try_exists()?,
        "actor cgroup remains: {:?}",
        bundle.group
    );
    Ok(())
}
