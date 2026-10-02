use std::time::Duration;

use crate::physical::oci_bundle::OciBundle;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(runc)]
#[lifecycle = runtime_gate]
fn hostile_runtime_never_starts<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-hostile")?;
    let bundle = OciBundle::new(&env, "hostile")?;
    let manifest = env
        .source()
        .join("crates/mithril-e2e/fixtures/convergence/direct-runc-recovery-v1.json");
    let mut actor = bundle.spawn(
        include_str!("../../../fixtures/process/runtime_hostile.json"),
        &manifest,
    )?;
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
    assert!(
        !bundle.markers.join("started").try_exists()?,
        "the actor ran"
    );
    assert!(
        !bundle.markers.join("hostile").try_exists()?,
        "the actor read the host file"
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
