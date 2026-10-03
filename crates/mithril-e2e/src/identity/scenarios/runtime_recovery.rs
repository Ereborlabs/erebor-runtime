use std::{env, fs, process::Command, time::Duration};

use crate::physical::oci_bundle::OciBundle;
use crate::platform::{actor_script, platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(runc)]
#[lifecycle = runtime_gate]
fn exact_recovery_can_start<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-recovery")?;
    let bundle = OciBundle::new(&env, "exact-recovery")?;
    for name in ["host-hook", "host-containerd"] {
        fs::create_dir(bundle.markers.join(name))?;
    }
    let input = include_str!("../../../fixtures/process/runtime_recovery_manifest.json");
    let manifest = bundle.manifest(input)?;
    let entry: serde_json::Value = serde_json::from_str(input)?;
    let args = entry["entries"][0]["args"]
        .as_array()
        .ok_or("recovery argv is missing")?;
    assert_eq!(args.len(), 38);
    let mut spec: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/process/runtime_recovery.json"
    ))?;
    spec["process"]["args"] = serde_json::Value::Array(args.clone());
    assert!(!bundle.markers.join("recovery").try_exists()?);
    let mut actor = bundle.spawn(&serde_json::to_string(&spec)?, &manifest)?;
    let status = actor
        .wait_exit("exact recovery start", Duration::from_secs(5))
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
        fs::read_to_string(bundle.markers.join("recovery"))?,
        "RECOVERY_ALLOWED"
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
        .wait_exit("recovery decision log", Duration::from_secs(5))
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
    assert!(
        !bundle.group.try_exists()?,
        "actor cgroup remains: {:?}",
        bundle.group
    );
    Ok(())
}

#[platform_test(runc)]
#[lifecycle = runtime_gate]
fn node_version_can_start<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-node-version")?;
    let bundle = OciBundle::new(&env, "node-version")?;
    for name in ["host-hook", "host-containerd"] {
        fs::create_dir(bundle.markers.join(name))?;
    }
    let source = actor_script(env.source(), "runtime_owner.py")?;
    let executable = env.work().join("runtime_owner.py");
    fs::copy(&source, &executable)?;
    let original = fs::read(&executable)?;
    let mut input: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/process/runtime_recovery_manifest.json"
    ))?;
    let args = input["entries"][0]["args"]
        .as_array()
        .ok_or("recovery argv is missing")?;
    assert_eq!(args.len(), 38);
    let mut spec: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/process/runtime_recovery.json"
    ))?;
    spec["process"]["args"] = serde_json::Value::Array(args.clone());
    for mounts in [
        &mut spec["mounts"],
        &mut input["entries"][0]["requiredMounts"],
    ] {
        let owner = mounts
            .as_array_mut()
            .ok_or("recovery mounts are missing")?
            .iter_mut()
            .find(|mount| mount["destination"] == "/owner")
            .ok_or("recovery actor mount is missing")?;
        owner["source"] = serde_json::json!(&executable);
    }
    let manifest = bundle.manifest(&serde_json::to_string(&input)?)?;
    let mut changed = original.clone();
    changed.push(b'\n');
    fs::write(&executable, &changed)?;
    assert_ne!(fs::read(&executable)?, original);
    assert!(!bundle.markers.join("recovery").try_exists()?);
    let mut actor = bundle.spawn(&serde_json::to_string(&spec)?, &manifest)?;
    let status = actor
        .wait_exit("Node version start", Duration::from_secs(5))
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
        fs::read_to_string(bundle.markers.join("recovery"))?,
        "RECOVERY_ALLOWED"
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
        &executable,
        &bundle.bundle,
        &bundle.state,
        &bundle.markers,
        &bundle.group,
    ] {
        assert!(!path.try_exists()?, "runtime test path remains: {path:?}");
    }
    Ok(())
}
