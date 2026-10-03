use std::{fs, path::Path, time::Duration};

use crate::physical::oci_bundle::OciBundle;
use crate::platform::{actor_script, platform_test, Platform, TestResult};

#[platform_test(runc)]
#[lifecycle = runtime_gate]
fn exact_installer_can_start<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-installer")?;
    let bundle = OciBundle::new(&env, "exact-installer")?;
    for name in ["host-hook", "host-containerd"] {
        fs::create_dir(bundle.markers.join(name))?;
    }
    let local = env.work().join("installer-local");
    fs::create_dir_all(local.join("bin"))?;
    fs::copy(
        actor_script(env.source(), "runtime_owner.py")?,
        local.join("bin/mithril-oci-hook"),
    )?;
    let input = include_str!("../../../fixtures/process/runtime_recovery_manifest.json");
    let entry: serde_json::Value = serde_json::from_str(input)?;
    let args = entry["entries"][1]["args"]
        .as_array()
        .ok_or("installer argv is missing")?;
    assert_eq!(args.len(), 12);
    let runtime = entry["entries"][1]["requiredMounts"][2]["source"]
        .as_str()
        .ok_or("K3s input is missing")?;
    assert!(
        Path::new(runtime).is_file(),
        "K3s input is absent: {runtime}"
    );
    let manifest = bundle.manifest(input)?;
    let mut spec: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/process/runtime_recovery.json"
    ))?;
    spec["process"]["args"] = serde_json::Value::Array(args.clone());
    let mounts = spec["mounts"]
        .as_array_mut()
        .ok_or("OCI mounts are missing")?;
    let owner = mounts
        .iter_mut()
        .find(|mount| mount["destination"] == "/owner")
        .ok_or("installer actor mount is missing")?;
    owner["destination"] = serde_json::json!("/usr/local");
    owner["source"] = serde_json::json!(&local);
    mounts.push(serde_json::json!({
        "destination": "/host-k3s", "type": "bind", "source": runtime,
        "options": ["bind", "ro"]
    }));
    assert!(!bundle.markers.join("installer").try_exists()?);
    let mut actor = bundle.spawn(&serde_json::to_string(&spec)?, &manifest)?;
    let status = actor
        .wait_exit("exact installer start", Duration::from_secs(5))
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
        fs::read_to_string(bundle.markers.join("installer"))?,
        "INSTALLER_ALLOWED"
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
        &local,
        &bundle.bundle,
        &bundle.state,
        &bundle.markers,
        &bundle.group,
    ] {
        assert!(!path.try_exists()?, "runtime test path remains: {path:?}");
    }
    Ok(())
}
