use erebor_interceptor::{Error, KernelHostConfig, KernelHostOwner};

use crate::capability::BpfPrototypeCompiler;
use crate::fixture::HuggingFaceFixture;
use crate::physical::{boot_identity, ProbeFile};
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = kernel_start]
fn clean_host_restarts<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("clean-host")?;
    let pin = env.maps().0.to_owned();
    assert!(!pin.try_exists()?, "pin root already exists: {pin:?}");
    let lease_path = env.work().join("qualification.lock");
    let lease = ProbeFile::new(&lease_path);
    let worker = HuggingFaceFixture::new(
        env.source()
            .join("crates/mithril-e2e/fixtures/hugging-face"),
    );
    let digest = worker.verify()?.protected_deployment_digest;
    let object = BpfPrototypeCompiler::new(env.source()).compile(env.work())?;
    let config = KernelHostConfig::qualification(
        &object.object_path,
        &object.object_sha256,
        "/sys/kernel/btf/vmlinux",
        &lease_path,
        Some(pin.clone()),
        boot_identity()?.0,
        1,
    );

    let first = KernelHostOwner::new(config.clone()).start()?;
    let manifest = first.manifest();
    assert!(manifest.ready, "{manifest:?}");
    assert!(!manifest.maps.is_empty() && !manifest.links.is_empty());
    assert!(manifest.maps.iter().all(|map| map.pin_path.is_some()));
    assert!(manifest.links.iter().all(|link| link.pin_path.is_some()));
    first.verify_live_manifest()?;
    assert!(matches!(
        KernelHostOwner::new(config.clone()).start(),
        Err(Error::StalePinRoot { path, .. }) if path == pin
    ));
    let mut contender = config.clone();
    contender.pin_root = None;
    match KernelHostOwner::new(contender).start() {
        Err(Error::LeaseOwned { .. }) => {}
        Err(error) => return Err(error.into()),
        Ok(other) => {
            other.shutdown()?;
            return Err("a concurrent kernel owner acquired the lease".into());
        }
    }
    first.verify_live_manifest()?;
    first.shutdown()?;
    assert!(!pin.try_exists()?, "first shutdown left pins: {pin:?}");

    let restarted = KernelHostOwner::new(config).start()?;
    let manifest = restarted.manifest();
    assert!(manifest.ready, "{manifest:?}");
    assert!(!manifest.maps.is_empty() && !manifest.links.is_empty());
    assert!(manifest.maps.iter().all(|map| map.pin_path.is_some()));
    assert!(manifest.links.iter().all(|link| link.pin_path.is_some()));
    restarted.verify_live_manifest()?;
    restarted.shutdown()?;
    assert!(!pin.try_exists()?, "second shutdown left pins: {pin:?}");
    assert_eq!(worker.verify()?.protected_deployment_digest, digest);

    lease.cleanup()?;
    assert!(!lease_path.try_exists()?);
    env.stop()
}
