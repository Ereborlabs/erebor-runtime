use std::os::unix::fs::MetadataExt as _;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn lifecycle_reuses_node<P: Platform + 'static>() -> TestResult<()> {
    let mut first = P::setup("lifecycle-first")?;
    first.start_control()?;
    first.start_node()?;
    first.install_policy("python_policy.json")?;
    first.node_ready()?;
    let pin = first.maps().0.to_owned();
    let inode = std::fs::metadata(&pin)?.ino();
    first.stop()?;

    let mut second = P::setup("lifecycle-second")?;
    second.start_control()?;
    second.start_node()?;
    second.install_policy("python_policy.json")?;
    second.node_ready()?;
    assert_eq!(std::fs::metadata(&pin)?.ino(), inode);
    second.stop()
}
