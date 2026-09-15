use std::os::unix::fs::MetadataExt as _;

use super::{platform_test, test_scope, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[scope = "scope-reuse"]
fn serial_scope_reuses_node<P: Platform + 'static>() -> TestResult<()> {
    let mut first = P::setup("scope-first")?;
    first.start_control()?;
    first.start_node()?;
    first.install_policy("scope_reuse/policy.json")?;
    first.node_ready()?;
    let pin = first.maps().0.to_owned();
    let inode = std::fs::metadata(&pin)?.ino();
    first.stop()?;

    let mut second = P::setup("scope-second")?;
    second.start_control()?;
    second.start_node()?;
    second.install_policy("scope_reuse/policy.json")?;
    second.node_ready()?;
    assert_eq!(std::fs::metadata(&pin)?.ino(), inode);
    second.stop()?;

    test_scope::<P, _>("scope-replaced", || {
        let mut third = P::setup("scope-third")?;
        third.start_control()?;
        third.start_node()?;
        third.install_policy("scope_reuse/policy.json")?;
        third.node_ready()?;
        assert_ne!(std::fs::metadata(third.maps().0)?.ino(), inode);
        third.stop()
    })
}
