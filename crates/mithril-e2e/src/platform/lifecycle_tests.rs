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
    let mut actor = first.start_actor("runtime_exec.py", &[])?;
    let denied = match first.add_actor(
        "python-runtime",
        &["/fixtures/ready.py", "/work/runtime-ready"],
    ) {
        Err(error) => error,
        Ok(mut added) => {
            added.stop()?;
            actor.stop()?;
            first.stop()?;
            return Err("the lifecycle admitted an unlisted runtime entry".into());
        }
    };
    let message = denied.to_string().to_lowercase();
    assert!(
        message.contains("exit status: 13") || message.contains("permission denied"),
        "the unlisted runtime entry was not denied with EACCES: {denied}"
    );
    actor.stop()?;
    first.stop()?;

    let mut second = P::setup("lifecycle-second")?;
    second.start_control()?;
    second.start_node()?;
    second.install_policy("python_policy.json")?;
    second.node_ready()?;
    assert_eq!(std::fs::metadata(&pin)?.ino(), inode);
    let mut actor = second.start_actor("ready.py", &[])?;
    second.task(actor.id(), "fresh lifecycle actor")?;
    actor.stop()?;
    second.stop()
}
