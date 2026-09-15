use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[scope = "identity"]
fn unlisted_exec_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-exec")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut init = env.start_actor("runtime_exec.py", &[])?;

    let error = match env.add_actor(
        "python-runtime",
        &["/fixtures/ready.py", "/work/runtime-ready"],
    ) {
        Err(error) => error,
        Ok(mut actor) => {
            actor.stop()?;
            init.stop()?;
            env.stop()?;
            return Err("Mithril allowed an unlisted runtime entry".into());
        }
    };
    assert!(
        error.to_string().contains("exit status: 13"),
        "the unlisted runtime entry was not denied with EACCES: {error}"
    );

    init.stop()?;
    env.stop()
}
