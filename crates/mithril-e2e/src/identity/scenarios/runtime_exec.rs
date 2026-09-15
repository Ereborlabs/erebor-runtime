use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[scope = "identity"]
fn unlisted_exec_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-exec")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("python_policy.json")?;
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
    let denial = error.to_string().to_lowercase();
    assert!(
        denial.contains("exit status: 13") || denial.contains("permission denied"),
        "the unlisted runtime entry was not denied with EACCES: {error}"
    );

    init.stop()?;
    env.stop()
}
