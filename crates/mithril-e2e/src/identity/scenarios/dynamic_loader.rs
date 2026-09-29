use std::{collections::BTreeSet, path::Path, time::Duration};

use mithril_control::{lower_kubernetes_policy, WorkloadProtectionPolicy};

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn dynamic_loader_needs_no_rule<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("dynamic-loader")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let mut main = env.start_actor("runtime_exec.py", &[], &labels)?;

    let mut shell = env.add_actor("bash", &[])?;
    let task = env.task(shell.id(), "shell entry")?;
    assert_eq!(task.snapshot.active_role_id, 7);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);

    shell.stop()?;
    main.send(b"loader\nstop\n")?;
    main.close();
    let status = main.wait_exit("loader report", Duration::from_secs(5))?;
    assert!(
        status.success(),
        "actor failed: {status}; {:?}",
        main.stderr()?
    );
    let maps = String::from_utf8(main.stdout(status)?)?;
    let loaders = maps
        .lines()
        .filter_map(|line| line.split_ascii_whitespace().last())
        .filter(|path| {
            Path::new(path).file_name().is_some_and(|name| {
                let name = name.as_encoded_bytes();
                name.starts_with(b"ld-linux") || name.starts_with(b"ld-musl")
            })
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !loaders.is_empty(),
        "shell has no mapped dynamic loader: {maps}"
    );

    let policy: WorkloadProtectionPolicy = serde_json::from_str(include_str!(
        "../../../fixtures/process/runtime_entries_policy.json"
    ))?;
    let policy = lower_kubernetes_policy(
        &policy,
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
        "00000000-0000-0000-0000-000000000003",
    )?;
    for loader in loaders {
        assert!(
            policy
                .path_selectors
                .iter()
                .all(|selector| selector.path_expression() != loader),
            "dynamic loader has a signed path rule: {loader}"
        );
    }

    main.stop()?;
    env.stop()
}
