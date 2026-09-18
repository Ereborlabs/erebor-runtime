use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn unlisted_exec_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-exec")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("python_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("runtime_exec.py", &[])?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();

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

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &path,
        "unlisted runtime entry evidence",
        Duration::from_secs(30),
        || {
            let events = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            *last.borrow_mut() = format!(
                "{:?}",
                events
                    .recent_effects
                    .iter()
                    .filter(|event| {
                        !seen.contains(&(event.source_cpu_id, event.source_sequence))
                    })
                    .rev()
                    .take(8)
                    .collect::<Vec<_>>()
            );
            Ok(events.recent_effects.into_iter().find(|event| {
                !seen.contains(&(event.source_cpu_id, event.source_sequence))
                    && event.reason == "UNSUPPORTED_OBJECT"
                    && event.effect_family == u32::from(KernelEffectFamilyV1::Exec as u16)
                    && event.operation == u32::from(KernelEffectOperationV1::Execute as u16)
                    && event.active_role_id == 2
                    && event.admitted_entry_rule_id == 0
                    && event.kernel_result == -libc::EACCES
            }))
        },
        || format!("last effects: {}", last.borrow()),
    )?;

    init.stop()?;
    env.stop()
}
