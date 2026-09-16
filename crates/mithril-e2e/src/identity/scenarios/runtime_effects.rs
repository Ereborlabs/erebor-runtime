use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn incomplete_probe_fails_closed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-effects")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("runtime_exec.py", &[])?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();

    let args = vec!["/work/missing"; 3_000];
    let error = match env.add_actor("cat", &args) {
        Err(error) => error,
        Ok(mut actor) => {
            actor.stop()?;
            init.stop()?;
            env.stop()?;
            return Err("Mithril allowed a declared probe with incomplete argv".into());
        }
    };
    let denial = error.to_string().to_lowercase();
    assert!(
        denial.contains("exit status: 13") || denial.contains("permission denied"),
        "the incomplete probe was not denied with EACCES: {error}"
    );

    let exec = u32::from(KernelEffectFamilyV1::Exec as u16);
    let execute = u32::from(KernelEffectOperationV1::Execute as u16);
    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    let (denied, infra) = wait_for(
        &path,
        "incomplete probe evidence",
        Duration::from_secs(30),
        || {
            let events = env
                .snapshot()
                .map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: source.to_string(),
                    }
                    .build()
                })?
                .recent_effects;
            *last.borrow_mut() = format!("{:?}", events.iter().rev().take(16).collect::<Vec<_>>());
            let events = events
                .into_iter()
                .filter(|event| !seen.contains(&(event.source_cpu_id, event.source_sequence)))
                .collect::<Vec<_>>();
            let denied = events.iter().find(|event| {
                event.reason == "UNSUPPORTED_OBJECT"
                    && event.effect_family == exec
                    && event.operation == execute
            });
            let infra = events.iter().find(|event| {
                event.reason == "RUNTIME_ENTRY_INFRASTRUCTURE"
                    && event.effect_family == exec
                    && event.operation == execute
                    && event.admitted_entry_rule_id == 0
            });
            Ok(denied.cloned().zip(infra.cloned()))
        },
        || format!("last effects: {}", last.borrow()),
    )?;
    assert_eq!(denied.effect_family, exec);
    assert_eq!(denied.operation, execute);
    assert_eq!(denied.active_role_id, 6);
    assert_eq!(denied.admitted_entry_rule_id, 0);
    assert_eq!(denied.kernel_result, -libc::EACCES);

    assert_eq!(infra.effect_family, exec);
    assert_eq!(infra.operation, execute);
    assert_eq!(infra.admitted_entry_rule_id, 0);

    init.stop()?;
    env.stop()
}
