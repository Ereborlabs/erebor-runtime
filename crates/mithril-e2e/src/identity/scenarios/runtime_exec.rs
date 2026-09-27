use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
use mithril_control::WorkloadProtectionPolicy as Policy;

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

struct ExecDenial {
    seen: BTreeSet<(u32, u64)>,
}

impl ExecDenial {
    fn new<P: Platform>(env: &P) -> TestResult<Self> {
        let seen = env
            .snapshot()?
            .recent_effects
            .into_iter()
            .map(|event| (event.source_cpu_id, event.source_sequence))
            .collect();
        Ok(Self { seen })
    }

    fn wait<P: Platform>(&self, env: &P) -> TestResult<()> {
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
                            !self
                                .seen
                                .contains(&(event.source_cpu_id, event.source_sequence))
                        })
                        .rev()
                        .take(8)
                        .collect::<Vec<_>>()
                );
                Ok(events.recent_effects.into_iter().find(|event| {
                    !self
                        .seen
                        .contains(&(event.source_cpu_id, event.source_sequence))
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
        Ok(())
    }
}

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn unlisted_exec_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-exec")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("python_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("runtime_exec.py", &[], &labels)?;
    let effects = ExecDenial::new(&env)?;

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

    effects.wait(&env)?;

    init.stop()?;
    env.stop()
}

#[platform_test(host, runc, kubernetes)]
#[lifecycle = recovery_exec]
fn recovered_unlisted_exec_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("recovered-runtime-exec")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy =
        serde_json::from_str(include_str!("../../../fixtures/process/python_policy.json"))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    env.place(init.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    let root = env.recovered(init.id(), "recovered runtime root")?;
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("recovered_application_root")
    );
    assert_ne!(root.snapshot.admitted_entry_rule_id, 0);
    let effects = ExecDenial::new(&env)?;

    let error = match env.add_actor("mkdir", &["/tmp/mithril-unlisted-recovery"]) {
        Err(error) => error,
        Ok(mut actor) => {
            actor.stop()?;
            init.stop()?;
            env.stop()?;
            return Err("Mithril allowed an unmatched entry after recovery".into());
        }
    };
    let denial = error.to_string().to_lowercase();
    assert!(
        denial.contains("exit status: 13") || denial.contains("permission denied"),
        "the recovered unmatched entry was not denied with EACCES: {error}"
    );
    effects.wait(&env)?;

    init.stop()?;
    env.stop()
}
