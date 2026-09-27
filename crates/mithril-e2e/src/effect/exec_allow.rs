use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn exec_allow_cannot_admit<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exec-allow")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("exec_allow_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    let task = env.task(init.id(), "exec-allow workload")?;
    let generation = task.snapshot.profile_generation_ref_id;
    let root_cookie = task.snapshot.task_cookie;
    let effects = EffectCheck::new(&env, task)?;

    let error = match env.add_actor("sleep", &["0.5"]) {
        Err(error) => error,
        Ok(mut actor) => {
            actor.stop()?;
            init.stop()?;
            env.stop()?;
            return Err("an undeclared runtime entry executed".into());
        }
    };
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("status: 13")
            || message.contains("exit code 13")
            || message.contains("permission denied"),
        "runtime entry did not fail with EACCES: {error}"
    );

    let allowed = effects.wait_match(&env, "signed executable Allow", |event| {
        event.reason == "EXACT_POLICY_ALLOW"
            && event.effect_family == u32::from(F::Exec as u16)
            && event.operation == u32::from(O::Execute as u16)
            && event.kernel_result == 0
            && event.task_cookie != root_cookie
            && event.active_role_id == 2
            && event.profile_generation_ref_id == generation
            && event.composite_atom_id != 0
            && event.exact_object_key_id == 0
    })?;
    assert_eq!(allowed.inode, 0, "{allowed:?}");
    assert_eq!(allowed.inode_generation, 0, "{allowed:?}");
    assert_eq!(allowed.admitted_entry_rule_id, 0);
    effects.wait_match(&env, "undeclared entry denial", |event| {
        event.reason == "UNSUPPORTED_OBJECT"
            && event.effect_family == u32::from(F::Exec as u16)
            && event.operation == u32::from(O::Execute as u16)
            && event.kernel_result == -libc::EACCES
            && event.task_cookie == allowed.task_cookie
            && event.active_role_id == allowed.active_role_id
            && event.admitted_entry_rule_id == 0
            && event.profile_generation_ref_id == generation
    })?;

    init.stop()?;
    env.stop()
}
