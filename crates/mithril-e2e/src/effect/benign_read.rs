use std::{fs, time::Duration};

use erebor_interceptor_abi::{
    ExecutionSetBindingStateV1 as Binding, KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O,
};
use mithril_control::{
    lower_kubernetes_policy, KubernetesPolicyModeV1 as Mode, WorkloadProtectionPolicy as Policy,
};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = identity]
fn exact_read_is_allowed<P: Platform>() -> TestResult<()> {
    let policy = include_str!("../../fixtures/process/benign_read_policy.json");
    let mut policy: Policy = serde_json::from_str(policy)?;
    let uid = policy.metadata.uid.as_deref().ok_or("missing policy UID")?;
    let compiled = lower_kubernetes_policy(&policy, uid, uid, uid)?;
    let selector = compiled
        .path_selectors
        .iter()
        .find(|item| item.path_expression() == "/tmp/mithril-descriptor-allowed")
        .ok_or("missing exact read selector")?;
    assert!(selector.requires_exact_object());
    let mut env = P::setup("benign-read")?;
    env.start_control()?;
    env.start_node()?;
    let mut init = env.start_actor("ready.py", &[], &policy.spec.pod_selector.match_labels)?;
    let args = ["/fixtures/retained_descriptor.py", "control"];
    let mut actors = [
        env.add_actor("python", &args)?,
        env.add_actor("python", &args)?,
    ];
    for actor in &mut actors {
        actor.ready()?;
    }
    let file = env.work().join("benign-read-policy.json");
    let input = file.to_str().ok_or("invalid policy path")?;
    let limit = Duration::from_secs(5);
    let mut bootstrap = policy.clone();
    for role in &mut bootstrap.spec.roles {
        role.files.clear();
    }
    fs::write(&file, serde_json::to_vec(&bootstrap)?)?;
    env.install_policy(input)?;
    env.recovered(init.id(), "benign read workload")?;

    for (mut actor, mode) in actors.into_iter().zip([Mode::Protect, Mode::Observe]) {
        policy.spec.mode = mode;
        fs::write(&file, serde_json::to_vec(&policy)?)?;
        env.install_policy(input)?;
        env.node_ready()?;
        let task = env.recovered(actor.id(), "benign read actor")?;
        let class = task.snapshot.root_class.as_deref();
        assert_eq!(class, Some("restored_or_unknown_root"));
        assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
        assert_eq!(task.snapshot.creator_task_cookie, None);
        let Some(group) = &task.snapshot.runtime_binding else {
            return Err("missing runtime binding".into());
        };
        let key = group.root_cgroup_id.to_ne_bytes();
        let binding = env
            .state::<Binding>("execution_set_bindings", &key, "read binding")?
            .ok_or("missing read binding")?;
        assert_ne!(binding.external_role_id, 0);
        assert_eq!(task.snapshot.active_role_id, binding.external_role_id);
        let effects = EffectCheck::new(&env, task.clone())?;

        actor.send(b"act\n")?;
        actor.wait_name(actor.id(), "control-0-0", "two fresh benign reads", limit)?;
        let events = effects.wait_many(
            &env,
            "EXACT_POLICY_ALLOW",
            (F::File, O::Read),
            0,
            2,
            "exact read evidence",
        )?;
        assert_eq!(events.len(), 2);
        let process = env.process(&task.snapshot.process_state_id)?;
        let generation = process.active_profile_generation_ref_id;
        assert_ne!(generation, 0);
        for event in events {
            assert_eq!(event.task_cookie, task.snapshot.task_cookie);
            assert_eq!(event.entry_instance_id, task.snapshot.entry_instance_id);
            assert_eq!(event.profile_generation_ref_id, generation);
            assert_eq!(event.exact_object_key_id, selector.kernel_handle());
            assert_ne!(event.composite_atom_id, 0);
        }

        actor.send(b"release\n")?;
        let status = actor.wait_exit("benign read completion", limit)?;
        assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
        actor.stop()?;
    }
    init.stop()?;
    env.stop()
}
