use std::{collections::BTreeSet, fs};

use erebor_interceptor_abi::{
    EntryAdmissionRuleKeyV1, EntryAdmissionRuleV1, ExecutionSetBindingStateV1,
};
use zerocopy::TryFromBytes as _;

use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn replacement_keeps_signed_entries<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("entry-replace")?;
    let bin = env.work().join("bin");
    fs::create_dir_all(&bin)?;
    ProcessFixture::fatal_exec(&bin.join("post-ponr-execfail"))?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("entry_map_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("ready.py", &[], &labels)?;
    let before = env
        .task(actor.id(), "actor before entry replacement")?
        .snapshot;
    let binding = before.runtime_binding.as_ref().ok_or("missing binding")?;
    let group = binding.root_cgroup_id.to_ne_bytes();

    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let middle = env
        .state::<ExecutionSetBindingStateV1>(
            "execution_set_bindings",
            &group,
            "intermediate entry binding",
        )?
        .ok_or("the intermediate entry binding disappeared")?
        .active_profile_generation_ref_id;
    assert!(middle > before.profile_generation_ref_id);
    env.install_policy("entry_map_policy.json")?;
    env.node_ready()?;
    let after = env
        .task(actor.id(), "actor after entry replacement")?
        .snapshot;
    assert_eq!(after.task_cookie, before.task_cookie);
    assert_eq!(after.process_state_id, before.process_state_id);
    assert_eq!(after.active_execution_id, before.active_execution_id);
    assert_eq!(after.entry_instance_id, before.entry_instance_id);
    assert_eq!(after.creator_task_cookie, before.creator_task_cookie);
    assert_eq!(after.active_role_id, before.active_role_id);
    assert_eq!(after.admitted_entry_rule_id, before.admitted_entry_rule_id);
    assert_ne!(after.admitted_entry_rule_id, 0);
    let current = env
        .state::<ExecutionSetBindingStateV1>(
            "execution_set_bindings",
            &group,
            "replaced entry binding",
        )?
        .ok_or("the replaced entry binding disappeared")?
        .active_profile_generation_ref_id;
    assert!(current > middle);

    let mut rules = Vec::new();
    for bytes in env.maps().1.keys("entry_admission_rules")? {
        let key = EntryAdmissionRuleKeyV1::try_read_from_bytes(&bytes)
            .map_err(|error| format!("invalid replacement admission key: {error}"))?;
        if key.profile_generation_ref_id == current {
            rules.push(
                env.state::<EntryAdmissionRuleV1>(
                    "entry_admission_rules",
                    &bytes,
                    "replaced signed entry",
                )?
                .ok_or("the replaced signed entry disappeared")?,
            );
        }
    }
    assert_eq!(rules.len(), 7, "{rules:?}");
    let ids: BTreeSet<_> = rules
        .iter()
        .map(|rule| rule.admitted_entry_rule_id)
        .collect();
    assert_eq!(ids.len(), 7, "{rules:?}");
    assert!(!ids.contains(&0));
    let terminal: BTreeSet<_> = rules
        .iter()
        .filter(|rule| rule.target_role_id == 8)
        .map(|rule| rule.admitted_entry_rule_id)
        .collect();
    assert_eq!(terminal.len(), 1, "{rules:?}");
    assert_eq!(
        rules.iter().filter(|rule| rule.target_role_id != 8).count(),
        6
    );

    actor.stop()?;
    env.stop()
}
