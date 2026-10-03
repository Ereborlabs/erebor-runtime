use std::{collections::BTreeSet, fs};

use erebor_interceptor_abi::{EntryAdmissionRuleKeyV1, EntryAdmissionRuleV1, ExactFileObjectKeyV1};
use zerocopy::TryFromBytes as _;

use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn signed_entries_are_complete<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("entry-map")?;
    let bin = env.work().join("bin");
    fs::create_dir_all(&bin)?;
    ProcessFixture::fatal_exec(&bin.join("post-ponr-execfail"))?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("entry_map_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("ready.py", &[], &labels)?;
    let task = env.task(actor.id(), "application entry")?;
    assert_eq!(task.snapshot.active_role_id, 1);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);

    let mut rules = Vec::new();
    for bytes in env.maps().1.keys("entry_admission_rules")? {
        let key = EntryAdmissionRuleKeyV1::try_read_from_bytes(&bytes)
            .map_err(|error| format!("invalid admission key: {error}"))?;
        if key.profile_generation_ref_id == task.snapshot.profile_generation_ref_id {
            rules.push(
                env.state::<EntryAdmissionRuleV1>(
                    "entry_admission_rules",
                    &bytes,
                    "signed admission rule",
                )?
                .ok_or("the signed admission rule disappeared")?,
            );
        }
    }
    assert_eq!(rules.len(), 7, "{rules:?}");
    let ids: BTreeSet<_> = rules
        .iter()
        .map(|rule| rule.admitted_entry_rule_id)
        .collect();
    assert_eq!(ids.len(), 7, "{rules:?}");
    for rule in &rules {
        assert_ne!(rule.target_role_id, 0, "{rule:?}");
        assert_ne!(rule.target_process_state_vector_id, 0, "{rule:?}");
        assert_ne!(rule.admitted_entry_rule_id, 0, "{rule:?}");
        assert_eq!(rule.reserved, 0, "{rule:?}");
        assert_eq!(rule.exact_object_key_id, 0, "{rule:?}");
        assert_eq!(rule.executable_object, ExactFileObjectKeyV1::default());
    }
    assert_eq!(
        rules.iter().filter(|rule| rule.target_role_id == 8).count(),
        1
    );
    assert_eq!(
        rules.iter().filter(|rule| rule.target_role_id != 8).count(),
        6
    );
    assert_eq!(
        task.entry_rule(&env)?.target_role_id,
        task.snapshot.active_role_id
    );

    actor.stop()?;
    env.stop()
}
