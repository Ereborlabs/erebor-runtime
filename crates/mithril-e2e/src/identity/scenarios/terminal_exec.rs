use std::{cell::RefCell, fs, time::Duration};

use erebor_interceptor_abi::{
    EntryAdmissionRuleV1, ExactFileObjectKeyV1, PendingExecStateV1, PendingExecV1,
};
use snafu::ResultExt as _;
use zerocopy::TryFromBytes as _;

use crate::error::{InterceptorSnafu, InvalidInputSnafu};
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host)]
#[lifecycle = terminal_entry]
fn terminal_entry_is_fatal<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("terminal-entry")?;
    let bin = env.work().join("bin");
    fs::create_dir_all(&bin)?;
    ProcessFixture::fatal_exec(&bin.join("post-ponr-execfail"))?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("fatal_exec_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let mut probe = env.add_actor("sleep", &["0.5"])?;
    let role = env.task(probe.id(), "termination role")?;
    assert!(role.snapshot.active_role_id != 0 && role.snapshot.admitted_entry_rule_id != 0);

    assert!(env.add_actor("post-ponr-execfail", &[]).is_err());
    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    let pending = wait_for(
        &path,
        "terminal entry evidence",
        Duration::from_secs(30),
        || {
            for key in env
                .maps()
                .1
                .keys("pending_execs")
                .context(InterceptorSnafu)?
            {
                let Some(bytes) = env
                    .maps()
                    .1
                    .lookup("pending_execs", &key)
                    .context(InterceptorSnafu)?
                else {
                    continue;
                };
                let value = PendingExecV1::try_read_from_bytes(&bytes).map_err(|error| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: format!("invalid pending exec: {error}"),
                    }
                    .build()
                })?;
                *last.borrow_mut() = format!("{value:?}");
                if value.state == PendingExecStateV1::PostPonrFatal {
                    return Ok(Some(value));
                }
            }
            Ok(None)
        },
        || format!("last pending exec: {}", last.borrow()),
    )?;

    let reader = env.maps().1;
    let mut admission = None;
    for key in reader
        .keys("entry_admission_rules")
        .context(InterceptorSnafu)?
    {
        let value = reader
            .lookup("entry_admission_rules", &key)
            .context(InterceptorSnafu)?
            .ok_or("the admission rule disappeared")?;
        let rule = EntryAdmissionRuleV1::try_read_from_bytes(&value)
            .map_err(|error| format!("invalid admission rule: {error}"))?;
        if rule.admitted_entry_rule_id == pending.admitted_entry_rule_id {
            admission = Some(rule);
            break;
        }
    }
    let rule = admission.ok_or("the terminal admission rule is missing")?;
    assert_eq!(rule.target_role_id, role.snapshot.active_role_id);
    assert_ne!(
        rule.admitted_entry_rule_id,
        role.snapshot.admitted_entry_rule_id
    );
    assert_ne!(rule.admitted_entry_rule_id, 0);
    assert_eq!(rule.exact_object_key_id, 0);
    assert_eq!(rule.executable_object, ExactFileObjectKeyV1::default());

    probe.stop()?;
    init.stop()?;
    env.stop()
}
