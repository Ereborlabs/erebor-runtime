use mithril_control::WorkloadProtectionPolicy as Policy;

use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::effect::EffectCheck;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = mount_race]
fn protected_mount_race_is_closed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-race")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../../fixtures/process/mount_race_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    let mut actor = env.add_actor("python3", &["/fixtures/mount_alias.py", "/work", "race"])?;
    actor.ready()?;
    let pid = actor.id();
    env.install_policy("mount_race_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    let task = env.recovered(pid, "mount race actor")?;
    let role = task.snapshot.active_role_id;
    let gen = task.snapshot.profile_generation_ref_id;
    let effects = EffectCheck::new(&env, task)?;
    if let Err(error) = actor.send(b"race\n") {
        return Err(format!("{error}; stderr: {:?}", actor.stderr()?).into());
    }
    actor.close();
    let result_path = env.work().join("mount-result.json");
    let result: serde_json::Value = wait_for(
        &result_path,
        "mount race result",
        Duration::from_secs(5),
        || {
            Ok(std::fs::read(&result_path)
                .ok()
                .and_then(|data| serde_json::from_slice(&data).ok()))
        },
        || format!("last result: {:?}", std::fs::read_to_string(&result_path)),
    )?;
    assert_eq!(result["mount_allowed"], 0);
    assert_eq!(result["mount_denied"], 8);
    assert_eq!(result["mount_other"], 0);
    assert_eq!(result["denied"], libc::EACCES);
    assert_eq!(result["allowed"], "allowed bind source\n");
    effects.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "deny",
    )?;
    effects.wait(&env, "EXACT_POLICY_ALLOW", F::File, O::OpenRead, 0, "allow")?;
    effects.wait_match(
        &env,
        "worker mount denial effect",
        |event| {
            event.reason == "UNSUPPORTED_OBJECT"
                && event.effect_family == u32::from(F::Mount as u16)
                && event.operation == u32::from(O::Mount as u16)
                && matches!(event.kernel_result, value if value == -libc::EACCES || value == -libc::EPERM)
                && event.active_role_id == role
                && event.profile_generation_ref_id == gen
        },
    ).map_err(|error| format!("{error}; actor stderr: {:?}", actor.stderr()))?;

    actor.stop()?;
    init.stop()?;
    env.stop()
}
