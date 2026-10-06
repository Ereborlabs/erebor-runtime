use std::{collections::BTreeSet, fs};

use erebor_interceptor_abi::{
    ExceptionRuntimeStateKindV1 as Kind, ExceptionRuntimeStateV1 as State,
    KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O,
};
use mithril_control::WorkloadProtectionException as Exception;

use super::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = exception]
fn overlapping_grants_are_rejected<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exception-overlap")?;
    env.start_control()?;
    env.start_node()?;
    fs::write(env.work().join("expired-secret"), b"")?;
    let labels = env.install_policy("exception_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("exception.py", &["single"], &labels)?;
    let task = env.task(actor.id(), "exception actor")?;
    let check = EffectCheck::new(&env, task.clone())?;
    actor.send(b"before\n")?;
    let text = actor.wait_text(&env.work().join("expired-result"), "ungranted write")?;
    assert_eq!(text.trim().parse::<i32>()?, libc::EACCES);
    let reason = "EXCEPTION_UNAVAILABLE";
    let denied = check.wait(&env, reason, F::File, O::OpenWrite, -libc::EACCES, "deny")?;
    assert_ne!(denied.composite_atom_id, 0);
    let generation = denied.profile_generation_ref_id;
    assert_eq!(generation, task.snapshot.profile_generation_ref_id);
    assert_eq!(denied.exact_object_key_id, 0);
    let mut request: Exception = serde_json::from_str(include_str!(
        "../../fixtures/process/one_use_exception.json"
    ))?;
    request.metadata.name = Some("first-write".into());
    request.metadata.uid = Some(uuid::Uuid::new_v4().to_string());
    let file = env.work().join("exception.json");
    let file = file.to_str().ok_or("invalid exception path")?;
    fs::write(file, serde_json::to_vec(&request)?)?;
    let map = "exception_runtime_states";
    let old = BTreeSet::from_iter(env.maps().1.keys(map)?);
    env.install_policy(file)?;
    let keys = BTreeSet::from_iter(env.maps().1.keys(map)?);
    let added: Vec<_> = keys.difference(&old).collect();
    assert_eq!(added.len(), 1);
    let key = added[0];
    let active = env
        .state::<State>(map, key, "exception")?
        .ok_or("missing authority")?;
    assert_eq!(active.state, Kind::Active);
    assert_eq!((active.maximum_uses, active.consumed_uses), (1, 0));
    let receipts = BTreeSet::from_iter(env.maps().1.keys("exception_use_receipts")?);

    request.metadata.name = Some("overlapping-write".into());
    request.metadata.uid = Some(uuid::Uuid::new_v4().to_string());
    fs::write(file, serde_json::to_vec(&request)?)?;
    let error = match env.install_policy(file) {
        Err(error) => error,
        Ok(_) => return Err("overlapping grant was accepted".into()),
    };
    let detail = error.to_string();
    assert!(
        detail.contains("the exception desired transaction failed: overlapping live grant")
            || (detail.contains("Kubernetes exception rejected:")
                && detail.contains("state: Failed")
                && detail.contains("ReconcileRejected")),
        "{detail}"
    );
    let after = BTreeSet::from_iter(env.maps().1.keys(map)?);
    assert!(after.is_subset(&keys), "{keys:?} -> {after:?}");
    let rows = BTreeSet::from_iter(env.maps().1.keys("exception_use_receipts")?);
    assert!(rows.is_subset(&receipts), "{receipts:?} -> {rows:?}");
    let kept = env.state::<State>(map, key, "exception")?;
    assert_eq!(kept, Some(active));
    for (command, output, code) in [
        ("first", "again-result", 0),
        ("second", "race-result", libc::EACCES),
    ] {
        let check = EffectCheck::new(&env, task.clone())?;
        actor.send(format!("{command}\n").as_bytes())?;
        let text = actor.wait_text(&env.work().join(output), command)?;
        assert_eq!(text.trim().parse::<i32>()?, code, "{command}");
        let reason = if code == 0 {
            "EXACT_POLICY_ALLOW"
        } else {
            "EXCEPTION_UNAVAILABLE"
        };
        let event = check.wait_match(&env, command, |event| {
            task.matches_effect(event, reason, F::File, O::OpenWrite, -code)
                && event.composite_atom_id == denied.composite_atom_id
        })?;
        assert_eq!(event.profile_generation_ref_id, generation);
        assert_eq!(event.exact_object_key_id, 0);
    }
    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
