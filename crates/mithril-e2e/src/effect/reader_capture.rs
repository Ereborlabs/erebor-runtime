use std::{cell::RefCell, collections::BTreeSet, fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::EffectCheck;
use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = mount_late]
fn capture_keeps_path_denials<P: Platform>() -> TestResult<()> {
    const CHURN: usize = 2_048;

    let mut env = P::setup("reader-capture")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("mount_alias_policy.json")?;
    env.node_ready()?;
    let tree = env.work().join("mount/secret");
    fs::create_dir_all(&tree)?;
    fs::write(tree.join("blocked"), b"protected capture\n")?;
    let mut actor = env.start_actor("read_path.py", &[], &labels)?;
    let task = env.task(actor.id(), "capture actor")?;
    let generation = task.snapshot.profile_generation_ref_id;
    let effects = EffectCheck::new(&env, task)?;
    let before = env.snapshot()?;
    let command = "/work/mount/secret/blocked\n";

    actor.send(command.repeat(5).as_bytes())?;
    actor.wait_text(&env.work().join("4.json"), "five captured reads")?;
    let captured = effects.wait_many(
        &env,
        "PATH_TREE_POLICY_DENY",
        (F::File, O::OpenRead),
        -libc::EACCES,
        5,
        "five captured path-tree denials",
    )?;
    let ids: BTreeSet<_> = captured
        .iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect();
    for event in &captured {
        assert_eq!(event.exact_object_key_id, 0, "{event:?}");
        assert_eq!(event.profile_generation_ref_id, generation, "{event:?}");
    }

    actor.send(command.repeat(CHURN).as_bytes())?;
    actor.wait_text(
        &env.work().join(format!("{}.json", CHURN + 4)),
        "window churn",
    )?;
    let denied = (libc::EACCES, 0);
    for index in 0..CHURN + 5 {
        let text = fs::read_to_string(env.work().join(format!("{index}.json")))?;
        assert_eq!(serde_json::from_str::<(i32, usize)>(&text)?, denied);
    }
    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    let after = wait_for(
        &path,
        "captured denials leave recent window",
        Duration::from_secs(30),
        || {
            let state = env.snapshot().map_err(|error| {
                InvalidInputSnafu {
                    path: &path,
                    reason: error.to_string(),
                }
                .build()
            })?;
            let remaining = state
                .recent_effects
                .iter()
                .filter(|event| ids.contains(&(event.source_cpu_id, event.source_sequence)))
                .count();
            *last.borrow_mut() = format!(
                "remaining={remaining}; pending={}",
                state.pending_evidence_records
            );
            Ok((remaining == 0 && state.pending_evidence_records == 0).then_some(state))
        },
        || last.borrow().clone(),
    )?;
    assert_eq!(ids.len(), 5, "{captured:?}");
    assert_eq!(
        after.reader_queue_dropped_events,
        before.reader_queue_dropped_events
    );
    assert_eq!(after.lost_effects, before.lost_effects);
    assert_eq!(after.decoder_errors, before.decoder_errors);
    assert_eq!(after.evidence_errors, before.evidence_errors);
    assert_eq!(after.wal_capacity_blocked, before.wal_capacity_blocked);

    actor.stop()?;
    env.stop()
}
