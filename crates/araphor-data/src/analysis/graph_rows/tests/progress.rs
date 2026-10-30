use super::*;
use crate::{DiscoveryEffectKeyV1, GraphSnapshotV1};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn observations() -> std::result::Result<Vec<Observation>, Box<dyn std::error::Error>> {
    let snapshot: GraphSnapshotV1 = serde_json::from_slice(include_bytes!("graph.json"))?;
    let first = snapshot.input_manifest.evidence[0].clone();
    let mut second = first.clone();
    second.durable_cursor += 1;
    let effect = DiscoveryEffectKeyV1 {
        task_cookie: 0,
        target_task_cookie: None,
        process_lineage_id: Vec::new(),
        authority_domain_id: Vec::new(),
        execution_set_id: Vec::new(),
        exact_object_id: Vec::new(),
        destination_id: 0,
        policy_rule_id: 0,
        reason: 0,
        decision: 0,
        effect_family: 0,
        operation: 0,
        operation_argument: None,
        configured_errno: 0,
        kernel_result: 0,
        exact_file_object: None,
    };
    Ok([first, second]
        .into_iter()
        .enumerate()
        .map(|(ordinal, id)| Observation {
            id,
            position: Position {
                commit_revision: 1,
                ordinal: ordinal as u32,
            },
            effect: effect.clone(),
            ingested_utc_ns: 1,
            observed_boottime_ns: 1,
            profile_generation_ref_id: None,
            original_kernel_sequence: None,
            coverage_interval_id: Vec::new(),
            process_instance_id: None,
            entry_instance_id: None,
            binding_id: None,
            role_id: None,
            state_id: None,
            entry_rule_id: None,
            proof_quality: snapshot.graph.edges[0].proof_quality,
        })
        .collect())
}

fn evaluation(
    records: &[Observation],
    previous_outputs: Vec<sdk::Dataset>,
    window_ns: u64,
) -> std::result::Result<sdk::Evaluation, Box<dyn std::error::Error>> {
    let input = |data| sdk::Input {
        data,
        revision: sdk::Revision {
            owner: "graph".into(),
            id: "1".into(),
            window: None,
        },
        coverage: sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        },
    };
    Ok(sdk::Evaluation {
        export: "detect".into(),
        inputs: vec![
            input(Observation::encode(records)?),
            input(Fact::encode(&[])?),
            input(Manifest::encode(&[Manifest { window_ns }])?),
        ],
        parameters: None,
        context: sdk::EvaluationContext {
            id: "graph-progress".into(),
            time_utc_ns: 1,
            seed: None,
        },
        checkpoint: None,
        previous_outputs,
    })
}

fn output(
    additions: &[Progress],
    removals: &[ProgressRemoval],
) -> std::result::Result<sdk::Output, Box<dyn std::error::Error>> {
    Ok(sdk::Output {
        datasets: vec![
            Progress::encode(additions)?,
            ProgressRemoval::encode(removals)?,
        ],
        ..Default::default()
    })
}

#[test]
fn native_defaults_store_no_progress_rows() -> TestResult {
    let records = observations()?;
    let evaluation = evaluation(&records, Vec::new(), 60)?;
    let expected = Progress::from_evaluation(&evaluation)?;
    let plan = GraphRows::progress_plan(
        &evaluation,
        &output(&expected, &[])?,
        Some(Detector::Process),
        true,
    )?;
    assert!(plan.additions.is_empty());
    assert!(plan.removals.is_empty());
    let expanded = GraphRows::expand_progress(
        &evaluation,
        Vec::new(),
        plan.root.as_deref(),
        Some(Detector::Process),
    )?;
    assert_eq!(expanded.len(), 2);
    assert_eq!(expanded.values().cloned().collect::<Vec<_>>(), {
        let mut sorted = expected;
        sorted.sort_by(|left, right| left.record.cmp(&right.record));
        sorted
    });
    let mut bad_root = plan.root.ok_or("missing root")?;
    bad_root[0] ^= 1;
    assert!(GraphRows::expand_progress(
        &evaluation,
        Vec::new(),
        Some(&bad_root),
        Some(Detector::Process),
    )
    .is_err());
    Ok(())
}

#[test]
fn native_delta_stores_only_changed_some_state() -> TestResult {
    let records = observations()?;
    let first = evaluation(&records[..1], Vec::new(), 60)?;
    let prior = Progress::from_evaluation(&first)?;
    let current = evaluation(&records, vec![Progress::encode(&prior)?], 60)?;
    let mut added = Progress::from_evaluation(&current)?[1].clone();
    added.state = Some("NATIVE_EFFECT".into());
    let plan = GraphRows::progress_plan(
        &current,
        &output(std::slice::from_ref(&added), &[])?,
        Some(Detector::Process),
        false,
    )?;
    assert_eq!(plan.additions, vec![added.clone()]);
    assert!(plan.removals.is_empty());
    let full = GraphRows::expand_progress(
        &current,
        plan.additions,
        plan.root.as_deref(),
        Some(Detector::Process),
    )?;
    assert_eq!(full.len(), 2);
    assert_eq!(full[&added.record].state, added.state);

    let previous = Progress::encode(&full.values().cloned().collect::<Vec<_>>())?;
    let next = evaluation(&records, vec![previous], 60)?;
    let mut cleared = added.clone();
    cleared.state = None;
    let plan = GraphRows::progress_plan(
        &next,
        &output(
            std::slice::from_ref(&cleared),
            &[ProgressRemoval {
                record: added.record.clone(),
            }],
        )?,
        Some(Detector::Process),
        false,
    )?;
    assert!(plan.additions.is_empty());
    assert_eq!(plan.removals, vec![added.record]);
    assert_eq!(
        GraphRows::expand_progress(
            &next,
            Vec::new(),
            plan.root.as_deref(),
            Some(Detector::Process)
        )?
        .len(),
        2
    );
    Ok(())
}

#[test]
fn native_progress_requires_exact_ports_and_input() -> TestResult {
    let records = observations()?;
    let evaluation = evaluation(&records, Vec::new(), 60)?;
    let expected = Progress::from_evaluation(&evaluation)?;
    assert!(GraphRows::progress_plan(
        &evaluation,
        &output(&expected[..1], &[])?,
        Some(Detector::Process),
        true,
    )
    .is_err());
    assert!(GraphRows::progress_plan(
        &evaluation,
        &output(&[expected[0].clone(), expected[0].clone()], &[])?,
        Some(Detector::Process),
        true,
    )
    .is_err());
    let mut wrong = expected.clone();
    wrong[0].digest[0] ^= 1;
    assert!(GraphRows::progress_plan(
        &evaluation,
        &output(&wrong, &[])?,
        Some(Detector::Process),
        true,
    )
    .is_err());
    assert!(GraphRows::progress_plan(
        &evaluation,
        &output(
            &expected,
            &[ProgressRemoval {
                record: expected[0].record.clone(),
            }],
        )?,
        Some(Detector::Process),
        true,
    )
    .is_err());
    let changed_window = self::evaluation(&records, Vec::new(), 120)?;
    assert!(GraphRows::progress_plan(
        &changed_window,
        &output(&expected, &[])?,
        Some(Detector::Process),
        true,
    )
    .is_err());
    Ok(())
}

#[test]
fn native_delta_rejects_inconsistent_operations() -> TestResult {
    let records = observations()?;
    let first = evaluation(&records[..1], Vec::new(), 60)?;
    let prior = Progress::from_evaluation(&first)?;
    let current = evaluation(&records, vec![Progress::encode(&prior)?], 60)?;
    assert!(GraphRows::progress_plan(
        &current,
        &output(&prior, &[])?,
        Some(Detector::Process),
        false,
    )
    .is_err());
    let absent = ProgressRemoval {
        record: records[1].id.clone(),
    };
    assert!(GraphRows::progress_plan(
        &current,
        &output(&[], std::slice::from_ref(&absent))?,
        Some(Detector::Process),
        false,
    )
    .is_err());
    let duplicate = ProgressRemoval {
        record: records[0].id.clone(),
    };
    assert!(GraphRows::progress_plan(
        &current,
        &output(&[], &[duplicate.clone(), duplicate])?,
        Some(Detector::Process),
        false,
    )
    .is_err());
    Ok(())
}

#[test]
fn explicit_progress_keeps_rows_and_rejects_root() -> TestResult {
    let records = observations()?;
    let evaluation = evaluation(&records[..1], Vec::new(), 60)?;
    let mut custom = Progress::from_evaluation(&evaluation)?;
    custom[0].state = Some("custom".into());
    let plan = GraphRows::progress_plan(&evaluation, &output(&custom, &[])?, None, true)?;
    assert_eq!(plan.additions, custom);
    assert!(plan.root.is_none());
    let rows = GraphRows::expand_progress(&evaluation, plan.additions, None, None)?;
    assert_eq!(rows.len(), 1);
    assert!(GraphRows::expand_progress(&evaluation, Vec::new(), Some(&[0; 32]), None).is_err());
    assert!(
        GraphRows::expand_progress(&evaluation, Vec::new(), None, Some(Detector::Process)).is_err()
    );
    Ok(())
}
