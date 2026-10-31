use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn threshold_retains_evidence_and_state() -> TestResult {
    let package = BurstDetector::package();
    let model = &package.exports[0];
    let first = Observation {
        id: araphor_analysis_builtins::discovery::DiscoveryRecordIdV1 {
            stream: araphor_analysis_builtins::discovery::EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "example".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            cpu_id: 0,
            durable_cursor: 1,
        },
        position: Position {
            commit_revision: 1,
            ordinal: 0,
        },
        effect: araphor_analysis_builtins::discovery::DiscoveryEffectKeyV1 {
            task_cookie: 7,
            target_task_cookie: None,
            process_lineage_id: vec![2; 16],
            authority_domain_id: vec![3; 16],
            execution_set_id: vec![4; 16],
            exact_object_id: vec![5; 16],
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
        },
        ingested_utc_ns: 10,
        observed_boottime_ns: 10,
        profile_generation_ref_id: None,
        original_kernel_sequence: None,
        coverage_interval_id: vec![6; 16],
        process_instance_id: Some([2; 16]),
        entry_instance_id: None,
        binding_id: None,
        role_id: None,
        state_id: None,
        entry_rule_id: None,
        proof_quality: ProofQualityV1::kernel_decision(TemporalCoverageV1::Complete),
    };
    let mut separate = first.clone();
    separate.id.stream.node_boot_id = [9; 16];
    separate.position.commit_revision = 2;
    let mut last = first.clone();
    last.id.durable_cursor = 3;
    last.position.commit_revision = 3;
    let expected = vec![first.id.clone(), last.id.clone()];
    let records = [first, separate, last];
    let record_count = records.len();
    let facts = records
        .iter()
        .enumerate()
        .map(|(row, record)| Fact {
            record: row as u32,
            key: AnalysisContextKeyV1 {
                tenant_id: record.id.stream.tenant_id,
                owner_id: "fixture".into(),
                entity_key: (row as u32).to_be_bytes().to_vec(),
                lifetime_key: record.id.stream.key(),
                owner_revision: 1,
            },
            sensitivity: ContextSensitivityV1::Tenant,
            value: GraphFactValueV1::Context {
                subject: GraphSubjectKeyV1::native(
                    &record.id.stream,
                    GraphSubjectKindV1::Task,
                    record.effect.task_cookie.to_be_bytes().to_vec(),
                ),
                action_id: "example".into(),
                classification: GraphContextActionV1::InMemory,
                proof_quality: record.proof_quality,
            },
        })
        .collect::<Vec<_>>();
    let mut support = records
        .iter()
        .enumerate()
        .map(|(row, record)| UnitSupport {
            record: record.id.clone(),
            proof: record.proof_quality,
            facts: facts
                .iter()
                .filter(|fact| fact.record as usize == row)
                .map(|fact| fact.key.clone())
                .collect(),
        })
        .collect::<Vec<_>>();
    support.sort_by(|left, right| left.record.cmp(&right.record));
    let units = records
        .iter()
        .map(|record| Unit {
            record: record.id.clone(),
            window_ns: 100,
            restricted: false,
            support: support.clone(),
        })
        .collect::<Vec<_>>();
    let inputs = vec![
        Unit::encode(&units)?,
        Unit::encode_removals(&[])?,
        model
            .change_inputs
            .as_ref()
            .ok_or("change inputs")?
            .reset_input(true)?,
        Observation::encode(&records)?,
        Fact::encode(&facts)?,
    ];
    let mut evaluation = sdk::Evaluation {
        previous_outputs: Vec::new(),
        export: "detect".into(),
        inputs: inputs
            .into_iter()
            .map(|data| sdk::Input {
                data,
                revision: sdk::Revision {
                    owner: "fixture".into(),
                    id: "1".into(),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                },
            })
            .collect(),
        parameters: Some(sdk::RecordBatch::try_new(
            Arc::new(model.parameters.clone()),
            vec![Arc::new(UInt64Array::from(vec![2]))],
        )?),
        context: sdk::EvaluationContext {
            id: "example".into(),
            time_utc_ns: 10,
            seed: Some(3),
        },
        checkpoint: None,
    };
    let output = BurstDetector::evaluate(&evaluation)?;
    let checked = package.check_evaluation(&evaluation)?;
    let supplied = <BurstDetector as sdk::Guest>::compute(&checked)?;
    checked.validate_output(&supplied)?;
    assert_eq!(supplied.evidence, output.evidence);
    for (actual, expected) in supplied.datasets.iter().zip(&output.datasets) {
        assert_eq!(actual.batches, expected.batches);
    }
    let mut other = package.clone();
    other.revision = "other".into();
    let other = other.check_evaluation(&evaluation)?;
    assert!(matches!(<BurstDetector as sdk::Guest>::compute(&other),
        Err(sdk::Error::Contract { code: sdk::ErrorCode::Incompatible, field, .. }) if field == "detector package"));
    let findings = FindingChange::decode(&output.datasets[2])?;
    assert_eq!(
        GraphPackageStateV1::decode(&output.datasets[4])?,
        [GraphPackageStateV1::Declared("0".into())]
    );
    assert!(output.checkpoint.is_none());
    assert!(model.checkpoint.is_none());
    assert!(Detector::supports_units(model));
    let contributions = Contribution::decode(&output.datasets[3])?;
    assert_eq!(contributions.len(), units.len());
    assert_eq!(contributions[0].findings, [0]);
    assert_eq!(contributions[0].subjects, [0]);
    assert!(contributions[1..]
        .iter()
        .all(|unit| unit.findings.is_empty() && unit.subjects.is_empty()));
    let state = contributions
        .iter()
        .find_map(|unit| unit.state.as_ref())
        .ok_or("declared state")?;
    assert_eq!(
        state.state,
        GraphPackageStateV1::Declared(record_count.to_string())
    );
    let last = records
        .iter()
        .max_by_key(|record| &record.id)
        .ok_or("last record")?;
    assert_eq!(state.position, last.position);
    assert_eq!(
        contributions
            .iter()
            .filter(|unit| unit.state.is_some())
            .count(),
        1
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].evidence, expected);
    assert_eq!(findings[0].state, FindingStateV1::CoverageInsufficient);
    assert_eq!(output.evidence.len(), 2);
    assert_eq!(output.reasons[0].code, "example-burst.THRESHOLD");
    assert_eq!(
        output.reasons[0]
            .details
            .column(1)
            .as_primitive::<UInt64Type>()
            .value(0),
        2
    );
    let encoded = sdk::wire::Output::encode(&package, &evaluation, &output)?;
    let decoded = encoded.decode(&package, &evaluation)?;
    evaluation.checkpoint = decoded.checkpoint;
    assert_eq!(
        BurstDetector::evaluate(&evaluation)?.evidence,
        output.evidence
    );
    let mut expected_units = contributions.clone();
    expected_units.sort_by(|left, right| left.record.cmp(&right.record));
    for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
        for reverse_facts in [false, true] {
            for reverse_units in [false, true] {
                let selected = order.map(|row| records[row].clone());
                let mut delivered = facts.clone();
                for fact in &mut delivered {
                    fact.record = order
                        .iter()
                        .position(|&row| row == fact.record as usize)
                        .ok_or("permuted record")? as u32;
                }
                if reverse_facts {
                    delivered.reverse();
                }
                let mut changed = units.clone();
                if reverse_units {
                    changed.reverse();
                }
                let mut permuted = evaluation.clone();
                permuted.inputs[0].data = Unit::encode(&changed)?;
                permuted.inputs[3].data = Observation::encode(&selected)?;
                permuted.inputs[4].data = Fact::encode(&delivered)?;
                let actual = BurstDetector::evaluate(&permuted)?;
                assert_eq!(
                    SubjectChange::decode(&actual.datasets[0])?,
                    SubjectChange::decode(&output.datasets[0])?
                );
                assert_eq!(FindingChange::decode(&actual.datasets[2])?, findings);
                let mut actual_units = Contribution::decode(&actual.datasets[3])?;
                actual_units.sort_by(|left, right| left.record.cmp(&right.record));
                assert_eq!(actual_units, expected_units);
                assert_eq!(
                    GraphPackageStateV1::decode(&actual.datasets[4])?,
                    GraphPackageStateV1::decode(&output.datasets[4])?
                );
                assert_eq!(
                    actual
                        .evidence
                        .iter()
                        .map(|link| selected[link.input.row as usize].id.clone())
                        .collect::<Vec<_>>(),
                    expected
                );
                assert_eq!(actual.reasons.len(), output.reasons.len());
                for (left, right) in actual.reasons.iter().zip(&output.reasons) {
                    assert_eq!(left.output, right.output);
                    assert_eq!(left.code, right.code);
                    assert_eq!(left.details, right.details);
                }
            }
        }
    }
    evaluation.inputs[0].data = Unit::encode(&units[1..])?;
    let partial = BurstDetector::evaluate(&evaluation)?;
    assert!(FindingChange::decode(&partial.datasets[2])?.is_empty());
    let partial = Contribution::decode(&partial.datasets[3])?;
    assert_eq!(partial.len(), units.len() - 1);
    assert!(partial
        .iter()
        .all(|unit| unit.findings.is_empty() && unit.subjects.is_empty()));
    evaluation.inputs[0].data = Unit::encode(&units[..1])?;
    let owner = BurstDetector::evaluate(&evaluation)?;
    assert_eq!(FindingChange::decode(&owner.datasets[2])?, findings);
    assert!(Contribution::decode(&owner.datasets[3])?[0].state.is_none());
    evaluation.inputs[0].data = Unit::encode(&[])?;
    evaluation.inputs[3].data = Observation::encode(&[])?;
    evaluation.inputs[4].data = Fact::encode(&[])?;
    let empty = BurstDetector::evaluate(&evaluation)?;
    assert!(Contribution::decode(&empty.datasets[3])?.is_empty());
    assert_eq!(
        GraphPackageStateV1::decode(&empty.datasets[4])?,
        [GraphPackageStateV1::Declared("0".into())]
    );
    evaluation.parameters = Some(sdk::RecordBatch::try_new(
        Arc::new(model.parameters.clone()),
        vec![Arc::new(UInt64Array::from(vec![1]))],
    )?);
    assert_eq!(
        BurstDetector::evaluate(&evaluation)
            .err()
            .ok_or("invalid threshold accepted")?
            .code(),
        sdk::ErrorCode::Invalid
    );
    Ok(())
}
