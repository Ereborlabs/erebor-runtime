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
    let mut last = first.clone();
    last.id.durable_cursor = 3;
    let expected = vec![first.id.clone(), last.id.clone()];
    let records = [first, separate, last];
    let record_count = records.len();
    let inputs = vec![
        Observation::encode(&records)?,
        Fact::encode(&[])?,
        Manifest::encode(&[Manifest { window_ns: 100 }])?,
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
    let findings = Finding::decode(&output.datasets[2])?;
    assert_eq!(
        GraphPackageStateV1::decode(&output.checkpoint.as_ref().ok_or("checkpoint")?.datasets[0])?,
        [GraphPackageStateV1::Declared(record_count.to_string())]
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
