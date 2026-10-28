use super::*;

pub(super) fn record() -> Observation {
    Observation {
        lifetime: vec![2],
        task: 3,
        process: Some([4; 16]),
        execution: vec![5; 16],
        object: vec![6; 16],
        role: Some(1),
        state: Some(1),
        exact_identity: true,
        policy_conflict: false,
        complete: true,
        network: false,
        denied: true,
        admitted: false,
        operation: Operation::Read,
        physical: Physical::Prevented,
        boottime: 10,
    }
}

pub(super) fn fact(record: u64, value: FactValue) -> Fact {
    Fact {
        identity: record,
        record,
        reviewed: true,
        value,
    }
}

pub(super) fn fixture(
    detector: Detector,
    records: &[Observation],
    facts: &[Fact],
) -> sdk::Result<sdk::Fixture> {
    let package = detector.descriptor();
    let model = &package.exports[0];
    let datasets = vec![
        Rows::encode(&model.inputs[0].port, records)?,
        Rows::encode(&model.inputs[1].port, facts)?,
        Rows::encode(&model.inputs[2].port, &[Manifest { window_ns: 100 }])?,
    ];
    Ok(sdk::Fixture {
        implementation: "shared-rust".into(),
        revision: "graph-v1".into(),
        evaluation: sdk::Evaluation {
            previous_outputs: Vec::new(),
            export: "detect".into(),
            inputs: datasets
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
            parameters: None,
            context: sdk::EvaluationContext {
                id: "evaluation".into(),
                time_utc_ns: 1,
                seed: None,
            },
            checkpoint: None,
        },
    })
}

pub(super) fn findings(
    detector: Detector,
    fixture: &sdk::Fixture,
) -> sdk::Result<(Vec<Finding>, sdk::Output)> {
    let package = detector.descriptor();
    let report = package.test(fixture, |evaluation| detector.evaluate(evaluation))?;
    let rows = Rows::decode(&package.exports[0].outputs[2], &report.output.datasets[2])?;
    Ok((rows, report.output))
}

pub(super) fn identity(cursor: u64) -> crate::discovery::DiscoveryRecordIdV1 {
    crate::discovery::DiscoveryRecordIdV1 {
        stream: crate::discovery::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        },
        cpu_id: 0,
        durable_cursor: cursor + 1,
    }
}

pub(super) fn subject(kind: GraphSubjectKindV1, bytes: Vec<u8>) -> GraphSubjectKeyV1 {
    GraphSubjectKeyV1::native(&identity(0).stream, kind, bytes)
}

pub(super) fn proof() -> ProofQualityV1 {
    ProofQualityV1 {
        source_authority: SourceAuthorityV1::AuthoritativeProvider,
        local_subject_binding: LocalSubjectBindingV1::ExactTask,
        remote_subject_binding: RemoteSubjectBindingV1::ExactRequest,
        operation_result_authority: OperationResultAuthorityV1::AuthoritativeSucceeded,
        temporal_coverage: TemporalCoverageV1::Complete,
        integrity: ProofIntegrityV1::AuthenticatedChannel,
    }
}

pub(super) fn context(classification: ContextClass) -> FactValue {
    FactValue::Context {
        subject: subject(GraphSubjectKindV1::Task, 3_u64.to_be_bytes().to_vec()),
        action_id: "context".into(),
        classification,
        proof_quality: proof(),
    }
}
