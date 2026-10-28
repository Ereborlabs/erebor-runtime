use super::*;
use erebor_interceptor_abi::{
    EffectPhysicalResultV1, KernelEffectFamilyV1, KernelEffectOperationV1,
};

pub(super) fn record() -> Observation {
    Observation {
        id: identity(0),
        effect: crate::discovery::DiscoveryEffectKeyV1 {
            task_cookie: 3,
            target_task_cookie: None,
            process_lineage_id: vec![4; 16],
            authority_domain_id: vec![4; 16],
            execution_set_id: vec![5; 16],
            exact_object_id: vec![6; 16],
            destination_id: 0,
            policy_rule_id: 1,
            reason: 1,
            decision: EffectPhysicalResultV1::DeniedBeforeEffect as u32,
            effect_family: KernelEffectFamilyV1::File as u32,
            operation: KernelEffectOperationV1::Read as u32,
            operation_argument: None,
            configured_errno: 1,
            kernel_result: -1,
            exact_file_object: None,
        },
        ingested_utc_ns: 10,
        observed_boottime_ns: 10,
        profile_generation_ref_id: Some(1),
        original_kernel_sequence: Some(1),
        coverage_interval_id: vec![7; 16],
        process_instance_id: Some([4; 16]),
        entry_instance_id: Some([8; 16]),
        binding_id: Some([9; 16]),
        role_id: Some(1),
        state_id: Some(1),
        entry_rule_id: Some(1),
        proof_quality: ProofQualityV1 {
            integrity: ProofIntegrityV1::AuthenticatedChannel,
            ..ProofQualityV1::kernel_decision(TemporalCoverageV1::Complete)
        },
    }
}

pub(super) fn fact(record: u32, value: FactValue) -> Fact {
    Fact {
        record,
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "fixture".into(),
            entity_key: record.to_be_bytes().to_vec(),
            lifetime_key: identity(0).stream.key(),
            owner_revision: 1,
        },
        sensitivity: ContextSensitivityV1::Tenant,
        value,
    }
}

pub(super) fn fixture(
    _detector: Detector,
    records: &[Observation],
    facts: &[Fact],
) -> sdk::Result<sdk::Fixture> {
    let mut records = records.to_vec();
    for (row, record) in records.iter_mut().enumerate() {
        record.id = identity(row as u64);
    }
    let datasets = vec![
        Observation::encode(&records)?,
        Fact::encode(facts)?,
        Manifest::encode(&[Manifest { window_ns: 100 }])?,
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
    let rows = Finding::decode(&report.output.datasets[2])?;
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
        subject: subject(GraphSubjectKindV1::Artifact, vec![9; 16]),
        action_id: "context".into(),
        classification,
        proof_quality: proof(),
    }
}
