use super::*;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, DiscoveryCoverageV1, EvidenceDecisionContext,
    EvidenceIntakeIdentityV1, EvidenceTemporalCoverage, GraphCoverageKeyV1,
    GraphPolicyActivationV1, GraphReadCompletionV1, GraphReadPathV1, RemoteSubjectBindingV1,
    SourceAuthorityV1,
};
use EffectPhysicalResultV1::{DeniedBeforeEffect, UnknownAfterPreEffect};

pub(super) fn source() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

pub(in crate::graph) fn wire(
    cursor: u64,
    physical_result: EffectPhysicalResultV1,
    family: u32,
    operation: u32,
    object: [u8; 16],
) -> EvidenceRecord {
    EvidenceRecord {
        observed_boottime_ns: cursor * 1_000,
        ingested_utc_ns: i64::try_from(cursor).unwrap_or(1),
        coverage_interval_id: vec![4; 16].into(),
        profile_generation_ref_id: Some(1),
        task_cookie: 9,
        process_lineage_id: vec![5; 16].into(),
        authority_domain_id: vec![6; 16].into(),
        execution_set_id: vec![7; 16].into(),
        exact_object_id: object.to_vec().into(),
        reason: 9,
        decision: physical_result as u32,
        effect_family: family,
        operation,
        configured_errno: if physical_result == DeniedBeforeEffect {
            -13
        } else {
            0
        },
        kernel_result: if physical_result == DeniedBeforeEffect {
            -13
        } else {
            0
        },
        temporal_coverage: EvidenceTemporalCoverage::Complete as i32,
        decision_context: Some(EvidenceDecisionContext {
            schema_version: 1,
            original_kernel_sequence: cursor,
            process_instance_id: vec![8; 16],
            entry_instance_id: vec![9; 16],
            binding_id: vec![10; 16],
            profile_generation_ref_id: 1,
            role_id: 1,
            state_id: 1,
            entry_rule_id: 1,
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub(in crate::graph) fn record(cursor: u64, wire: &EvidenceRecord) -> Result<DiscoveryRecordV1> {
    DiscoveryRecordV1::try_from((
        DiscoveryRecordIdV1 {
            stream: source(),
            cpu_id: 0,
            durable_cursor: cursor,
        },
        Vec::<u8>::try_from(wire)?.as_slice(),
    ))
}

pub(super) fn input(records: Vec<DiscoveryRecordV1>) -> GraphReplayInputV1 {
    let first = records.first().map_or(1, |record| record.id.durable_cursor);
    let last = records
        .last()
        .map_or(first, |record| record.id.durable_cursor);
    let input_positions = records
        .iter()
        .map(|record| {
            (
                record.id.clone(),
                araphor_data::StorePositionV1 {
                    commit_revision: record.id.durable_cursor + 1,
                    ordinal: 0,
                },
            )
        })
        .collect();
    GraphReplayInputV1 {
        source: source(),
        records,
        input_positions,
        coverage: vec![DiscoveryCoverageV1 {
            stream: source(),
            cpu_id: 0,
            first_cursor: first,
            last_cursor: last,
            expected_records: last - first + 1,
            coverage_revision: 1,
            coverage_interval_id: [4; 16],
            state: DiscoveryCoverageStateV1::Healthy,
            gap_reasons: vec![],
        }],
        coverage_keys: vec![GraphCoverageKeyV1 {
            source: source(),
            cpu_id: 0,
            report_revision: 1,
            interval_id: [4; 16],
            interval_revision: 1,
            state: DiscoveryCoverageStateV1::Healthy,
            gap_reasons: vec![],
        }],
        facts: vec![],
        missing_ranges: vec![],
    }
}

pub(in crate::graph) fn fact(
    record: &DiscoveryRecordV1,
    index: u64,
    value: GraphFactValueV1,
) -> Result<AnalysisContextVersionV1> {
    let fact = GraphFactV1 {
        record_id: record.id.clone(),
        value,
    };
    fact.validate()?;
    Ok(AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: source().tenant_id,
            owner_id: "qualified-fixture-input".into(),
            entity_key: index.to_be_bytes().to_vec(),
            lifetime_key: source().key(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: serde_json::to_vec(&fact).map_err(|_| {
            GraphInvalidSnafu {
                field: "fixture fact",
            }
            .build()
        })?,
    })
}

pub(in crate::graph) fn policy(
    record: &DiscoveryRecordV1,
    index: u64,
) -> Result<AnalysisContextVersionV1> {
    let activation = AnalysisContextKeyV1 {
        tenant_id: source().tenant_id,
        owner_id: "activation-fixture".into(),
        entity_key: record.id.durable_cursor.to_be_bytes().to_vec(),
        lifetime_key: source().key(),
        owner_revision: 1,
    };
    fact(
        record,
        index,
        GraphFactValueV1::Policy(PolicyObservationProvenanceV1 {
            source: source(),
            profile_generation_ref_id: 1,
            observations: vec![record.id.clone()],
            policy_source_revision_id: Some("reviewed-source".into()),
            candidate_content_id: Some("candidate".into()),
            target_snapshot_digest: Some("target".into()),
            node_bound_generation_digest: Some("generation".into()),
            activation_acknowledgement: Some(activation),
            state: PolicyProvenanceStateV1::Exact,
            limits: vec![],
        }),
    )
}

pub(in crate::graph) fn activation(record: &DiscoveryRecordV1) -> Result<AnalysisContextVersionV1> {
    let key = AnalysisContextKeyV1 {
        tenant_id: source().tenant_id,
        owner_id: "activation-fixture".into(),
        entity_key: record.id.durable_cursor.to_be_bytes().to_vec(),
        lifetime_key: source().key(),
        owner_revision: 1,
    };
    let value = GraphFactValueV1::Activation(GraphPolicyActivationV1 {
        tenant_id: uuid::Uuid::from_bytes(source().tenant_id).to_string(),
        node_id: source().node_id,
        node_boot_id: source().node_boot_id.to_vec(),
        label_epoch: source().label_epoch,
        candidate_content_id: "candidate".into(),
        policy_source_revision_id: "reviewed-source".into(),
        target_snapshot_digest: "target".into(),
        state: "ACTIVE".into(),
        node_bound_generation_digest: Some("generation".into()),
        profile_generation_ref_id: Some(1),
        readback_digest: Some("readback".into()),
        probe_result_digest: Some("probe".into()),
        reason_code: None,
        observed_utc_ns: 1,
    });
    let fact = GraphFactV1 {
        record_id: record.id.clone(),
        value,
    };
    Ok(AnalysisContextVersionV1 {
        key,
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: serde_json::to_vec(&fact).map_err(|_| {
            GraphInvalidSnafu {
                field: "activation fixture",
            }
            .build()
        })?,
    })
}

pub(super) fn authority_proof() -> ProofQualityV1 {
    ProofQualityV1 {
        source_authority: SourceAuthorityV1::AuthoritativeProvider,
        local_subject_binding: LocalSubjectBindingV1::ExactProcess,
        remote_subject_binding: RemoteSubjectBindingV1::ExactRequest,
        operation_result_authority: OperationResultAuthorityV1::AuthoritativeSucceeded,
        temporal_coverage: TemporalCoverageV1::Complete,
        integrity: ProofIntegrityV1::Signed,
    }
}

pub(super) fn credential_input() -> Result<GraphReplayInputV1> {
    credential_input_from(1)
}

pub(in crate::graph) fn credential_input_from(first: u64) -> Result<GraphReplayInputV1> {
    let records = vec![
        record(first, &wire(first, UnknownAfterPreEffect, 2, 4, [20; 16]))?,
        record(
            first + 1,
            &wire(first + 1, UnknownAfterPreEffect, 3, 13, [21; 16]),
        )?,
        record(
            first + 2,
            &wire(first + 2, UnknownAfterPreEffect, 3, 13, [21; 16]),
        )?,
    ];
    let mut input = input(records);
    for (index, record) in input.records.iter().enumerate() {
        input.facts.push(policy(record, 10 + index as u64)?);
    }
    input.facts.push(fact(
        &input.records[0],
        1,
        GraphFactValueV1::Credential {
            object_id: [20; 16],
            expected_access: false,
            reviewed_policy_revision: "reviewed-source".into(),
            completion: Some(GraphReadCompletionV1 {
                admission_record: input.records[0].id.clone(),
                owner: "qualified-read-owner".into(),
                completion_id: "read-1".into(),
                task_cookie: 9,
                process_instance_id: [8; 16],
                object_id: [20; 16],
                file_description_id: "fd-lifetime-1".into(),
                path: GraphReadPathV1::Read,
                result: 2,
                byte_count: 2,
                credential_lease_id: Some("lease-1".into()),
                principal_id: Some("principal".into()),
            }),
            proof_quality: authority_proof(),
            principal_id: Some("principal".into()),
        },
    )?);
    input.facts.push(fact(
        &input.records[1],
        2,
        GraphFactValueV1::Channel {
            task_cookie: 9,
            process_instance_id: [8; 16],
            socket_object_id: [21; 16],
            authority_id: "provider".into(),
            carried_request_id: "request-1".into(),
            credential_lease_id: "lease-1".into(),
            principal_id: "principal".into(),
            operation_id: "repository-write".into(),
            proof_quality: authority_proof(),
        },
    )?);
    input.facts.push(fact(
        &input.records[2],
        3,
        GraphFactValueV1::AuthorityUse {
            authority_id: "provider".into(),
            process_instance_id: Some([8; 16]),
            task_cookie: Some(9),
            credential_object_id: Some([20; 16]),
            socket_object_id: Some([21; 16]),
            request_id: Some("request-1".into()),
            credential_lease_id: Some("lease-1".into()),
            principal_id: "principal".into(),
            operation_id: "repository-write".into(),
            outside_reviewed_behavior: true,
            proof_quality: authority_proof(),
            workload_binding: Some(GraphSubjectKeyV1::native(
                &source(),
                GraphSubjectKindV1::ExecutionSet,
                vec![7; 16],
            )),
        },
    )?);
    for record in &input.records {
        input.facts.push(activation(record)?);
    }
    Ok(input)
}
