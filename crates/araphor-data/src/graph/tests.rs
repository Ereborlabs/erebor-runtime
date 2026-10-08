use std::sync::{Arc, Mutex};

use super::*;
use crate::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn source() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

fn wire(
    cursor: u64,
    decision: u32,
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
        decision,
        effect_family: family,
        operation,
        configured_errno: -13,
        kernel_result: if decision == 2 { -13 } else { 0 },
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

fn record(cursor: u64, wire: &EvidenceRecord) -> Result<DiscoveryRecordV1> {
    DiscoveryRecordV1::try_from((
        DiscoveryRecordIdV1 {
            stream: source(),
            cpu_id: 0,
            durable_cursor: cursor,
        },
        Vec::<u8>::try_from(wire)?.as_slice(),
    ))
}

fn input(records: Vec<DiscoveryRecordV1>) -> GraphReplayInputV1 {
    let first = records.first().map_or(1, |record| record.id.durable_cursor);
    let last = records
        .last()
        .map_or(first, |record| record.id.durable_cursor);
    GraphReplayInputV1 {
        source: source(),
        records,
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

fn fact(
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

fn policy(record: &DiscoveryRecordV1, index: u64) -> Result<AnalysisContextVersionV1> {
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

fn activation(record: &DiscoveryRecordV1) -> Result<AnalysisContextVersionV1> {
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

fn authority_proof() -> ProofQualityV1 {
    ProofQualityV1 {
        source_authority: SourceAuthorityV1::AuthoritativeProvider,
        local_subject_binding: LocalSubjectBindingV1::ExactProcess,
        remote_subject_binding: RemoteSubjectBindingV1::ExactRequest,
        operation_result_authority: OperationResultAuthorityV1::AuthoritativeSucceeded,
        temporal_coverage: TemporalCoverageV1::Complete,
        integrity: ProofIntegrityV1::Signed,
    }
}

fn credential_input() -> Result<GraphReplayInputV1> {
    credential_input_from(1)
}

fn credential_input_from(first: u64) -> Result<GraphReplayInputV1> {
    let records = vec![
        record(first, &wire(first, 0, 2, 4, [20; 16]))?,
        record(first + 1, &wire(first + 1, 0, 3, 13, [21; 16]))?,
        record(first + 2, &wire(first + 2, 0, 3, 13, [21; 16]))?,
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

#[test]
fn control_graph_subject_lifetime_does_not_use_collector_epoch() {
    let first = GraphSubjectKeyV1::native(
        &source(),
        GraphSubjectKindV1::Task,
        1_u64.to_be_bytes().to_vec(),
    );
    let mut other = source();
    other.source_id = [4; 16];
    other.source_epoch = 2;
    assert_eq!(
        first,
        GraphSubjectKeyV1::native(
            &other,
            GraphSubjectKindV1::Task,
            1_u64.to_be_bytes().to_vec()
        )
    );
    other.node_boot_id = [5; 16];
    assert_ne!(
        first,
        GraphSubjectKeyV1::native(
            &other,
            GraphSubjectKindV1::Task,
            1_u64.to_be_bytes().to_vec()
        )
    );
    let external = GraphSubjectKeyV1 {
        tenant_id: source().tenant_id,
        authority: GraphSubjectAuthorityV1::External {
            authority_id: "external-estate".into(),
        },
        kind: GraphSubjectKindV1::External,
        identity: b"sandbox-lifetime".to_vec(),
    };
    assert!(external.validate().is_ok());
}

#[test]
fn control_graph_denial_and_missing_lifetime() -> TestResult {
    let mut denied = wire(1, 2, 2, 2, [20; 16]);
    let graph = GraphAndFindingOwner::derive(&input(vec![record(1, &denied)?]))?;
    assert_eq!(graph.findings[0].state, FindingStateV1::Confirmed);
    assert_eq!(
        graph.findings[0].effects[0].physical_result,
        GraphPhysicalResultV1::Prevented
    );
    assert!(graph.findings[0]
        .limits
        .contains(&"NATIVE_ANCESTRY_UNAVAILABLE".into()));
    assert!(graph
        .graph
        .branches
        .iter()
        .all(|branch| branch.state != GraphBranchStateV1::TerminalVerified));
    denied.task_cookie = 0;
    denied
        .decision_context
        .as_mut()
        .ok_or("context")?
        .process_instance_id = vec![0; 16];
    let graph = GraphAndFindingOwner::derive(&input(vec![record(1, &denied)?]))?;
    assert_eq!(
        graph.findings[0].state,
        FindingStateV1::CoverageInsufficient
    );
    assert_eq!(graph.findings[0].effects[0].process_instance_id, None);
    assert_eq!(
        graph.findings[0].effects[0]
            .proof_quality
            .local_subject_binding,
        LocalSubjectBindingV1::None
    );
    assert_eq!(
        graph.findings[0].subject_id.kind,
        GraphSubjectKindV1::External
    );
    Ok(())
}

#[test]
fn control_graph_native_parent_is_exact_and_local() -> TestResult {
    let mut input = input(vec![record(1, &wire(1, 2, 2, 2, [20; 16]))?]);
    let parent = GraphSubjectKeyV1::native(
        &source(),
        GraphSubjectKindV1::Task,
        5_u64.to_be_bytes().to_vec(),
    );
    let child = GraphSubjectKeyV1::native(
        &source(),
        GraphSubjectKindV1::Task,
        99_u64.to_be_bytes().to_vec(),
    );
    input.facts.push(fact(
        &input.records[0],
        1,
        GraphFactValueV1::NativeParent {
            parent: parent.clone(),
            child,
            proof_quality: ProofQualityV1::kernel_decision(TemporalCoverageV1::Complete),
        },
    )?);
    let graph = GraphAndFindingOwner::derive(&input)?;
    assert!(graph
        .graph
        .edges
        .iter()
        .all(|edge| edge.key.edge_type != GraphEdgeTypeV1::NativeParent));
    let child = GraphSubjectKeyV1::native(
        &source(),
        GraphSubjectKindV1::Task,
        9_u64.to_be_bytes().to_vec(),
    );
    input.facts = vec![fact(
        &input.records[0],
        2,
        GraphFactValueV1::NativeParent {
            parent: parent.clone(),
            child: child.clone(),
            proof_quality: ProofQualityV1::kernel_decision(TemporalCoverageV1::Complete),
        },
    )?];
    assert!(GraphAndFindingOwner::derive(&input)?
        .graph
        .edges
        .iter()
        .any(|edge| edge.key.edge_type == GraphEdgeTypeV1::NativeParent));
    let mut foreign = child;
    foreign.authority = GraphSubjectAuthorityV1::Native {
        node_id: "other".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
    };
    assert!(fact(
        &input.records[0],
        3,
        GraphFactValueV1::NativeParent {
            parent,
            child: foreign,
            proof_quality: ProofQualityV1::kernel_decision(TemporalCoverageV1::Complete)
        }
    )
    .is_err());
    Ok(())
}

#[test]
fn control_graph_replay_is_byte_identical_including_revision() -> TestResult {
    let input = credential_input()?;
    let expected = GraphAndFindingOwner::derive(&input)?;
    let mut reordered = input.clone();
    reordered.records.reverse();
    reordered.records.push(input.records[0].clone());
    reordered.facts.reverse();
    reordered.facts.push(input.facts[0].clone());
    reordered.coverage_keys.reverse();
    let replayed = GraphAndFindingOwner::derive(&reordered)?;
    assert_eq!(
        serde_json::to_vec(&expected.graph)?,
        serde_json::to_vec(&replayed.graph)?
    );
    assert_eq!(
        serde_json::to_vec(&expected.findings)?,
        serde_json::to_vec(&replayed.findings)?
    );
    assert_eq!(
        expected
            .findings
            .iter()
            .find(|finding| finding.package_id == "HF-DW-001")
            .ok_or("DW")?
            .state,
        FindingStateV1::Confirmed
    );
    Ok(())
}

#[test]
fn control_graph_read_channel_and_provider_results_stay_separate() -> TestResult {
    for result in [0_i64, -5, 1] {
        let mut input = credential_input()?;
        let mut read = GraphFactV1::try_from(&input.facts[3])?;
        if let GraphFactValueV1::Credential {
            completion: Some(completion),
            ..
        } = &mut read.value
        {
            completion.result = result;
            completion.byte_count = u64::try_from(result).unwrap_or(0);
        }
        input.facts[3].body = serde_json::to_vec(&read)?;
        let graph = GraphAndFindingOwner::derive(&input)?;
        let finding = graph
            .findings
            .iter()
            .find(|finding| finding.package_id == "HF-DW-001")
            .ok_or("DW")?;
        assert_eq!(
            finding.state,
            if result > 0 {
                FindingStateV1::Confirmed
            } else {
                FindingStateV1::CoverageInsufficient
            }
        );
        assert!(finding
            .effects
            .iter()
            .all(|effect| effect.physical_result == GraphPhysicalResultV1::Unknown));
        assert!(finding.limits.contains(&"TLS_PAYLOAD_UNOBSERVABLE".into()));
    }
    for cursor in [1_usize, 2] {
        let mut input = credential_input()?;
        let mut denied = input.records[cursor - 1].decode()?;
        denied.decision = 2;
        denied.kernel_result = -13;
        input.records[cursor - 1] = record(cursor as u64, &denied)?;
        let graph = GraphAndFindingOwner::derive(&input)?;
        assert_eq!(
            graph
                .findings
                .iter()
                .find(|finding| finding.package_id == "HF-DW-001")
                .ok_or("DW")?
                .state,
            FindingStateV1::CoverageInsufficient
        );
    }
    Ok(())
}

#[test]
fn control_graph_contradictions_require_same_operation() -> TestResult {
    let mut input = credential_input()?;
    let mut denied = GraphFactV1::try_from(&input.facts[5])?;
    if let GraphFactValueV1::AuthorityUse {
        operation_id,
        proof_quality,
        ..
    } = &mut denied.value
    {
        *operation_id = "unrelated-operation".into();
        proof_quality.operation_result_authority = OperationResultAuthorityV1::AuthoritativeDenied;
    }
    input
        .facts
        .push(fact(&input.records[2], 30, denied.value.clone())?);
    let graph = GraphAndFindingOwner::derive(&input)?;
    assert!(graph
        .findings
        .iter()
        .all(|finding| finding.reason != FindingReasonV1::Contradiction));
    if let GraphFactValueV1::AuthorityUse { operation_id, .. } = &mut denied.value {
        *operation_id = "repository-write".into();
    }
    input.facts.pop();
    input.facts.push(fact(&input.records[2], 30, denied.value)?);
    let graph = GraphAndFindingOwner::derive(&input)?;
    assert_eq!(
        graph
            .findings
            .iter()
            .find(|finding| finding.package_id == "HF-DW-001")
            .ok_or("DW")?
            .reason,
        FindingReasonV1::Contradiction
    );
    input.facts.reverse();
    assert_eq!(
        serde_json::to_vec(&graph.findings)?,
        serde_json::to_vec(&GraphAndFindingOwner::derive(&input)?.findings)?
    );
    Ok(())
}

#[test]
fn control_graph_credential_versions_cannot_overwrite_conflict() -> TestResult {
    let mut input = credential_input()?;
    let mut zero = GraphFactV1::try_from(&input.facts[3])?;
    if let GraphFactValueV1::Credential {
        completion: Some(completion),
        ..
    } = &mut zero.value
    {
        completion.result = 0;
        completion.byte_count = 0;
    }
    input.facts.push(fact(&input.records[0], 30, zero.value)?);
    let expected = GraphAndFindingOwner::derive(&input)?;
    assert_eq!(
        expected
            .findings
            .iter()
            .find(|finding| finding.package_id == "HF-DW-001")
            .ok_or("DW")?
            .reason,
        FindingReasonV1::Contradiction
    );
    input.facts.reverse();
    assert_eq!(
        serde_json::to_vec(&expected.findings)?,
        serde_json::to_vec(&GraphAndFindingOwner::derive(&input)?.findings)?
    );
    Ok(())
}

#[test]
fn control_graph_kubernetes_preserves_partial_stages() -> TestResult {
    let mut input = input(vec![record(1, &wire(1, 0, 3, 13, [20; 16]))?]);
    let stage = KubernetesStageProofV1 {
        cluster_id: "cluster".into(),
        carried_request_id: Some("request".into()),
        audit_id: Some("audit".into()),
        object_uid: Some("object".into()),
        resource_version: Some("version".into()),
        owner_uid: Some("owner".into()),
        pod_uid: Some("pod".into()),
        node_id: Some("remote-node".into()),
        full_container_id: None,
        remote_admission_id: None,
        proof_quality: authority_proof(),
    };
    input.facts.push(fact(
        &input.records[0],
        1,
        GraphFactValueV1::Kubernetes(stage.clone()),
    )?);
    let graph = GraphAndFindingOwner::derive(&input)?;
    assert_eq!(
        graph.packages[2].state,
        GraphPackageStateV1::KubernetesScheduled
    );
    assert!(graph
        .graph
        .facts
        .iter()
        .any(|fact| fact.value == GraphFactValueV1::Kubernetes(stage.clone())));
    assert!(graph.findings[0]
        .limits
        .contains(&"REMOTE_RUNTIME_ADMISSION_MISSING".into()));
    assert!(graph.findings[0]
        .limits
        .contains(&"CROSS_NODE_CAUSALITY_UNQUALIFIED".into()));
    assert!(graph
        .graph
        .edges
        .iter()
        .all(|edge| edge.key.edge_type != GraphEdgeTypeV1::NativeParent));
    Ok(())
}

#[derive(Default)]
struct Inputs(Mutex<Vec<AnalysisContextVersionV1>>);
impl GraphContextProvider for Inputs {
    fn facts(&self, record: &DiscoveryRecordV1) -> Result<Vec<AnalysisContextVersionV1>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| {
                GraphInvalidSnafu {
                    field: "fixture context",
                }
                .build()
            })?
            .iter()
            .filter(|fact| {
                GraphFactV1::try_from(*fact).is_ok_and(|fact| fact.record_id == record.id)
            })
            .cloned()
            .collect())
    }
}

fn accept(store: &AnalysisStore, records: &[DiscoveryRecordV1]) -> Result<()> {
    let frames: Vec<_> = records
        .iter()
        .map(|record| record.wire_record.clone())
        .collect();
    let mut bytes = Vec::new();
    let mut ends = Vec::new();
    for frame in frames {
        bytes.extend(frame);
        ends.push(bytes.len());
    }
    let outcome = store.accept_validated_batch(
        source(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: records.first().map_or(1, |record| record.id.durable_cursor),
            last_cursor: records.last().map_or(1, |record| record.id.durable_cursor),
            intake_utc_ns: 1,
            framed_records: bytes.into(),
            frame_ends: ends,
        },
    )?;
    assert_eq!(outcome, EvidenceStoreOutcomeV1::Accepted);
    Ok(())
}

fn coverage(store: &AnalysisStore, last: u64, revision: u64, state: &str) -> Result<()> {
    use prost::Message as _;
    let report = CoverageReport {
        source_id: source().source_id.to_vec(),
        cpu_id: 0,
        source_epoch: source().source_epoch,
        revision,
        intervals: vec![CoverageInterval {
            interval_id: vec![4; 16],
            source_epoch: source().source_epoch,
            revision,
            state: state.into(),
            first_sequence: 1,
            last_sequence: Some(last),
            opening_counters: Some(Default::default()),
            closing_counters: Some(CoverageCounters {
                attempted: last,
                requested: last,
                emitted: last,
                next_sequence: last + 1,
                ..Default::default()
            }),
            ..Default::default()
        }],
    };
    store.accept_validated_coverage(ValidatedCoverageV1 {
        identity: source(),
        cpu_id: 0,
        revision,
        encoded_report: report.encode_to_vec(),
    })?;
    Ok(())
}

#[test]
fn control_graph_required_registration_precedes_intake_without_discovery() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("analysis"),
        RetentionLimitsV1 {
            raw_max_age_ns: 1,
            raw_max_bytes: 100_000,
        },
        Default::default(),
    )?);
    let owner = GraphAndFindingOwner::new(store.clone(), Arc::new(Inputs::default()))?;
    assert!(!store.discovery_enabled());
    accept(&store, &[record(1, &wire(1, 2, 2, 2, [20; 16]))?])?;
    let health = store
        .processor_health(&ProcessorScopeV1 {
            processor_id: GRAPH_PROCESSOR.into(),
            method_version: 1,
            identity: source(),
        })?
        .ok_or("health")?;
    assert_eq!(health.class, ProcessorClassV1::Required);
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&source(), 10)?
            .removed_records,
        0
    );
    assert_eq!(owner.process(10)?, 1);
    assert_eq!(owner.findings(source().tenant_id)?.len(), 1);
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&source(), 11)?
            .removed_records,
        0
    );
    drop(owner);
    assert!(!store.graph_enabled());
    accept(&store, &[record(2, &wire(2, 2, 2, 2, [20; 16]))?])?;
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&source(), 12)?
            .removed_records,
        0
    );
    Ok(())
}

#[test]
fn control_graph_new_source_registration_preserves_pending_other_source() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("analysis"),
        RetentionLimitsV1 {
            raw_max_age_ns: 1,
            raw_max_bytes: 100_000,
        },
        Default::default(),
    )?);
    let owner = GraphAndFindingOwner::new(store.clone(), Arc::new(Inputs::default()))?;
    let observation = record(1, &wire(1, 2, 2, 2, [20; 16]))?;
    accept(&store, &[observation.clone()])?;
    let mut other = source();
    other.source_id = [4; 16];
    assert_eq!(
        store.accept_validated_batch(
            other.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: observation.wire_record.clone().into(),
                frame_ends: vec![observation.wire_record.len()]
            }
        )?,
        EvidenceStoreOutcomeV1::Accepted
    );
    for source in [&source(), &other] {
        let status = store.source_status(source)?.ok_or("source")?;
        assert_eq!(status.receipt.contiguous_cursor, 1);
        assert_eq!(status.retained_event_count, 1);
        assert_eq!(
            EvidenceRetentionOwner::new(&store)
                .retain(source, 10)?
                .removed_records,
            0
        );
    }
    assert_eq!(owner.process(10)?, 2);
    assert_eq!(owner.findings(source().tenant_id)?.len(), 2);
    Ok(())
}

#[test]
fn control_graph_committed_revision_retry_late_expiry_and_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("analysis");
    let store = Arc::new(AnalysisStore::open_with_limits(
        &path,
        RetentionLimitsV1 {
            raw_max_age_ns: 1,
            raw_max_bytes: 100_000,
        },
        Default::default(),
    )?);
    let provider = Arc::new(Inputs::default());
    let owner = GraphAndFindingOwner::new(store.clone(), provider.clone())?;
    let observation = record(1, &wire(1, 2, 2, 2, [20; 16]))?;
    accept(&store, &[observation.clone()])?;
    owner.process(10)?;
    let original = owner.findings(source().tenant_id)?.remove(0);
    let revision = store.meta()?.commit_revision;
    assert!(!owner.refresh(&source(), 11)?);
    assert_eq!(store.meta()?.commit_revision, revision);
    provider
        .0
        .lock()
        .map_err(|_| "provider")?
        .extend([policy(&observation, 1)?, activation(&observation)?]);
    assert!(owner.refresh(&source(), 12)?);
    let current = owner.findings(source().tenant_id)?.remove(0);
    assert_ne!(original.revision, current.revision);
    assert_eq!(
        owner.finding(source().tenant_id, &original.finding_id, &original.revision)?,
        Some(original.clone())
    );
    assert!(owner.findings([99; 16])?.is_empty());
    let deadline = owner
        .snapshot(&source())?
        .ok_or("snapshot")?
        .witness_deadline_utc_ns;
    assert_eq!(deadline, 10 + GRAPH_WITNESS_TTL_NS);
    EvidenceRetentionOwner::new(&store).retain(&source(), deadline + 1)?;
    assert!(owner.refresh(&source(), deadline + 2)?);
    assert!(owner
        .findings(source().tenant_id)?
        .remove(0)
        .limits
        .contains(&"RETAINED_INPUT_EXPIRED".into()));
    accept(&store, &[record(2, &wire(2, 2, 2, 2, [20; 16]))?])?;
    owner.process(deadline + 3)?;
    owner.process(deadline + 3)?;
    assert_eq!(
        store
            .processor_health(&ProcessorScopeV1 {
                processor_id: GRAPH_PROCESSOR.into(),
                method_version: 1,
                identity: source()
            })?
            .ok_or("health")?
            .consumed_cursor,
        2
    );
    drop(owner);
    drop(store);
    let store = Arc::new(AnalysisStore::open(path)?);
    let owner = GraphAndFindingOwner::new(store, provider)?;
    assert_eq!(
        owner.finding(source().tenant_id, &original.finding_id, &original.revision)?,
        Some(original)
    );
    Ok(())
}

#[test]
fn control_graph_provenance_requires_retained_exact_acknowledgement() -> TestResult {
    let input = credential_input()?;
    let mut missing = input.clone();
    missing.facts.retain(|fact| {
        !matches!(
            GraphFactV1::try_from(fact).map(|fact| fact.value),
            Ok(GraphFactValueV1::Activation(_))
        )
    });
    assert!(GraphAndFindingOwner::derive(&missing).is_err());
    let mut foreign = input.clone();
    let mut policy = GraphFactV1::try_from(&foreign.facts[0])?;
    if let GraphFactValueV1::Policy(policy) = &mut policy.value {
        policy
            .activation_acknowledgement
            .as_mut()
            .ok_or("ACK")?
            .tenant_id = [99; 16];
    }
    foreign.facts[0].body = serde_json::to_vec(&policy)?;
    assert!(GraphAndFindingOwner::derive(&foreign).is_err());
    let mut wrong_generation = input;
    let activation = wrong_generation
        .facts
        .iter_mut()
        .find(|fact| {
            matches!(
                GraphFactV1::try_from(&**fact).map(|fact| fact.value),
                Ok(GraphFactValueV1::Activation(_))
            )
        })
        .ok_or("activation")?;
    let mut body = GraphFactV1::try_from(&*activation)?;
    if let GraphFactValueV1::Activation(activation) = &mut body.value {
        activation.profile_generation_ref_id = Some(2);
    }
    activation.body = serde_json::to_vec(&body)?;
    assert!(GraphAndFindingOwner::derive(&wrong_generation).is_err());
    Ok(())
}

#[test]
fn control_graph_transition_history_does_not_replace_exact_generation() -> TestResult {
    let mut input = credential_input()?;
    let mut previous = GraphFactV1::try_from(&input.facts[0])?;
    let mut acknowledgement = activation(&input.records[0])?;
    acknowledgement.key.owner_revision = 2;
    let mut body = GraphFactV1::try_from(&acknowledgement)?;
    if let GraphFactValueV1::Activation(activation) = &mut body.value {
        activation.state = "RECEIVED".into();
        activation.profile_generation_ref_id = None;
        activation.node_bound_generation_digest = None;
        activation.readback_digest = None;
        activation.probe_result_digest = None;
    }
    acknowledgement.body = serde_json::to_vec(&body)?;
    if let GraphFactValueV1::Policy(policy) = &mut previous.value {
        policy.state = PolicyProvenanceStateV1::Missing;
        policy.activation_acknowledgement = Some(acknowledgement.key.clone());
        policy.node_bound_generation_digest = None;
        policy.limits = vec!["ACTIVATION_NOT_ACTIVE".into()];
    }
    input.facts.extend([
        fact(&input.records[0], 30, previous.value.clone())?,
        acknowledgement.clone(),
    ]);
    acknowledgement.key.owner_revision = 3;
    if let GraphFactValueV1::Activation(activation) = &mut body.value {
        activation.state = "STAGED".into();
    }
    acknowledgement.body = serde_json::to_vec(&body)?;
    input.facts.push(acknowledgement.clone());
    acknowledgement.key.owner_revision = 4;
    if let GraphFactValueV1::Activation(activation) = &mut body.value {
        activation.state = "ACTIVE".into();
        activation.profile_generation_ref_id = Some(2);
    }
    acknowledgement.body = serde_json::to_vec(&body)?;
    input.facts.push(acknowledgement);
    let graph = GraphAndFindingOwner::derive(&input)?;
    let finding = graph
        .findings
        .iter()
        .find(|finding| finding.package_id == "HF-DW-001")
        .ok_or("finding")?;
    assert_eq!(finding.state, FindingStateV1::Confirmed);
    assert!(!finding.limits.contains(&"POLICY_PROVENANCE_MISSING".into()));
    assert_eq!(graph.graph.facts.len(), input.facts.len());
    let mut stale = activation(&input.records[0])?;
    stale.key.owner_revision = 5;
    let mut body = GraphFactV1::try_from(&stale)?;
    if let GraphFactValueV1::Activation(activation) = &mut body.value {
        activation.state = "STALE".into();
    }
    stale.body = serde_json::to_vec(&body)?;
    if let GraphFactValueV1::Policy(policy) = &mut previous.value {
        policy.state = PolicyProvenanceStateV1::Contradicted;
        policy.activation_acknowledgement = Some(stale.key.clone());
        policy.node_bound_generation_digest = Some("generation".into());
        policy.limits = vec!["ACTIVATION_NOT_ACTIVE".into()];
    }
    input
        .facts
        .extend([fact(&input.records[0], 31, previous.value)?, stale]);
    let graph = GraphAndFindingOwner::derive(&input)?;
    assert_eq!(
        graph
            .findings
            .iter()
            .find(|finding| finding.package_id == "HF-DW-001")
            .ok_or("finding")?
            .reason,
        FindingReasonV1::Contradiction
    );
    input.facts.reverse();
    assert_eq!(
        serde_json::to_vec(&graph.findings)?,
        serde_json::to_vec(&GraphAndFindingOwner::derive(&input)?.findings)?
    );
    Ok(())
}

#[test]
fn control_graph_mmap_and_other_operation_cannot_borrow_read_bytes() -> TestResult {
    let mut input = credential_input()?;
    let mut read = GraphFactV1::try_from(&input.facts[3])?;
    if let GraphFactValueV1::Credential {
        completion: Some(completion),
        ..
    } = &mut read.value
    {
        completion.path = GraphReadPathV1::Mmap;
    }
    input.facts[3].body = serde_json::to_vec(&read)?;
    let graph = GraphAndFindingOwner::derive(&input)?;
    assert_eq!(
        graph
            .findings
            .iter()
            .find(|finding| finding.package_id == "HF-DW-001")
            .ok_or("finding")?
            .state,
        FindingStateV1::CoverageInsufficient
    );
    if let GraphFactValueV1::Credential {
        completion: Some(completion),
        ..
    } = &mut read.value
    {
        completion.path = GraphReadPathV1::Read;
        completion.admission_record = input.records[1].id.clone();
    }
    input.facts[3].body = serde_json::to_vec(&read)?;
    assert!(GraphAndFindingOwner::derive(&input).is_err());
    Ok(())
}

#[test]
fn control_graph_shared_principal_is_contextual_only() -> TestResult {
    let mut input = credential_input()?;
    let mut use_fact = GraphFactV1::try_from(&input.facts[5])?;
    if let GraphFactValueV1::AuthorityUse {
        process_instance_id,
        task_cookie,
        credential_object_id,
        socket_object_id,
        ..
    } = &mut use_fact.value
    {
        *process_instance_id = Some([22; 16]);
        *task_cookie = Some(22);
        *credential_object_id = None;
        *socket_object_id = None;
    }
    input.facts[5].body = serde_json::to_vec(&use_fact)?;
    let graph = GraphAndFindingOwner::derive(&input)?;
    let finding = graph
        .findings
        .iter()
        .find(|finding| finding.package_id == "HF-DW-001")
        .ok_or("finding")?;
    assert_eq!(finding.reason, FindingReasonV1::ContextualCredentialPivot);
    assert_eq!(finding.state, FindingStateV1::CoverageInsufficient);
    assert!(graph
        .graph
        .edges
        .iter()
        .filter(|edge| edge.key.edge_type == GraphEdgeTypeV1::CredentialAuthority)
        .all(|edge| edge.key.cause == GraphCauseV1::Contextual));
    if let GraphFactValueV1::AuthorityUse {
        workload_binding, ..
    } = &mut use_fact.value
    {
        workload_binding.as_mut().ok_or("workload")?.identity = vec![8; 16];
    }
    input.facts[5].body = serde_json::to_vec(&use_fact)?;
    assert_eq!(
        GraphAndFindingOwner::derive(&input)?
            .findings
            .iter()
            .find(|finding| finding.package_id == "HF-DW-001")
            .ok_or("finding")?
            .reason,
        FindingReasonV1::MissingAuthorityProof
    );
    Ok(())
}

#[test]
fn control_graph_finding_preserves_restricted_context_sensitivity() -> TestResult {
    let mut input = credential_input()?;
    input.facts[3].sensitivity = ContextSensitivityV1::HostRestricted;
    let graph = GraphAndFindingOwner::derive(&input)?;
    assert!(graph
        .findings
        .iter()
        .all(|finding| finding.sensitivity == ContextSensitivityV1::HostRestricted));
    Ok(())
}

#[test]
fn control_graph_window_boundary_preserves_credential_join() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let input = credential_input_from(256)?;
    let provider = Arc::new(Inputs(Mutex::new(input.facts)));
    let owner = GraphAndFindingOwner::new(store.clone(), provider)?;
    let mut records = (1..256)
        .map(|cursor| record(cursor, &wire(cursor, 0, 2, 2, [30; 16])))
        .collect::<Result<Vec<_>>>()?;
    records.extend(input.records);
    for batch in records.chunks(128) {
        accept(&store, batch)?;
    }
    coverage(&store, 258, 1, "HEALTHY")?;
    for _ in 0..8 {
        owner.process(10)?;
    }
    assert_eq!(
        store
            .processor_health(&GraphAndFindingOwner::scope(&source()))?
            .ok_or("health")?
            .consumed_cursor,
        258
    );
    let (result_id, finding) = owner
        .current_findings(source().tenant_id)?
        .into_iter()
        .find(|(_, finding)| finding.package_id == "HF-DW-001")
        .ok_or("finding")?;
    assert_eq!(finding.state, FindingStateV1::Confirmed);
    assert_eq!(
        finding
            .evidence
            .iter()
            .map(|record| record.durable_cursor)
            .collect::<Vec<_>>(),
        vec![256, 257, 258]
    );
    assert_eq!(
        owner.finding_result(source().tenant_id, &result_id, &finding.finding_id)?,
        Some(finding.clone())
    );
    assert_eq!(
        owner.finding_result([99; 16], &result_id, &finding.finding_id)?,
        None
    );
    Ok(())
}

#[test]
fn control_graph_many_coverage_revisions_preserve_frozen_input() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let owner = GraphAndFindingOwner::new(store.clone(), Arc::new(Inputs::default()))?;
    accept(&store, &[record(1, &wire(1, 2, 2, 2, [20; 16]))?])?;
    coverage(&store, 1, 1, "HEALTHY")?;
    owner.process(10)?;
    let original = owner.current_findings(source().tenant_id)?.remove(0);
    for revision in 2..=258 {
        coverage(&store, 1, revision, "HEALTHY")?;
    }
    assert!(owner.refresh(&source(), 11)?);
    let current = owner.findings(source().tenant_id)?.remove(0);
    assert_eq!(current.state, FindingStateV1::Confirmed);
    assert_eq!(
        current
            .revision
            .coverage
            .iter()
            .map(|key| key.report_revision)
            .collect::<Vec<_>>(),
        vec![1, 258]
    );
    assert_eq!(
        owner.finding_result(source().tenant_id, &original.0, &original.1.finding_id)?,
        Some(original.1)
    );
    Ok(())
}

struct FailingInputs(std::sync::atomic::AtomicBool);
impl GraphContextProvider for FailingInputs {
    fn facts(&self, _record: &DiscoveryRecordV1) -> Result<Vec<AnalysisContextVersionV1>> {
        if self.0.load(std::sync::atomic::Ordering::Acquire) {
            return GraphInvalidSnafu {
                field: "injected provider failure",
            }
            .fail();
        }
        Ok(vec![])
    }
}

#[test]
fn control_graph_required_failure_is_unhealthy_and_recovers() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let provider = Arc::new(FailingInputs(std::sync::atomic::AtomicBool::new(true)));
    let owner = GraphAndFindingOwner::new(store.clone(), provider.clone())?;
    accept(&store, &[record(1, &wire(1, 2, 2, 2, [20; 16]))?])?;
    assert!(owner.process(10).is_err());
    assert_eq!(
        store
            .processor_health(&GraphAndFindingOwner::scope(&source()))?
            .ok_or("health")?
            .state,
        ProcessorStateV1::ProcessingFailed
    );
    accept(&store, &[record(2, &wire(2, 2, 2, 2, [20; 16]))?])?;
    provider
        .0
        .store(false, std::sync::atomic::Ordering::Release);
    for _ in 0..3 {
        owner.process(11)?;
    }
    let health = store
        .processor_health(&GraphAndFindingOwner::scope(&source()))?
        .ok_or("health")?;
    assert_eq!(health.consumed_cursor, 2);
    assert_ne!(health.state, ProcessorStateV1::ProcessingFailed);
    provider.0.store(true, std::sync::atomic::Ordering::Release);
    assert!(owner.refresh(&source(), 12).is_err());
    let health = store
        .processor_health(&GraphAndFindingOwner::scope(&source()))?
        .ok_or("health")?;
    assert_eq!(health.consumed_cursor, health.accepted_cursor);
    assert_eq!(health.state, ProcessorStateV1::ProcessingFailed);
    provider
        .0
        .store(false, std::sync::atomic::Ordering::Release);
    owner.refresh(&source(), 13)?;
    assert_ne!(
        store
            .processor_health(&GraphAndFindingOwner::scope(&source()))?
            .ok_or("health")?
            .state,
        ProcessorStateV1::ProcessingFailed
    );
    Ok(())
}

#[test]
fn control_graph_context_and_result_bounds_keep_required_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let records = (1..=256)
        .map(|cursor| record(cursor, &wire(cursor, 2, 2, 2, [20; 16])))
        .collect::<Result<Vec<_>>>()?;
    let mut facts = Vec::new();
    for (index, record) in records.iter().enumerate() {
        for offset in 0..3 {
            let mut value = fact(
                record,
                (index * 3 + offset) as u64,
                GraphFactValueV1::Baseline {
                    role_id: 1,
                    state_id: 1,
                    outside_reviewed_baseline: false,
                    reviewed_policy_revision: "reviewed-source".into(),
                },
            )?;
            value.key.owner_id = "qualified-control-context-owner".repeat(3);
            value.key.entity_key = vec![u8::try_from(index)?; 256];
            value.key.lifetime_key = vec![u8::try_from(offset)?; 256];
            facts.push(value);
        }
    }
    let provider = Arc::new(Inputs(Mutex::new(facts)));
    let owner = GraphAndFindingOwner::new(store.clone(), provider)?;
    for batch in records.chunks(128) {
        accept(&store, batch)?;
    }
    coverage(&store, 256, 1, "HEALTHY")?;
    for _ in 0..=records.len() * 2 {
        owner.process(10)?;
        if store
            .processor_health(&GraphAndFindingOwner::scope(&source()))?
            .ok_or("health")?
            .consumed_cursor
            == 256
        {
            break;
        }
    }
    assert_eq!(
        store
            .processor_health(&GraphAndFindingOwner::scope(&source()))?
            .ok_or("health")?
            .consumed_cursor,
        256
    );
    let current = owner.current_findings(source().tenant_id)?;
    assert_eq!(current.len(), 256);
    let mut checked = std::collections::BTreeSet::new();
    for (id, finding) in current {
        if checked.insert(id.clone()) {
            let body = store
                .read_result(source().tenant_id, &id)?
                .ok_or("result")?;
            assert!(body.len() <= crate::analysis::MAX_RESULT_BYTES);
            assert!(body.len() <= GRAPH_WINDOW_BYTES);
        }
        assert!(finding.revision.context.len() <= 256);
    }
    Ok(())
}

#[test]
fn control_graph_result_crashes() -> TestResult {
    let input = credential_input()?;
    let provider = Arc::new(Inputs(Mutex::new(input.facts.clone())));
    if let Some(root) = std::env::var_os("ARAPHOR_CRASH_ROOT") {
        let store = Arc::new(AnalysisStore::open(std::path::PathBuf::from(root))?);
        let owner = GraphAndFindingOwner::new(store, provider)?;
        owner.process(10)?;
        return Err("the graph result crash did not occur".into());
    }
    let mut expected = None;
    for boundary in ["result.before", "result.after"] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("analysis");
        let store = Arc::new(AnalysisStore::open(&path)?);
        let owner = GraphAndFindingOwner::new(store.clone(), provider.clone())?;
        accept(&store, &input.records)?;
        coverage(&store, 3, 1, "HEALTHY")?;
        for fact in &input.facts {
            store.commit_context(fact)?;
        }
        let before = store.meta()?.commit_revision;
        drop(owner);
        drop(store);
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "graph::tests::control_graph_result_crashes"])
            .env("ARAPHOR_CRASH_ROOT", &path)
            .env("ARAPHOR_CRASH_POINT", boundary)
            .status()?;
        assert_eq!(status.code(), Some(73), "{boundary}");
        let store = Arc::new(AnalysisStore::open(&path)?);
        let owner = GraphAndFindingOwner::new(store.clone(), provider.clone())?;
        let committed = boundary == "result.after";
        assert_eq!(store.meta()?.commit_revision, before + u64::from(committed));
        assert_eq!(
            store
                .processor_health(&GraphAndFindingOwner::scope(&source()))?
                .ok_or("health")?
                .consumed_cursor,
            if committed { 3 } else { 0 }
        );
        let usage = store.witness_usage(source().tenant_id, 11)?;
        assert_eq!(
            usage.referenced_bytes,
            if committed {
                input
                    .records
                    .iter()
                    .map(|record| record.wire_record.len() as u64)
                    .sum()
            } else {
                0
            }
        );
        assert_eq!(usage.context_bytes > 0, committed);
        assert_eq!(owner.snapshot(&source())?.is_some(), committed);
        owner.process(11)?;
        let snapshot = owner.snapshot(&source())?.ok_or("snapshot")?;
        assert_eq!(snapshot.input_manifest.evidence.len(), 3);
        assert_eq!(snapshot.input_manifest.context.len(), input.facts.len());
        let bytes = serde_json::to_vec(&(snapshot.graph, snapshot.findings))?;
        if let Some(expected) = &expected {
            assert_eq!(&bytes, expected);
        } else {
            expected = Some(bytes);
        }
        let revision = store.meta()?.commit_revision;
        owner.refresh(&source(), 12)?;
        assert_eq!(store.meta()?.commit_revision, revision);
    }
    Ok(())
}
