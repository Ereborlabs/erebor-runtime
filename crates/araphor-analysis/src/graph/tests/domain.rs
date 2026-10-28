use super::super::*;
use super::fixture::*;
use super::{derive, TestResult};
use araphor_data::{GraphReadPathV1, KubernetesStageProofV1};
use EffectPhysicalResultV1::{DeniedBeforeEffect, UnknownAfterPreEffect};

#[test]
fn physical_results_keep_stages() -> TestResult {
    let stages = [
        (DeniedBeforeEffect, 2, 2),
        (EffectPhysicalResultV1::PacketDroppedAfterRewrite, 3, 13),
        (
            EffectPhysicalResultV1::TerminationQueuedBeforeUserMode,
            1,
            1,
        ),
    ];
    let records = stages
        .into_iter()
        .enumerate()
        .map(|(index, (result, family, operation))| {
            let cursor = index as u64 + 1;
            record(cursor, &wire(cursor, result, family, operation, [20; 16]))
        })
        .collect::<Result<Vec<_>>>()?;
    let snapshot = derive(&input(records))?;
    assert_eq!(snapshot.findings.len(), 3);
    for finding in &snapshot.findings {
        let effect = finding.effects.first().ok_or("effect")?;
        assert_eq!(finding.reason, FindingReasonV1::UnexpectedEffect);
        snapshot.input_manifest.validate_finding(finding)?;
        match effect.source_decision {
            1 => {
                assert_eq!(effect.physical_result, GraphPhysicalResultV1::Prevented);
                assert_eq!(effect.kernel_result, -13);
            }
            2 => {
                assert_eq!(effect.physical_result, GraphPhysicalResultV1::PacketDropped);
                assert_eq!(effect.kernel_result, 0);
                assert!(finding
                    .limits
                    .contains(&"SYSCALL_COMPLETION_UNPROVEN".into()));
                assert!(finding
                    .limits
                    .contains(&"PROVIDER_WRITE_AND_CONTENT_UNPROVEN".into()));
            }
            3 => {
                assert_eq!(
                    effect.physical_result,
                    GraphPhysicalResultV1::TerminationQueued
                );
                assert_eq!(effect.kernel_result, 0);
                assert!(finding
                    .limits
                    .contains(&"TERMINATION_COMPLETION_UNPROVEN".into()));
            }
            _ => return Err("source physical result changed".into()),
        }
    }
    let mut unknown = wire(4, UnknownAfterPreEffect, 2, 2, [20; 16]);
    unknown.kernel_result = -13;
    assert!(derive(&input(vec![record(4, &unknown)?]))?
        .findings
        .is_empty());
    let mut denied_read = credential_input()?;
    let mut read = denied_read.records[0].decode()?;
    read.decision = DeniedBeforeEffect as u32;
    read.kernel_result = -13;
    denied_read.records[0] = record(1, &read)?;
    assert!(derive(&denied_read)?.findings.iter().all(|finding| {
        finding.package_id != "HF-DW-001" || finding.reason != FindingReasonV1::CredentialPivot
    }));
    let mut dropped = credential_input()?;
    for record in dropped.records.iter_mut().skip(1) {
        let mut wire = record.decode()?;
        wire.decision = EffectPhysicalResultV1::PacketDroppedAfterRewrite as u32;
        record.wire_record = Vec::<u8>::try_from(&wire)?;
    }
    assert!(derive(&dropped)?.findings.iter().all(|finding| {
        finding.package_id != "HF-DW-001" || finding.reason != FindingReasonV1::CredentialPivot
    }));
    Ok(())
}

#[test]
fn subject_lifetime_is_native() {
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
fn missing_lifetime_stays_unknown() -> TestResult {
    let mut denied = wire(1, DeniedBeforeEffect, 2, 2, [20; 16]);
    let graph = derive(&input(vec![record(1, &denied)?]))?;
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
    let graph = derive(&input(vec![record(1, &denied)?]))?;
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
fn parent_requires_exact_lifetime() -> TestResult {
    let mut input = input(vec![record(
        1,
        &wire(1, DeniedBeforeEffect, 2, 2, [20; 16]),
    )?]);
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
    let graph = derive(&input)?;
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
    assert!(derive(&input)?
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
fn replay_is_byte_identical() -> TestResult {
    let input = credential_input()?;
    let expected = derive(&input)?;
    let mut reordered = input.clone();
    reordered.records.reverse();
    reordered.records.push(input.records[0].clone());
    reordered.facts.reverse();
    reordered.facts.push(input.facts[0].clone());
    reordered.coverage_keys.reverse();
    let replayed = derive(&reordered)?;
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
fn operation_results_stay_separate() -> TestResult {
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
        let graph = derive(&input)?;
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
        let graph = derive(&input)?;
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
fn contradictions_require_same_operation() -> TestResult {
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
    let graph = derive(&input)?;
    assert!(graph
        .findings
        .iter()
        .all(|finding| finding.reason != FindingReasonV1::Contradiction));
    if let GraphFactValueV1::AuthorityUse { operation_id, .. } = &mut denied.value {
        *operation_id = "repository-write".into();
    }
    input.facts.pop();
    input.facts.push(fact(&input.records[2], 30, denied.value)?);
    let graph = derive(&input)?;
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
        serde_json::to_vec(&derive(&input)?.findings)?
    );
    Ok(())
}

#[test]
fn credential_versions_preserve_conflict() -> TestResult {
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
    let expected = derive(&input)?;
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
        serde_json::to_vec(&derive(&input)?.findings)?
    );
    Ok(())
}

#[test]
fn kubernetes_preserves_partial_stages() -> TestResult {
    let mut input = input(vec![record(
        1,
        &wire(1, UnknownAfterPreEffect, 3, 13, [20; 16]),
    )?]);
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
    let graph = derive(&input)?;
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

#[test]
fn policy_requires_retained_ack() -> TestResult {
    let input = credential_input()?;
    let mut missing = input.clone();
    missing.facts.retain(|fact| {
        !matches!(
            GraphFactV1::try_from(fact).map(|fact| fact.value),
            Ok(GraphFactValueV1::Activation(_))
        )
    });
    assert!(derive(&missing).is_err());
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
    assert!(derive(&foreign).is_err());
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
    assert!(derive(&wrong_generation).is_err());
    Ok(())
}

#[test]
fn history_preserves_exact_generation() -> TestResult {
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
    let graph = derive(&input)?;
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
    let graph = derive(&input)?;
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
        serde_json::to_vec(&derive(&input)?.findings)?
    );
    Ok(())
}

#[test]
fn mmap_cannot_borrow_completion() -> TestResult {
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
    let graph = derive(&input)?;
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
    assert!(derive(&input).is_err());
    Ok(())
}

#[test]
fn shared_principal_stays_contextual() -> TestResult {
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
    let graph = derive(&input)?;
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
        derive(&input)?
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
fn restricted_context_stays_restricted() -> TestResult {
    let mut input = credential_input()?;
    input.facts[3].sensitivity = ContextSensitivityV1::HostRestricted;
    let graph = derive(&input)?;
    assert!(graph
        .findings
        .iter()
        .all(|finding| finding.sensitivity == ContextSensitivityV1::HostRestricted));
    Ok(())
}
