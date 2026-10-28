use super::*;
use crate::Rows;
use erebor_interceptor_abi::{EffectPhysicalResultV1, KernelEffectFamilyV1};

mod fixture;
use fixture::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn detector_declarations_stay_independent() {
    for detector in [
        Detector::Process,
        Detector::Credentials,
        Detector::Kubernetes,
    ] {
        let mut first = detector.descriptor();
        let second = detector.descriptor();
        assert_eq!(first, second);
        assert!(std::sync::Arc::ptr_eq(
            &first.exports[0].outputs[2].schema.fields()[0],
            &second.exports[0].outputs[2].schema.fields()[0],
        ));
        first.exports[0].outputs.clear();
        assert_eq!(detector.descriptor(), second);
        assert_eq!(second.id, detector.id());
    }
}

#[test]
fn record_index_keeps_fact_ordinals() -> TestResult {
    let detector = Detector::Process;
    let parent = FactValue::NativeParent {
        parent: subject(GraphSubjectKindV1::Task, 2_u64.to_be_bytes().to_vec()),
        child: subject(GraphSubjectKindV1::Task, 3_u64.to_be_bytes().to_vec()),
        proof_quality: proof(),
    };
    let fixture = fixture(
        detector,
        &[record(), record(), record()],
        &[
            fact(1, parent.clone()),
            fact(0, parent.clone()),
            fact(2, context(ContextClass::InMemory)),
            fact(1, parent),
        ],
    )?;
    let (findings, output) = findings(detector, &fixture)?;
    let edges = Relationship::decode(&output.datasets[1])?;
    assert_eq!(
        edges
            .iter()
            .filter_map(|edge| edge.fact.map(|fact| (edge.record, fact)))
            .collect::<Vec<_>>(),
        [(0, 1), (1, 0)]
    );
    let metadata = Metadata::decode(&output.datasets[4])?.remove(0);
    assert_eq!(metadata.facts.len(), 4);
    assert_eq!(metadata.facts[0].value, metadata.facts[3].value);
    assert_eq!(metadata.facts[0].record, metadata.facts[3].record);
    assert_eq!(
        findings
            .iter()
            .find(|finding| finding.context == Some(2))
            .map(|finding| (finding.record, finding.context)),
        Some((2, Some(2)))
    );
    Ok(())
}

#[test]
fn process_replay_checkpoint() -> TestResult {
    let detector = Detector::Process;
    let mut fixture = fixture(detector, &[record()], &[])?;
    let (first, output) = findings(detector, &fixture)?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].reason_code, "HF-PROC-001.UNEXPECTED_EFFECT");
    assert_eq!(first[0].state, FindingStateV1::Confirmed);
    assert_eq!(first[0].evidence, [identity(0)]);
    fixture.evaluation.inputs.reverse();
    fixture.evaluation.checkpoint = output.checkpoint;
    let (replay, _) = findings(detector, &fixture)?;
    assert_eq!(serde_json::to_value(first)?, serde_json::to_value(replay)?);
    Ok(())
}

#[test]
fn process_context_classifications() -> TestResult {
    let detector = Detector::Process;
    for (classification, reason) in [
        (ContextClass::OutsideAuthority, "OUTSIDE_AUTHORITY"),
        (ContextClass::InMemory, "IN_MEMORY_ONLY"),
        (ContextClass::PayloadUnobservable, "PAYLOAD_UNOBSERVABLE"),
    ] {
        let fixture = fixture(detector, &[record()], &[fact(0, context(classification))])?;
        let (rows, _) = findings(detector, &fixture)?;
        assert_eq!(rows.len(), 2);
        let context = rows
            .iter()
            .find(|row| row.context == Some(0))
            .ok_or("context finding")?;
        assert_eq!(context.reason_code, format!("HF-PROC-001.{reason}"));
        assert_eq!(context.state, FindingStateV1::CoverageInsufficient);
        let mut same = fact(0, fixture::context(classification));
        let FactValue::Context { subject: value, .. } = &mut same.value else {
            return Err("context fixture".into());
        };
        *value = subject(GraphSubjectKindV1::Task, 3_u64.to_be_bytes().to_vec());
        let same = fixture::fixture(detector, &[record()], &[same])?;
        let (rows, _) = findings(detector, &same)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason_code, "HF-PROC-001.UNEXPECTED_EFFECT");
        assert_eq!(rows[0].state, FindingStateV1::Confirmed);
    }
    Ok(())
}

#[test]
fn fact_reference_is_exact() -> TestResult {
    let fixture = fixture(
        Detector::Process,
        &[record()],
        &[fact(u32::MAX, context(ContextClass::InMemory))],
    )?;
    Detector::Process.descriptor().validate()?;
    assert!(matches!(Detector::Process.evaluate(&fixture.evaluation),
        Err(sdk::Error::Contract { code: sdk::ErrorCode::Invalid, field, .. })
            if field == "graph record reference"));
    Ok(())
}

#[test]
fn kubernetes_retains_missing_proof() -> TestResult {
    let detector = Detector::Kubernetes;
    let stage = KubernetesStageProofV1 {
        cluster_id: "cluster".into(),
        carried_request_id: Some("request".into()),
        audit_id: Some("audit".into()),
        object_uid: Some("object".into()),
        resource_version: Some("1".into()),
        owner_uid: Some("owner".into()),
        pod_uid: Some("pod".into()),
        node_id: Some("node".into()),
        full_container_id: Some("container".into()),
        remote_admission_id: Some("admission".into()),
        proof_quality: proof(),
    };
    let fixture = fixture(
        detector,
        &[record()],
        &[fact(0, FactValue::Kubernetes(stage))],
    )?;
    let (rows, output) = findings(detector, &fixture)?;
    assert_eq!(
        rows[0].limits,
        [
            "CROSS_NODE_CAUSALITY_UNQUALIFIED",
            "POLICY_PROVENANCE_MISSING"
        ]
    );
    assert_eq!(rows[0].state, FindingStateV1::CoverageInsufficient);
    let state = output.checkpoint.ok_or("checkpoint")?;
    let rows: Vec<State> = Rows::decode(
        &detector.descriptor().exports[0]
            .checkpoint
            .as_ref()
            .ok_or("checkpoint descriptor")?
            .datasets[0],
        &state.datasets[0],
    )?;
    assert_eq!(rows[0].value, "REMOTE_ADMISSION");
    Ok(())
}

#[test]
fn credential_exact_and_missing() -> TestResult {
    let detector = Detector::Credentials;
    let mut read = record();
    read.effect.decision = EffectPhysicalResultV1::UnknownAfterPreEffect as u32;
    let mut channel = read.clone();
    channel.effect.effect_family = KernelEffectFamilyV1::Network as u32;
    channel.effect.exact_object_id = vec![7; 16];
    channel.observed_boottime_ns = 11;
    let mut remote = read.clone();
    remote.observed_boottime_ns = 12;
    let credential = FactValue::Credential {
        object_id: [6; 16],
        expected_access: false,
        reviewed_policy_revision: "reviewed".into(),
        proof_quality: proof(),
        completion: Some(GraphReadCompletionV1 {
            admission_record: identity(0),
            owner: "node".into(),
            completion_id: "read".into(),
            task_cookie: 3,
            process_instance_id: [4; 16],
            object_id: [6; 16],
            file_description_id: "fd".into(),
            path: ReadPath::Read,
            result: 8,
            byte_count: 8,
            credential_lease_id: Some("lease".into()),
            principal_id: Some("principal".into()),
        }),
        principal_id: Some("principal".into()),
    };
    let channel_fact = FactValue::Channel {
        task_cookie: 3,
        process_instance_id: [4; 16],
        socket_object_id: [7; 16],
        authority_id: "provider".into(),
        carried_request_id: "request".into(),
        credential_lease_id: "lease".into(),
        principal_id: "principal".into(),
        operation_id: "write".into(),
        proof_quality: proof(),
    };
    let authority = FactValue::AuthorityUse {
        authority_id: "provider".into(),
        process_instance_id: Some([4; 16]),
        task_cookie: Some(3),
        credential_object_id: Some([6; 16]),
        socket_object_id: Some([7; 16]),
        request_id: Some("request".into()),
        credential_lease_id: Some("lease".into()),
        principal_id: "principal".into(),
        operation_id: "write".into(),
        outside_reviewed_behavior: true,
        workload_binding: Some(subject(GraphSubjectKindV1::ExecutionSet, vec![5; 16])),
        proof_quality: proof(),
    };
    let facts = vec![
        fact(0, credential),
        fact(1, channel_fact),
        fact(2, authority),
        fact(
            0,
            FactValue::Policy(PolicyObservationProvenanceV1 {
                source: identity(0).stream.clone(),
                profile_generation_ref_id: 1,
                observations: vec![identity(0)],
                policy_source_revision_id: Some("reviewed".into()),
                candidate_content_id: Some("candidate".into()),
                target_snapshot_digest: Some("target".into()),
                node_bound_generation_digest: Some("generation".into()),
                activation_acknowledgement: Some(AnalysisContextKeyV1 {
                    tenant_id: [1; 16],
                    owner_id: "activation".into(),
                    entity_key: vec![1],
                    lifetime_key: identity(0).stream.key(),
                    owner_revision: 1,
                }),
                state: PolicyProvenanceStateV1::Exact,
                limits: Vec::new(),
            }),
        ),
    ];
    let mut complete = fixture(detector, &[read, channel, remote], &facts)?;
    let batch = complete.evaluation.inputs[0].data.batches.remove(0);
    complete.evaluation.inputs[0].data.batches = vec![batch.slice(0, 1), batch.slice(1, 2)];
    let (rows, output) = findings(detector, &complete)?;
    assert_eq!(rows[0].reason_code, "HF-DW-001.CREDENTIAL_PIVOT");
    assert_eq!(rows[0].state, FindingStateV1::Confirmed);
    assert_eq!(rows[0].evidence, [identity(0), identity(1), identity(2)]);
    assert_eq!(output.evidence.len(), 3);
    authority_identity_order(&complete, &facts)?;
    let mut missing = complete;
    missing.evaluation.inputs[1].data = Fact::encode(&[facts[0].clone(), facts[3].clone()])?;
    let (rows, _) = findings(detector, &missing)?;
    assert_eq!(rows[0].reason_code, "HF-DW-001.MISSING_AUTHORITY_PROOF");
    assert_eq!(rows[0].state, FindingStateV1::CoverageInsufficient);
    Ok(())
}

fn authority_identity_order(complete: &sdk::Fixture, facts: &[Fact]) -> TestResult {
    let detector = Detector::Credentials;
    let package = detector.descriptor();
    let records = Observation::decode(&complete.evaluation.inputs[0].data)?;
    let mut blocked = records[1].clone();
    blocked.effect.decision = EffectPhysicalResultV1::DeniedBeforeEffect as u32;
    let mut records = vec![
        records[0].clone(),
        blocked,
        records[1].clone(),
        records[2].clone(),
        records[2].clone(),
        records[2].clone(),
    ];
    let mut carried = facts[1].clone();
    carried.record = 2;
    let mut first = facts[2].clone();
    first.record = 4;
    let mut earlier = facts[2].clone();
    earlier.record = 3;
    let mut duplicate = first.clone();
    duplicate.key.owner_revision += 1;
    let mut later = facts[2].clone();
    later.record = 5;
    let facts = vec![
        facts[0].clone(),
        carried,
        first,
        earlier,
        duplicate,
        later,
        facts[3].clone(),
    ];
    for network in [true, false] {
        let family = if network {
            KernelEffectFamilyV1::Network
        } else {
            KernelEffectFamilyV1::File
        };
        records[1].effect.effect_family = family as u32;
        records[2].effect.effect_family = family as u32;
        let fixture = fixture(detector, &records, &facts)?;
        package.validate_evaluation(&fixture.evaluation)?;
        let mut manifests = Manifest::decode(&fixture.evaluation.inputs[2].data)?;
        let mut computation = Computation::new(
            Observation::decode(&fixture.evaluation.inputs[0].data)?,
            facts.clone(),
            manifests.pop().ok_or("graph manifest")?,
            detector,
        )?;
        let (reason, evidence, prefix) = if network {
            (
                "CREDENTIAL_PIVOT",
                vec![0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 4, 5],
                9,
            )
        } else {
            ("CONTEXTUAL_CREDENTIAL_PIVOT", vec![0, 3, 4, 5], 1)
        };
        let credential = &computation.facts[0].value;
        assert!(matches!(credential, FactValue::Credential { .. }));
        let mut joined_evidence = vec![0];
        let matched = computation.authorities(
            &computation.records[0],
            credential,
            true,
            &mut joined_evidence,
        )?;
        assert_eq!(computation.fact_ids[2], computation.fact_ids[4]);
        assert_ne!(computation.facts[2].key, computation.facts[4].key);
        assert_eq!(matched, [(3, network), (2, network), (5, network)]);
        assert_eq!(joined_evidence, evidence[..prefix]);
        computation.credentials()?;
        assert_eq!(computation.findings.len(), 1);
        assert_eq!(computation.edges.len(), 3);
        assert_eq!(
            computation
                .edges
                .values()
                .map(|edge| edge.fact)
                .collect::<Vec<_>>(),
            [Some(3), Some(2), Some(5)]
        );
        for (index, edge) in computation.edges.values().enumerate() {
            assert_eq!(edge.record, 0);
            assert_eq!(
                edge.edge.key.edge_type,
                GraphEdgeTypeV1::CredentialAuthority
            );
            assert!(matches!(
                (network, edge.edge.key.cause),
                (true, GraphCauseV1::Direct) | (false, GraphCauseV1::Contextual)
            ));
            assert_eq!(
                edge.edge.key.evidence,
                evidence[..prefix + index + 1]
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
            );
        }
        let finding = computation
            .findings
            .values()
            .next()
            .ok_or("credential finding")?;
        assert_eq!(finding.reason_code, format!("HF-DW-001.{reason}"));
        assert_eq!(finding.state == FindingStateV1::Confirmed, network);
        assert_eq!(
            finding.evidence,
            evidence
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|row| identity(u64::from(row)))
                .collect::<Vec<_>>()
        );
        let expected_edges = computation.edges.values().cloned().collect();
        authority_publication(computation, &fixture, expected_edges)?;
        if network {
            let mut changed = facts.clone();
            let FactValue::AuthorityUse { proof_quality, .. } = &mut changed[2].value else {
                return Err("authority fixture".into());
            };
            proof_quality.remote_subject_binding = RemoteSubjectBindingV1::Contextual;
            let mut computation = Computation::new(
                Observation::decode(&fixture.evaluation.inputs[0].data)?,
                changed,
                Manifest::decode(&fixture.evaluation.inputs[2].data)?.remove(0),
                detector,
            )?;
            assert_ne!(computation.fact_ids[2], computation.fact_ids[4]);
            let matched = computation.authorities(
                &computation.records[0],
                &computation.facts[0].value,
                true,
                &mut vec![0],
            )?;
            assert!(matched.contains(&(2, false)));
            assert!(matched.contains(&(4, true)));
            computation.credentials()?;
            let finding = computation
                .findings
                .values()
                .next()
                .ok_or("contextual finding")?;
            assert_eq!(finding.reason_code, "HF-DW-001.CONTEXTUAL_CREDENTIAL_PIVOT");
            assert_eq!(finding.state, FindingStateV1::CoverageInsufficient);
        }
    }
    Ok(())
}

fn authority_publication(
    computation: Computation,
    fixture: &sdk::Fixture,
    expected_edges: Vec<Relationship>,
) -> TestResult {
    let package = Detector::Credentials.descriptor();
    let model = &package.exports[0];
    let expected_finding = computation
        .findings
        .values()
        .next()
        .ok_or("saved finding")?
        .clone();
    let prior_subjects = computation.subjects.clone();
    let expected_facts = computation.facts.clone();
    let expected_state = computation.state.value.clone();
    let output = computation.output(&package)?;
    package.validate_output(&fixture.evaluation, &output)?;
    let subjects = Subject::decode(&output.datasets[0])?;
    let edges = Relationship::decode(&output.datasets[1])?;
    assert_eq!(edges.len(), expected_edges.len());
    for (mut actual, expected) in edges.into_iter().zip(expected_edges) {
        for (actual, expected) in [
            (actual.edge.key.from, expected.edge.key.from),
            (actual.edge.key.to, expected.edge.key.to),
        ] {
            assert_eq!(
                subjects[actual as usize].key,
                prior_subjects[expected as usize].key
            );
        }
        actual.edge.key.from = expected.edge.key.from;
        actual.edge.key.to = expected.edge.key.to;
        assert_eq!(actual, expected);
    }
    let findings = Finding::decode(&output.datasets[2])?;
    assert_eq!(findings, [expected_finding]);
    assert_eq!(output.reasons.len(), 1);
    assert_eq!(output.reasons[0].code, findings[0].reason_code);
    let details = ReasonDetails::decode(&sdk::Dataset {
        name: model.outputs[2].name.clone(),
        batches: vec![output.reasons[0].details.clone()],
    })?;
    let metadata = Metadata::decode(&output.datasets[4])?.remove(0);
    assert_eq!(metadata.facts, expected_facts);
    let record_rows = metadata
        .record_ids
        .iter()
        .enumerate()
        .map(|(row, id)| (id, row as u32))
        .collect();
    assert_eq!(
        details,
        [ReasonDetails::from_finding(&findings[0], &record_rows)?]
    );
    assert_eq!(
        output
            .evidence
            .iter()
            .map(|link| link.input.row)
            .collect::<Vec<_>>(),
        details[0]
            .evidence
            .iter()
            .map(|row| u64::from(*row))
            .collect::<Vec<_>>()
    );
    assert!(output.evidence.iter().all(|link| {
        link.output.dataset == "findings" && link.output.row == 0 && link.input.dataset == "records"
    }));
    let checkpoint = output.checkpoint.ok_or("checkpoint")?;
    assert_eq!(checkpoint.version, 1);
    let states: Vec<State> = Rows::decode(
        &model
            .checkpoint
            .as_ref()
            .ok_or("checkpoint descriptor")?
            .datasets[0],
        &checkpoint.datasets[0],
    )?;
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].value, expected_state);
    Ok(())
}

#[test]
fn empty_inputs_retain_state() -> TestResult {
    for (detector, state) in [
        (Detector::Process, "WAITING"),
        (Detector::Credentials, "WAITING"),
        (Detector::Kubernetes, "KUBERNETES_PROOF_MISSING"),
    ] {
        let fixture = fixture(detector, &[], &[])?;
        let output = detector.evaluate(&fixture.evaluation)?;
        assert!(Subject::decode(&output.datasets[0])?.is_empty());
        assert!(Relationship::decode(&output.datasets[1])?.is_empty());
        assert!(Finding::decode(&output.datasets[2])?.is_empty());
        assert!(GraphBranchV1::decode(&output.datasets[3])?.is_empty());
        let metadata = Metadata::decode(&output.datasets[4])?;
        assert_eq!(metadata.len(), 1);
        assert!(metadata[0].record_ids.is_empty());
        assert!(metadata[0].facts.is_empty());
        assert_eq!(metadata[0].package.accepted_cursor_watermark, 0);
        assert_eq!(metadata[0].package.observed_boottime_watermark_ns, 0);
        assert_eq!(serde_json::to_value(&metadata[0].package.state)?, state);
        let package = detector.descriptor();
        let spec = package.exports[0]
            .checkpoint
            .as_ref()
            .ok_or("checkpoint declaration")?;
        let checkpoint = output.checkpoint.as_ref().ok_or("checkpoint")?;
        let states: Vec<State> = Rows::decode(&spec.datasets[0], &checkpoint.datasets[0])?;
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].value, state);
        assert!(output.evidence.is_empty());
        assert!(output.reasons.is_empty());
    }
    Ok(())
}

#[test]
fn declared_reason_keeps_semantics() -> TestResult {
    let detector = Detector::Process;
    let fixture = fixture(detector, &[record()], &[])?;
    let (mut rows, _) = findings(detector, &fixture)?;
    let mut finding = rows.remove(0);
    finding.limits.clear();
    for (label, reason, expected) in [
        (
            "OUTSIDE_AUTHORITY",
            FindingReasonV1::OutsideAuthority,
            GraphBranchStateV1::OutsideAuthority,
        ),
        (
            "CONTEXTUAL_CREDENTIAL_PIVOT",
            FindingReasonV1::ContextualCredentialPivot,
            GraphBranchStateV1::ContextualOnly,
        ),
    ] {
        finding.reason_code = format!("{}.{}", detector.id(), label);
        let value = sdk::ReasonValue {
            output: sdk::RowRef {
                dataset: "findings".into(),
                row: 0,
            },
            code: finding.reason_code.clone(),
            details: sdk::RecordBatch::try_new(
                std::sync::Arc::new(sdk::Schema::new(vec![sdk::Field::new(
                    "count",
                    sdk::DataType::UInt64,
                    false,
                )])),
                vec![std::sync::Arc::new(sdk::arrow_array::UInt64Array::from(
                    vec![1],
                ))],
            )?,
        };
        let declared = FindingReasonV1::Declared(DeclaredFindingReasonV1::from_value(&value)?);
        assert_eq!(
            GraphBranchV1::from_finding(&finding, &reason).state,
            expected
        );
        assert_eq!(
            GraphBranchV1::from_finding(&finding, &declared).state,
            GraphBranchStateV1::Open
        );
    }
    Ok(())
}
