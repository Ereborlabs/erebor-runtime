use super::credential::CredentialIndex;
use super::*;
use erebor_interceptor_abi::{EffectPhysicalResultV1, KernelEffectFamilyV1};

mod fixture;
mod incremental;
mod units;
use fixture::*;
use units::UnitFixture;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn graph_identities_use_stable_binary_keys() -> TestResult {
    let source = identity(0);
    let key = subject(GraphSubjectKindV1::Task, 3_u64.to_be_bytes().to_vec());
    let first = FindingV1::identity("HF-PROC-001", &source, &key)?;
    assert_eq!(first, FindingV1::identity("HF-PROC-001", &source, &key)?);
    assert_eq!(first.len(), 64);
    assert_ne!(
        first,
        FindingV1::identity("HF-PROC-001", &identity(1), &key)?
    );
    assert_ne!(
        first,
        FindingV1::identity(
            "HF-PROC-001",
            &source,
            &subject(GraphSubjectKindV1::Task, 4_u64.to_be_bytes().to_vec())
        )?
    );
    assert_ne!(
        GraphSubjectKeyV1::provider_identity(&None, "principal", "read")?,
        GraphSubjectKeyV1::provider_identity(&Some(String::new()), "principal", "read")?
    );
    assert_ne!(
        GraphSubjectKeyV1::kubernetes_identity("object", &Some("1".into()))?,
        GraphSubjectKeyV1::kubernetes_identity("object", &Some("2".into()))?
    );
    assert_ne!(
        GraphSubjectKeyV1::kubernetes_identity("object", &None)?,
        GraphSubjectKeyV1::kubernetes_identity("object", &Some(String::new()))?
    );
    Ok(())
}

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
fn record_anchor_keeps_fact_identity() -> TestResult {
    let detector = Detector::Process;
    let parent = FactValue::NativeParent {
        parent: subject(GraphSubjectKindV1::Task, 2_u64.to_be_bytes().to_vec()),
        child: subject(GraphSubjectKindV1::Task, 3_u64.to_be_bytes().to_vec()),
        proof_quality: proof(),
    };
    let mut facts = vec![
        fact(1, parent.clone()),
        fact(0, parent.clone()),
        fact(2, context(ContextClass::InMemory)),
        fact(1, parent.clone()),
    ];
    UnitFixture::keys(&mut facts);
    let fixture = fixture(detector, &[record(), record(), record()], &facts)?;
    let (findings, output) = findings(detector, &fixture)?;
    let edges = RelationshipChange::decode(UnitFixture::data(&output, "relationships")?)?;
    assert_eq!(
        edges
            .iter()
            .filter_map(|edge| edge
                .anchor
                .fact
                .as_ref()
                .map(|fact| (edge.anchor.record.clone(), fact.value.clone())))
            .collect::<Vec<_>>(),
        [(identity(0), parent.clone()), (identity(1), parent),]
    );
    assert_eq!(Fact::decode(&fixture.evaluation.inputs[4].data)?.len(), 4);
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
fn process_unit_keeps_finding() -> TestResult {
    let detector = Detector::Process;
    let mut fixture = fixture(detector, &[record()], &[])?;
    let (first, output) = findings(detector, &fixture)?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].reason_code, "HF-PROC-001.UNEXPECTED_EFFECT");
    assert_eq!(first[0].state, FindingStateV1::Confirmed);
    assert_eq!(first[0].evidence, [identity(0)]);
    assert!(output.checkpoint.is_none());
    fixture.evaluation.inputs.reverse();
    let (replayed, output) = findings(detector, &fixture)?;
    assert_eq!(first, replayed);
    assert!(output.checkpoint.is_none());
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
    let rows = Contribution::decode(UnitFixture::data(&output, "contributions")?)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].state.as_ref().map(|state| &state.state),
        Some(&GraphPackageStateV1::RemoteAdmission)
    );
    assert!(output.checkpoint.is_none());
    Ok(())
}

fn credential_fixture() -> sdk::Result<sdk::Fixture> {
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
    let mut facts = vec![
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
    UnitFixture::keys(&mut facts);
    fixture(detector, &[read, channel, remote], &facts)
}

#[test]
fn credential_exact_and_missing() -> TestResult {
    let detector = Detector::Credentials;
    let mut complete = credential_fixture()?;
    let facts = Fact::decode(&complete.evaluation.inputs[4].data)?;
    let batch = complete.evaluation.inputs[3].data.batches.remove(0);
    complete.evaluation.inputs[3].data.batches = vec![batch.slice(0, 1), batch.slice(1, 2)];
    let (rows, output) = findings(detector, &complete)?;
    assert_eq!(rows.len(), 2);
    let read = rows
        .iter()
        .find(|row| row.record == 0)
        .ok_or("read finding")?;
    assert_eq!(read.reason_code, "HF-DW-001.MISSING_AUTHORITY_PROOF");
    assert_eq!(read.state, FindingStateV1::CoverageInsufficient);
    assert_eq!(read.evidence, [identity(0)]);
    let remote = rows
        .iter()
        .find(|row| row.record == 2)
        .ok_or("remote finding")?;
    assert_eq!(remote.reason_code, "HF-DW-001.CREDENTIAL_PIVOT");
    assert_eq!(remote.state, FindingStateV1::Confirmed);
    assert_eq!(remote.evidence, [identity(0), identity(1), identity(2)]);
    assert_eq!(output.evidence.len(), 4);
    authority_identity_order(&complete, &facts)?;
    let records = Observation::decode(&complete.evaluation.input("records")?.data)?;
    let missing = fixture(detector, &records, &[facts[0].clone(), facts[3].clone()])?;
    let (rows, _) = findings(detector, &missing)?;
    assert_eq!(rows[0].reason_code, "HF-DW-001.MISSING_AUTHORITY_PROOF");
    assert_eq!(rows[0].state, FindingStateV1::CoverageInsufficient);
    Ok(())
}

#[test]
fn network_authority_uses_prior_channel() -> TestResult {
    let detector = Detector::Credentials;
    let mut fixture = credential_fixture()?;
    let mut records = Observation::decode(&fixture.evaluation.inputs[3].data)?;
    records[2].effect.effect_family = KernelEffectFamilyV1::Network as u32;
    fixture.evaluation.inputs[3].data = Observation::encode(&records)?;
    let (findings, _) = findings(detector, &fixture)?;
    let authority = findings
        .iter()
        .find(|finding| finding.record == 2)
        .ok_or("network authority finding")?;
    assert_eq!(authority.state, FindingStateV1::Confirmed);
    assert_eq!(authority.evidence, [identity(0), identity(1), identity(2)]);
    Ok(())
}

#[test]
fn unrelated_credential_fact_does_not_contradict_read() -> TestResult {
    let detector = Detector::Credentials;
    let fixture = credential_fixture()?;
    let mut facts = Fact::decode(&fixture.evaluation.inputs[4].data)?;
    let mut unrelated = facts[0].clone();
    unrelated.key.owner_revision += 1;
    if let FactValue::Credential {
        object_id,
        expected_access,
        ..
    } = &mut unrelated.value
    {
        *object_id = [9; 16];
        *expected_access = true;
    }
    facts.push(unrelated);
    let records = Observation::decode(&fixture.evaluation.input("records")?.data)?;
    let fixture = fixture::fixture(detector, &records, &facts)?;
    let (findings, _) = findings(detector, &fixture)?;
    assert!(findings
        .iter()
        .all(|finding| finding.reason_code != "HF-DW-001.CONTRADICTION"));
    assert_eq!(findings.len(), 2);
    Ok(())
}

#[test]
fn channel_fact_must_match_observed_socket() -> TestResult {
    let detector = Detector::Credentials;
    let mut fixture = credential_fixture()?;
    let mut records = Observation::decode(&fixture.evaluation.inputs[3].data)?;
    records[1].effect.exact_object_id = vec![8; 16];
    fixture.evaluation.inputs[3].data = Observation::encode(&records)?;
    let (findings, output) = findings(detector, &fixture)?;
    assert!(findings.iter().all(|finding| {
        finding.reason_code != "HF-DW-001.CREDENTIAL_PIVOT"
            && finding.state != FindingStateV1::Confirmed
    }));
    assert!(
        RelationshipChange::decode(UnitFixture::data(&output, "relationships")?)?
            .iter()
            .all(|edge| edge.key.cause != GraphCauseV1::Direct)
    );
    Ok(())
}

#[test]
fn known_task_mismatch_blocks_channel_join() -> TestResult {
    let detector = Detector::Credentials;
    let mut fixture = credential_fixture()?;
    let mut records = Observation::decode(&fixture.evaluation.inputs[3].data)?;
    records[1].effect.task_cookie = 4;
    fixture.evaluation.inputs[3].data = Observation::encode(&records)?;
    let mut facts = Fact::decode(&fixture.evaluation.inputs[4].data)?;
    if let FactValue::Channel { task_cookie, .. } = &mut facts[1].value {
        *task_cookie = 4;
    }
    fixture.evaluation.inputs[4].data = Fact::encode(&facts)?;
    let (findings, output) = findings(detector, &fixture)?;
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|finding| finding.record != 1));
    assert!(findings.iter().all(|finding| {
        finding.reason_code != "HF-DW-001.CREDENTIAL_PIVOT"
            && finding.state != FindingStateV1::Confirmed
    }));
    assert!(
        RelationshipChange::decode(UnitFixture::data(&output, "relationships")?)?
            .iter()
            .all(|edge| edge.key.cause != GraphCauseV1::Direct)
    );
    Ok(())
}

fn authority_identity_order(complete: &sdk::Fixture, facts: &[Fact]) -> TestResult {
    let detector = Detector::Credentials;
    let records = Observation::decode(&complete.evaluation.input("records")?.data)?;
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
    let mut facts = vec![
        facts[0].clone(),
        carried,
        first,
        earlier,
        duplicate,
        later,
        facts[3].clone(),
    ];
    UnitFixture::keys(&mut facts);
    for network in [true, false] {
        let family = if network {
            KernelEffectFamilyV1::Network
        } else {
            KernelEffectFamilyV1::File
        };
        records[1].effect.effect_family = family as u32;
        records[2].effect.effect_family = family as u32;
        let fixture = fixture(detector, &records, &facts)?;
        let records = Observation::decode(&fixture.evaluation.input("records")?.data)?;
        let computation = Computation::indexed(
            records.clone(),
            facts.clone(),
            Manifest { window_ns: 100 },
            detector,
        )?;
        let index = CredentialIndex::new(&computation)?;
        let matched = computation.authorities(
            &records[0],
            &facts[0].value,
            true,
            records[5].position,
            None,
            &index,
        )?;
        assert_eq!(computation.fact_ids[2], computation.fact_ids[4]);
        assert_ne!(facts[2].key, facts[4].key);
        assert_eq!(
            matched
                .iter()
                .map(|value| (value.fact_index, value.direct))
                .collect::<Vec<_>>(),
            [(3, network), (2, network), (5, network)]
        );
        assert!(matched
            .iter()
            .all(|value| value.channels.as_slice() == if network { &[2][..] } else { &[][..] }));
        let (findings, output) = findings(detector, &fixture)?;
        assert_eq!(findings.len(), 4);
        let contributions = Contribution::decode(UnitFixture::data(&output, "contributions")?)?;
        let owner = contributions
            .iter()
            .find(|unit| unit.record == records[5].id)
            .ok_or("authority unit")?;
        let edges = RelationshipChange::decode(UnitFixture::data(&output, "relationships")?)?;
        let edges = owner
            .relationships
            .iter()
            .map(|row| &edges[*row as usize])
            .collect::<Vec<_>>();
        assert_eq!(edges.len(), 3);
        assert_eq!(
            edges
                .iter()
                .map(|edge| edge.anchor.fact.as_ref().map(|fact| fact.key.clone()))
                .collect::<BTreeSet<_>>(),
            [
                Some(facts[3].key.clone()),
                Some(facts[2].key.clone()),
                Some(facts[5].key.clone())
            ]
            .into_iter()
            .collect()
        );
        for edge in edges {
            assert_eq!(edge.anchor.record, records[0].id);
            assert_eq!(edge.key.edge_type, GraphEdgeTypeV1::CredentialAuthority);
            assert!(matches!(
                (network, edge.key.cause),
                (true, GraphCauseV1::Direct) | (false, GraphCauseV1::Contextual)
            ));
            let anchor = edge.anchor.fact.as_ref().ok_or("authority fact anchor")?;
            let mut evidence = vec![records[0].id.clone(), anchor.record.clone()];
            if network {
                evidence.push(records[2].id.clone());
            }
            evidence.sort();
            evidence.dedup();
            assert_eq!(edge.key.evidence, evidence);
        }
        let finding = findings
            .iter()
            .find(|finding| finding.record == 5)
            .ok_or("authority finding")?;
        assert_eq!(
            finding.reason_code,
            format!(
                "HF-DW-001.{}",
                if network {
                    "CREDENTIAL_PIVOT"
                } else {
                    "CONTEXTUAL_CREDENTIAL_PIVOT"
                }
            )
        );
        assert_eq!(finding.state == FindingStateV1::Confirmed, network);
        assert_eq!(
            finding.evidence,
            [0u32, 3, 4, 5]
                .into_iter()
                .chain(network.then_some(2))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|row| identity(u64::from(row)))
                .collect::<Vec<_>>()
        );
        if network {
            let mut changed = facts.clone();
            let FactValue::AuthorityUse { proof_quality, .. } = &mut changed[2].value else {
                return Err("authority fixture".into());
            };
            proof_quality.remote_subject_binding = RemoteSubjectBindingV1::Contextual;
            let computation = Computation::indexed(
                records.clone(),
                changed.clone(),
                Manifest { window_ns: 100 },
                detector,
            )?;
            assert_ne!(computation.fact_ids[2], computation.fact_ids[4]);
            let matched = computation.authorities(
                &records[0],
                &changed[0].value,
                true,
                records[5].position,
                None,
                &CredentialIndex::new(&computation)?,
            )?;
            assert!(matched
                .iter()
                .any(|value| value.fact_index == 2 && !value.direct));
            assert!(matched
                .iter()
                .any(|value| value.fact_index == 4 && value.direct));
            let current = fixture::fixture(detector, &records, &changed)?;
            let (rows, _) = fixture::findings(detector, &current)?;
            let finding = rows
                .iter()
                .find(|finding| finding.record == 5)
                .ok_or("contextual finding")?;
            assert_eq!(finding.reason_code, "HF-DW-001.CONTEXTUAL_CREDENTIAL_PIVOT");
            assert_eq!(finding.state, FindingStateV1::CoverageInsufficient);
        }
    }
    Ok(())
}

#[test]
fn empty_inputs_retain_state() -> TestResult {
    for (detector, state) in [
        (Detector::Process, GraphPackageStateV1::Waiting),
        (Detector::Credentials, GraphPackageStateV1::Waiting),
        (
            Detector::Kubernetes,
            GraphPackageStateV1::KubernetesProofMissing,
        ),
    ] {
        let fixture = fixture(detector, &[], &[])?;
        let output = detector.evaluate(&fixture.evaluation)?;
        for name in ["subjects", "relationships", "findings", "contributions"] {
            assert_eq!(UnitFixture::data(&output, name)?.rows(), 0);
        }
        assert_eq!(
            GraphPackageStateV1::decode(UnitFixture::data(&output, "state")?)?,
            [state]
        );
        assert!(output.checkpoint.is_none());
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
