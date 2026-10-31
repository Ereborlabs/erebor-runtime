use super::*;

#[derive(Debug, Eq, PartialEq)]
struct UnitImage {
    subjects: Vec<SubjectChange>,
    relationships: Vec<RelationshipChange>,
    findings: Vec<FindingChange>,
    state: Option<UnitState>,
}

#[derive(Debug, Eq, PartialEq)]
struct Image {
    units: BTreeMap<crate::discovery::DiscoveryRecordIdV1, UnitImage>,
    state: Vec<GraphPackageStateV1>,
    evidence: BTreeSet<(String, crate::discovery::DiscoveryRecordIdV1)>,
}

impl Image {
    fn new(output: &sdk::Output, records: &[Observation], facts: &[Fact]) -> TestResult<Self> {
        let subjects = SubjectChange::decode(UnitFixture::data(output, "subjects")?)?;
        let relationships =
            RelationshipChange::decode(UnitFixture::data(output, "relationships")?)?;
        let findings = FindingChange::decode(UnitFixture::data(output, "findings")?)?;
        let contributions = Contribution::decode(UnitFixture::data(output, "contributions")?)?;
        let record_ids = records
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>();
        let mut reasons = BTreeSet::new();
        for reason in &output.reasons {
            assert_eq!(reason.output.dataset, "findings");
            let finding = findings
                .get(reason.output.row as usize)
                .ok_or("reason row")?;
            assert!(reasons.insert(finding.finding_id.clone()));
            assert_eq!(reason.code, finding.reason_code);
            let details = ReasonDetails::decode(&sdk::Dataset {
                name: ReasonDetails::port().name,
                batches: vec![reason.details.clone()],
            })?;
            assert_eq!(details.len(), 1);
            let details = &details[0];
            assert_eq!(
                Anchor::from_positions(details.record, details.context, &record_ids, facts)?,
                finding.anchor
            );
            assert_eq!(
                details
                    .evidence
                    .iter()
                    .map(|&row| record_ids[row as usize].clone())
                    .collect::<Vec<_>>(),
                finding.evidence
            );
            assert_eq!(details.limits, finding.limits);
            assert_eq!(
                details.confirmed,
                finding.state == FindingStateV1::Confirmed
            );
            assert_eq!(
                format!("{}.{}", finding.package_id, details.reason),
                finding.reason_code
            );
        }
        assert_eq!(reasons.len(), findings.len());
        let mut evidence = BTreeSet::new();
        for link in &output.evidence {
            assert_eq!(link.output.dataset, "findings");
            assert_eq!(link.input.dataset, "records");
            let finding = findings
                .get(link.output.row as usize)
                .ok_or("evidence output")?;
            let record = record_ids
                .get(link.input.row as usize)
                .ok_or("evidence input")?;
            assert!(evidence.insert((finding.finding_id.clone(), record.clone())));
        }
        assert_eq!(
            evidence,
            findings
                .iter()
                .flat_map(|finding| finding
                    .evidence
                    .iter()
                    .map(|record| (finding.finding_id.clone(), record.clone())))
                .collect()
        );
        let mut owners = [
            vec![0usize; subjects.len()],
            vec![0usize; relationships.len()],
            vec![0usize; findings.len()],
        ];
        let mut units = BTreeMap::new();
        for contribution in contributions {
            for (kind, members) in [
                &contribution.subjects,
                &contribution.relationships,
                &contribution.findings,
            ]
            .into_iter()
            .enumerate()
            {
                for &row in members {
                    *owners[kind].get_mut(row as usize).ok_or("unit row")? += 1;
                }
            }
            let mut image = UnitImage {
                subjects: contribution
                    .subjects
                    .iter()
                    .map(|&row| subjects[row as usize].clone())
                    .collect(),
                relationships: contribution
                    .relationships
                    .iter()
                    .map(|&row| relationships[row as usize].clone())
                    .collect(),
                findings: contribution
                    .findings
                    .iter()
                    .map(|&row| findings[row as usize].clone())
                    .collect(),
                state: contribution.state,
            };
            image
                .subjects
                .sort_by(|left, right| left.key.cmp(&right.key));
            image
                .relationships
                .sort_by(|left, right| left.key.cmp(&right.key));
            image
                .findings
                .sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
            assert!(units.insert(contribution.record, image).is_none());
        }
        assert!(owners.iter().flatten().all(|&count| count == 1));
        assert!(output.checkpoint.is_none());
        Ok(Self {
            units,
            state: GraphPackageStateV1::decode(UnitFixture::data(output, "state")?)?,
            evidence,
        })
    }

    fn permutations(
        detector: Detector,
        records: &[Observation],
        facts: &[Fact],
    ) -> TestResult<Self> {
        let units = UnitFixture::units(detector, records, facts);
        let expected = Self::new(
            &UnitFixture::run(detector, records, facts, &units)?,
            records,
            facts,
        )?;
        for case in 0..9 {
            let mut selected = records.to_vec();
            let mut delivered = facts.to_vec();
            let mut changed = units.clone();
            if case & 1 != 0 {
                selected.reverse();
            }
            if case & 2 != 0 {
                delivered.reverse();
            }
            if case & 4 != 0 {
                changed.reverse();
            }
            if case == 8 {
                selected.rotate_left(1);
                delivered.rotate_left(1);
                changed.rotate_left(1);
            }
            for fact in &mut delivered {
                let id = &records[fact.record as usize].id;
                fact.record = selected
                    .iter()
                    .position(|record| &record.id == id)
                    .ok_or("permuted record")? as u32;
            }
            let output = UnitFixture::run(detector, &selected, &delivered, &changed)?;
            assert_eq!(
                Self::new(&output, &selected, &delivered)?,
                expected,
                "case {case}"
            );
        }
        Ok(expected)
    }
}

#[test]
fn process_fact_key_permutations() -> TestResult {
    let records = UnitFixture::records(3);
    let external = subject(GraphSubjectKindV1::External, vec![9; 16]);
    let mut contexts = [
        context(ContextClass::OutsideAuthority),
        context(ContextClass::InMemory),
        context(ContextClass::PayloadUnobservable),
    ];
    for context in &mut contexts {
        let FactValue::Context { subject, .. } = context else {
            return Err("context fixture".into());
        };
        *subject = external.clone();
    }
    let parent = FactValue::NativeParent {
        parent: subject(GraphSubjectKindV1::Process, vec![8; 16]),
        child: records[1].task_subject(),
        proof_quality: proof(),
    };
    let mut policy = match Fact::decode(&credential_fixture()?.evaluation.input("facts")?.data)?
        .remove(3)
        .value
    {
        FactValue::Policy(policy) => policy,
        _ => return Err("policy fixture".into()),
    };
    policy.state = PolicyProvenanceStateV1::Contradicted;
    policy.observations = vec![records[2].id.clone()];
    let mut task_context = context(ContextClass::OutsideAuthority);
    let FactValue::Context { subject, .. } = &mut task_context else {
        return Err("task context fixture".into());
    };
    *subject = records[0].task_subject();
    let mut facts = vec![
        fact(0, contexts[0].clone()),
        fact(0, contexts[1].clone()),
        fact(0, contexts[2].clone()),
        fact(1, parent.clone()),
        fact(1, parent),
        fact(0, task_context.clone()),
        fact(2, FactValue::Policy(policy)),
        fact(2, task_context),
    ];
    UnitFixture::keys(&mut facts);
    let image = Image::permutations(Detector::Process, &records, &facts)?;
    let root = &image.units[&records[0].id];
    let finding = root
        .findings
        .iter()
        .find(|finding| finding.subject_id == external)
        .ok_or("context finding")?;
    assert_eq!(finding.reason_code, "HF-PROC-001.PAYLOAD_UNOBSERVABLE");
    assert_eq!(
        finding.anchor.fact.as_ref().map(|fact| &fact.key),
        Some(&facts[2].key)
    );
    let subject = root
        .subjects
        .iter()
        .find(|subject| subject.key == external)
        .ok_or("context subject")?;
    assert_eq!(
        subject.anchor.fact.as_ref().map(|fact| &fact.key),
        Some(&facts[0].key)
    );
    let parent = image.units[&records[1].id]
        .relationships
        .iter()
        .find(|edge| edge.key.edge_type == GraphEdgeTypeV1::NativeParent)
        .ok_or("parent edge")?;
    assert_eq!(
        parent.anchor.fact.as_ref().map(|fact| &fact.key),
        Some(&facts[3].key)
    );
    let task = root
        .findings
        .iter()
        .find(|finding| finding.subject_id == records[0].task_subject())
        .ok_or("confirmed task finding")?;
    assert_eq!(task.reason_code, "HF-PROC-001.UNEXPECTED_EFFECT");
    assert_eq!(task.state, FindingStateV1::Confirmed);
    assert!(task.anchor.fact.is_none());
    let contradicted = &image.units[&records[2].id];
    assert_eq!(contradicted.findings.len(), 1);
    assert_eq!(
        contradicted.findings[0].reason_code,
        "HF-PROC-001.CONTRADICTION"
    );
    assert!(contradicted.findings[0].anchor.fact.is_none());
    Ok(())
}

#[test]
fn kubernetes_fact_key_permutations() -> TestResult {
    let records = UnitFixture::records(2);
    let audit = KubernetesStageProofV1 {
        cluster_id: "cluster".into(),
        carried_request_id: Some("request".into()),
        audit_id: Some("audit".into()),
        object_uid: Some("object".into()),
        resource_version: Some("1".into()),
        owner_uid: None,
        pod_uid: None,
        node_id: None,
        full_container_id: None,
        remote_admission_id: None,
        proof_quality: proof(),
    };
    let mut remote = audit.clone();
    remote.full_container_id = Some("container".into());
    remote.remote_admission_id = Some("admission".into());
    let mut facts = vec![
        fact(0, FactValue::Kubernetes(audit.clone())),
        fact(1, FactValue::Kubernetes(audit)),
        fact(0, FactValue::Kubernetes(remote.clone())),
        fact(0, FactValue::Kubernetes(remote)),
        fact(0, context(ContextClass::InMemory)),
    ];
    UnitFixture::keys(&mut facts);
    let image = Image::permutations(Detector::Kubernetes, &records, &facts)?;
    let root = &image.units[&records[0].id];
    let state = root.state.as_ref().ok_or("Kubernetes state")?;
    assert_eq!(state.state, GraphPackageStateV1::RemoteAdmission);
    assert_eq!(state.fact.as_ref(), Some(&facts[3].key));
    assert_eq!(root.findings.len(), 1);
    assert!(root.findings[0].anchor.fact.is_none());
    assert!(!root.findings[0]
        .limits
        .iter()
        .any(|limit| limit == "REMOTE_RUNTIME_ADMISSION_MISSING"));
    assert_eq!(root.relationships.len(), 1);
    assert_eq!(
        root.relationships[0]
            .anchor
            .fact
            .as_ref()
            .map(|fact| &fact.key),
        Some(&facts[0].key)
    );
    Ok(())
}

#[test]
fn credential_authority_key_permutations() -> TestResult {
    let fixture = credential_fixture()?;
    let mut records = Observation::decode(&fixture.evaluation.input("records")?.data)?;
    let mut facts = Fact::decode(&fixture.evaluation.input("facts")?.data)?;
    records[1].position.ordinal = 2;
    records[2].position.ordinal = 3;
    let mut read = records[0].clone();
    read.id = identity(3);
    read.position.ordinal = 1;
    let mut credential = facts[0].clone();
    credential.record = 3;
    if let FactValue::Credential {
        completion: Some(completion),
        ..
    } = &mut credential.value
    {
        completion.admission_record = read.id.clone();
        completion.completion_id = "second-read".into();
    }
    let mut policy = facts[3].clone();
    policy.record = 3;
    if let FactValue::Policy(policy) = &mut policy.value {
        policy.observations = vec![read.id.clone()];
    }
    records.push(read);
    facts.push(facts[2].clone());
    let mut denied = facts[2].clone();
    if let FactValue::AuthorityUse { proof_quality, .. } = &mut denied.value {
        proof_quality.operation_result_authority = OperationResultAuthorityV1::AuthoritativeDenied;
    }
    facts.extend([denied, credential, policy]);
    UnitFixture::keys(&mut facts);
    let image = Image::permutations(Detector::Credentials, &records, &facts)?;
    let remote = &image.units[&records[2].id];
    assert_eq!(
        remote.state.as_ref().map(|state| &state.state),
        Some(&GraphPackageStateV1::Contradicted)
    );
    assert!(!remote.relationships.is_empty());
    assert!(remote
        .relationships
        .iter()
        .all(|edge| edge.anchor.record == records[0].id || edge.anchor.record == records[3].id));
    assert!(remote.relationships.iter().all(|edge| edge
        .anchor
        .fact
        .as_ref()
        .is_some_and(|fact| fact.key == facts[2].key)));
    let task = records[0].task_subject();
    let subject = remote
        .subjects
        .iter()
        .find(|subject| subject.key == task)
        .ok_or("shared task")?;
    assert_eq!(subject.anchor.record, records[0].id);
    Ok(())
}
