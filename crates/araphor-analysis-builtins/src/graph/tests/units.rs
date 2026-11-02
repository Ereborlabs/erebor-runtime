use super::*;

mod permutations;

pub(super) struct UnitFixture;

impl UnitFixture {
    fn records(count: usize) -> Vec<Observation> {
        (0..count)
            .map(|row| {
                let mut value = record();
                value.id = identity(row as u64);
                value.position.ordinal = row as u32;
                value
            })
            .collect()
    }

    pub(super) fn keys(facts: &mut [Fact]) {
        for (index, fact) in facts.iter_mut().enumerate() {
            fact.key.entity_key = (index as u64).to_be_bytes().to_vec();
        }
        facts.sort_by(|left, right| left.key.cmp(&right.key));
    }

    pub(super) fn units(detector: Detector, records: &[Observation], facts: &[Fact]) -> Vec<Unit> {
        let restricted = facts
            .iter()
            .any(|fact| fact.sensitivity == ContextSensitivityV1::HostRestricted);
        records
            .iter()
            .enumerate()
            .map(|(root, record)| {
                let base = (0..records.len())
                    .filter(|&row| matches!(detector, Detector::Credentials) || row == root)
                    .collect::<BTreeSet<_>>();
                let references = facts
                    .iter()
                    .filter(|fact| base.contains(&(fact.record as usize)))
                    .filter_map(|fact| match &fact.value {
                        FactValue::Policy(policy) => Some(policy.observations.iter()),
                        _ => None,
                    })
                    .flatten()
                    .collect::<BTreeSet<_>>();
                let mut support = records
                    .iter()
                    .enumerate()
                    .filter(|(row, record)| base.contains(row) || references.contains(&record.id))
                    .map(|(row, record)| {
                        let mut keys = facts
                            .iter()
                            .filter(|fact| fact.record as usize == row)
                            .map(|fact| fact.key.clone())
                            .collect::<Vec<_>>();
                        keys.sort();
                        UnitSupport {
                            record: record.id.clone(),
                            proof: record.proof_quality,
                            facts: keys,
                        }
                    })
                    .collect::<Vec<_>>();
                support.sort_by(|left, right| left.record.cmp(&right.record));
                Unit {
                    record: record.id.clone(),
                    window_ns: 100,
                    restricted,
                    support,
                }
            })
            .collect()
    }

    pub(super) fn run(
        detector: Detector,
        records: &[Observation],
        facts: &[Fact],
        units: &[Unit],
    ) -> sdk::Result<sdk::Output> {
        let package = detector.descriptor();
        let changes = package.exports[0]
            .change_inputs
            .as_ref()
            .ok_or_else(|| Computation::invalid("unit test changes"))?;
        let datasets = vec![
            Unit::encode(units)?,
            Unit::encode_removals(&[])?,
            changes.reset_input(true)?,
            Observation::encode(records)?,
            Fact::encode(facts)?,
            Unit::encode_affected(
                &units
                    .iter()
                    .map(|unit| unit.record.clone())
                    .collect::<Vec<_>>(),
            )?,
        ];
        detector.evaluate(&sdk::Evaluation {
            export: "detect".into(),
            inputs: datasets
                .into_iter()
                .map(|data| sdk::Input {
                    data,
                    revision: sdk::Revision {
                        owner: "fixture".into(),
                        id: "cut".into(),
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
                id: "unit-test".into(),
                time_utc_ns: 1,
                seed: None,
            },
            checkpoint: None,
            previous_outputs: Vec::new(),
        })
    }

    pub(super) fn data<'a>(output: &'a sdk::Output, name: &str) -> sdk::Result<&'a sdk::Dataset> {
        output
            .datasets
            .iter()
            .find(|data| data.name == name)
            .ok_or_else(|| Computation::invalid("unit test dataset"))
    }
}

#[test]
fn unit_ports_keep_native_values() -> TestResult {
    let records = UnitFixture::records(2);
    let mut facts = vec![fact(0, context(ContextClass::OutsideAuthority))];
    UnitFixture::keys(&mut facts);
    facts[0].sensitivity = ContextSensitivityV1::HostRestricted;
    let native = Fact::encode(&facts)?;
    let sensitivity = native.batches[0]
        .column_by_name("sensitivity")
        .and_then(|column| {
            column
                .as_any()
                .downcast_ref::<sdk::arrow_array::StringArray>()
        })
        .ok_or("native sensitivity string")?;
    assert_eq!(sensitivity.value(0), "HostRestricted");
    let units = UnitFixture::units(Detector::Process, &records, &facts);
    assert_eq!(Unit::decode(&Unit::encode(&units)?)?, units);
    assert_eq!(Unit::decode(&Unit::encode_removals(&units)?)?, units);
    let values = vec![Contribution {
        record: records[0].id.clone(),
        subjects: vec![0, 1],
        relationships: vec![2],
        findings: vec![3],
        state: Some(UnitState {
            state: GraphPackageStateV1::NativeEffect,
            position: records[0].position,
            fact: Some(facts[0].key.clone()),
        }),
    }];
    assert_eq!(
        Contribution::decode(&Contribution::encode(&values)?)?,
        values
    );
    for detector in [
        Detector::Process,
        Detector::Credentials,
        Detector::Kubernetes,
    ] {
        let package = detector.descriptor();
        package.validate()?;
        assert!(package.exports[0].checkpoint.is_none());
        assert_eq!(package.exports[0].input_mode, sdk::InputMode::Resolved);
        assert!(Detector::supports_units(&package.exports[0]));
        let mut changed = package.exports[0].clone();
        changed.inputs[3].source = sdk::InputSource::Query("SELECT * FROM records".into());
        assert!(!Detector::supports_units(&changed));
    }
    Ok(())
}

#[test]
fn process_units_keep_shared_subjects_and_context() -> TestResult {
    let records = UnitFixture::records(2);
    let mut facts = vec![
        fact(0, context(ContextClass::OutsideAuthority)),
        fact(1, context(ContextClass::InMemory)),
    ];
    UnitFixture::keys(&mut facts);
    let output = UnitFixture::run(
        Detector::Process,
        &records,
        &facts,
        &UnitFixture::units(Detector::Process, &records, &facts),
    )?;
    let findings = FindingChange::decode(UnitFixture::data(&output, "findings")?)?;
    assert_eq!(findings.len(), 4);
    assert!(findings
        .iter()
        .any(|finding| finding.reason_code == "HF-PROC-001.OUTSIDE_AUTHORITY"));
    assert!(findings
        .iter()
        .any(|finding| finding.reason_code == "HF-PROC-001.IN_MEMORY_ONLY"));
    let subjects = SubjectChange::decode(UnitFixture::data(&output, "subjects")?)?;
    let rows = Contribution::decode(UnitFixture::data(&output, "contributions")?)?;
    assert_eq!(rows.len(), 2);
    let first = rows[0]
        .subjects
        .iter()
        .map(|row| &subjects[*row as usize].key)
        .collect::<BTreeSet<_>>();
    let second = rows[1]
        .subjects
        .iter()
        .map(|row| &subjects[*row as usize].key)
        .collect::<BTreeSet<_>>();
    assert!(!first.is_disjoint(&second));
    Ok(())
}

#[test]
fn policy_references_change_unit_support() -> TestResult {
    let records = UnitFixture::records(3);
    let mut policy = match Fact::decode(&credential_fixture()?.evaluation.input("facts")?.data)?
        .remove(3)
        .value
    {
        FactValue::Policy(policy) => policy,
        _ => return Err("policy fixture".into()),
    };
    policy.observations = vec![records[0].id.clone(), records[1].id.clone()];
    let mut next = policy.clone();
    next.observations = vec![records[1].id.clone(), records[2].id.clone()];
    let mut facts = vec![
        fact(0, FactValue::Policy(policy.clone())),
        fact(1, FactValue::Policy(next)),
    ];
    UnitFixture::keys(&mut facts);
    let before = UnitFixture::units(Detector::Process, &records, &facts);
    assert_eq!(
        before[0]
            .support
            .iter()
            .map(|support| &support.record)
            .collect::<Vec<_>>(),
        [&records[0].id, &records[1].id]
    );
    let retained = vec![records[0].clone(), records[2].clone()];
    let remaining = facts[..1].to_vec();
    let after = UnitFixture::units(Detector::Process, &retained, &remaining);
    assert_ne!(before[0], after[0]);
    assert_eq!(before[2], after[1]);
    assert_eq!(after[0].support.len(), 1);
    let output = UnitFixture::run(Detector::Process, &retained, &remaining, &after)?;
    let findings = FindingChange::decode(UnitFixture::data(&output, "findings")?)?;
    assert!(findings
        .iter()
        .any(|finding| finding.policy_provenance.contains(&policy)));
    Ok(())
}

#[test]
fn credential_units_keep_late_support_and_proof_changes() -> TestResult {
    let fixture = credential_fixture()?;
    let mut records = Observation::decode(&fixture.evaluation.input("records")?.data)?;
    let mut facts = Fact::decode(&fixture.evaluation.input("facts")?.data)?;
    UnitFixture::keys(&mut facts);
    let output = UnitFixture::run(
        Detector::Credentials,
        &records,
        &facts,
        &UnitFixture::units(Detector::Credentials, &records, &facts),
    )?;
    assert!(
        FindingChange::decode(UnitFixture::data(&output, "findings")?)?
            .iter()
            .any(|finding| finding.state == FindingStateV1::Confirmed)
    );
    let mut removed = facts.clone();
    removed.retain(|fact| !matches!(fact.value, FactValue::AuthorityUse { .. }));
    let output = UnitFixture::run(
        Detector::Credentials,
        &records,
        &removed,
        &UnitFixture::units(Detector::Credentials, &records, &removed),
    )?;
    assert!(
        RelationshipChange::decode(UnitFixture::data(&output, "relationships")?)?
            .iter()
            .all(|edge| edge.key.edge_type != GraphEdgeTypeV1::CredentialAuthority)
    );
    let mut downgraded = records.clone();
    downgraded[1].proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
    let output = UnitFixture::run(
        Detector::Credentials,
        &downgraded,
        &facts,
        &UnitFixture::units(Detector::Credentials, &downgraded, &facts),
    )?;
    assert!(
        FindingChange::decode(UnitFixture::data(&output, "findings")?)?
            .iter()
            .filter(|finding| finding.anchor.record == records[2].id)
            .all(|finding| finding.state != FindingStateV1::Confirmed)
    );
    for (index, record) in records.iter_mut().enumerate() {
        record.position.ordinal = (index * 2) as u32;
    }
    let mut late = records[0].clone();
    late.id = identity(3);
    late.position.ordinal = 1;
    late.observed_boottime_ns = 9;
    records.push(late);
    for index in [0, 3] {
        let mut added = facts[index].clone();
        added.record = 3;
        added.key.entity_key = (facts.len() as u64).to_be_bytes().to_vec();
        match &mut added.value {
            FactValue::Credential {
                completion: Some(completion),
                ..
            } => {
                completion.admission_record = records[3].id.clone();
                completion.completion_id = "late-read".into();
            }
            FactValue::Policy(policy) => policy.observations = vec![records[3].id.clone()],
            _ => {}
        }
        facts.push(added);
    }
    let output = UnitFixture::run(
        Detector::Credentials,
        &records,
        &facts,
        &UnitFixture::units(Detector::Credentials, &records, &facts),
    )?;
    assert!(
        FindingChange::decode(UnitFixture::data(&output, "findings")?)?
            .iter()
            .any(|finding| finding.evidence.contains(&records[3].id))
    );
    Ok(())
}

#[test]
fn credential_units_isolate_shared_lookup_rows() -> TestResult {
    let fixture = credential_fixture()?;
    let records = Observation::decode(&fixture.evaluation.input("records")?.data)?;
    let mut facts = Fact::decode(&fixture.evaluation.input("facts")?.data)?;
    UnitFixture::keys(&mut facts);
    let mut units = UnitFixture::units(Detector::Credentials, &records, &facts);
    units[2]
        .support
        .retain(|support| support.record == records[2].id);
    let output = UnitFixture::run(Detector::Credentials, &records, &facts, &units)?;
    let contributions = Contribution::decode(UnitFixture::data(&output, "contributions")?)?;
    assert!(contributions[2].subjects.is_empty());
    assert!(contributions[2].relationships.is_empty());
    assert!(contributions[2].findings.is_empty());
    assert!(contributions[2].state.is_none());
    Ok(())
}

#[test]
fn restriction_flag_updates_unit_without_local_fact() -> TestResult {
    let records = UnitFixture::records(2);
    let mut classified = fact(1, context(ContextClass::OutsideAuthority));
    classified.sensitivity = ContextSensitivityV1::HostRestricted;
    let mut facts = vec![classified];
    UnitFixture::keys(&mut facts);
    let units = UnitFixture::units(Detector::Process, &records, &facts);
    let output = UnitFixture::run(Detector::Process, &records[..1], &[], &units[..1])?;
    let findings = FindingChange::decode(UnitFixture::data(&output, "findings")?)?;
    assert!(!findings.is_empty());
    assert!(findings
        .iter()
        .all(|finding| finding.sensitivity == ContextSensitivityV1::HostRestricted));
    Ok(())
}

#[test]
fn kubernetes_state_uses_last_relevant_fact() -> TestResult {
    let records = UnitFixture::records(2);
    let stage = KubernetesStageProofV1 {
        cluster_id: "cluster".into(),
        carried_request_id: Some("request".into()),
        audit_id: Some("audit".into()),
        object_uid: None,
        resource_version: None,
        owner_uid: None,
        pod_uid: None,
        node_id: None,
        full_container_id: None,
        remote_admission_id: None,
        proof_quality: proof(),
    };
    let mut remote = stage.clone();
    remote.full_container_id = Some("container".into());
    remote.remote_admission_id = Some("admission".into());
    let mut facts = vec![
        fact(0, FactValue::Kubernetes(stage)),
        fact(1, FactValue::Kubernetes(remote)),
        fact(0, context(ContextClass::OutsideAuthority)),
    ];
    UnitFixture::keys(&mut facts);
    let units = UnitFixture::units(Detector::Kubernetes, &records, &facts);
    let output = UnitFixture::run(Detector::Kubernetes, &records, &facts, &units)?;
    let states = Contribution::decode(UnitFixture::data(&output, "contributions")?)?;
    let first = states[0].state.as_ref().ok_or("first state")?;
    let second = states[1].state.as_ref().ok_or("second state")?;
    assert_eq!(first.fact.as_ref(), Some(&facts[0].key));
    assert_eq!(second.fact.as_ref(), Some(&facts[1].key));
    assert_eq!(second.state, GraphPackageStateV1::RemoteAdmission);
    Ok(())
}

#[test]
fn unit_states_keep_record_order_and_position_proof() -> TestResult {
    let mut records = UnitFixture::records(3);
    records[1].position.ordinal = 2;
    records[2].position.ordinal = 1;
    let mut policy = match Fact::decode(&credential_fixture()?.evaluation.input("facts")?.data)?
        .remove(3)
        .value
    {
        FactValue::Policy(policy) => policy,
        _ => return Err("policy fixture".into()),
    };
    policy.state = PolicyProvenanceStateV1::Contradicted;
    let mut facts = vec![fact(1, FactValue::Policy(policy))];
    UnitFixture::keys(&mut facts);
    let units = UnitFixture::units(Detector::Process, &records, &facts);
    let output = UnitFixture::run(Detector::Process, &records, &facts, &units)?;
    let contributions = Contribution::decode(UnitFixture::data(&output, "contributions")?)?;
    let by_id = contributions
        .iter()
        .filter(|value| value.state.is_some())
        .max_by_key(|value| &value.record)
        .and_then(|value| value.state.as_ref())
        .ok_or("record state")?;
    let by_position = contributions
        .iter()
        .filter_map(|value| value.state.as_ref())
        .max_by_key(|value| value.position)
        .ok_or("position state")?;
    assert_eq!(by_id.state, GraphPackageStateV1::NativeEffect);
    assert_eq!(by_position.state, GraphPackageStateV1::Contradicted);
    assert!(contributions.iter().all(|value| value
        .state
        .as_ref()
        .is_none_or(|state| state.fact.is_none())));
    Ok(())
}

#[test]
fn units_require_exact_lookup_support() -> TestResult {
    let records = UnitFixture::records(1);
    let mut facts = vec![fact(0, context(ContextClass::InMemory))];
    UnitFixture::keys(&mut facts);
    let units = UnitFixture::units(Detector::Process, &records, &facts);
    for case in 0..4 {
        let mut changed = units.clone();
        match case {
            0 => changed[0].support.clear(),
            1 => changed[0].support[0].proof.temporal_coverage = TemporalCoverageV1::Unknown,
            2 => changed[0].support[0].facts.clear(),
            _ => changed.push(changed[0].clone()),
        }
        assert!(UnitFixture::run(Detector::Process, &records, &facts, &changed).is_err());
    }
    Ok(())
}
