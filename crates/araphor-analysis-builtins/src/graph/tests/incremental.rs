use super::*;

mod state;

fn input(
    detector: Detector,
    records: &[Observation],
    facts: &[Fact],
    window: u64,
) -> sdk::Result<sdk::Evaluation> {
    let mut evaluation = fixture(detector, records, facts)?.evaluation;
    evaluation.inputs[0].data = Observation::encode(records)?;
    evaluation.inputs[2].data = Manifest::encode(&[Manifest { window_ns: window }])?;
    Ok(evaluation)
}

fn input_exact(
    detector: Detector,
    records: &[Observation],
    facts: &[Fact],
) -> sdk::Result<sdk::Evaluation> {
    let mut evaluation = fixture(detector, records, facts)?.evaluation;
    evaluation.inputs[0].data = Observation::encode(records)?;
    Ok(evaluation)
}

fn records(count: usize) -> Vec<Observation> {
    (0..count)
        .map(|row| {
            let mut value = record();
            value.id = identity(row as u64);
            value.position.ordinal = row as u32;
            value.observed_boottime_ns += row as u64;
            value.ingested_utc_ns += row as i64;
            value
        })
        .collect()
}

fn package_state(output: &sdk::Output) -> sdk::Result<GraphPackageStateV1> {
    let checkpoint = output
        .checkpoint
        .as_ref()
        .ok_or_else(|| Computation::invalid("graph test checkpoint"))?;
    GraphPackageStateV1::decode(&checkpoint.datasets[0])?
        .into_iter()
        .next()
        .ok_or_else(|| Computation::invalid("graph test state"))
}

fn measured(detector: Detector, evaluation: &sdk::Evaluation) -> sdk::Result<(sdk::Output, usize)> {
    let package = detector.descriptor();
    let mut work = 0;
    let output = package.check_evaluation(evaluation)?.evaluate(|checked| {
        let mut manifests = Manifest::read(checked)?;
        let mut computation = Computation::new(
            Observation::read(checked)?,
            Fact::read(checked)?,
            manifests.remove(0),
            detector,
        )?;
        computation.update(evaluation)?;
        work = computation.work;
        computation.output()
    })?;
    Ok((output, work))
}

fn continued(
    detector: Detector,
    current: &sdk::Evaluation,
    prior: &sdk::Output,
) -> sdk::Result<(sdk::Output, usize)> {
    let mut complete = current.clone();
    complete.checkpoint = None;
    complete.previous_outputs.clear();
    let expected = detector.evaluate(&complete)?;
    let mut resumed = complete.clone();
    resumed.checkpoint = prior.checkpoint.clone();
    if let Some(checkpoint) = &mut resumed.checkpoint {
        checkpoint.datasets.reverse();
    }
    resumed.previous_outputs = normalized_prior(prior)?;
    resumed.previous_outputs.reverse();
    let actual = detector.evaluate(&resumed)?;
    let (counted, work) = measured(detector, &resumed)?;
    let package = detector.descriptor();
    let same = |left: &sdk::Dataset, right: &sdk::Dataset| {
        left.name == right.name && left.batches == right.batches
    };
    assert!(
        matches!(
            (actual.checkpoint.as_ref(), expected.checkpoint.as_ref()),
            (Some(left), Some(right))
                if left.version == right.version
                    && left.datasets.len() == right.datasets.len()
                    && left.datasets.iter().zip(&right.datasets).all(|(left, right)| same(left, right))
        ),
        "checkpoint"
    );
    assert!(
        sdk::wire::Output::encode(&package, &resumed, &counted)?
            == sdk::wire::Output::encode(&package, &resumed, &actual)?,
        "counted and public {detector:?} execution"
    );
    let mut subjects = SubjectChange::decode(&prior.datasets[0])?
        .into_iter()
        .map(|row| (row.key.clone(), row))
        .collect::<BTreeMap<_, _>>();
    for row in SubjectRemoval::decode(&actual.datasets[1])? {
        assert!(subjects.remove(&row.key).is_some());
    }
    for row in SubjectChange::decode(&actual.datasets[0])? {
        assert!(subjects.insert(row.key.clone(), row).is_none());
    }
    assert_eq!(
        subjects,
        SubjectChange::decode(&expected.datasets[0])?
            .into_iter()
            .map(|row| (row.key.clone(), row))
            .collect()
    );
    let mut edges = RelationshipChange::decode(&prior.datasets[2])?
        .into_iter()
        .map(|row| (row.key.clone(), row))
        .collect::<BTreeMap<_, _>>();
    for row in RelationshipRemoval::decode(&actual.datasets[3])? {
        assert!(edges.remove(&row.key).is_some());
    }
    for row in RelationshipChange::decode(&actual.datasets[2])? {
        assert!(edges.insert(row.key.clone(), row).is_none());
    }
    assert_eq!(
        edges,
        RelationshipChange::decode(&expected.datasets[2])?
            .into_iter()
            .map(|row| (row.key.clone(), row))
            .collect()
    );
    let mut findings = FindingChange::decode(&prior.datasets[4])?
        .into_iter()
        .map(|row| (row.finding_id.clone(), row))
        .collect::<BTreeMap<_, _>>();
    for row in FindingRemoval::decode(&actual.datasets[5])? {
        assert!(findings.remove(&row.finding_id).is_some());
    }
    for row in FindingChange::decode(&actual.datasets[4])? {
        assert!(findings.insert(row.finding_id.clone(), row).is_none());
    }
    for row in findings.values_mut() {
        row.prior_reason = None;
    }
    assert_eq!(
        findings,
        FindingChange::decode(&expected.datasets[4])?
            .into_iter()
            .map(|row| (row.finding_id.clone(), row))
            .collect()
    );
    let mut progress = Progress::decode(&prior.datasets[6])?
        .into_iter()
        .map(|row| (row.record.clone(), row))
        .collect::<BTreeMap<_, _>>();
    for row in ProgressRemoval::decode(&actual.datasets[7])? {
        assert!(progress.remove(&row.record).is_some());
    }
    for row in Progress::decode(&actual.datasets[6])? {
        assert!(progress.insert(row.record.clone(), row).is_none());
    }
    assert_eq!(
        progress,
        Progress::decode(&expected.datasets[6])?
            .into_iter()
            .map(|row| (row.record.clone(), row))
            .collect()
    );
    Ok((expected, work))
}

fn credential_input() -> sdk::Result<(Vec<Observation>, Vec<Fact>)> {
    let fixture = credential_fixture()?;
    Ok((
        Observation::decode(&fixture.evaluation.input("records")?.data)?,
        Fact::decode(&fixture.evaluation.input("facts")?.data)?,
    ))
}

#[test]
fn finding_delta_tracks_stable_anchor() -> TestResult {
    let detector = Detector::Process;
    let input = input(
        detector,
        &records(2),
        &[fact(0, context(ContextClass::OutsideAuthority))],
        100,
    )?;
    let output = detector.evaluate(&input)?;
    let finding = FindingChange::decode(&output.datasets[4])?
        .into_iter()
        .find(|finding| finding.anchor.fact.is_some())
        .ok_or("context finding")?;
    let original = finding.anchor;
    let ids = Observation::decode(&input.inputs[0].data)?
        .into_iter()
        .map(|record| record.id)
        .collect::<Vec<_>>();
    let mut facts = Fact::decode(&input.inputs[1].data)?;
    assert_eq!(original, Anchor::from_positions(0, Some(0), &ids, &facts)?);
    assert_ne!(original, Anchor::from_positions(1, Some(0), &ids, &facts)?);
    facts[0].key.owner_revision += 1;
    assert_ne!(original, Anchor::from_positions(0, Some(0), &ids, &facts)?);
    Ok(())
}

#[test]
fn late_authority_creates_finding() -> TestResult {
    let detector = Detector::Credentials;
    let (records, facts) = credential_input()?;
    let first_facts = facts
        .iter()
        .filter(|fact| fact.record == 0)
        .cloned()
        .collect::<Vec<_>>();
    let first = input(detector, &records[..1], &first_facts, 100)?;
    let prior = detector.evaluate(&first)?;
    assert_eq!(
        FindingChange::decode(&prior.datasets[4])?[0].reason_code,
        "HF-DW-001.MISSING_AUTHORITY_PROOF"
    );
    let original = FindingChange::decode(&prior.datasets[4])?.remove(0);
    let current = input(detector, &records, &facts, 100)?;
    let (output, work) = continued(detector, &current, &prior)?;
    assert_eq!(work, 2);
    let findings = FindingChange::decode(&output.datasets[4])?;
    assert!(findings.iter().any(|finding| finding == &original));
    let confirmed = findings
        .iter()
        .find(|finding| finding.anchor.record == records[2].id)
        .ok_or("authority finding")?;
    assert_eq!(confirmed.state, FindingStateV1::Confirmed);
    assert_eq!(confirmed.evidence.len(), 3);
    let mut resumed = current.clone();
    resumed.checkpoint = prior.checkpoint.clone();
    resumed.previous_outputs = normalized_prior(&prior)?;
    let delta = detector.evaluate(&resumed)?;
    assert!(FindingRemoval::decode(&delta.datasets[5])?.is_empty());
    let additions = FindingChange::decode(&delta.datasets[4])?;
    assert_eq!(additions.len(), 1);
    assert_eq!(additions[0].finding_id, confirmed.finding_id);
    assert_eq!(continued(detector, &current, &output)?.1, 0);
    Ok(())
}

#[test]
fn earlier_selected_read_rebuilds_later_finding() -> TestResult {
    let detector = Detector::Credentials;
    let (records, facts) = credential_input()?;
    let mut prior_facts = vec![facts[1].clone(), facts[2].clone()];
    prior_facts[0].record = 0;
    prior_facts[1].record = 1;
    let prior = detector.evaluate(&input(detector, &records[1..], &prior_facts, 100)?)?;
    assert!(FindingChange::decode(&prior.datasets[4])?.is_empty());
    let current = input(detector, &records, &facts, 100)?;
    let (output, work) = continued(detector, &current, &prior)?;
    assert_eq!(work, 3);
    assert!(FindingChange::decode(&output.datasets[4])?
        .iter()
        .any(|finding| {
            finding.anchor.record == records[2].id && finding.state == FindingStateV1::Confirmed
        }));
    Ok(())
}

#[test]
fn contextual_authority_needs_no_network() -> TestResult {
    let detector = Detector::Credentials;
    let (mut records, mut facts) = credential_input()?;
    records.remove(1);
    facts.retain(|fact| fact.record != 1);
    for fact in &mut facts {
        if fact.record == 2 {
            fact.record = 1;
        }
    }
    let first_facts = facts
        .iter()
        .filter(|fact| fact.record == 0)
        .cloned()
        .collect::<Vec<_>>();
    let prior = detector.evaluate(&input(detector, &records[..1], &first_facts, 100)?)?;
    let (output, work) = continued(detector, &input(detector, &records, &facts, 100)?, &prior)?;
    assert_eq!(work, 1);
    let findings = FindingChange::decode(&output.datasets[4])?;
    assert_eq!(
        findings
            .iter()
            .find(|finding| finding.anchor.record == records[1].id)
            .ok_or("contextual authority finding")?
            .reason_code,
        "HF-DW-001.CONTEXTUAL_CREDENTIAL_PIVOT"
    );
    Ok(())
}

#[test]
fn retained_state_survives_update() -> TestResult {
    let detector = Detector::Credentials;
    let (base, facts) = credential_input()?;
    let mut later = base[0].clone();
    later.id = identity(3);
    later.position.ordinal = 3;
    later.observed_boottime_ns = 1_000;
    later.ingested_utc_ns = 1_000;
    let old_records = vec![base[0].clone(), later.clone()];
    let mut old_facts = facts
        .iter()
        .filter(|fact| fact.record == 0)
        .cloned()
        .collect::<Vec<_>>();
    let mut later_credential = facts[0].clone();
    later_credential.record = 1;
    old_facts.push(later_credential);
    let prior = detector.evaluate(&input(detector, &old_records, &old_facts, 100)?)?;
    let mut current_records = base;
    current_records[1].position = Position {
        commit_revision: 2,
        ordinal: 0,
    };
    current_records[2].position = Position {
        commit_revision: 2,
        ordinal: 1,
    };
    current_records.push(later);
    let mut current_facts = facts;
    let mut later_fact = old_facts.last().ok_or("later credential")?.clone();
    later_fact.record = 3;
    current_facts.push(later_fact);
    let (output, work) = continued(
        detector,
        &input(detector, &current_records, &current_facts, 100)?,
        &prior,
    )?;
    assert_eq!(work, 2);
    assert_eq!(
        package_state(&output)?,
        GraphPackageStateV1::CoverageInsufficient
    );
    assert!(FindingChange::decode(&output.datasets[4])?
        .iter()
        .any(|finding| finding.state == FindingStateV1::Confirmed));
    Ok(())
}

#[test]
fn new_network_creates_finding() -> TestResult {
    let detector = Detector::Credentials;
    let (records, facts) = credential_input()?;
    let old_records = [records[0].clone(), records[2].clone()];
    let mut old_facts = facts.clone();
    old_facts.remove(1);
    old_facts[1].record = 1;
    let prior = detector.evaluate(&input(detector, &old_records, &old_facts, 100)?)?;
    assert_eq!(
        FindingChange::decode(&prior.datasets[4])?[0].reason_code,
        "HF-DW-001.CONTEXTUAL_CREDENTIAL_PIVOT"
    );
    let original = FindingChange::decode(&prior.datasets[4])?.remove(0);
    let mut network = records[1].clone();
    network.id = identity(3);
    network.position = Position {
        commit_revision: 2,
        ordinal: 0,
    };
    network.ingested_utc_ns = records[2].ingested_utc_ns + 1;
    let current_records = [records[0].clone(), records[2].clone(), network.clone()];
    let mut current_facts = facts.clone();
    current_facts[1].record = 2;
    current_facts[2].record = 1;
    let mut current = input(detector, &current_records, &current_facts, 100)?;
    for input in &mut current.inputs[..2] {
        let batch = input.data.batches.remove(0);
        input.data.batches = vec![batch.slice(0, 1), batch.slice(1, batch.num_rows() - 1)];
    }
    let (output, work) = continued(detector, &current, &prior)?;
    assert_eq!(work, 1);
    let mut resumed = current.clone();
    resumed.checkpoint = prior.checkpoint.clone();
    resumed.previous_outputs = normalized_prior(&prior)?;
    let delta = detector.evaluate(&resumed)?;
    assert!(FindingRemoval::decode(&delta.datasets[5])?.is_empty());
    let additions = FindingChange::decode(&delta.datasets[4])?;
    assert_eq!(additions.len(), 1);
    assert_ne!(additions[0].finding_id, original.finding_id);
    assert_eq!(additions[0].anchor.record, network.id);
    let retained = FindingChange::decode(&output.datasets[4])?;
    assert!(retained.iter().any(|finding| finding == &original));
    assert_eq!(additions[0].state, FindingStateV1::Confirmed);
    Ok(())
}

#[test]
fn network_finding_uses_its_own_channel() -> TestResult {
    let detector = Detector::Credentials;
    let (mut records, mut facts) = credential_input()?;
    let prior = detector.evaluate(&input(detector, &records, &facts, 100)?)?;
    let prior_findings = FindingChange::decode(&prior.datasets[4])?;
    let mut network = records[1].clone();
    network.id = identity(3);
    network.position.ordinal = 3;
    network.observed_boottime_ns = 13;
    network.ingested_utc_ns = 13;
    records.push(network.clone());
    let mut channel = facts[1].clone();
    channel.record = 3;
    channel.key.entity_key = 3_u32.to_be_bytes().to_vec();
    if let FactValue::Channel {
        carried_request_id, ..
    } = &mut channel.value
    {
        *carried_request_id = "other-request".into();
    }
    facts.push(channel);
    let current = input(detector, &records, &facts, 100)?;
    let (full, work) = continued(detector, &current, &prior)?;
    assert_eq!(work, 1);
    let full_findings = FindingChange::decode(&full.datasets[4])?;
    assert!(prior_findings
        .iter()
        .all(|prior| full_findings.contains(prior)));
    let mut resumed = current;
    resumed.checkpoint = prior.checkpoint.clone();
    resumed.previous_outputs = normalized_prior(&prior)?;
    let delta = detector.evaluate(&resumed)?;
    assert!(FindingRemoval::decode(&delta.datasets[5])?.is_empty());
    let additions = FindingChange::decode(&delta.datasets[4])?;
    assert_eq!(additions.len(), 1);
    assert_eq!(additions[0].anchor.record, network.id);
    assert_eq!(
        additions[0].reason_code,
        "HF-DW-001.CONTEXTUAL_CREDENTIAL_PIVOT"
    );
    assert_ne!(additions[0].state, FindingStateV1::Confirmed);
    assert_eq!(
        additions[0].evidence,
        [identity(0), identity(2), identity(3)]
    );
    let edges = RelationshipChange::decode(&delta.datasets[2])?;
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].key.cause, GraphCauseV1::Contextual);
    assert_eq!(edges[0].key.evidence, additions[0].evidence);
    Ok(())
}

#[test]
fn cross_cpu_events_keep_earlier_findings() -> TestResult {
    let detector = Detector::Credentials;
    for positions in [
        [(1, 0), (2, 0), (3, 0), (4, 0)],
        [(10, 0), (10, 1), (10, 2), (10, 3)],
    ] {
        let (mut records, mut facts) = credential_input()?;
        for (row, record) in records.iter_mut().enumerate() {
            record.id.cpu_id = u32::from(row != 0);
            record.id.durable_cursor = if row == 0 { 100 } else { row as u64 };
            record.position = Position {
                commit_revision: positions[row].0,
                ordinal: positions[row].1,
            };
            record.ingested_utc_ns = if row == 2 { 19 } else { 20 };
        }
        if let FactValue::Credential {
            completion: Some(completion),
            ..
        } = &mut facts[0].value
        {
            completion.admission_record = records[0].id.clone();
        }
        if let FactValue::Policy(policy) = &mut facts[3].value {
            policy.observations = vec![records[0].id.clone()];
        }
        let first_facts = facts
            .iter()
            .filter(|fact| fact.record == 0)
            .cloned()
            .collect::<Vec<_>>();
        let prior = detector.evaluate(&input_exact(detector, &records[..1], &first_facts)?)?;
        let original = FindingChange::decode(&prior.datasets[4])?.remove(0);
        let full = input_exact(detector, &records, &facts)?;
        let (output, work) = continued(detector, &full, &prior)?;
        assert_eq!(work, 2);
        let findings = FindingChange::decode(&output.datasets[4])?;
        assert!(findings.iter().any(|finding| finding == &original));
        let remote = findings
            .iter()
            .find(|finding| finding.anchor.record == records[2].id)
            .ok_or("remote finding")?;
        assert_eq!(remote.state, FindingStateV1::Confirmed);

        let mut later = records[1].clone();
        later.id.durable_cursor = 3;
        later.position = Position {
            commit_revision: positions[3].0,
            ordinal: positions[3].1,
        };
        later.ingested_utc_ns = 18;
        let mut channel = facts[1].clone();
        channel.record = 3;
        channel.key.entity_key = later.id.durable_cursor.to_be_bytes().to_vec();
        let mut next_records = records.clone();
        next_records.push(later.clone());
        let mut next_facts = facts.clone();
        next_facts.push(channel);
        let current = input_exact(detector, &next_records, &next_facts)?;
        let (next, next_work) = continued(detector, &current, &output)?;
        assert_eq!(next_work, 1);
        let next_findings = FindingChange::decode(&next.datasets[4])?;
        assert!(next_findings.iter().any(|finding| finding == &original));
        assert!(next_findings.iter().any(|finding| finding == remote));
        let network = next_findings
            .iter()
            .find(|finding| finding.anchor.record == later.id)
            .ok_or("new network finding")?;
        assert_eq!(network.state, FindingStateV1::Confirmed);
        assert_ne!(network.finding_id, remote.finding_id);
    }
    Ok(())
}

#[test]
fn authority_event_detects_conflict_across_reads() -> TestResult {
    let detector = Detector::Credentials;
    let (base, facts) = credential_input()?;
    let mut second = base[0].clone();
    second.id = identity(1);
    second.position.ordinal = 1;
    second.effect.task_cookie = 4;
    second.effect.execution_set_id = vec![9; 16];
    second.process_instance_id = Some([8; 16]);
    let mut remote = base[2].clone();
    remote.position.ordinal = 2;
    let mut second_credential = facts[0].clone();
    second_credential.record = 1;
    second_credential.key.entity_key = 1_u32.to_be_bytes().to_vec();
    if let FactValue::Credential { completion, .. } = &mut second_credential.value {
        *completion = None;
    }
    let mut success = facts[2].clone();
    success.record = 2;
    let mut denied = success.clone();
    denied.key.owner_revision += 1;
    if let FactValue::AuthorityUse {
        workload_binding,
        proof_quality,
        ..
    } = &mut denied.value
    {
        *workload_binding = Some(subject(GraphSubjectKindV1::ExecutionSet, vec![9; 16]));
        proof_quality.operation_result_authority = OperationResultAuthorityV1::AuthoritativeDenied;
    }
    let evaluation = input(
        detector,
        &[base[0].clone(), second, remote.clone()],
        &[facts[0].clone(), second_credential, success, denied],
        100,
    )?;
    let output = detector.evaluate(&evaluation)?;
    let findings = FindingChange::decode(&output.datasets[4])?;
    assert_eq!(findings.len(), 3);
    assert!(findings.iter().any(|finding| {
        finding.anchor.record == remote.id
            && finding.reason_code == "HF-DW-001.CONTRADICTION"
            && finding.state == FindingStateV1::CoverageInsufficient
    }));
    assert!(RelationshipChange::decode(&output.datasets[2])?
        .iter()
        .all(|edge| edge.key.cause == GraphCauseV1::Contradicted));
    Ok(())
}

#[test]
fn shared_edges_update_seeds() -> TestResult {
    let detector = Detector::Credentials;
    let (base, facts) = credential_input()?;
    let mut second = base[0].clone();
    second.id = identity(1);
    second.position.ordinal = 1;
    let mut network = base[1].clone();
    network.id = identity(2);
    network.position.ordinal = 2;
    let mut records = vec![base[0].clone(), second, network];
    let mut selected = vec![facts[0].clone()];
    let mut credential = facts[0].clone();
    credential.record = 1;
    if let FactValue::Credential {
        completion: Some(completion),
        ..
    } = &mut credential.value
    {
        completion.admission_record = identity(1);
    }
    selected.push(credential);
    let mut channel = facts[1].clone();
    channel.record = 2;
    selected.push(channel);
    for row in 0..2 {
        let mut authority = facts[2].clone();
        authority.record = row;
        selected.push(authority);
        let mut policy = facts[3].clone();
        policy.record = row;
        if let FactValue::Policy(policy) = &mut policy.value {
            policy.observations = vec![identity(u64::from(row))];
        }
        selected.push(policy);
    }
    let prior = detector.evaluate(&input(detector, &records, &selected, 100)?)?;
    let edges = RelationshipChange::decode(&prior.datasets[2])?;
    assert_eq!(
        edges
            .iter()
            .filter(|edge| edge.key.evidence == [identity(0), identity(1), identity(2)])
            .count(),
        1
    );
    let original_findings = FindingChange::decode(&prior.datasets[4])?;
    assert_eq!(original_findings.len(), 3);
    let remaining = records[1..].to_vec();
    let remaining_facts = selected
        .iter()
        .filter(|fact| fact.record != 0)
        .cloned()
        .map(|mut fact| {
            fact.record -= 1;
            fact
        })
        .collect::<Vec<_>>();
    let (expired, work) = continued(
        detector,
        &input(detector, &remaining, &remaining_facts, 100)?,
        &prior,
    )?;
    assert_eq!(work, 2);
    assert_eq!(
        RelationshipChange::decode(&expired.datasets[2])?
            .iter()
            .filter(|edge| edge.key.evidence == [identity(1), identity(2)])
            .count(),
        1
    );
    let mut denied = base[2].clone();
    denied.id = identity(3);
    denied.position.ordinal = 3;
    records.push(denied);
    let mut authority = facts[2].clone();
    authority.record = 3;
    if let FactValue::AuthorityUse { proof_quality, .. } = &mut authority.value {
        proof_quality.operation_result_authority = OperationResultAuthorityV1::AuthoritativeDenied;
    }
    selected.push(authority);
    let (output, work) = continued(
        detector,
        &input(detector, &records, &selected, 100)?,
        &prior,
    )?;
    assert_eq!(work, 1);
    let findings = FindingChange::decode(&output.datasets[4])?;
    assert_eq!(findings.len(), 4);
    assert!(original_findings
        .iter()
        .all(|finding| findings.contains(finding)));
    assert!(findings.iter().any(|finding| {
        finding.anchor.record == records[3].id && finding.reason_code == "HF-DW-001.CONTRADICTION"
    }));
    assert!(RelationshipChange::decode(&output.datasets[2])?
        .iter()
        .any(|edge| edge.key.cause == GraphCauseV1::Contradicted));
    Ok(())
}

#[test]
fn suppressed_finding_keeps_state() -> TestResult {
    let detector = Detector::Credentials;
    let (mut records, mut facts) = credential_input()?;
    let mut unreviewed = facts[0].clone();
    unreviewed.key.owner_revision += 1;
    if let FactValue::Credential {
        reviewed_policy_revision,
        ..
    } = &mut unreviewed.value
    {
        *reviewed_policy_revision = "missing".into();
    }
    facts.push(unreviewed);
    let prior = detector.evaluate(&input(detector, &records, &facts, 100)?)?;
    assert!(FindingChange::decode(&prior.datasets[4])?
        .iter()
        .any(|finding| finding.anchor.record == records[2].id
            && finding.reason_code == "HF-DW-001.CONTEXTUAL_CREDENTIAL_PIVOT"
            && finding.state == FindingStateV1::CoverageInsufficient));
    assert_eq!(package_state(&prior)?, GraphPackageStateV1::ContextualPivot);
    let mut added = record();
    added.id = identity(3);
    added.position.ordinal = 3;
    added.observed_boottime_ns = 1_000;
    records.push(added);
    let (_, work) = continued(detector, &input(detector, &records, &facts, 100)?, &prior)?;
    assert_eq!(work, 1);
    Ok(())
}

#[test]
fn merged_edge_keeps_anchor() -> TestResult {
    let detector = Detector::Credentials;
    let (base, facts) = credential_input()?;
    let mut records = vec![base[0].clone(), base[1].clone(), base[1].clone()];
    records[2].id = identity(2);
    records[2].position.ordinal = 2;
    let mut denied = facts[2].clone();
    if let FactValue::AuthorityUse { proof_quality, .. } = &mut denied.value {
        proof_quality.operation_result_authority = OperationResultAuthorityV1::AuthoritativeDenied;
        proof_quality.remote_subject_binding = RemoteSubjectBindingV1::Contextual;
    }
    let mut channel = facts[1].clone();
    channel.record = 2;
    let mut succeeded = facts[2].clone();
    succeeded.record = 1;
    let selected = vec![
        denied,
        facts[0].clone(),
        facts[1].clone(),
        channel,
        succeeded,
        facts[3].clone(),
    ];
    let old_facts = selected
        .iter()
        .filter(|fact| fact.record != 2)
        .cloned()
        .collect::<Vec<_>>();
    let prior = detector.evaluate(&input(detector, &records[..2], &old_facts, 100)?)?;
    let (output, work) = continued(
        detector,
        &input(detector, &records, &selected, 100)?,
        &prior,
    )?;
    assert_eq!(work, 1);
    let edges = RelationshipChange::decode(&output.datasets[2])?;
    assert_eq!(edges.len(), 3);
    assert!(RelationshipChange::decode(&prior.datasets[2])?
        .iter()
        .all(|original| edges.contains(original)));
    assert_eq!(
        edges
            .iter()
            .filter(|edge| edge.key.cause == GraphCauseV1::Contradicted)
            .count(),
        2
    );
    let ids = records
        .iter()
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    let anchor = Anchor::from_positions(0, Some(4), &ids, &selected)?;
    let edge = edges
        .iter()
        .find(|edge| edge.anchor == anchor && edge.key.cause == GraphCauseV1::Contradicted)
        .ok_or("contradicted edge")?;
    assert_eq!(edge.key.evidence, [identity(0), identity(1), identity(2)]);
    assert_eq!(edge.key.cause, GraphCauseV1::Contradicted);
    assert_eq!(edge.anchor, anchor);
    let FactValue::AuthorityUse { proof_quality, .. } = selected[4].value else {
        return Err("authority fixture".into());
    };
    assert_eq!(edge.proof_quality, proof_quality);
    let denied_anchor = Anchor::from_positions(0, Some(0), &ids, &selected)?;
    let denied_edge = edges
        .iter()
        .find(|edge| edge.anchor == denied_anchor && edge.key.cause == GraphCauseV1::Contradicted)
        .ok_or("denied edge")?;
    let FactValue::AuthorityUse { proof_quality, .. } = selected[0].value else {
        return Err("denied authority fixture".into());
    };
    assert_eq!(denied_edge.proof_quality, proof_quality);
    Ok(())
}
