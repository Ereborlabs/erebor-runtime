use super::*;

mod state;

fn input(
    detector: Detector,
    records: &[Observation],
    facts: &[Fact],
    window: u64,
) -> sdk::Result<sdk::Evaluation> {
    let mut evaluation = fixture(detector, records, facts)?.evaluation;
    let mut units = UnitFixture::units(detector, records, facts);
    for unit in &mut units {
        unit.window_ns = window;
    }
    evaluation.inputs[0].data = Unit::encode(&units)?;
    evaluation.inputs[3].data = Observation::encode(records)?;
    evaluation.inputs[4].data = Fact::encode(facts)?;
    evaluation.inputs[5].data = Unit::encode_affected(
        &records
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>(),
    )?;
    evaluation.inputs[6].data = Unit::window_data(
        &records
            .first()
            .map_or_else(|| identity(0).stream, |record| record.id.stream.clone())
            .key(),
        records.first().map_or(1, |record| record.id.durable_cursor),
        u64::MAX,
        false,
    )?;
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
    let finding = FindingChange::decode(UnitFixture::data(&output, "findings")?)?
        .into_iter()
        .find(|finding| finding.anchor.fact.is_some())
        .ok_or("context finding")?;
    let original = finding.anchor;
    let ids = Observation::decode(&input.input("records")?.data)?
        .into_iter()
        .map(|record| record.id)
        .collect::<Vec<_>>();
    let mut facts = Fact::decode(&input.input("facts")?.data)?;
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
        FindingChange::decode(UnitFixture::data(&prior, "findings")?)?[0].reason_code,
        "HF-DW-001.MISSING_AUTHORITY_PROOF"
    );
    let original = FindingChange::decode(UnitFixture::data(&prior, "findings")?)?.remove(0);
    let current = input(detector, &records, &facts, 100)?;
    let output = detector.evaluate(&current)?;
    let findings = FindingChange::decode(UnitFixture::data(&output, "findings")?)?;
    assert!(findings.iter().any(|finding| finding == &original));
    let confirmed = findings
        .iter()
        .find(|finding| finding.anchor.record == records[2].id)
        .ok_or("authority finding")?;
    assert_eq!(confirmed.state, FindingStateV1::Confirmed);
    assert_eq!(confirmed.evidence.len(), 3);
    let mut selected = UnitFixture::units(detector, &records, &facts);
    selected.retain(|unit| unit.record != records[0].id);
    let delta = UnitFixture::run(detector, &records, &facts, &selected)?;
    let additions = FindingChange::decode(UnitFixture::data(&delta, "findings")?)?;
    assert_eq!(additions.len(), 1);
    assert_eq!(additions[0].finding_id, confirmed.finding_id);
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
    assert!(FindingChange::decode(UnitFixture::data(&prior, "findings")?)?.is_empty());
    let current = input(detector, &records, &facts, 100)?;
    let output = detector.evaluate(&current)?;
    assert!(
        FindingChange::decode(UnitFixture::data(&output, "findings")?)?
            .iter()
            .any(|finding| {
                finding.anchor.record == records[2].id && finding.state == FindingStateV1::Confirmed
            })
    );
    let narrow = detector.evaluate(&input(detector, &records, &facts, 1)?)?;
    let narrow_findings = FindingChange::decode(UnitFixture::data(&narrow, "findings")?)?;
    let read = narrow_findings
        .iter()
        .find(|finding| finding.anchor.record == records[0].id)
        .ok_or("narrow-window read finding")?;
    assert_eq!(read.reason_code, "HF-DW-001.MISSING_AUTHORITY_PROOF");
    assert_eq!(read.state, FindingStateV1::CoverageInsufficient);
    assert_eq!(read.evidence, [records[0].id.clone()]);
    assert!(narrow_findings
        .iter()
        .all(|finding| finding.state != FindingStateV1::Confirmed));
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
    assert_eq!(
        FindingChange::decode(UnitFixture::data(&prior, "findings")?)?[0].reason_code,
        "HF-DW-001.MISSING_AUTHORITY_PROOF"
    );
    let output = detector.evaluate(&input(detector, &records, &facts, 100)?)?;
    let findings = FindingChange::decode(UnitFixture::data(&output, "findings")?)?;
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
    later_credential.key.entity_key = 4_u64.to_be_bytes().to_vec();
    old_facts.push(later_credential);
    let prior = detector.evaluate(&input(detector, &old_records, &old_facts, 100)?)?;
    let state = Contribution::decode(UnitFixture::data(&prior, "contributions")?)?
        .into_iter()
        .find(|unit| unit.record == old_records[1].id)
        .and_then(|unit| unit.state)
        .ok_or("later read state")?;
    assert_eq!(state.state, GraphPackageStateV1::CoverageInsufficient);
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
    let output = detector.evaluate(&input(detector, &current_records, &current_facts, 100)?)?;
    assert_eq!(
        Contribution::decode(UnitFixture::data(&output, "contributions")?)?
            .into_iter()
            .find(|unit| unit.record == current_records[3].id)
            .and_then(|unit| unit.state),
        Some(state)
    );
    assert!(
        FindingChange::decode(UnitFixture::data(&output, "findings")?)?
            .iter()
            .any(|finding| finding.state == FindingStateV1::Confirmed)
    );
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
    let original = FindingChange::decode(UnitFixture::data(&prior, "findings")?)?
        .into_iter()
        .find(|finding| finding.anchor.record == old_records[1].id)
        .ok_or("prior authority finding")?;
    assert_eq!(
        original.reason_code,
        "HF-DW-001.CONTEXTUAL_CREDENTIAL_PIVOT"
    );
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
    for input in &mut current.inputs[3..5] {
        let batch = input.data.batches.remove(0);
        input.data.batches = vec![batch.slice(0, 1), batch.slice(1, batch.num_rows() - 1)];
    }
    let output = detector.evaluate(&current)?;
    let mut selected = UnitFixture::units(detector, &current_records, &current_facts);
    selected.retain(|unit| unit.record == network.id);
    let delta = UnitFixture::run(detector, &current_records, &current_facts, &selected)?;
    let additions = FindingChange::decode(UnitFixture::data(&delta, "findings")?)?;
    assert_eq!(additions.len(), 1);
    assert_ne!(additions[0].finding_id, original.finding_id);
    assert_eq!(additions[0].anchor.record, network.id);
    let retained = FindingChange::decode(UnitFixture::data(&output, "findings")?)?;
    assert!(retained.iter().any(|finding| finding == &original));
    assert_eq!(additions[0].state, FindingStateV1::Confirmed);
    Ok(())
}

#[test]
fn network_finding_uses_its_own_channel() -> TestResult {
    let detector = Detector::Credentials;
    let (mut records, mut facts) = credential_input()?;
    let prior = detector.evaluate(&input(detector, &records, &facts, 100)?)?;
    let prior_findings = FindingChange::decode(UnitFixture::data(&prior, "findings")?)?;
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
    let full = detector.evaluate(&current)?;
    let full_findings = FindingChange::decode(UnitFixture::data(&full, "findings")?)?;
    assert!(prior_findings
        .iter()
        .all(|prior| full_findings.contains(prior)));
    let mut selected = UnitFixture::units(detector, &records, &facts);
    selected.retain(|unit| unit.record == network.id);
    let delta = UnitFixture::run(detector, &records, &facts, &selected)?;
    let additions = FindingChange::decode(UnitFixture::data(&delta, "findings")?)?;
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
    let edges = RelationshipChange::decode(UnitFixture::data(&delta, "relationships")?)?;
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
        let prior = detector.evaluate(&input(detector, &records[..1], &first_facts, 100)?)?;
        let original = FindingChange::decode(UnitFixture::data(&prior, "findings")?)?.remove(0);
        let full = input(detector, &records, &facts, 100)?;
        let output = detector.evaluate(&full)?;
        let findings = FindingChange::decode(UnitFixture::data(&output, "findings")?)?;
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
        channel.key.entity_key = 4_u64.to_be_bytes().to_vec();
        let mut next_records = records.clone();
        next_records.push(later.clone());
        let mut next_facts = facts.clone();
        next_facts.push(channel);
        let current = input(detector, &next_records, &next_facts, 100)?;
        let next = detector.evaluate(&current)?;
        let next_findings = FindingChange::decode(UnitFixture::data(&next, "findings")?)?;
        assert!(next_findings.iter().any(|finding| finding == &original));
        assert!(next_findings.iter().any(|finding| finding == remote));
        let network = next_findings
            .iter()
            .find(|finding| finding.anchor.record == later.id)
            .ok_or("new network finding")?;
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
    let findings = FindingChange::decode(UnitFixture::data(&output, "findings")?)?;
    assert_eq!(findings.len(), 3);
    assert!(findings.iter().any(|finding| {
        finding.anchor.record == remote.id
            && finding.reason_code == "HF-DW-001.CONTRADICTION"
            && finding.state == FindingStateV1::CoverageInsufficient
    }));
    assert!(
        RelationshipChange::decode(UnitFixture::data(&output, "relationships")?)?
            .iter()
            .all(|edge| edge.key.cause == GraphCauseV1::Contradicted)
    );
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
    UnitFixture::keys(&mut selected);
    let prior = detector.evaluate(&input(detector, &records, &selected, 100)?)?;
    let edges = RelationshipChange::decode(UnitFixture::data(&prior, "relationships")?)?;
    let network = Contribution::decode(UnitFixture::data(&prior, "contributions")?)?
        .into_iter()
        .find(|unit| unit.record == records[2].id)
        .ok_or("network unit")?;
    assert_eq!(
        network
            .relationships
            .iter()
            .filter(
                |row| edges[**row as usize].key.evidence == [identity(0), identity(1), identity(2)]
            )
            .count(),
        1
    );
    let original_findings = FindingChange::decode(UnitFixture::data(&prior, "findings")?)?;
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
    let expired = detector.evaluate(&input(detector, &remaining, &remaining_facts, 100)?)?;
    let network = Contribution::decode(UnitFixture::data(&expired, "contributions")?)?
        .into_iter()
        .find(|unit| unit.record == records[2].id)
        .ok_or("surviving network unit")?;
    let edges = RelationshipChange::decode(UnitFixture::data(&expired, "relationships")?)?;
    assert_eq!(
        network
            .relationships
            .iter()
            .filter(|row| edges[**row as usize].key.evidence == [identity(1), identity(2)])
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
    authority.key.entity_key = (selected.len() as u64).to_be_bytes().to_vec();
    selected.push(authority);
    let output = detector.evaluate(&input(detector, &records, &selected, 100)?)?;
    let findings = FindingChange::decode(UnitFixture::data(&output, "findings")?)?;
    assert_eq!(findings.len(), 4);
    assert!(original_findings
        .iter()
        .all(|finding| findings.contains(finding)));
    assert!(findings.iter().any(|finding| {
        finding.anchor.record == records[3].id && finding.reason_code == "HF-DW-001.CONTRADICTION"
    }));
    assert!(
        RelationshipChange::decode(UnitFixture::data(&output, "relationships")?)?
            .iter()
            .any(|edge| edge.key.cause == GraphCauseV1::Contradicted)
    );
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
    assert!(
        FindingChange::decode(UnitFixture::data(&prior, "findings")?)?
            .iter()
            .any(|finding| finding.anchor.record == records[2].id
                && finding.reason_code == "HF-DW-001.CONTEXTUAL_CREDENTIAL_PIVOT"
                && finding.state == FindingStateV1::CoverageInsufficient)
    );
    assert_eq!(
        Contribution::decode(UnitFixture::data(&prior, "contributions")?)?
            .into_iter()
            .find(|unit| unit.record == records[2].id)
            .and_then(|unit| unit.state)
            .map(|state| state.state),
        Some(GraphPackageStateV1::ContextualPivot)
    );
    let mut added = record();
    added.id = identity(3);
    added.position.ordinal = 3;
    added.observed_boottime_ns = 1_000;
    records.push(added);
    let output = detector.evaluate(&input(detector, &records, &facts, 100)?)?;
    assert_eq!(
        Contribution::decode(UnitFixture::data(&output, "contributions")?)?
            .into_iter()
            .find(|unit| unit.record == records[2].id)
            .and_then(|unit| unit.state)
            .map(|state| state.state),
        Some(GraphPackageStateV1::ContextualPivot)
    );
    assert!(
        FindingChange::decode(UnitFixture::data(&output, "findings")?)?
            .iter()
            .any(|finding| finding.anchor.record == records[2].id
                && finding.reason_code == "HF-DW-001.CONTEXTUAL_CREDENTIAL_PIVOT"
                && finding.state == FindingStateV1::CoverageInsufficient)
    );
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
    let mut selected = vec![
        denied,
        facts[0].clone(),
        facts[1].clone(),
        channel,
        succeeded,
        facts[3].clone(),
    ];
    UnitFixture::keys(&mut selected);
    let old_facts = selected
        .iter()
        .filter(|fact| fact.record != 2)
        .cloned()
        .collect::<Vec<_>>();
    let prior = detector.evaluate(&input(detector, &records[..2], &old_facts, 100)?)?;
    let output = detector.evaluate(&input(detector, &records, &selected, 100)?)?;
    let all_edges = RelationshipChange::decode(UnitFixture::data(&output, "relationships")?)?;
    let contributions = Contribution::decode(UnitFixture::data(&output, "contributions")?)?;
    let owner = contributions
        .iter()
        .find(|unit| unit.record == records[2].id)
        .ok_or("new network unit")?;
    let edges = owner
        .relationships
        .iter()
        .map(|row| &all_edges[*row as usize])
        .collect::<Vec<_>>();
    assert_eq!(all_edges.len(), 3);
    assert_eq!(edges.len(), 2);
    let previous_edges = RelationshipChange::decode(UnitFixture::data(&prior, "relationships")?)?;
    let previous = Contribution::decode(UnitFixture::data(&prior, "contributions")?)?
        .into_iter()
        .find(|unit| unit.record == records[1].id)
        .ok_or("old network unit")?;
    let retained = contributions
        .iter()
        .find(|unit| unit.record == records[1].id)
        .ok_or("retained network unit")?;
    assert_eq!(
        previous
            .relationships
            .iter()
            .map(|row| &previous_edges[*row as usize])
            .collect::<Vec<_>>(),
        retained
            .relationships
            .iter()
            .map(|row| &all_edges[*row as usize])
            .collect::<Vec<_>>()
    );
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
