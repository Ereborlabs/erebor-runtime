use super::*;

#[test]
fn insertions_rebind_native_rows() -> TestResult {
    for detector in [Detector::Process, Detector::Kubernetes] {
        let mut old = records(2);
        for record in &mut old {
            record.id.cpu_id = 1;
        }
        let value = match detector {
            Detector::Process => context(ContextClass::OutsideAuthority),
            Detector::Kubernetes => FactValue::Kubernetes(KubernetesStageProofV1 {
                cluster_id: "cluster".into(),
                carried_request_id: None,
                audit_id: None,
                object_uid: Some("object".into()),
                resource_version: Some("1".into()),
                owner_uid: None,
                pod_uid: None,
                node_id: None,
                full_container_id: None,
                remote_admission_id: None,
                proof_quality: proof(),
            }),
            Detector::Credentials => return Err("detector fixture".into()),
        };
        let mut old_facts = vec![
            fact(0, value.clone()),
            fact(1, value.clone()),
            fact(0, value.clone()),
        ];
        UnitFixture::keys(&mut old_facts);
        let prior = detector.evaluate(&input(detector, &old, &old_facts, 100)?)?;
        assert_eq!(
            Contribution::decode(UnitFixture::data(&prior, "contributions")?)?.len(),
            2
        );
        let mut added = record();
        added.observed_boottime_ns = 12;
        added.position.commit_revision = 2;
        let current = vec![added, old[0].clone(), old[1].clone()];
        let mut added_fact = fact(0, value);
        if let FactValue::Kubernetes(stage) = &mut added_fact.value {
            stage.node_id = Some("worker".into());
        }
        added_fact.key.entity_key = 3_u64.to_be_bytes().to_vec();
        let mut current_facts = vec![added_fact];
        for mut fact in old_facts {
            fact.record += 1;
            current_facts.push(fact);
        }
        let evaluation = input(detector, &current, &current_facts, 100)?;
        let output = detector.evaluate(&evaluation)?;
        let subjects = SubjectChange::decode(UnitFixture::data(&output, "subjects")?)?;
        let contributions = Contribution::decode(UnitFixture::data(&output, "contributions")?)?;
        assert_eq!(contributions.len(), current.len());
        for contribution in &contributions {
            assert_eq!(
                contribution.subjects.len(),
                if matches!(detector, Detector::Process) {
                    5
                } else {
                    2
                }
            );
            for &row in &contribution.subjects {
                assert_eq!(subjects[row as usize].anchor.record, contribution.record);
            }
        }
        if matches!(detector, Detector::Process) {
            let expected = Anchor::from_positions(
                1,
                Some(3),
                &current.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
                &current_facts,
            )?;
            assert!(
                FindingChange::decode(UnitFixture::data(&output, "findings")?)?
                    .iter()
                    .any(|finding| finding.anchor == expected)
            );
        } else {
            assert!(
                RelationshipChange::decode(UnitFixture::data(&output, "relationships")?)?
                    .iter()
                    .any(|edge| edge.anchor.record == current[1].id && edge.anchor.fact.is_some())
            );
            for unit in &contributions {
                let expected = if unit.record == current[0].id {
                    GraphPackageStateV1::KubernetesScheduled
                } else {
                    GraphPackageStateV1::KubernetesObject
                };
                assert_eq!(
                    unit.state.as_ref().map(|state| &state.state),
                    Some(&expected)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn inserted_state_keeps_last() -> TestResult {
    let detector = Detector::Process;
    let mut old = records(2);
    old[1].id.durable_cursor = 3;
    let prior = detector.evaluate(&input(detector, &old, &[], 100)?)?;
    assert!(
        Contribution::decode(UnitFixture::data(&prior, "contributions")?)?
            .iter()
            .all(|unit| unit
                .state
                .as_ref()
                .is_some_and(|state| state.state == GraphPackageStateV1::NativeEffect))
    );
    let mut added = record();
    added.id = identity(1);
    added.position.ordinal = 2;
    let policy = PolicyObservationProvenanceV1 {
        source: added.id.stream.clone(),
        profile_generation_ref_id: 1,
        observations: vec![added.id.clone()],
        policy_source_revision_id: Some("review".into()),
        candidate_content_id: Some("candidate".into()),
        target_snapshot_digest: Some("target".into()),
        node_bound_generation_digest: Some("generation".into()),
        activation_acknowledgement: None,
        state: PolicyProvenanceStateV1::Contradicted,
        limits: vec!["POLICY_PROVENANCE_CONTRADICTED".into()],
    };
    let current = [old[0].clone(), added, old[1].clone()];
    let output = detector.evaluate(&input(
        detector,
        &current,
        &[fact(1, FactValue::Policy(policy))],
        100,
    )?)?;
    let contributions = Contribution::decode(UnitFixture::data(&output, "contributions")?)?;
    assert_eq!(
        contributions
            .iter()
            .map(|unit| unit.record.clone())
            .collect::<Vec<_>>(),
        current
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        contributions
            .iter()
            .map(|unit| unit
                .state
                .as_ref()
                .map(|state| (state.state.clone(), state.position)))
            .collect::<Vec<_>>(),
        [
            Some((GraphPackageStateV1::NativeEffect, current[0].position)),
            Some((GraphPackageStateV1::Contradicted, current[1].position)),
            Some((GraphPackageStateV1::NativeEffect, current[2].position)),
        ]
    );
    assert_eq!(
        GraphPackageStateV1::decode(UnitFixture::data(&output, "state")?)?,
        [GraphPackageStateV1::Waiting]
    );
    assert!(
        FindingChange::decode(UnitFixture::data(&output, "findings")?)?
            .iter()
            .any(|finding| finding.anchor.record == current[1].id
                && finding.reason_code == "HF-PROC-001.CONTRADICTION")
    );
    Ok(())
}

#[test]
fn restricted_fact_updates_findings() -> TestResult {
    let detector = Detector::Process;
    let old = records(2);
    let prior = detector.evaluate(&input(detector, &old, &[], 100)?)?;
    let previous = FindingChange::decode(UnitFixture::data(&prior, "findings")?)?;
    assert!(previous
        .iter()
        .all(|finding| finding.sensitivity == ContextSensitivityV1::Tenant));
    let mut added = fact(2, context(ContextClass::OutsideAuthority));
    added.sensitivity = ContextSensitivityV1::HostRestricted;
    let output = detector.evaluate(&input(detector, &records(3), &[added], 100)?)?;
    let findings = FindingChange::decode(UnitFixture::data(&output, "findings")?)?;
    for old in previous {
        let current = findings
            .iter()
            .find(|finding| finding.finding_id == old.finding_id)
            .ok_or("retained finding")?;
        assert_eq!(current.sensitivity, ContextSensitivityV1::HostRestricted);
    }
    assert!(findings
        .iter()
        .all(|finding| finding.sensitivity == ContextSensitivityV1::HostRestricted));
    Ok(())
}

#[test]
fn changed_unit_support_changes_findings() -> TestResult {
    let detector = Detector::Process;
    let records = records(2);
    let mut facts = vec![
        fact(0, context(ContextClass::OutsideAuthority)),
        fact(1, context(ContextClass::InMemory)),
    ];
    UnitFixture::keys(&mut facts);
    let prior = detector.evaluate(&input(detector, &records, &facts, 100)?)?;
    let findings = FindingChange::decode(UnitFixture::data(&prior, "findings")?)?;
    let original = findings
        .iter()
        .find(|finding| finding.reason_code == "HF-PROC-001.OUTSIDE_AUTHORITY")
        .ok_or("outside finding")?;
    let mut revised = facts.clone();
    revised[0].key.owner_revision += 1;
    let output = detector.evaluate(&input(detector, &records, &revised, 100)?)?;
    let changed = FindingChange::decode(UnitFixture::data(&output, "findings")?)?
        .into_iter()
        .find(|finding| finding.reason_code == original.reason_code)
        .ok_or("revised finding")?;
    assert_eq!(changed.finding_id, original.finding_id);
    assert_ne!(changed.anchor, original.anchor);
    assert_eq!(
        changed.anchor.fact.as_ref().ok_or("revised anchor")?.key,
        revised[0].key
    );
    revised[0].value = context(ContextClass::PayloadUnobservable);
    let output = detector.evaluate(&input(detector, &records, &revised, 100)?)?;
    let changed = FindingChange::decode(UnitFixture::data(&output, "findings")?)?
        .into_iter()
        .find(|finding| finding.reason_code == "HF-PROC-001.PAYLOAD_UNOBSERVABLE")
        .ok_or("changed context finding")?;
    assert_eq!(
        changed.anchor.fact.as_ref().ok_or("changed anchor")?.value,
        revised[0].value
    );
    let mut gapped = records.clone();
    gapped[0].proof_quality.temporal_coverage = TemporalCoverageV1::Gapped;
    let output = detector.evaluate(&input(detector, &gapped, &facts, 100)?)?;
    let changed = FindingChange::decode(UnitFixture::data(&output, "findings")?)?
        .into_iter()
        .find(|finding| finding.anchor.record == records[0].id && finding.anchor.fact.is_none())
        .ok_or("gapped effect finding")?;
    assert_eq!(changed.state, FindingStateV1::CoverageInsufficient);
    assert!(changed
        .limits
        .iter()
        .any(|limit| limit == "SOURCE_COVERAGE_INSUFFICIENT"));
    Ok(())
}

#[test]
fn expired_authority_support_disappears() -> TestResult {
    let detector = Detector::Credentials;
    let (old, mut facts) = credential_input()?;
    for fact in &mut facts {
        if let FactValue::AuthorityUse {
            workload_binding, ..
        } = &mut fact.value
        {
            *workload_binding = None;
        }
    }
    let prior = detector.evaluate(&input(detector, &old, &facts, 100)?)?;
    let read = FindingChange::decode(UnitFixture::data(&prior, "findings")?)?
        .into_iter()
        .find(|finding| finding.anchor.record == old[0].id)
        .ok_or("read finding")?;
    assert!(
        RelationshipChange::decode(UnitFixture::data(&prior, "relationships")?)?
            .iter()
            .any(|edge| edge.key.edge_type == GraphEdgeTypeV1::CredentialAuthority)
    );
    for removed in [1, 2] {
        let mut current = old.clone();
        current.remove(removed);
        let selected = facts
            .iter()
            .filter(|fact| fact.record != removed as u32)
            .cloned()
            .map(|mut fact| {
                if fact.record > removed as u32 {
                    fact.record -= 1;
                }
                fact
            })
            .collect::<Vec<_>>();
        let output = detector.evaluate(&input(detector, &current, &selected, 100)?)?;
        let mut changed = UnitFixture::units(detector, &current, &selected);
        changed.retain(|unit| unit.record != old[0].id);
        let delta = UnitFixture::run(detector, &current, &selected, &changed)?;
        assert!(
            FindingChange::decode(UnitFixture::data(&delta, "findings")?)?
                .iter()
                .all(|finding| finding.finding_id != read.finding_id)
        );
        assert!(
            FindingChange::decode(UnitFixture::data(&output, "findings")?)?
                .iter()
                .any(|finding| finding == &read)
        );
        assert!(
            RelationshipChange::decode(UnitFixture::data(&output, "relationships")?)?
                .iter()
                .all(|edge| edge.key.edge_type != GraphEdgeTypeV1::CredentialAuthority)
        );
        assert!(
            SubjectChange::decode(UnitFixture::data(&output, "subjects")?)?
                .iter()
                .all(|subject| !matches!(
                    subject.key.authority,
                    GraphSubjectAuthorityV1::Provider { .. }
                ))
        );
    }
    Ok(())
}

#[test]
fn surviving_parent_reanchors_process() -> TestResult {
    let detector = Detector::Process;
    let mut old = records(2);
    old[1].process_instance_id = Some([8; 16]);
    old[1].effect.task_cookie = 4;
    let parent = GraphSubjectKeyV1::native(
        &old[0].id.stream,
        GraphSubjectKindV1::Process,
        old[0].process_instance_id.ok_or("process")?.to_vec(),
    );
    let facts = [fact(
        1,
        FactValue::NativeParent {
            parent: parent.clone(),
            child: old[1].task_subject(),
            proof_quality: proof(),
        },
    )];
    let prior = detector.evaluate(&input(detector, &old, &facts, 100)?)?;
    assert_eq!(
        SubjectChange::decode(UnitFixture::data(&prior, "subjects")?)?
            .iter()
            .find(|subject| subject.key == parent)
            .ok_or("old process")?
            .anchor
            .fact,
        None,
    );
    let mut remaining = facts[0].clone();
    remaining.record = 0;
    let output = detector.evaluate(&input(detector, &old[1..], &[remaining.clone()], 100)?)?;
    let subject = SubjectChange::decode(UnitFixture::data(&output, "subjects")?)?
        .into_iter()
        .find(|subject| subject.key == parent)
        .ok_or("reanchored process")?;
    assert_eq!(
        subject.anchor,
        Anchor::from_positions(0, Some(0), &[old[1].id.clone()], &[remaining])?
    );
    Ok(())
}

#[test]
fn expired_state_and_sensitivity() -> TestResult {
    let detector = Detector::Process;
    let mut old = records(2);
    old[0].effect.decision =
        erebor_interceptor_abi::EffectPhysicalResultV1::UnknownAfterPreEffect as u32;
    let mut restricted = fact(1, context(ContextClass::InMemory));
    restricted.sensitivity = ContextSensitivityV1::HostRestricted;
    restricted.key.entity_key = 1_u64.to_be_bytes().to_vec();
    let retained = fact(0, context(ContextClass::OutsideAuthority));
    let prior = detector.evaluate(&input(
        detector,
        &old,
        &[retained.clone(), restricted],
        100,
    )?)?;
    assert!(
        Contribution::decode(UnitFixture::data(&prior, "contributions")?)?
            .iter()
            .find(|unit| unit.record == old[1].id)
            .ok_or("effect unit")?
            .state
            .as_ref()
            .is_some_and(|state| state.state == GraphPackageStateV1::NativeEffect)
    );
    assert!(
        FindingChange::decode(UnitFixture::data(&prior, "findings")?)?
            .iter()
            .all(|finding| finding.sensitivity == ContextSensitivityV1::HostRestricted)
    );
    let output = detector.evaluate(&input(detector, &old[..1], &[retained], 100)?)?;
    let contributions = Contribution::decode(UnitFixture::data(&output, "contributions")?)?;
    assert_eq!(contributions.len(), 1);
    assert!(contributions[0].state.is_none());
    assert_eq!(
        GraphPackageStateV1::decode(UnitFixture::data(&output, "state")?)?,
        [GraphPackageStateV1::Waiting]
    );
    assert!(
        FindingChange::decode(UnitFixture::data(&output, "findings")?)?
            .iter()
            .all(|finding| finding.sensitivity == ContextSensitivityV1::Tenant)
    );
    Ok(())
}
