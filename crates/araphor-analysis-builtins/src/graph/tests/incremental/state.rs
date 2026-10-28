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
        let old_facts = vec![
            fact(0, value.clone()),
            fact(1, value.clone()),
            fact(0, value.clone()),
        ];
        let (prior, work) = measured(detector, &input(detector, &old, &old_facts, 100)?)?;
        assert_eq!(
            work,
            if matches!(detector, Detector::Process) {
                2
            } else {
                3
            }
        );
        let mut added = record();
        added.observed_boottime_ns = 12;
        let current = vec![added, old[0].clone(), old[1].clone()];
        let mut added_fact = fact(0, value);
        if let FactValue::Kubernetes(stage) = &mut added_fact.value {
            stage.node_id = Some("worker".into());
        }
        let mut current_facts = vec![added_fact];
        for mut fact in old_facts {
            fact.record += 1;
            current_facts.push(fact);
        }
        let evaluation = input(detector, &current, &current_facts, 100)?;
        let (output, work) = continued(detector, &evaluation, &prior)?;
        assert_eq!(work, 1);
        assert_eq!(
            Metadata::decode(&output.datasets[4])?[0].facts,
            current_facts
        );
        let subjects = Subject::decode(&output.datasets[0])?;
        assert_eq!(
            subjects.len(),
            if matches!(detector, Detector::Process) {
                5
            } else {
                2
            }
        );
        assert!(subjects.iter().all(|subject| subject.record == 0));
        if matches!(detector, Detector::Process) {
            assert!(Finding::decode(&output.datasets[2])?
                .iter()
                .any(|finding| finding.record == 1 && finding.context == Some(3)));
        } else {
            assert!(Relationship::decode(&output.datasets[1])?
                .iter()
                .any(|edge| edge.record == 1 && edge.fact == Some(1)));
            assert_eq!(
                Metadata::decode(&output.datasets[4])?[0].package.state,
                GraphPackageStateV1::KubernetesObject
            );
        }
        assert_eq!(continued(detector, &evaluation, &output)?.1, 0);
    }
    Ok(())
}

#[test]
fn inserted_state_keeps_last() -> TestResult {
    let detector = Detector::Process;
    let mut old = records(2);
    old[1].id.durable_cursor = 3;
    let prior = detector.evaluate(&input(detector, &old, &[], 100)?)?;
    let mut added = record();
    added.id = identity(1);
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
    let (output, work) = continued(
        detector,
        &input(
            detector,
            &current,
            &[fact(1, FactValue::Policy(policy))],
            100,
        )?,
        &prior,
    )?;
    assert_eq!(work, 1);
    assert_eq!(
        Metadata::decode(&output.datasets[4])?[0].package.state,
        GraphPackageStateV1::NativeEffect
    );
    let checkpoint = output.checkpoint.as_ref().ok_or("checkpoint")?;
    let progress = Progress::decode(
        checkpoint
            .datasets
            .iter()
            .find(|data| data.name == "progress")
            .ok_or("progress")?,
    )?;
    assert_eq!(
        progress
            .iter()
            .map(|row| row.state.as_deref())
            .collect::<Vec<_>>(),
        [
            Some("NATIVE_EFFECT"),
            Some("CONTRADICTED"),
            Some("NATIVE_EFFECT")
        ]
    );
    assert!(Finding::decode(&output.datasets[2])?
        .iter()
        .any(|finding| finding.record == 1 && finding.reason_code == "HF-PROC-001.CONTRADICTION"));
    Ok(())
}

#[test]
fn restricted_fact_updates_findings() -> TestResult {
    let detector = Detector::Process;
    let old = records(2);
    let prior = detector.evaluate(&input(detector, &old, &[], 100)?)?;
    let previous = Finding::decode(&prior.datasets[2])?;
    assert!(previous
        .iter()
        .all(|finding| finding.sensitivity == ContextSensitivityV1::Tenant));
    let mut added = fact(2, context(ContextClass::OutsideAuthority));
    added.sensitivity = ContextSensitivityV1::HostRestricted;
    let (output, work) = continued(
        detector,
        &input(detector, &records(3), &[added], 100)?,
        &prior,
    )?;
    assert_eq!(work, 1);
    let findings = Finding::decode(&output.datasets[2])?;
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
fn changed_inputs_rebuild() -> TestResult {
    let detector = Detector::Process;
    let old = records(3);
    let facts = vec![
        fact(0, context(ContextClass::OutsideAuthority)),
        fact(0, context(ContextClass::InMemory)),
        fact(1, context(ContextClass::OutsideAuthority)),
    ];
    let prior = detector.evaluate(&input(detector, &old, &facts, 100)?)?;
    for case in 0..8 {
        let mut current = old.clone();
        let mut selected = facts.clone();
        let mut window = 100;
        match case {
            0 => current[0].proof_quality.temporal_coverage = TemporalCoverageV1::Gapped,
            1 => selected.push(fact(0, context(ContextClass::PayloadUnobservable))),
            2 => selected[0].key.owner_revision += 1,
            3 => {
                current.swap(0, 1);
                for fact in &mut selected {
                    fact.record = match fact.record {
                        0 => 1,
                        1 => 0,
                        row => row,
                    };
                }
            }
            4 => {
                current.remove(0);
                selected.retain(|fact| fact.record != 0);
                for fact in &mut selected {
                    fact.record -= 1;
                }
            }
            5 => window = 50,
            6 => selected.swap(0, 1),
            7 => selected[0].value = context(ContextClass::PayloadUnobservable),
            _ => return Err("fallback fixture".into()),
        }
        let (_, work) = continued(
            detector,
            &input(detector, &current, &selected, window)?,
            &prior,
        )?;
        assert_eq!(work, current.len(), "fallback {case}");
    }
    let empty = input(detector, &[], &[], 100)?;
    let (output, work) = continued(detector, &empty, &prior)?;
    assert_eq!(work, 0);
    assert!(Metadata::decode(&output.datasets[4])?[0]
        .record_ids
        .is_empty());
    let (_, work) = continued(detector, &input(detector, &old, &facts, 100)?, &output)?;
    assert_eq!(work, old.len());
    Ok(())
}

#[test]
fn incompatible_progress_rebuilds() -> TestResult {
    let detector = Detector::Process;
    let current = input(detector, &records(2), &[], 100)?;
    let prior = detector.evaluate(&current)?;
    for case in 0..4 {
        let mut saved = prior.clone();
        let checkpoint = saved.checkpoint.as_mut().ok_or("checkpoint")?;
        let dataset = checkpoint
            .datasets
            .iter_mut()
            .find(|data| data.name == "progress")
            .ok_or("progress")?;
        let mut progress = Progress::decode(dataset)?;
        match case {
            0 => {
                progress.pop();
            }
            1 => progress[0].digest = vec![0; 31].into(),
            2 => {
                let mut digest = progress[0].digest.clone().into_vec();
                digest[0] ^= 128;
                progress[0].digest = digest.into();
            }
            3 => progress[0].state = Some("DIRECT_PIVOT".into()),
            _ => return Err("progress fixture".into()),
        }
        *dataset = Progress::encode(&progress)?;
        let mut admitted = current.clone();
        admitted.checkpoint = saved.checkpoint.clone();
        admitted.previous_outputs = saved.datasets.clone();
        detector.descriptor().check_evaluation(&admitted)?;
        assert_eq!(
            continued(detector, &current, &saved)?.1,
            2,
            "progress {case}"
        );
    }
    let mut invalid = current;
    invalid.previous_outputs = prior.datasets;
    invalid.checkpoint = prior.checkpoint;
    detector.descriptor().check_evaluation(&invalid)?;
    let checkpoint = invalid.checkpoint.as_mut().ok_or("checkpoint")?;
    let dataset = checkpoint
        .datasets
        .iter_mut()
        .find(|data| data.name == "progress")
        .ok_or("progress")?;
    dataset.batches = Manifest::encode(&[Manifest { window_ns: 100 }])?.batches;
    assert!(detector.descriptor().check_evaluation(&invalid).is_err());
    Ok(())
}
