use super::*;
use araphor_data::{
    analysis::AnalysisStore, AnalysisWitnessV1, EvidenceIntakeIdentityV1, EvidenceRetentionOwner,
    ProcessorStateV1, RetentionLimitsV1, ValidatedEvidenceBatchV1,
};

fn request() -> ProcessorRetirementV1 {
    ProcessorRetirementV1 {
        scope: ProcessorScopeV1 {
            processor_id: "detector".into(),
            method_version: 1,
            identity: EvidenceIntakeIdentityV1 {
                node_id: "n".into(),
                ..super::scope().identity
            },
        },
        change_id: "change-1".into(),
        reason: "Retire this detector version.".into(),
        expected_cursor: 1,
        cutoff_cursor: 3,
    }
}

#[test]
fn analysis_store_required_retirement() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: Some(100),
    };
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    let mut input = request();
    input.scope.identity.node_id = "n".repeat(128);
    store.register_processor(&input.scope, ProcessorClassV1::Required, 1)?;
    store.accept_validated_batch(
        input.scope.identity.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 3,
            intake_utc_ns: 1,
            framed_records: vec![1, 2, 3].into(),
            frame_ends: vec![1, 2, 3],
        },
    )?;
    let result = AnalysisResultCommitV1 {
        body: vec![1],
        created_utc_ns: 2,
        witnesses: vec![AnalysisWitnessV1 {
            identity: input.scope.identity.clone().into(),
            cursor: 1,
            expires_utc_ns: 100,
        }],
        ..super::contracts::result(input.scope.clone(), "finding".into())
    };
    let result_receipt = store.commit_result(&result)?;
    let before = store.meta()?;
    let revisions = store.subscribe_revision();
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&input.scope.identity, 10)?
            .removed_records,
        0
    );
    let mut changed = input.clone();
    changed.cutoff_cursor = 2;
    assert!(store.retire_required(&changed).is_err());
    changed = input.clone();
    changed.expected_cursor = 0;
    assert!(store.retire_required(&changed).is_err());
    changed = input.clone();
    changed.scope.identity.tenant_id = [9; 16];
    assert!(store.retire_required(&changed).is_err());
    assert_eq!(store.meta()?, before);
    assert!(!revisions.has_changed()?);
    assert!(store.processor_retirement(&input.scope)?.is_none());
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&input.scope.identity, 10)?
            .removed_records,
        0
    );
    let revision = store.retire_required(&input)?;
    drop(store);
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    let health = store
        .processor_health(&input.scope)?
        .ok_or("health absent")?;
    assert_eq!(health.state, ProcessorStateV1::Retired);
    assert!(health.incomplete);
    assert_eq!(health.consumed_cursor, 1);
    assert_eq!(health.resume_floor, 0);
    assert_eq!(
        store.processor_retirement(&input.scope)?,
        Some((input.clone(), revision))
    );
    assert!(store.processor_retirement(&changed.scope)?.is_none());
    assert_eq!(store.commit_result(&result)?, result_receipt);
    assert!(store
        .register_processor(&input.scope, ProcessorClassV1::Required, 1)
        .is_err());
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&input.scope.identity, 10)?
            .removed_records,
        0
    );
    let page = store.read_page(&input.scope.identity, 1)?;
    assert_eq!(page.records.len(), 3);
    assert_eq!(page.records[0].cursor, 1);
    assert_eq!(page.next_cursor, None);
    assert_eq!(store.read_page(&input.scope.identity, 2)?.records.len(), 2);
    store.accept_validated_batch(
        input.scope.identity.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 4,
            last_cursor: 4,
            intake_utc_ns: 10,
            framed_records: vec![4].into(),
            frame_ends: vec![1],
        },
    )?;
    let before = store.meta()?;
    assert_eq!(store.retire_required(&input)?, revision);
    assert_eq!(store.meta()?, before);
    changed = input.clone();
    changed.reason = "Different change".into();
    assert!(store.retire_required(&changed).is_err());
    let mut next = result.clone();
    next.result_id = "late-finding".into();
    next.expected_cursor = 1;
    next.consumed_cursor = 4;
    assert!(store.commit_result(&next).is_err());
    drop(store);
    let reopened = AnalysisStore::open_with_retention(&root, limits)?;
    assert_eq!(
        reopened.processor_retirement(&input.scope)?,
        Some((input.clone(), revision))
    );
    assert_eq!(reopened.retire_required(&input)?, revision);
    assert_eq!(
        reopened
            .processor_health(&input.scope)?
            .ok_or("retired health")?
            .state,
        ProcessorStateV1::Retired
    );
    let mut replacement = input.scope.clone();
    replacement.method_version = 2;
    reopened.register_processor(&replacement, ProcessorClassV1::Required, 4)?;
    assert!(reopened.processor_retirement(&replacement)?.is_none());
    let view = reopened.view()?;
    let states = view
        .snapshot()
        .prefix(b"\0data/@progress/state/")
        .map(|row| {
            let (_, bytes) = row?;
            assert_eq!(bytes.first(), Some(&0));
            Ok::<_, Box<dyn std::error::Error>>(rmp_serde::from_slice::<super::State>(&bytes[1..])?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(states.len(), 2);
    assert_eq!(
        states
            .iter()
            .filter(|state| state.scope == input.scope)
            .count(),
        1
    );
    assert_eq!(
        states
            .iter()
            .filter(|state| state.scope == replacement)
            .count(),
        1
    );
    assert_eq!(
        reopened
            .processor_health(&replacement)?
            .ok_or("replacement health")?
            .class,
        ProcessorClassV1::Required
    );
    Ok(())
}

#[test]
fn analysis_store_retirement_recovery() -> TestResult {
    for fault in ["cutoff", "missing-gap", "retired"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let mut input = request();
        input.expected_cursor = 0;
        input.cutoff_cursor = 1;
        store.register_processor(&input.scope, ProcessorClassV1::Required, 1)?;
        store.accept_validated_batch(
            input.scope.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: vec![1].into(),
                frame_ends: vec![1],
            },
        )?;
        store.retire_required(&input)?;
        let view = store.view()?;
        let mut tx = store.write()?;
        if fault == "missing-gap" {
            let mut gaps = view.snapshot().prefix(b"\0data/@progress/gap/");
            let (key, _) = gaps.next().ok_or("retirement gap")??;
            assert!(gaps.next().is_none());
            tx.native().remove(key);
        } else {
            let mut states = view.snapshot().prefix(b"\0data/@progress/state/");
            let (key, bytes) = states.next().ok_or("retired state")??;
            assert!(states.next().is_none());
            assert_eq!(bytes.first(), Some(&0));
            let mut state: super::State = rmp_serde::from_slice(&bytes[1..])?;
            if fault == "cutoff" {
                state
                    .retirement
                    .as_mut()
                    .ok_or("retirement")?
                    .0
                    .cutoff_cursor = 9;
            } else {
                state.retirement = None;
            }
            state.revision = tx.revision();
            let mut bytes = vec![0];
            bytes.extend(rmp_serde::to_vec_named(&state)?);
            tx.native().insert(key, bytes);
        }
        tx.commit([])?;
        drop(view);
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "{fault}");
    }
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let mut input = request();
    input.expected_cursor = 0;
    input.cutoff_cursor = 0;
    store.register_processor(&input.scope, ProcessorClassV1::Optional, 1)?;
    assert!(store.retire_required(&input).is_err());
    input.scope.method_version = 2;
    store.register_processor(&input.scope, ProcessorClassV1::Required, 1)?;
    store.retire_required(&input)?;
    assert!(
        !store
            .processor_health(&input.scope)?
            .ok_or("health absent")?
            .incomplete
    );
    Ok(())
}
