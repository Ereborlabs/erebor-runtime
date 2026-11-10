#![cfg(feature = "test-fixtures")]

use std::collections::{BTreeMap, BTreeSet};

use araphor_data::{
    AnalysisCommitStage, AnalysisExtractLimits, AnalysisReadControl, AnalysisReadModeV1,
    AnalysisResultCommitV1, AnalysisSelectionV1, AnalysisStore, AnalysisTableRead,
    AnalysisWitnessV1, EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1,
    PackageErrorCodeV1 as Code, ProcessorClassV1, ProcessorScopeV1, RetentionLimitsV1,
    StorageLimitsV1, StorePositionV1, ValidatedEvidenceBatchV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn identity() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

fn batch(cursor: u64) -> ValidatedEvidenceBatchV1 {
    ValidatedEvidenceBatchV1 {
        cpu_id: 7,
        first_cursor: cursor,
        last_cursor: cursor,
        intake_utc_ns: 100,
        framed_records: vec![cursor as u8; 3].into(),
        frame_ends: vec![3],
    }
}

fn result(scope: &ProcessorScopeV1, expected: u64, consumed: u64) -> AnalysisResultCommitV1 {
    AnalysisResultCommitV1 {
        scope: scope.clone(),
        expected_cursor: expected,
        consumed_cursor: consumed,
        coverage_revision: 0,
        context_revision: 0,
        result_id: format!("{}-{consumed}", scope.processor_id),
        body: vec![4],
        created_utc_ns: 200,
        witnesses: Vec::new(),
        context_refs: Vec::new(),
    }
}

#[test]
fn required_backlog_bytes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let limits = RetentionLimitsV1 { raw_max_age_ns: None, raw_max_bytes: Some(10) };
    let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
    let source = identity();
    let slow = ProcessorScopeV1 { processor_id: "slow".into(), method_version: 1, identity: source.clone() };
    let mut fast = slow.clone();
    fast.processor_id = "fast".into();
    let mut other = slow.clone();
    other.processor_id = "other".into();
    other.identity.source_id = [4; 16];
    store.register_processor(&slow, ProcessorClassV1::Required, 1)?;
    store.register_processor(&fast, ProcessorClassV1::Required, 1)?;
    store.register_processor(&other, ProcessorClassV1::Required, 1)?;
    store.accept_validated_batch(source.clone(), ValidatedEvidenceBatchV1 {
        cpu_id: 7, first_cursor: 1, last_cursor: 2, intake_utc_ns: 100,
        framed_records: vec![1; 7].into(), frame_ends: vec![2, 7],
    })?;
    store.accept_validated_batch(other.identity.clone(), batch(1))?;
    assert!(matches!(store.accept_validated_batch(source.clone(), batch(3)), Err(araphor_data::Error::ProtectedInputCapacity { resource: "bytes", .. })));
    store.commit_result(&result(&slow, 0, 1))?;
    store.commit_result(&result(&fast, 0, 2))?;
    assert!(store.accept_validated_batch(source.clone(), batch(3)).is_err());
    store.set_commit_hook(AnalysisCommitStage::BeforeResultCommit, || Err(Code::Denied.error("rollback")))?;
    assert!(store.commit_result(&result(&slow, 1, 2)).is_err());
    assert!(store.accept_validated_batch(source.clone(), batch(3)).is_err());
    drop(store);
    let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
    assert!(store.accept_validated_batch(source.clone(), batch(3)).is_err());
    store.commit_result(&result(&slow, 1, 2))?;
    store.accept_validated_batch(source.clone(), batch(3))?;
    let mut late = slow.clone();
    late.processor_id = "late".into();
    store.register_processor_guarded(&late, ProcessorClassV1::Required, 1, || Err(Code::Denied.error("registration rollback"))).expect_err("guarded registration");
    store.accept_validated_batch(source.clone(), batch(4))?;
    store.register_processor(&late, ProcessorClassV1::Required, 1)?;
    assert!(store.accept_validated_batch(source.clone(), batch(5)).is_err());
    store.retire_required(&araphor_data::ProcessorRetirementV1 {
        scope: late, change_id: "retire".into(), reason: "Retire the old consumer.".into(), expected_cursor: 0, cutoff_cursor: 4,
    })?;
    store.commit_result(&result(&other, 0, 1))?;
    store.accept_validated_batch(source, batch(5))?;
    Ok(())
}

#[test]
fn required_backlog_age() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let limits = RetentionLimitsV1 { raw_max_age_ns: Some(50), raw_max_bytes: None };
    let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
    let source = identity();
    let scope = ProcessorScopeV1 { processor_id: "age".into(), method_version: 1, identity: source.clone() };
    store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    let mut input = batch(3);
    input.intake_utc_ns = 10;
    assert_eq!(store.accept_validated_batch(source.clone(), input)?, EvidenceStoreOutcomeV1::Pending);
    store.accept_validated_batch(source.clone(), batch(1))?;
    let mut input = batch(2);
    input.intake_utc_ns = 120;
    store.accept_validated_batch(source.clone(), input.clone())?;
    let mut next = batch(4);
    next.intake_utc_ns = 120;
    assert!(matches!(store.accept_validated_batch(source.clone(), next.clone()), Err(araphor_data::Error::ProtectedInputCapacity { resource: "age", .. })));
    assert_eq!(store.accept_validated_batch(source.clone(), input)?, EvidenceStoreOutcomeV1::Accepted);
    drop(store);
    let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
    assert!(store.accept_validated_batch(source.clone(), next.clone()).is_err());
    store.commit_result(&result(&scope, 0, 1))?;
    assert!(store.accept_validated_batch(source.clone(), next.clone()).is_err());
    store.commit_result(&result(&scope, 1, 3))?;
    store.accept_validated_batch(source, next)?;
    Ok(())
}

#[test]
fn retired_backlog_expires() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_limits(directory.path().join("data"),
        RetentionLimitsV1 { raw_max_age_ns: Some(50), raw_max_bytes: Some(3) }, Default::default())?;
    let source = identity();
    let mut scope = ProcessorScopeV1 { processor_id: "old".into(), method_version: 1, identity: source.clone() };
    store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    store.accept_validated_batch(source.clone(), batch(1))?;
    store.retire_required(&araphor_data::ProcessorRetirementV1 {
        scope: scope.clone(), change_id: "retire".into(), reason: "Retire the old consumer.".into(), expected_cursor: 0, cutoff_cursor: 1,
    })?;
    assert_eq!(araphor_data::EvidenceRetentionOwner::new(&store).retain(&source, 151)?.removed_records, 1);
    scope.processor_id = "new".into();
    store.register_processor(&scope, ProcessorClassV1::Required, 2)?;
    let mut input = batch(2);
    input.intake_utc_ns = 151;
    store.accept_validated_batch(source, input)?;
    Ok(())
}

#[test]
fn capacity_keeps_maintenance() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let retention = RetentionLimitsV1 { raw_max_age_ns: Some(1), raw_max_bytes: None };
    let store = AnalysisStore::open_with_limits(&root, retention, Default::default())?;
    let source = identity();
    let scope = ProcessorScopeV1 { processor_id: "required".into(), method_version: 1, identity: source.clone() };
    store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    store.accept_validated_batch(source.clone(), batch(1))?;
    drop(store);
    let store = AnalysisStore::open_with_limits(&root, retention, StorageLimitsV1 {
        storage_entries: Some(0), ..Default::default()
    })?;
    let before = store.meta()?;
    let mut other = scope.clone();
    other.processor_id = "other".into();
    assert!(matches!(store.register_processor(&other, ProcessorClassV1::Optional, 1),
        Err(araphor_data::Error::StorageCapacity { resource: "storage entries", .. })));
    assert_eq!(store.meta()?, before);
    store.retire_required(&araphor_data::ProcessorRetirementV1 {
        scope, change_id: "retire".into(), reason: "Release the old input.".into(), expected_cursor: 0, cutoff_cursor: 1,
    })?;
    assert_eq!(araphor_data::EvidenceRetentionOwner::new(&store).retain(&source, 102)?.removed_records, 1);
    store.checkpoint()?;
    let before = store.meta()?;
    assert!(matches!(store.backup(&root.join("backups").join("refused")), Err(araphor_data::Error::StorageCapacity { .. })));
    assert!(!root.join("backups").exists());
    assert_eq!(store.meta()?, before);
    assert!(store.storage_health()?.write_ready);
    Ok(())
}

#[test]
fn durable_raw_recovery_and_backup() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let source = identity();
    store.set_commit_hook(AnalysisCommitStage::AfterSync, || {
        Err(Code::Denied.error("after sync"))
    })?;
    assert!(store
        .accept_validated_batch(source.clone(), batch(1))
        .is_err());
    assert!(store.meta().is_err());
    store.recover()?;
    assert_eq!(
        store
            .source_receipt(&source)?
            .ok_or("recovered receipt")?
            .contiguous_cursor,
        1
    );
    let first = store.meta()?;
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(1))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    assert_eq!(store.meta()?, first);
    store.accept_validated_batch(source.clone(), batch(2))?;
    let before = store.meta()?;
    store.checkpoint()?;
    assert_eq!(store.meta()?, before);
    let backup = root.join("backups").join("snapshot");
    let manifest = store.backup(&backup)?;
    assert_eq!(store.meta()?, before);
    assert_eq!(manifest.commit_revision, before.commit_revision);
    assert!(!manifest.database_files.is_empty());
    let refused = directory.path().join("refused-restore");
    assert!(AnalysisStore::restore_with_limits(&backup, &refused, StorageLimitsV1 {
        storage_entries: Some(0), ..Default::default()
    }).is_err());
    assert!(!refused.exists());
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    let meta = restored.meta()?;
    assert_eq!(meta.store_uuid, before.store_uuid);
    assert_eq!(meta.commit_revision, before.commit_revision);
    assert_eq!(meta.recovery_epoch, before.recovery_epoch + 1);
    assert_eq!(restored.read_page(&source, 1)?.records.len(), 2);
    assert_eq!(
        restored
            .read_page_at(
                &restored.read_at(first.commit_revision)?,
                &source,
                1,
                &AnalysisReadControl::default()
            )?
            .records
            .len(),
        1
    );
    restored.accept_validated_batch(source.clone(), batch(3))?;
    assert_eq!(restored.read_page(&source, 1)?.records.len(), 3);
    Ok(())
}

#[test]
fn witness_admission_and_expiry_changes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let retention = RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: None,
    };
    let store = AnalysisStore::open_with_limits(
        &root,
        retention,
        StorageLimitsV1 {
            source_entries: Some(1),
            ..Default::default()
        },
    )?;
    let source = identity();
    store.accept_validated_batch(source.clone(), batch(1))?;
    let mut foreign = source.clone();
    foreign.node_id = "node-b".into();
    assert!(store
        .accept_validated_batch(foreign.clone(), batch(1))
        .is_err());
    assert!(store.source_receipt(&foreign)?.is_none());
    let scope = ProcessorScopeV1 {
        processor_id: "retained".into(),
        method_version: 1,
        identity: source.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    let result = AnalysisResultCommitV1 {
        scope,
        expected_cursor: 0,
        consumed_cursor: 1,
        coverage_revision: 0,
        context_revision: 0,
        result_id: "result".into(),
        body: vec![4],
        created_utc_ns: 101,
        witnesses: vec![AnalysisWitnessV1 {
            identity: source.clone().into(),
            cursor: 1,
            expires_utc_ns: 200,
        }],
        context_refs: Vec::new(),
    };
    let receipt = store.commit_result(&result)?;
    let mut selected = AnalysisSelectionV1::new(source.tenant_id, Vec::new());
    selected.results = vec![result.result_id.clone(), "absent".into()];
    let requests = BTreeMap::new();
    let captured = store.read_tables(
        &selected,
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            now: 101,
            mode: AnalysisReadModeV1::Metadata,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(captured.extraction.missing_results, ["absent"]);
    assert_eq!(captured.extraction.witnesses.len(), 1);
    assert_eq!(captured.extraction.witnesses[0].cursor, 1);
    assert_eq!(
        captured
            .extraction
            .references
            .iter()
            .find_map(|reference| reference.result())
            .ok_or("explicit result reference")?
            .commit_revision,
        receipt.commit_revision
    );
    let usage = store.witness_usage(source.tenant_id, 101)?;
    assert_eq!(usage.referenced_bytes, 3);
    assert_eq!(usage.charged_bytes, usage.segment_bytes);
    assert_eq!(usage.extra_segment_bytes + 3, usage.segment_bytes);
    drop(store);
    let store = AnalysisStore::open_with_limits(
        &root,
        retention,
        StorageLimitsV1 {
            witness_max_bytes: Some(usage.charged_bytes - 1),
            ..Default::default()
        },
    )?;
    assert_eq!(store.commit_result(&result)?, receipt);
    let before = store.meta()?;
    assert!(store
        .accept_validated_batch(source.clone(), batch(2))
        .is_err());
    assert_eq!(store.meta()?, before);
    let owner = araphor_data::EvidenceRetentionOwner::new(&store);
    assert_eq!(owner.retain(&source, 199)?.removed_records, 0);
    let expired = owner.retain(&source, 201)?;
    assert_eq!(expired.removed_records, 1);
    assert_eq!(store.meta()?.commit_revision, expired.commit_revision);
    let requests = BTreeMap::from([(
        "events".into(),
        Some(BTreeSet::from([
            AnalysisStore::table_schemas()["events"].index_of("source_cursor")?
        ])),
    )]);
    let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
    let read = || AnalysisTableRead {
        requests: &requests,
        event_ranges: None,
        now: 201,
        mode: AnalysisReadModeV1::Changes(StorePositionV1 {
            commit_revision: before.commit_revision,
            ordinal: u32::MAX,
        }),
    };
    let changes = store.read_tables(
        &selection,
        read(),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(changes.exhausted);
    let gaps = &changes.removals[&source.clone().into()];
    assert_eq!(
        (
            gaps[0].first_cursor,
            gaps[0].last_cursor,
            gaps[0].commit_revision
        ),
        (1, 1, expired.commit_revision)
    );
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?.commit_revision, expired.commit_revision);
    let changes = store.read_tables(
        &selection,
        read(),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(changes.removals[&source.into()], *gaps);
    Ok(())
}
