#![cfg(feature = "native-store")]

use std::{collections::BTreeSet, ops::Bound, time::Duration};

use araphor_data::{
    analysis::native::NativeStore, AnalysisContextKeyV1, AnalysisContextVersionV1,
    AnalysisReadControl, AnalysisSelectionV1, AnalysisTableRequests, ContextSensitivityV1,
    EvidenceIntakeIdentityV1, EvidenceRecord, InputSubscription, ManagedBudget, Selection,
    StorePositionV1, ValidatedCoverageV1, ValidatedEvidenceBatchV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Budget;
impl ManagedBudget for Budget {
    fn limit(&self) -> usize {
        usize::MAX
    }
    fn check(&self) -> araphor_data::Result<()> {
        Ok(())
    }
    fn reserve(&self, _: usize) -> araphor_data::Result<Box<dyn std::any::Any + Send + Sync>> {
        Ok(Box::new(()))
    }
}

fn source(node: &str) -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: node.into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

fn context(owner: &str, revision: u64) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: owner.into(),
            entity_key: vec![2],
            lifetime_key: vec![3],
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![7; 4096],
    }
}

fn batch(cursor: u64, intake: u64) -> araphor_data::Result<ValidatedEvidenceBatchV1> {
    batch_range(cursor, 1, intake)
}

fn batch_range(
    first: u64,
    count: u64,
    intake: u64,
) -> araphor_data::Result<ValidatedEvidenceBatchV1> {
    let mut body = Vec::new();
    let mut frame_ends = Vec::new();
    for cursor in first..first + count {
        body.extend(Vec::<u8>::try_from(&EvidenceRecord {
            task_cookie: cursor,
            ..Default::default()
        })?);
        frame_ends.push(body.len());
    }
    Ok(ValidatedEvidenceBatchV1 {
        cpu_id: 7,
        first_cursor: first,
        last_cursor: first + count - 1,
        intake_utc_ns: intake,
        frame_ends,
        framed_records: body.into(),
    })
}

#[tokio::test]
async fn raw_position_is_the_last_matching_record_in_the_original_span() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let initial = store.view()?;
    let control = AnalysisReadControl::default();
    let mut selection = AnalysisSelectionV1::new([1; 16], vec![source("node-a")]);
    selection.cursor_until = Bound::Included(3);
    let mut events =
        store.subscribe_inputs(&selection, &requests("events"), None, &control, &Budget)?;
    let mut coverage =
        store.subscribe_inputs(&selection, &requests("coverage"), None, &control, &Budget)?;
    store.accept_validated_batch(source("node-a"), batch_range(1, 5, 100)?)?;
    let matched = changed(&mut events).await?;
    assert_eq!(matched.ordinal, 2);
    assert_eq!(changed(&mut coverage).await?.ordinal, 4);
    let mut replay = store.subscribe_inputs_at(
        &initial,
        &selection,
        &requests("events"),
        None,
        &control,
        &Budget,
    )?;
    assert_eq!(changed(&mut replay).await?, matched);
    unchanged(&mut events).await?;
    let old = araphor_data::AnalysisStore::open(directory.path().join("old"))?;
    old.accept_validated_batch(source("node-a"), batch_range(1, 5, 100)?)?;
    let head = old.subscribe_inputs(&selection, &requests("events"), None, &control, &Budget)?;
    assert_eq!(head.position(), matched);
    Ok(())
}

#[tokio::test]
async fn missing_saved_journal_cut_is_rejected_while_history_remains_readable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let first = store.commit_context(&context("watched", 1))?;
    store.database().inner().flush_memtables()?;
    store.database().inner().rotate_journal()?;
    store.commit_context(&context("watched", 2))?;
    let cursor = store.view()?.snapshot().cursor()?.ok_or("current cursor")?;
    store.database().inner().retain_after(cursor)?;
    store.database().inner().collect_journals()?;
    let historical = store.read_at(first)?;
    assert!(historical.context(&context("watched", 1).key)?.is_some());
    assert!(historical.snapshot().cursor()?.is_none());
    let control = AnalysisReadControl::default();
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    assert!(store
        .subscribe_inputs_at(
            &historical,
            &selection,
            &requests("context_versions"),
            None,
            &control,
            &Budget
        )
        .is_err());
    let mut current = store.subscribe_inputs(
        &selection,
        &requests("context_versions"),
        None,
        &control,
        &Budget,
    )?;
    store.commit_context(&context("watched", 3))?;
    assert_eq!(
        changed(&mut current).await?.commit_revision,
        store.view()?.revision()
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_record_is_retried_without_advancing_the_shared_reader() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let control = AnalysisReadControl::default();
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let mut subscription = store.subscribe_inputs(
        &selection,
        &requests("context_versions"),
        None,
        &control,
        &Budget,
    )?;
    let mut tx = store.write()?;
    let key = [
        b"\0data/context/tenant/".as_slice(),
        &[1; 16],
        &tx.revision().to_be_bytes(),
        &1u64.to_be_bytes(),
    ]
    .concat();
    tx.native().insert(key, [0, 0xc1]);
    tx.commit([])?;
    for _ in 0..2 {
        assert!(
            tokio::time::timeout(Duration::from_secs(5), subscription.changed())
                .await?
                .is_err()
        );
    }
    Ok(())
}

fn requests(name: &str) -> AnalysisTableRequests {
    [(name.into(), None)].into()
}

async fn changed(
    subscription: &mut InputSubscription,
) -> Result<StorePositionV1, Box<dyn std::error::Error>> {
    Ok(tokio::time::timeout(Duration::from_secs(5), subscription.changed()).await??)
}

async fn unchanged(subscription: &mut InputSubscription) -> TestResult {
    assert!(
        tokio::time::timeout(Duration::from_millis(20), subscription.changed())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn recovery_log_routing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let initial = store.view()?;
    let control = AnalysisReadControl::default();
    let mut selection = AnalysisSelectionV1::new([1; 16], vec![source("node-a")]);
    selection.cursor_from = Bound::Included(3);
    selection.cursor_until = Bound::Included(5);
    let mut events =
        store.subscribe_inputs(&selection, &requests("events"), None, &control, &Budget)?;
    let mut coverage =
        store.subscribe_inputs(&selection, &requests("coverage"), None, &control, &Budget)?;
    let mut contexts = store.subscribe_inputs(
        &selection,
        &requests("context_versions"),
        None,
        &control,
        &Budget,
    )?;
    store.record_recovery_floor(&source("node-b"), 5)?;
    store.record_recovery_floor(&source("node-a"), 2)?;
    unchanged(&mut events).await?;
    let first = changed(&mut coverage).await?;
    assert_eq!(first.commit_revision, store.view()?.revision());
    store.record_recovery_floor(&source("node-a"), 5)?;
    let matched = changed(&mut events).await?;
    assert_eq!(matched.ordinal, u32::MAX);
    assert_eq!(changed(&mut coverage).await?, matched);
    let head = store.database().inner().journal_head()?;
    store.record_recovery_floor(&source("node-a"), 5)?;
    assert_eq!(store.database().inner().journal_head()?, head);
    unchanged(&mut events).await?;
    unchanged(&mut coverage).await?;
    unchanged(&mut contexts).await?;
    let revision = initial.revision();
    drop((events, coverage, contexts, initial, store));
    let store = NativeStore::open(&root)?;
    let initial = store.read_at(revision)?;
    let mut replay = store.subscribe_inputs_at(
        &initial,
        &selection,
        &requests("events"),
        None,
        &control,
        &Budget,
    )?;
    assert_eq!(changed(&mut replay).await?, matched);
    unchanged(&mut replay).await?;
    store.record_recovery_floor(&source("node-a"), 6)?;
    unchanged(&mut replay).await?;
    Ok(())
}

#[tokio::test]
async fn original_logs_route_matches_and_resume_after_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let initial = store.view()?;
    let control = AnalysisReadControl::default();
    let mut selection = AnalysisSelectionV1::tenant([1; 16]);
    selection.sources = Selection::Exact(vec![source("node-a")]);
    let owners = BTreeSet::from(["watched".into()]);
    let mut contexts = store.subscribe_inputs(
        &selection,
        &requests("context_versions"),
        Some(&owners),
        &control,
        &Budget,
    )?;
    let mut events =
        store.subscribe_inputs(&selection, &requests("events"), None, &control, &Budget)?;
    let mut coverage =
        store.subscribe_inputs(&selection, &requests("coverage"), None, &control, &Budget)?;
    store.commit_context(&context("other", 1))?;
    store.accept_validated_batch(source("node-b"), batch(1, 100)?)?;
    unchanged(&mut contexts).await?;
    unchanged(&mut events).await?;
    unchanged(&mut coverage).await?;
    let context_revision = store.commit_context(&context("watched", 1))?;
    assert_eq!(
        changed(&mut contexts).await?,
        StorePositionV1 {
            commit_revision: context_revision,
            ordinal: u32::MAX
        }
    );
    unchanged(&mut events).await?;
    store.accept_validated_batch(source("node-a"), batch(1, 100)?)?;
    let raw_revision = store.view()?.revision();
    let raw_position = changed(&mut events).await?;
    assert_eq!(raw_position.commit_revision, raw_revision);
    assert_ne!(raw_position.ordinal, u32::MAX);
    assert_eq!(changed(&mut coverage).await?, raw_position);
    let saved = store.view()?;
    let native = saved.snapshot().cursor()?;
    store.accept_validated_batch(source("node-a"), batch(2, 100)?)?;
    assert_eq!(store.view()?.snapshot().cursor()?, native);
    let later_raw = store.view()?.revision();
    let later_context = store.commit_context(&context("watched", 2))?;
    let mut lagging = store.subscribe_inputs_at(
        &initial,
        &selection,
        &requests("context_versions"),
        Some(&owners),
        &control,
        &Budget,
    )?;
    assert_eq!(changed(&mut lagging).await?.commit_revision, later_context);
    assert_eq!(changed(&mut events).await?.commit_revision, later_raw);
    assert_eq!(changed(&mut contexts).await?.commit_revision, later_context);
    unchanged(&mut events).await?;
    unchanged(&mut contexts).await?;
    let saved_revision = saved.revision();
    drop((lagging, contexts, events, coverage, saved, initial));
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    let saved = store.read_at(saved_revision)?;
    assert_eq!(saved.snapshot().cursor()?, native);
    let mut resumed = store.subscribe_inputs_at(
        &saved,
        &selection,
        &requests("events"),
        None,
        &control,
        &Budget,
    )?;
    assert_eq!(changed(&mut resumed).await?.commit_revision, later_raw);
    unchanged(&mut resumed).await?;
    store.accept_validated_batch(source("node-a"), batch(3, 100)?)?;
    assert_eq!(
        changed(&mut resumed).await?.commit_revision,
        store.view()?.revision()
    );
    Ok(())
}

#[tokio::test]
async fn coverage_and_raw_filters_ignore_native_mirrors_and_rollbacks() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let control = AnalysisReadControl::default();
    let mut selection = AnalysisSelectionV1::new([1; 16], vec![source("node-a")]);
    selection.cursor_from = Bound::Included(2);
    selection.received_from = Bound::Included(200);
    let mut events =
        store.subscribe_inputs(&selection, &requests("events"), None, &control, &Budget)?;
    let mut coverage =
        store.subscribe_inputs(&selection, &requests("coverage"), None, &control, &Budget)?;
    store.accept_validated_batch(source("node-a"), batch(1, 200)?)?;
    unchanged(&mut events).await?;
    changed(&mut coverage).await?;
    store.accept_validated_batch(source("node-a"), batch(2, 100)?)?;
    unchanged(&mut events).await?;
    changed(&mut coverage).await?;
    let mut aborted = store.write()?;
    aborted.coverage(&ValidatedCoverageV1 {
        identity: source("node-a"),
        cpu_id: 7,
        revision: 1,
        encoded_report: vec![1],
    })?;
    aborted.rollback();
    unchanged(&mut coverage).await?;
    store.accept_validated_coverage(ValidatedCoverageV1 {
        identity: source("node-a"),
        cpu_id: 7,
        revision: 1,
        encoded_report: vec![1],
    })?;
    assert_eq!(changed(&mut coverage).await?.ordinal, u32::MAX);
    unchanged(&mut events).await?;
    store.commit_context(&context("unrelated", 1))?;
    unchanged(&mut coverage).await?;
    store.accept_validated_batch(source("node-a"), batch(3, 200)?)?;
    assert_eq!(
        changed(&mut events).await?.commit_revision,
        store.view()?.revision()
    );
    let foreign = NativeStore::open(&directory.path().join("foreign"))?;
    let foreign_view = foreign.view()?;
    assert!(store
        .subscribe_inputs_at(
            &foreign_view,
            &selection,
            &requests("events"),
            None,
            &control,
            &Budget
        )
        .is_err());
    Ok(())
}
