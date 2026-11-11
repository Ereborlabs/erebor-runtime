use super::*;
use araphor_data::{
    AnalysisCommitStage, AnalysisContextVersionV1, AnalysisResultCommitV1, EvidenceRetentionOwner,
    RetentionLimitsV1, ValidatedEvidenceBatchV1,
};

fn check_history(
    store: &NativeStore,
    key: &[u8],
    expected: &[State],
    context: &AnalysisContextVersionV1,
) -> TestResult {
    let mut view = store.read_at(store.meta()?.commit_revision)?;
    for wanted in expected.iter().rev() {
        let bytes = view.snapshot().get(key)?.ok_or("historical state")?;
        assert_eq!(bytes.first(), Some(&0));
        let actual: State = rmp_serde::from_slice(&bytes[1..])?;
        assert_eq!(&actual, wanted);
        let result = view.processor_result(&wanted.scope)?;
        if let Some(head) = &wanted.head {
            let result = result.ok_or("historical result")?;
            assert_eq!(result.result_id, head.result_id);
            assert_eq!(result.commit_revision, head.commit_revision);
            assert_eq!(result.body, b"finding");
        } else {
            assert!(result.is_none());
        }
        if wanted.context != 0 {
            assert_eq!(
                view.context(&context.key)?,
                Some((context.clone(), wanted.context))
            );
        }
        view = store.read_at(actual.revision.checked_sub(1).ok_or("state revision")?)?;
    }
    assert!(view.snapshot().get(key)?.is_none());
    Ok(())
}

#[test]
fn processor_versions_commit_once() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: None,
    };
    let store = NativeStore::open_with_retention(&root, limits)?;
    let mut scope = scope();
    scope.processor_id = "history".into();
    let registered = store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    let journal = store.database().inner().journal_head()?;
    assert_eq!(
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?,
        registered
    );
    assert!(
        store
            .register_processor(&scope, ProcessorClassV1::Optional, 1)
            .is_err()
    );
    let mut denied = scope.clone();
    denied.processor_id = "denied".into();
    assert!(
        store
            .register_processor_guarded(&denied, ProcessorClassV1::Required, 1, || Err(
                Code::Conflict.error("history registration")
            ))
            .is_err()
    );
    assert_eq!(store.meta()?.commit_revision, registered);
    assert_eq!(store.database().inner().journal_head()?, journal);
    let key = {
        let view = store.view()?;
        let mut entries = view.snapshot().prefix(b"\0data/@progress/state/");
        let (key, _) = entries.next().ok_or("registered state")??;
        assert!(entries.next().is_none());
        key.to_vec()
    };
    store.accept_validated_batch(
        scope.identity.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 2,
            intake_utc_ns: 1_000_000_000,
            framed_records: b"onetwo".to_vec().into(),
            frame_ends: vec![3, 6],
        },
    )?;
    let mut context = super::super::attempts::context(1);
    context.key.owner_id = "processor-history".into();
    context.body = b"context".to_vec();
    let context_revision = store.commit_context(&context)?;
    assert!(store.read_at(registered)?.context(&context.key)?.is_none());
    let first = AnalysisResultCommitV1 {
        scope: scope.clone(),
        expected_cursor: 0,
        consumed_cursor: 1,
        coverage_revision: 0,
        context_revision,
        result_id: "first".into(),
        body: b"finding".to_vec(),
        created_utc_ns: 100,
        witnesses: Vec::new(),
        context_refs: vec![araphor_data::AnalysisContextRefV1 {
            key: context.key.clone(),
            commit_revision: context_revision,
        }],
    };
    let first_receipt = store.commit_result(&first)?;
    let journal = store.database().inner().journal_head()?;
    assert_eq!(store.commit_result(&first)?, first_receipt);
    assert_eq!(store.meta()?.commit_revision, first_receipt.commit_revision);
    assert_eq!(store.database().inner().journal_head()?, journal);
    let mut second = first.clone();
    second.result_id = "second".into();
    second.context_revision = 0;
    second.context_refs.clear();
    assert!(store.commit_result(&second).is_err());
    second.expected_cursor = 1;
    second.consumed_cursor = 2;
    let before = store.meta()?;
    store.set_commit_hook(AnalysisCommitStage::BeforeResultCommit, || {
        Err(Code::Conflict.error("history rollback"))
    })?;
    assert!(store.commit_result(&second).is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert_eq!(
        store
            .processor_result(&scope)?
            .ok_or("first result")?
            .result_id,
        "first"
    );
    let second_receipt = store.commit_result(&second)?;
    let retirement = ProcessorRetirementV1 {
        scope: scope.clone(),
        change_id: "history-retired".into(),
        reason: "Stop this processor.".into(),
        expected_cursor: 2,
        cutoff_cursor: 2,
    };
    let retired = store.retire_required(&retirement)?;
    let journal = store.database().inner().journal_head()?;
    assert_eq!(store.retire_required(&retirement)?, retired);
    assert_eq!(store.meta()?.commit_revision, retired);
    assert_eq!(store.database().inner().journal_head()?, journal);
    let initial = State {
        scope: scope.clone(),
        class: ProcessorClassV1::Required,
        start: 1,
        consumed: 0,
        resumed: 0,
        coverage: 0,
        context: 0,
        required: 0,
        head: None,
        retirement: None,
        revision: registered,
    };
    let first_state = State {
        consumed: 1,
        required: 1,
        context: context_revision,
        head: Some(araphor_data::analysis::PackageResultRefV1 {
            result_id: "first".into(),
            commit_revision: first_receipt.commit_revision,
        }),
        revision: first_receipt.commit_revision,
        ..initial.clone()
    };
    let second_state = State {
        consumed: 2,
        required: 2,
        head: Some(araphor_data::analysis::PackageResultRefV1 {
            result_id: "second".into(),
            commit_revision: second_receipt.commit_revision,
        }),
        revision: second_receipt.commit_revision,
        ..initial.clone()
    };
    let retired_state = State {
        retirement: Some((retirement, retired)),
        revision: retired,
        ..second_state.clone()
    };
    let expected = [initial, first_state, second_state, retired_state];
    check_history(&store, &key, &expected, &context)?;
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&scope.identity, 10_000_000_000)?
            .removed_records,
        2
    );
    check_history(&store, &key, &expected, &context)?;
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open_with_retention(&root, limits)?;
    check_history(&store, &key, &expected, &context)?;
    Ok(())
}
