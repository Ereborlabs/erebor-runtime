use super::*;
use crate :: { AnalysisCommitStage , EvidenceRetentionOwner , ProcessorRetirementV1 , RetentionLimitsV1 } ;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn versions(store: &AnalysisStore) -> Result<Vec<(u64, u64, bool, String)>> {
    store.read_snapshot(|reader| {
        reader
            .prepare(
                "SELECT commit_revision, consumed_cursor, retired, result_id
                 FROM processor_versions ORDER BY commit_revision",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare processor history test",
            })?
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read processor history test",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode processor history test",
            })
    })
}

#[test]
fn processor_versions_commit_once() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: None,
    };
    let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
    let scope = ProcessorScopeV1 {
        processor_id: "history".into(),
        method_version: 1,
        identity: crate::analysis::tests::identity(),
    };
    let registered = store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    assert_eq!(
        versions(&store)?,
        vec![(registered, 0, false, String::new())]
    );
    assert_eq!(
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?,
        registered
    );
    assert!(store
        .register_processor(&scope, ProcessorClassV1::Optional, 1)
        .is_err());
    let mut rejected = scope.clone();
    rejected.processor_id = "denied".into();
    assert!(store
        .register_processor_guarded(&rejected, ProcessorClassV1::Required, 1, || {
            AnalysisConflictSnafu.fail()
        })
        .is_err());
    assert_eq!(versions(&store)?.len(), 1);
    assert!(store
        .writer()?
        .get()?
        .execute(
            "INSERT INTO processor_versions SELECT * FROM processor_versions",
            []
        )
        .is_err());
    assert_eq!(versions(&store)?.len(), 1);
    store.accept_validated_batch(
        scope.identity.clone(),
        crate::analysis::tests::batch(1, &[b"one", b"two"]),
    )?;
    let context = crate::AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: scope.identity.tenant_id,
            owner_id: "processor-history".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: b"context".to_vec(),
    };
    let context_revision = store.commit_context(&context)?;
    let mut first = crate::analysis::tests::result(scope.clone(), "first".into());
    first.context_revision = context_revision;
    first.context_refs.push(AnalysisContextRefV1 {
        key: context.key,
        commit_revision: context_revision,
    });
    let first_receipt = store.commit_result(&first)?;
    assert_eq!(store.commit_result(&first)?, first_receipt);
    let mut second = crate::analysis::tests::result(scope.clone(), "second".into());
    assert!(store.commit_result(&second).is_err());
    second.expected_cursor = 1;
    second.consumed_cursor = 2;
    let before = store.meta()?;
    store.set_commit_hook(AnalysisCommitStage::BeforeResultCommit, || {
        AnalysisConflictSnafu.fail()
    })?;
    assert!(store.commit_result(&second).is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(versions(&store)?.len(), 2);
    assert_eq!(
        store
            .processor_result(&scope)?
            .ok_or("processor result")?
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
    assert_eq!(store.retire_required(&retirement)?, retired);
    let expected = vec![
        (registered, 0, false, String::new()),
        (first_receipt.commit_revision, 1, false, "first".into()),
        (second_receipt.commit_revision, 2, false, "second".into()),
        (retired, 2, true, "second".into()),
    ];
    assert_eq!(versions(&store)?, expected);
    assert_eq!(
        store.writer()?.get()?.query_row(
            "SELECT context_revision FROM processor_versions WHERE result_id = 'first'",
            [],
            |row| row.get::<_, u64>(0),
        )?,
        context_revision
    );
    assert_eq!(
        store.writer()?.get()?.query_row(
            "SELECT context_revision FROM processor_progress",
            [],
            |row| row.get::<_, u64>(0),
        )?,
        0
    );
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&scope.identity, 10_000_000_000)?
            .removed_records,
        2
    );
    AnalysisStore::validate_state(store.writer()?.get()?, &root)?;
    drop(store);
    let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
    assert_eq!(versions(&store)?, expected);
    let mut writer = store.writer()?;
    for mutation in [
        "UPDATE processor_versions SET start_cursor = 2 WHERE result_id = ''",
        "UPDATE processor_versions SET class = 'optional' WHERE result_id = ''",
        "UPDATE processor_versions SET consumed_cursor = 0, required_floor = 0 WHERE result_id = 'second' AND NOT retired",
        "UPDATE processor_versions SET retirement_revision = retirement_revision - 1 WHERE retired",
        "UPDATE processor_versions SET commit_revision = 0 WHERE result_id = ''",
    ] {
        let transaction = writer.get_mut()?.transaction()?;
        assert_eq!(transaction.execute(mutation, [])?, 1, "{mutation}");
        assert!(AnalysisStore::validate_state(&transaction, &root).is_err(), "{mutation}");
        transaction.rollback()?;
    }
    AnalysisStore::validate_state(writer.get()?, &root)?;
    Ok(())
}
