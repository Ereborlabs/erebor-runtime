use super::*;

#[test]
fn captured_profile_contexts_atomic() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let profile = profile();
    store.accept_validated_batch(
        profile.scope.identity.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        },
    )?;
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    let context = crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: profile.scope.identity.tenant_id,
            owner_id: "profile-input-test".into(),
            entity_key: b"immutable-input".to_vec(),
            lifetime_key: b"captured".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: b"exact-input".to_vec(),
    };
    let before = store.meta()?;
    let mut changes = store.subscribe_revision();
    let control = std::sync::Arc::new(crate::AnalysisReadControl::default());
    let cancelled = std::sync::Arc::clone(&control);
    store.set_commit_hook(crate::AnalysisCommitStage::BeforeResultCommit, move || {
        cancelled.cancel()
    })?;
    assert!(matches!(
        store.commit_working_profile_guarded(
            commit(&profile),
            PreparedProfile::captured(profile.clone(), vec![context.clone()])?,
            None,
            || control.check(),
        ),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.context_version(&context.key)?, None);
    assert_eq!(store.processor_result(&profile.scope)?, None);
    assert!(!changes.has_changed()?);
    let receipt = store.commit_working_profile_guarded(
        commit(&profile),
        PreparedProfile::captured(profile.clone(), vec![context.clone()])?,
        None,
        || Ok(()),
    )?;
    changes.borrow_and_update();
    let retained = store
        .processor_result(&profile.scope)?
        .ok_or("profile absent")?;
    let captured = DiscoveryProfileV1::try_from(retained.body.as_slice())?;
    assert_eq!(store.context_version(&context.key)?, Some(context.clone()));
    let revision: u64 = store.reader()?.get()?.query_row(
        "SELECT commit_revision FROM context_versions WHERE owner_id = ?",
        duckdb::params![context.key.owner_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        captured.context_refs,
        [crate::AnalysisContextRefV1 {
            key: context.key.clone(),
            commit_revision: revision
        }]
    );
    let (request,): (Vec<u8>,) = store.reader()?.get()?.query_row(
        "SELECT request_meta FROM analysis_results WHERE result_id = ?",
        duckdb::params![profile.profile_id],
        |row| Ok((row.get(0)?,)),
    )?;
    assert_eq!(
        AnalysisResultCommitV1::request_refs(&request)?.1,
        captured.context_refs
    );
    let committed = store.meta()?;
    assert_eq!(
        store.commit_working_profile_guarded(
            commit(&profile),
            PreparedProfile::captured(profile.clone(), vec![context.clone()])?,
            None,
            || Ok(()),
        )?,
        receipt
    );
    assert_eq!(store.meta()?, committed);
    assert!(!changes.has_changed()?);
    let mut changed = context;
    changed.body.push(1);
    assert!(store
        .commit_working_profile_guarded(
            commit(&profile),
            PreparedProfile::captured(profile.clone(), vec![changed])?,
            None,
            || Ok(()),
        )
        .is_err());
    assert_eq!(store.meta()?, committed);
    assert!(!changes.has_changed()?);
    drop(store);
    assert_eq!(
        AnalysisStore::open(root)?.processor_result(&profile.scope)?,
        Some(retained)
    );
    Ok(())
}
