use super::*;

fn notice_at(
    store: &AnalysisStore,
    profile: &DiscoveryProfileV1,
    revision: u64,
) -> Result<Option<(u64, u64)>> {
    store.read_snapshot(|reader| {
        reader
            .query_row(
                &format!(
                    "SELECT facts_revision, coverage_revision FROM ({}) WHERE tenant_id = ? AND result_id = ?",
                    AnalysisStore::result_state("main", Some(revision))
                ),
                params![profile.scope.identity.tenant_id.as_slice(), profile.profile_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(crate::AnalysisDatabaseSnafu {
                operation: "read historical profile notice test",
            })
    })
}

#[test]
fn notices_keep_each_interval() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let mut first = profile();
    first.sealed = true;
    store.accept_validated_batch(
        first.scope.identity.clone(),
        crate::analysis::tests::batch(1, &[b"one"]),
    )?;
    store.register_processor(&first.scope, ProcessorClassV1::Optional, 1)?;
    let original =
        store.commit_working_profile(commit(&first), PreparedProfile::new(first.clone())?, None)?;
    let prior = PackageResultRefV1 {
        result_id: first.profile_id.clone(),
        commit_revision: original.commit_revision,
    };
    let mut second = first.clone();
    second.profile_id = "profile-b".into();
    second.interval_id = "interval-b".into();
    second.sealed = false;
    second.created_utc_ns = 20;
    second.updated_utc_ns = 20;
    let current = store.commit_working_profile(
        commit(&second),
        PreparedProfile::new(second.clone())?,
        Some(prior.clone()),
    )?;
    let frozen = [
        store.frozen_result(&first.profile_id)?,
        store.frozen_result(&second.profile_id)?,
    ];
    let head = store.processor_result(&first.scope)?;
    let mut health = store.processor_health(&first.scope)?;
    let mut changes = store.subscribe_revision();
    store.mark_notice(&first, original.commit_revision, 4, 3)?;
    let first_notice = store.meta()?.commit_revision;
    assert_eq!(first_notice, current.commit_revision + 1);
    assert!(changes.has_changed()?);
    changes.borrow_and_update();
    store.mark_notice(&second, current.commit_revision, 9, 2)?;
    let second_notice = store.meta()?.commit_revision;
    assert_eq!(second_notice, first_notice + 1);
    assert!(changes.has_changed()?);
    changes.borrow_and_update();
    store.mark_notice(&first, original.commit_revision, 2, 1)?;
    assert_eq!(store.meta()?.commit_revision, second_notice);
    assert!(!changes.has_changed()?);
    assert_eq!(
        notice_at(&store, &first, original.commit_revision)?,
        Some((0, 0))
    );
    assert_eq!(notice_at(&store, &second, original.commit_revision)?, None);
    assert_eq!(notice_at(&store, &first, first_notice)?, Some((4, 3)));
    assert_eq!(notice_at(&store, &second, first_notice)?, Some((0, 0)));
    assert_eq!(notice_at(&store, &first, second_notice)?, Some((4, 3)));
    assert_eq!(notice_at(&store, &second, second_notice)?, Some((9, 2)));
    assert_eq!(store.processor_result(&first.scope)?, head);
    health.as_mut().ok_or("processor health")?.read_revision = second_notice;
    assert_eq!(store.processor_health(&first.scope)?, health);
    assert_eq!(store.frozen_result(&first.profile_id)?, frozen[0]);
    assert_eq!(store.frozen_result(&second.profile_id)?, frozen[1]);
    assert_eq!(
        store.commit_working_profile(commit(&first), PreparedProfile::new(first.clone())?, None)?,
        original
    );
    let mut third = second.clone();
    third.profile_id = "profile-c".into();
    third.revision += 1;
    third.updated_utc_ns += 1;
    assert!(store
        .commit_working_profile(
            commit(&third),
            PreparedProfile::new(third.clone())?,
            Some(prior)
        )
        .is_err());
    assert_eq!(store.meta()?.commit_revision, second_notice);
    assert!(store
        .read_result(third.scope.identity.tenant_id, &third.profile_id)?
        .is_none());
    assert!(store
        .commit_working_profile(
            commit(&third),
            PreparedProfile::new(third.clone())?,
            Some(PackageResultRefV1 {
                result_id: second.profile_id.clone(),
                commit_revision: first_notice,
            }),
        )
        .is_err());
    assert_eq!(store.meta()?.commit_revision, second_notice);
    let mut rewritten = first.clone();
    rewritten.revision += 1;
    rewritten.updated_utc_ns += 1;
    assert!(store
        .commit_working_profile(
            commit(&rewritten),
            PreparedProfile::new(rewritten)?,
            Some(PackageResultRefV1 {
                result_id: second.profile_id.clone(),
                commit_revision: current.commit_revision,
            }),
        )
        .is_err());
    assert_eq!(store.meta()?.commit_revision, second_notice);
    assert_eq!(store.frozen_result(&first.profile_id)?, frozen[0]);
    AnalysisStore::validate_state(store.writer()?.get()?, &root)?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(notice_at(&store, &first, first_notice)?, Some((4, 3)));
    assert_eq!(notice_at(&store, &second, first_notice)?, Some((0, 0)));
    assert_eq!(store.frozen_result(&first.profile_id)?, frozen[0]);
    assert_eq!(store.frozen_result(&second.profile_id)?, frozen[1]);
    Ok(())
}
