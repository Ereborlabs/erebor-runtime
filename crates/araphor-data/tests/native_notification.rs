

use araphor_data::{
    analysis::{native::NativeStore, NotificationLookup},
    AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1, NotificationAttemptV1,
    NotificationDeliveryKindV1, NotificationFindingRefV1, NotificationKeyV1,
    NotificationObligationV1, NotificationPriorityV1, NotificationRouteRefV1,
    NotificationSinkHealthV1, PackageErrorCodeV1 as Code, UnconfirmedNotificationConcernV1,
    NOTIFICATION_STATE_OWNER,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn state(id: u128) -> NotificationObligationV1 {
    NotificationObligationV1 {
        schema_version: 1,
        key: NotificationKeyV1 {
            tenant_id: [1; 16],
            notification_id: id.to_be_bytes(),
        },
        revision: 1,
        finding: Some(NotificationFindingRefV1 {
            finding_id: "finding-a".into(),
            result_id: "result-a".into(),
        }),
        unconfirmed_concern: None,
        finding_revision: 1,
        package_id: "package".into(),
        required_action: None,
        sensitivity: ContextSensitivityV1::Tenant,
        source_priority: NotificationPriorityV1::Info,
        minimum_priority: NotificationPriorityV1::Info,
        route: Some(NotificationRouteRefV1 {
            route_id: "route".into(),
            revision: 1,
        }),
        escalation: None,
        first_seen_utc_ns: 1,
        deadline_utc_ns: Some(100),
        overdue_since_utc_ns: None,
        attempt_sequence: 0,
        attempts: Vec::new(),
        sink_health: NotificationSinkHealthV1::Unknown,
        failure: None,
        human_acknowledgement: None,
        agent_receipt: None,
        advisory: None,
    }
}

fn context(state: &NotificationObligationV1) -> araphor_data::Result<AnalysisContextVersionV1> {
    Ok(AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: state.key.tenant_id,
            owner_id: NOTIFICATION_STATE_OWNER.into(),
            entity_key: state.key.notification_id.to_vec(),
            lifetime_key: b"obligation".to_vec(),
            owner_revision: state.revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: state.sensitivity,
        body: state.encode()?,
    })
}

#[test]
fn lookup_keeps_route_sentinel() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open_with_limits(&root, Default::default(), araphor_data::StorageLimitsV1 {
        notification_routes: Some(1), ..Default::default()
    })?;
    for id in 1..=5 { store.commit_context(&context(&state(id))?)?; }
    assert_eq!(store.notification_states([1; 16], NotificationLookup::Finding("finding-a", None))?.len(), 3);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.notification_states([1; 16], NotificationLookup::Finding("finding-a", None))?.len(), 5);
    Ok(())
}

#[test]
fn checked_batch_preserves_subject_pending_versions_and_rollback() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let mut subject = state(1);
    let first = context(&subject)?;
    subject.revision = 2;
    subject.finding_revision = 2;
    subject.finding.as_mut().ok_or("finding")?.result_id = "result-b".into();
    let captured = context(&subject)?;
    let mut pending = subject.clone();
    pending.revision = 3;
    pending.attempt_sequence = 1;
    pending.attempts.push(NotificationAttemptV1 {
        number: 1,
        kind: NotificationDeliveryKindV1::Finding,
        finding_revision: 2,
        context_revision: 2,
        priority: NotificationPriorityV1::Info,
        started_utc_ns: 5,
        completed_utc_ns: None,
        result: None,
    });
    let pending = context(&pending)?;
    let writes = vec![
        (first.clone(), 0),
        (captured.clone(), 1),
        (pending.clone(), 2),
    ];
    let before = store.view()?;
    let cursor = store.database().inner().journal_head()?;
    assert!(store
        .commit_contexts_checked(&writes, || Err(Code::Denied.error("guard")))
        .is_err());
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store
        .context_heads([1; 16], NOTIFICATION_STATE_OWNER, 1)?
        .is_empty());
    let mut bad = writes.clone();
    bad[2].1 = 8;
    assert!(store.commit_contexts_checked(&bad, || Ok(())).is_err());
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store
        .notification_states([1; 16], NotificationLookup::Finding("finding-a", None))?
        .is_empty());
    let refs = store.commit_contexts_checked(&writes, || Ok(()))?;
    assert!(refs
        .iter()
        .all(|reference| reference.commit_revision == refs[0].commit_revision));
    assert!(before
        .context_head_page([1; 16], NOTIFICATION_STATE_OWNER, None)?
        .is_empty());
    assert_eq!(
        store.context_version(&captured.key)?,
        Some(captured.clone())
    );
    assert_eq!(
        store.context_heads([1; 16], NOTIFICATION_STATE_OWNER, 1)?,
        vec![pending.clone()]
    );
    let loaded = NotificationObligationV1::try_from(
        &store.context_version(&pending.key)?.ok_or("pending")?,
    )?;
    assert!(loaded.pending(NotificationDeliveryKindV1::Finding));
    assert_eq!(
        loaded.attempts[0].context_revision,
        captured.key.owner_revision
    );
    let committed = store.view()?.revision();
    assert_eq!(store.commit_contexts_checked(&writes, || Ok(()))?, refs);
    assert_eq!(store.view()?.revision(), committed);
    let mut checked = false;
    assert!(store
        .commit_contexts_checked(&[], || {
            checked = true;
            Ok(())
        })?
        .is_empty());
    assert!(checked);
    store.database().inner().flush_memtables()?;
    store.database().inner().rotate_journal()?;
    store.database().inner().major_compact()?;
    drop(before);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.context_version(&captured.key)?, Some(captured));
    assert_eq!(
        store.notification_states([1; 16], NotificationLookup::Finding("finding-a", None))?,
        vec![pending]
    );
    Ok(())
}

#[test]
fn current_lookups_move_atomically_and_historical_inserts_do_not_move_them() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let mut a = state(1);
    let first = context(&a)?;
    let mut b = state(2);
    b.key.tenant_id = [2; 16];
    store.commit_contexts(&[first.clone(), context(&b)?])?;
    let old = store.view()?;
    let old_revision = old.revision();
    a.revision = 7;
    a.finding.as_mut().ok_or("finding")?.finding_id = "finding-b".into();
    a.required_action = Some("inspect".into());
    let current = context(&a)?;
    store.commit_context(&current)?;
    let mut historical = a.clone();
    historical.revision = 5;
    historical.required_action = None;
    historical.finding.as_mut().ok_or("finding")?.finding_id = "historical".into();
    store.commit_context(&context(&historical)?)?;
    assert!(store
        .notification_states([1; 16], NotificationLookup::Finding("finding-a", None))?
        .is_empty());
    assert!(store
        .notification_states([1; 16], NotificationLookup::Finding("historical", None))?
        .is_empty());
    assert_eq!(
        store.notification_states(
            [1; 16],
            NotificationLookup::Finding("finding-b", Some("inspect"))
        )?,
        vec![current.clone()]
    );
    assert_eq!(
        old.notification_states([1; 16], NotificationLookup::Finding("finding-a", None))?,
        vec![first.clone()]
    );
    assert_eq!(
        store
            .read_at(old_revision)?
            .notification_states([1; 16], NotificationLookup::Finding("finding-a", None))?,
        vec![first.clone()]
    );
    assert_eq!(
        store.notification_states([2; 16], NotificationLookup::Finding("finding-a", None))?,
        vec![context(&b)?]
    );
    a.revision = 8;
    a.required_action = None;
    a.finding = None;
    a.unconfirmed_concern = Some(UnconfirmedNotificationConcernV1 {
        concern_id: [7; 16],
        model_label: "model".into(),
        summary: "summary".into(),
        context: Vec::new(),
        sensitivity: ContextSensitivityV1::Tenant,
        suggested_priority: NotificationPriorityV1::Info,
    });
    let concern = context(&a)?;
    store.commit_context_checked(&concern, 7)?;
    assert!(store
        .notification_states(
            [1; 16],
            NotificationLookup::Finding("finding-b", Some("inspect"))
        )?
        .is_empty());
    assert_eq!(
        store.notification_states([1; 16], NotificationLookup::Concern([7; 16], "route"))?,
        vec![concern.clone()]
    );
    assert!(store
        .notification_states([1; 16], NotificationLookup::Concern([7; 16], "other"))?
        .is_empty());
    assert!(store
        .notification_states([0; 16], NotificationLookup::Finding("finding-a", None))
        .is_err());
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(old);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.notification_states([1; 16], NotificationLookup::Concern([7; 16], "route"))?,
        vec![concern]
    );
    assert_eq!(
        store
            .read_at(old_revision)?
            .notification_states([1; 16], NotificationLookup::Finding("finding-a", None))?,
        vec![first]
    );
    Ok(())
}

#[test]
fn lookup_keys_keep_long_finding_identity_and_recovery_checks_postings() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let finding = format!("[quoted\\value]{}", "a".repeat(80000));
    let mut a = state(1);
    a.finding.as_mut().ok_or("finding")?.finding_id = finding.clone();
    let first = context(&a)?;
    store.commit_context(&first)?;
    assert_eq!(
        store.notification_states([1; 16], NotificationLookup::Finding(&finding, None))?,
        vec![first]
    );
    let key = store
        .view()?
        .snapshot()
        .prefix(b"\0data/notice/")
        .next()
        .ok_or("posting")??
        .0;
    let mut tx = store.write()?;
    tx.native().remove(key);
    tx.commit([])?;
    drop(store);
    assert!(NativeStore::open(&root).is_err());
    Ok(())
}
