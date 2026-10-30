use super::*;
use crate::{
    AnalysisContextKeyV1, ContextSensitivityV1, NotificationFindingRefV1, NotificationKeyV1,
    NotificationPriorityV1, NotificationRouteRefV1, NotificationSinkHealthV1,
    UnconfirmedNotificationConcernV1,
};

enum Subject<'a> {
    Finding(&'a str, Option<&'a str>),
    Concern([u8; 16], &'a str),
}

fn context(
    tenant: [u8; 16],
    entity: u32,
    revision: u64,
    subject: Subject<'_>,
) -> Result<AnalysisContextVersionV1> {
    let (finding, unconfirmed_concern, required_action, route) = match subject {
        Subject::Finding(id, action) => (
            Some(NotificationFindingRefV1 {
                finding_id: id.into(),
                result_id: "result".into(),
            }),
            None,
            action.map(str::to_string),
            None,
        ),
        Subject::Concern(id, route) => (
            None,
            Some(UnconfirmedNotificationConcernV1 {
                concern_id: id,
                model_label: "model".into(),
                summary: "summary".into(),
                context: vec![],
                sensitivity: ContextSensitivityV1::Tenant,
                suggested_priority: NotificationPriorityV1::Info,
            }),
            None,
            Some(NotificationRouteRefV1 {
                route_id: route.into(),
                revision: 1,
            }),
        ),
    };
    let state = NotificationObligationV1 {
        schema_version: 1,
        key: NotificationKeyV1 {
            tenant_id: tenant,
            notification_id: u128::from(entity).to_be_bytes(),
        },
        revision,
        finding,
        unconfirmed_concern,
        finding_revision: 1,
        package_id: "package".into(),
        required_action,
        sensitivity: ContextSensitivityV1::Tenant,
        source_priority: NotificationPriorityV1::Info,
        minimum_priority: NotificationPriorityV1::Info,
        route,
        escalation: None,
        first_seen_utc_ns: 1,
        deadline_utc_ns: None,
        overdue_since_utc_ns: None,
        attempt_sequence: 0,
        attempts: vec![],
        sink_health: NotificationSinkHealthV1::Unknown,
        failure: None,
        human_acknowledgement: None,
        agent_receipt: None,
        advisory: None,
    };
    Ok(AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: tenant,
            owner_id: crate::NOTIFICATION_STATE_OWNER.into(),
            entity_key: state.key.notification_id.to_vec(),
            lifetime_key: b"obligation".to_vec(),
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: state.sensitivity,
        body: state.encode()?,
    })
}

#[test]
fn control_notification_scoped_heads() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let tenant = [1; 16];
    let finding = "[\"seed\",\"quoted\\subject\"]";
    for entity in 1..=257 {
        let version = context(tenant, entity, 1, Subject::Finding("other", None))?;
        store.commit_context(&version)?;
    }
    let tail = context(tenant, 257, 2, Subject::Finding(finding, Some("inspect")))?;
    store.commit_context_checked(&tail, 1)?;
    let lookup = || NotificationLookup::Finding(finding, Some("inspect"));
    assert_eq!(
        store.notification_states(tenant, lookup())?,
        vec![tail.clone()]
    );
    assert!(store.notification_states([2; 16], lookup())?.is_empty());
    assert!(store
        .notification_states(tenant, NotificationLookup::Finding(finding, None))?
        .is_empty());
    let foreign = context([2; 16], 257, 1, Subject::Finding(finding, Some("inspect")))?;
    store.commit_context(&foreign)?;
    assert_eq!(
        store.notification_states(tenant, lookup())?,
        vec![tail.clone()]
    );
    let current = context(tenant, 257, 3, Subject::Finding("later", None))?;
    store.commit_context_checked(&current, 2)?;
    assert!(store.notification_states(tenant, lookup())?.is_empty());
    assert_eq!(
        store.notification_states(tenant, NotificationLookup::Finding("later", None))?,
        vec![current]
    );
    assert_eq!(store.context_version(&tail.key)?, Some(tail));
    assert!(store.notification_states([0; 16], lookup()).is_err());
    Ok(())
}

#[test]
fn control_notification_scoped_concerns() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_limits(
        directory.path().join("analysis"),
        Default::default(),
        crate::StorageLimitsV1 {
            notification_routes: Some(32),
            ..Default::default()
        },
    )?;
    let tenant = [1; 16];
    let concern = [7; 16];
    let version = context(tenant, 1, 1, Subject::Concern(concern, "human"))?;
    store.commit_context(&version)?;
    assert_eq!(
        store.notification_states(tenant, NotificationLookup::Concern(concern, "human"))?,
        vec![version]
    );
    assert!(store
        .notification_states(tenant, NotificationLookup::Concern(concern, "other"))?
        .is_empty());
    assert!(store
        .notification_states(tenant, NotificationLookup::Concern([8; 16], "human"))?
        .is_empty());
    assert!(store
        .notification_states(tenant, NotificationLookup::Concern([0; 16], "human"))
        .is_err());
    for entity in 2..=40 {
        store.commit_context(&context(tenant, entity, 1, Subject::Finding("same", None))?)?;
    }
    assert_eq!(
        store
            .notification_states(tenant, NotificationLookup::Finding("same", None))?
            .len(),
        34
    );
    Ok(())
}

#[test]
fn notification_lookup_is_unbounded() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("analysis");
    let store = AnalysisStore::open(&path)?;
    for entity in 1..=40 {
        store.commit_context(&context(
            [1; 16],
            entity,
            1,
            Subject::Finding("same", None),
        )?)?;
    }
    assert_eq!(
        store
            .notification_states([1; 16], NotificationLookup::Finding("same", None))?
            .len(),
        40
    );
    drop(store);
    let store = AnalysisStore::open_with_limits(
        path,
        Default::default(),
        crate::StorageLimitsV1 {
            notification_routes: Some(usize::MAX),
            ..Default::default()
        },
    )?;
    assert_eq!(
        store
            .notification_states([1; 16], NotificationLookup::Finding("same", None))?
            .len(),
        40
    );
    Ok(())
}

#[test]
fn historical_notification_insert_keeps_current_head(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("analysis");
    let store = AnalysisStore::open(&path)?;
    let current = context([1; 16], 1, 3, Subject::Finding("current", None))?;
    store.commit_context(&current)?;
    let historical = context([1; 16], 1, 1, Subject::Finding("historical", None))?;
    store.commit_context(&historical)?;
    assert_eq!(
        store.context_head(
            [1; 16],
            crate::NOTIFICATION_STATE_OWNER,
            &current.key.entity_key,
            b"obligation",
        )?,
        Some(current.clone())
    );
    assert_eq!(
        store.notification_states([1; 16], NotificationLookup::Finding("current", None))?,
        vec![current.clone()]
    );
    assert!(store
        .notification_states([1; 16], NotificationLookup::Finding("historical", None))?
        .is_empty());
    drop(store);
    let reopened = AnalysisStore::open(&path)?;
    assert_eq!(
        reopened.notification_states([1; 16], NotificationLookup::Finding("current", None))?,
        vec![current]
    );
    Ok(())
}

#[test]
fn notification_head_read_keeps_generic_context_behavior(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let state = context([1; 16], 1, 1, Subject::Finding("first", None))?;
    assert!(store
        .context_head(
            [1; 16],
            crate::NOTIFICATION_STATE_OWNER,
            &state.key.entity_key,
            b"obligation",
        )?
        .is_none());
    store.commit_context(&state)?;
    let mut generic = state.clone();
    generic.key.owner_id = "generic".into();
    generic.key.lifetime_key = b"other".to_vec();
    generic.body = b"generic context".to_vec();
    store.commit_context(&generic)?;
    let mut latest = generic.clone();
    latest.key.owner_revision = 2;
    latest.body = b"next generic context".to_vec();
    store.commit_context(&latest)?;
    assert_eq!(
        store.context_head([1; 16], "generic", &state.key.entity_key, b"other")?,
        Some(latest)
    );
    assert_eq!(
        store.context_head(
            [1; 16],
            crate::NOTIFICATION_STATE_OWNER,
            &state.key.entity_key,
            b"obligation",
        )?,
        Some(state)
    );
    Ok(())
}

#[test]
fn notification_batch_advances_head_once_and_retry_is_stable(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let first = context([1; 16], 1, 1, Subject::Finding("first", None))?;
    let second = context([1; 16], 1, 2, Subject::Finding("second", None))?;
    let references = store.commit_contexts(&[first.clone(), second.clone()])?;
    assert_eq!(references[0].commit_revision, references[1].commit_revision);
    let revision = store.meta()?.commit_revision;
    assert_eq!(store.commit_context(&second)?, revision);
    assert_eq!(store.meta()?.commit_revision, revision);
    assert_eq!(store.context_version(&first.key)?, Some(first));
    assert_eq!(
        store.notification_states([1; 16], NotificationLookup::Finding("second", None))?,
        vec![second]
    );
    assert!(store
        .notification_states([1; 16], NotificationLookup::Finding("first", None))?
        .is_empty());
    Ok(())
}

#[test]
fn notification_head_rolls_back_conflicts_and_invalid_binary(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let first = context([1; 16], 1, 1, Subject::Finding("first", None))?;
    store.commit_context_checked(&first, 0)?;
    let revision = store.meta()?.commit_revision;
    let next = context([1; 16], 1, 2, Subject::Finding("next", None))?;
    assert!(store.commit_context_checked(&next, 0).is_err());
    let mut malformed = next.clone();
    malformed.body.push(0);
    assert!(store.commit_context_checked(&malformed, 1).is_err());
    assert_eq!(store.meta()?.commit_revision, revision);
    assert_eq!(
        store.notification_states([1; 16], NotificationLookup::Finding("first", None))?,
        vec![first]
    );
    store.commit_context_checked(&next, 1)?;
    assert_eq!(
        store.notification_states([1; 16], NotificationLookup::Finding("next", None))?,
        vec![next]
    );
    Ok(())
}

#[test]
fn notification_head_rejects_corrupt_indexes() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let faults = [
        ("DELETE FROM notification_heads", false),
        (
            "UPDATE notification_heads SET finding_key = 'wrong'::BLOB",
            false,
        ),
        (
            "UPDATE notification_heads SET commit_revision = commit_revision + 1",
            true,
        ),
        (
            "UPDATE context_versions SET version_key = 'wrong'::BLOB",
            true,
        ),
    ];
    for (fault, immediate) in faults {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("analysis");
        let store = AnalysisStore::open(&path)?;
        let state = context([1; 16], 1, 1, Subject::Finding("first", None))?;
        store.commit_context(&state)?;
        {
            let mut writer = store.writer()?;
            writer.get_mut()?.execute(fault, [])?;
        }
        if immediate {
            assert!(store
                .context_head(
                    [1; 16],
                    crate::NOTIFICATION_STATE_OWNER,
                    &state.key.entity_key,
                    b"obligation",
                )
                .is_err());
        }
        drop(store);
        assert!(AnalysisStore::open(&path).is_err());
    }
    Ok(())
}

#[test]
fn notification_head_write_failure_rolls_back_context_and_retry(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let first = context([1; 16], 1, 1, Subject::Finding("first", None))?;
    let competing = context([1; 16], 2, 2, Subject::Finding("other", None))?;
    let next = context([1; 16], 1, 2, Subject::Finding("next", None))?;
    store.commit_context(&first)?;
    store.commit_context(&competing)?;
    let before = store.meta()?.commit_revision;
    {
        let mut writer = store.writer()?;
        writer.get_mut()?.execute(
            "CREATE UNIQUE INDEX notification_failure_idx ON notification_heads(owner_revision)",
            [],
        )?;
    }
    assert!(store.commit_context_checked(&next, 1).is_err());
    assert_eq!(store.meta()?.commit_revision, before);
    assert!(store.context_version(&next.key)?.is_none());
    assert_eq!(
        store.notification_states([1; 16], NotificationLookup::Finding("first", None))?,
        vec![first]
    );
    assert_eq!(
        store.notification_states([1; 16], NotificationLookup::Finding("other", None))?,
        vec![competing]
    );
    {
        let mut writer = store.writer()?;
        writer
            .get_mut()?
            .execute("DROP INDEX notification_failure_idx", [])?;
    }
    store.commit_context_checked(&next, 1)?;
    assert_eq!(
        store.notification_states([1; 16], NotificationLookup::Finding("next", None))?,
        vec![next]
    );
    Ok(())
}
