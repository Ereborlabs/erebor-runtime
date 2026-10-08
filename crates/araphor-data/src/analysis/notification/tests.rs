use super::*;
use crate::{AnalysisContextKeyV1, ContextSensitivityV1};

fn context(tenant: [u8; 16], entity: u32, body: serde_json::Value) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: tenant,
            owner_id: crate::NOTIFICATION_STATE_OWNER.into(),
            entity_key: entity.to_be_bytes().to_vec(),
            lifetime_key: b"obligation".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: body.to_string().into_bytes(),
    }
}

#[test]
fn control_notification_scoped_heads() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let tenant = [1; 16];
    let finding = "[\"seed\",\"quoted\\subject\"]";
    for entity in 1..=257 {
        let version = context(
            tenant,
            entity,
            serde_json::json!({
                "finding": {"finding_id": "other"}, "required_action": null
            }),
        );
        store.commit_context(&version)?;
    }
    let mut tail = context(
        tenant,
        257,
        serde_json::json!({
            "finding": {"finding_id": finding}, "required_action": "inspect"
        }),
    );
    tail.key.owner_revision = 2;
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
    let mut foreign = tail.clone();
    foreign.key.tenant_id = [2; 16];
    foreign.key.owner_revision = 1;
    foreign.body = b"not JSON".to_vec();
    store.commit_context(&foreign)?;
    assert_eq!(
        store.notification_states(tenant, lookup())?,
        vec![tail.clone()]
    );
    let mut current = tail.clone();
    current.key.owner_revision = 3;
    current.body = serde_json::json!({
        "finding": {"finding_id": "later"}, "required_action": null
    })
    .to_string()
    .into_bytes();
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
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let tenant = [1; 16];
    let concern = [7; 16];
    let mut version = context(
        tenant,
        1,
        serde_json::json!({
            "unconfirmed_concern": {"concern_id": concern},
            "route": {"route_id": "human"}
        }),
    );
    version.body =
        serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&version.body)?)?;
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
        store.commit_context(&context(
            tenant,
            entity,
            serde_json::json!({
                "finding": {"finding_id": "same"}, "required_action": null
            }),
        ))?;
    }
    assert_eq!(
        store
            .notification_states(tenant, NotificationLookup::Finding("same", None))?
            .len(),
        crate::MAX_NOTIFICATION_ROUTES + 2
    );
    Ok(())
}
