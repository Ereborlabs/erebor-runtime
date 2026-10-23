use super::*;

#[test]
fn notification_counts_unlimited() -> TestResult {
    let mut config: NotificationControlConfigV1 = serde_json::from_str("{}")?;
    assert_eq!(config.grant_limit, None);
    assert_eq!(config.route_limit, None);
    for number in 1..=257u128 {
        let tenant = number.to_be_bytes();
        config.grants.push(grant(tenant));
        config.routes.push(policy(tenant, "primary"));
    }
    config.validate()?;
    let dir = tempfile::tempdir()?;
    let store = crate::ControlStore::open(dir.path().join("control"))?;
    let data = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let owner = ControlNotificationOwner::new(store.clone(), data, config, 10)?;
    assert_eq!(store.authority_state()?.notification_grants.len(), 257);
    let last = grant(257u128.to_be_bytes());
    owner.authority().check(&last, 10)?;
    assert_eq!(owner.router().health(&last, 10)?.configured_routes, 1);
    let added = grant(258u128.to_be_bytes());
    owner.authority().replace(added.clone())?;
    owner.authority().check(&added, 10)?;
    assert_eq!(store.authority_state()?.notification_grants.len(), 258);
    Ok(())
}

#[test]
fn notification_count_rejections_atomic() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("control");
    let store = crate::ControlStore::open(&path)?;
    let data = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let owner = ControlNotificationOwner::new(
        store.clone(),
        Arc::clone(&data),
        NotificationControlConfigV1 {
            grants: vec![grant([1; 16]), grant([2; 16])],
            routes: vec![policy([1; 16], "primary")],
            ..Default::default()
        },
        10,
    )?;
    let saved = store.authority_state()?;
    let meta = data.meta()?;
    let mut invalid = grant([3; 16]);
    invalid.principal_id = [0; 16];
    for config in [
        NotificationControlConfigV1 {
            grants: vec![grant([3; 16])],
            grant_limit: Some(0),
            ..Default::default()
        },
        NotificationControlConfigV1 {
            routes: vec![policy([1; 16], "primary")],
            route_limit: Some(0),
            ..Default::default()
        },
        NotificationControlConfigV1 {
            grants: vec![grant([3; 16]), grant([4; 16])],
            grant_limit: Some(1),
            ..Default::default()
        },
        NotificationControlConfigV1 {
            grants: vec![grant([1; 16])],
            routes: vec![policy([1; 16], "primary"), policy([1; 16], "escalation")],
            route_limit: Some(1),
            ..Default::default()
        },
        NotificationControlConfigV1 {
            grants: vec![grant([3; 16])],
            grant_limit: Some(2),
            ..Default::default()
        },
        NotificationControlConfigV1 {
            grant_limit: Some(1),
            ..Default::default()
        },
        NotificationControlConfigV1 {
            grants: vec![grant([3; 16]), grant([3; 16])],
            ..Default::default()
        },
        NotificationControlConfigV1 {
            routes: vec![policy([1; 16], "primary"), policy([1; 16], "primary")],
            ..Default::default()
        },
        NotificationControlConfigV1 {
            grants: vec![invalid],
            ..Default::default()
        },
    ] {
        assert!(
            ControlNotificationOwner::new(store.clone(), Arc::clone(&data), config, 10).is_err()
        );
        assert_eq!(store.authority_state()?, saved);
        assert_eq!(data.meta()?, meta);
    }
    owner.authority().check(&grant([1; 16]), 10)?;
    owner.authority().check(&grant([2; 16]), 10)?;
    drop((owner, store));
    assert_eq!(crate::ControlStore::open(path)?.authority_state()?, saved);
    Ok(())
}

#[test]
fn grant_limit_keeps_revisions() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("control");
    let store = crate::ControlStore::open(&path)?;
    let first = grant([1; 16]);
    let empty = ConfiguredNotificationAuthority::new(store.clone(), &[], Some(0))?;
    let saved = store.authority_state()?;
    assert!(empty.replace(first.clone()).is_err());
    assert_eq!(store.authority_state()?, saved);
    let owner =
        ConfiguredNotificationAuthority::new(store.clone(), std::slice::from_ref(&first), Some(1))?;
    let full = store.authority_state()?;
    owner.replace(first.clone())?;
    assert_eq!(store.authority_state()?, full);
    assert!(owner.replace(grant([2; 16])).is_err());
    assert_eq!(store.authority_state()?, full);
    let mut next = first.clone();
    next.authorization_revision = 2;
    owner.replace(next.clone())?;
    owner.check(&next, 10)?;
    assert!(owner.check(&first, 10).is_err());
    let replaced = store.authority_state()?;
    assert_eq!(replaced.notification_grants.len(), 1);
    assert!(owner.replace(first).is_err());
    assert_eq!(store.authority_state()?, replaced);
    owner.revoke(next.tenant_id, next.principal_id, 2)?;
    let revoked = store.authority_state()?;
    assert!(owner.replace(next.clone()).is_err());
    assert!(owner.replace(grant([2; 16])).is_err());
    assert_eq!(store.authority_state()?, revoked);
    drop((empty, owner, store));
    let store = crate::ControlStore::open(path)?;
    let owner =
        ConfiguredNotificationAuthority::new(store.clone(), std::slice::from_ref(&next), Some(1))?;
    assert_eq!(store.authority_state()?, revoked);
    assert!(owner.check(&next, 10).is_err());
    next.authorization_revision = 3;
    owner.replace(next.clone())?;
    owner.check(&next, 10)?;
    assert_eq!(store.authority_state()?.notification_grants.len(), 1);
    Ok(())
}
