use super::*;

fn managers() -> Vec<InvestigateGrant> {
    vec![InvestigateGrant {
        subject: "alice".into(),
        tenant_id: Uuid::from_bytes([1; 16]).to_string(),
    }]
}

#[test]
fn package_permission_is_explicit() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    let session = super::super::tests::session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let inspect = access.package_grant(selection.clone(), PackageActionV1::Inspect)?;
    owner.check_package(&inspect, PackageActionV1::Inspect)?;
    assert!(access
        .package_grant(selection.clone(), PackageActionV1::Install)
        .is_err());
    owner.replace_package_managers(managers())?;
    let grant = access.package_grant(selection, PackageActionV1::Install)?;
    assert_ne!(
        grant.authorization_id.as_deref(),
        Some(session.token.as_str())
    );
    owner.check_package(&grant, PackageActionV1::Run)?;
    let mut changes = PackageAuthorization::changes(owner.as_ref());
    owner.replace_package_managers(Vec::new())?;
    assert!(changes.has_changed()?);
    changes.borrow_and_update();
    assert!(owner.check_package(&grant, PackageActionV1::Run).is_err());
    owner.replace_package_managers(managers())?;
    assert!(owner.check_package(&grant, PackageActionV1::Run).is_err());
    Ok(())
}

#[test]
fn package_logout_revokes_grant() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    owner.replace_package_managers(managers())?;
    let session = super::super::tests::session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let grant = access.package_grant(AnalysisSelectionV1::tenant([1; 16]), PackageActionV1::Run)?;
    owner.check_package(&grant, PackageActionV1::Run)?;
    owner.logout(&session.token, &owner.origin, &session.csrf)?;
    assert!(owner.check_package(&grant, PackageActionV1::Run).is_err());
    Ok(())
}

#[test]
fn package_tenant_trust_pins() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    let pin = PackageTrustPinV1 {
        tenant_id: Uuid::from_bytes([1; 16]).to_string(),
        bundle_digest: "a".repeat(64),
    };
    owner.replace_package_trust(vec![pin.clone()])?;
    let state = owner.state()?;
    assert!(state
        .package_trust
        .contains(&([1; 16], pin.bundle_digest.clone())));
    assert!(!state
        .package_trust
        .contains(&([2; 16], pin.bundle_digest.clone())));
    drop(state);
    assert!(owner
        .replace_package_trust(vec![pin.clone(), pin.clone()])
        .is_err());
    let mut invalid = pin;
    invalid.bundle_digest = "A".repeat(64);
    assert!(owner.replace_package_trust(vec![invalid]).is_err());
    Ok(())
}

#[test]
fn package_commit_holds_authority() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let owner = super::super::tests::owner()?;
    owner.replace_package_managers(managers())?;
    let session = super::super::tests::session(&owner)?;
    let access = owner.browser(&session.token, [1; 16], &owner.origin, None, false)?;
    let grant = access.package_grant(AnalysisSelectionV1::tenant([1; 16]), PackageActionV1::Run)?;
    let bundle = PackageBundleV1 {
        schema_version: 1,
        root: araphor_data::PackageRefV1 {
            package_id: "lock-fixture".into(),
            revision: "1".into(),
        },
        artifacts: Vec::new(),
    };
    owner.replace_package_trust(vec![PackageTrustPinV1 {
        tenant_id: Uuid::from_bytes([1; 16]).to_string(),
        bundle_digest: bundle.digest()?,
    }])?;
    let mut committed = false;
    owner.commit(&grant, PackageActionV1::Run, &bundle, &mut || {
        assert!(matches!(
            owner.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        committed = true;
        Ok(())
    })?;
    assert!(committed);
    owner.replace_package_trust(Vec::new())?;
    committed = false;
    assert!(owner
        .commit(&grant, PackageActionV1::Run, &bundle, &mut || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    owner.commit(&grant, PackageActionV1::Remove, &bundle, &mut || {
        committed = true;
        Ok(())
    })?;
    assert!(committed);
    owner.replace_package_managers(Vec::new())?;
    assert!(owner
        .commit(&grant, PackageActionV1::Remove, &bundle, &mut || Ok(()))
        .is_err());
    Ok(())
}
