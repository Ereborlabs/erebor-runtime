use araphor_data::*;

use super::*;

mod limits;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn control_notification_revocation_survives_restart_and_requires_new_revision() -> TestResult {
    let dir = tempfile::tempdir()?;
    let grant = NotificationGrantV1 {
        tenant_id: [1; 16],
        principal_id: [2; 16],
        principal: NotificationPrincipalV1::Human,
        authorization_revision: 1,
        routes: vec!["route".into()],
        operations: vec![NotificationOperationV1::Read],
        max_sensitivity: ContextSensitivityV1::Tenant,
        expires_utc_ns: 1000,
    };
    {
        let owner = ConfiguredNotificationAuthority::new(
            crate::ControlStore::open(dir.path())?,
            std::slice::from_ref(&grant),
            None,
        )?;
        owner.check(&grant, 100)?;
        owner.revoke(grant.tenant_id, grant.principal_id, 1)?;
        assert!(owner.check(&grant, 100).is_err());
    }
    let owner = ConfiguredNotificationAuthority::new(
        crate::ControlStore::open(dir.path())?,
        std::slice::from_ref(&grant),
        None,
    )?;
    assert!(owner.check(&grant, 101).is_err());
    assert!(owner.replace(grant.clone()).is_err());
    let mut next = grant.clone();
    next.authorization_revision = 2;
    owner.replace(next.clone())?;
    assert!(owner.check(&grant, 102).is_err());
    owner.check(&next, 102)?;
    Ok(())
}

pub(crate) fn grant(tenant: [u8; 16]) -> NotificationGrantV1 {
    NotificationGrantV1 {
        tenant_id: tenant,
        principal_id: [9; 16],
        principal: NotificationPrincipalV1::Agent,
        authorization_revision: 1,
        routes: vec!["escalation".into(), "primary".into()],
        operations: vec![
            NotificationOperationV1::Configure,
            NotificationOperationV1::Read,
            NotificationOperationV1::SubmitConcern,
        ],
        max_sensitivity: ContextSensitivityV1::HostRestricted,
        expires_utc_ns: 1000,
    }
}

pub(crate) fn policy(tenant: [u8; 16], route: &str) -> NotificationPolicyV1 {
    NotificationPolicyV1 {
        tenant_id: tenant,
        route_id: route.into(),
        revision: 1,
        package_ids: vec![if route == "primary" {
            "HF-PROC-001".into()
        } else {
            "HF-XNODE-001".into()
        }],
        minimum_priority: NotificationPriorityV1::High,
        acknowledgement_ns: 100,
        retry_limit: 4,
        retry_delay_ns: 1,
        escalation_route_id: "escalation".into(),
        max_sensitivity: ContextSensitivityV1::HostRestricted,
        allow_concerns: true,
    }
}
