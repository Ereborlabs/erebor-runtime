use super::super::*;
use NotificationDeliveryKindV1::{AcknowledgementEscalation, Finding};
use NotificationFailureV1::TransportFailed;

mod ack;
mod authority;
mod delivery;
mod restart;
mod route;

const NOW: u64 = 1_791_400_000_000_000_000;

impl ReplayQualification {
    fn notification_input(&self) -> crate::platform::TestResult<EvidenceIntakeIdentityV1> {
        self.accept(
            3,
            &[
                GraphNotificationQualification::native(1, true),
                GraphNotificationQualification::native(2, false),
            ],
        )
    }

    fn notification_policy(&self, route: &str, package: &str) -> NotificationPolicyV1 {
        NotificationPolicyV1 {
            tenant_id: self.authenticated.tenant_id,
            route_id: route.into(),
            revision: 1,
            package_ids: vec![package.into()],
            minimum_priority: NotificationPriorityV1::Critical,
            acknowledgement_ns: 100,
            retry_limit: 3,
            retry_delay_ns: 10,
            escalation_route_id: "human".into(),
            max_sensitivity: ContextSensitivityV1::Tenant,
            allow_concerns: false,
        }
    }

    fn notification_router(
        &self,
        grants: &[NotificationGrantV1],
    ) -> crate::platform::TestResult<(ControlStore, NotificationRouter)> {
        let store = ControlStore::open(self.root.path().join("notification-control"))?;
        let authority = Arc::new(ConfiguredNotificationAuthority::new(
            store.clone(),
            grants,
            None,
        )?);
        let router = NotificationRouter::new(self.data.clone(), authority)?;
        Ok((store, router))
    }
}
