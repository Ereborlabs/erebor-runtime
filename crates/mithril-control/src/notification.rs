use std::sync::Arc;

use araphor_analysis::NotificationRouter;
use araphor_data::{
    AnalysisStore, NotificationAuthorization, NotificationFailureV1, NotificationGrantV1,
    NotificationPolicyV1, NotificationSink, NotificationSinkResultV1,
};
use serde::Deserialize;

use crate::Result;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationControlConfigV1 {
    pub grants: Vec<NotificationGrantV1>,
    pub routes: Vec<NotificationPolicyV1>,
    pub grant_limit: Option<usize>,
    pub route_limit: Option<usize>,
}

impl NotificationControlConfigV1 {
    pub fn validate(&self) -> Result<()> {
        if self
            .grant_limit
            .is_some_and(|limit| self.grants.len() > limit)
            || self
                .route_limit
                .is_some_and(|limit| self.routes.len() > limit)
        {
            return Err(crate::error::InvalidConfigurationSnafu {
                reason: "notification configuration exceeds its count bound",
            }
            .build());
        }
        let mut grants = std::collections::BTreeSet::new();
        let mut routes = std::collections::BTreeSet::new();
        for grant in &self.grants {
            grant.validate()?;
            if !grants.insert((grant.tenant_id, grant.principal_id)) {
                return Err(crate::error::InvalidConfigurationSnafu {
                    reason: "notification configuration repeats a principal",
                }
                .build());
            }
        }
        for route in &self.routes {
            route.validate()?;
            if !routes.insert((route.tenant_id, &route.route_id)) {
                return Err(crate::error::InvalidConfigurationSnafu {
                    reason: "notification configuration repeats a route",
                }
                .build());
            }
        }
        Ok(())
    }
}

pub struct ConfiguredNotificationAuthority {
    store: crate::ControlStore,
    grant_limit: Option<usize>,
}

impl ConfiguredNotificationAuthority {
    pub fn new(
        store: crate::ControlStore,
        grants: &[NotificationGrantV1],
        grant_limit: Option<usize>,
    ) -> Result<Self> {
        let mut configured = std::collections::BTreeSet::new();
        for grant in grants {
            grant.validate()?;
            if !configured.insert((grant.tenant_id, grant.principal_id)) {
                return Err(notification_denied("duplicate configured grant").into());
            }
        }
        let owner = Self { store, grant_limit };
        owner.store.update_authority(|state| {
            if grant_limit.is_some_and(|limit| state.notification_grants.len() > limit) {
                return Err(notification_denied("notification grant capacity").into());
            }
            let mut changed = false;
            for (key, current) in &mut state.notification_grants {
                if !configured.contains(key) && !current.revoked {
                    current.revoked = true;
                    changed = true;
                }
            }
            for grant in grants {
                if state
                    .notification_grants
                    .get(&(grant.tenant_id, grant.principal_id))
                    .is_some_and(|prior| prior.grant == *grant)
                {
                    continue;
                }
                changed |= owner.replace_grant(state, grant.clone())?;
            }
            Ok(changed)
        })?;
        Ok(owner)
    }

    pub fn replace(&self, grant: NotificationGrantV1) -> Result<()> {
        grant.validate()?;
        self.store
            .update_authority(|state| self.replace_grant(state, grant))
    }

    fn replace_grant(
        &self,
        state: &mut crate::authority::AuthorityStateV1,
        grant: NotificationGrantV1,
    ) -> Result<bool> {
        let grants = &mut state.notification_grants;
        let key = (grant.tenant_id, grant.principal_id);
        if let Some(prior) = grants.get(&key) {
            if prior.grant == grant && !prior.revoked {
                return Ok(false);
            }
            if grant.authorization_revision <= prior.grant.authorization_revision {
                return Err(notification_denied("notification authorization revision").into());
            }
        }
        if self.grant_limit.is_some_and(|limit| grants.len() >= limit) && !grants.contains_key(&key)
        {
            return Err(notification_denied("notification grant capacity").into());
        }
        grants.insert(
            key,
            crate::authority::ConfiguredNotificationGrantV1 {
                grant,
                revoked: false,
            },
        );
        Ok(true)
    }

    pub fn revoke(&self, tenant: [u8; 16], principal: [u8; 16], revision: u64) -> Result<()> {
        self.store.update_authority(|state| {
            let grant = state
                .notification_grants
                .get_mut(&(tenant, principal))
                .ok_or_else(|| notification_denied("notification revoke scope"))?;
            if revision != grant.grant.authorization_revision {
                return Err(notification_denied("notification revoke revision").into());
            }
            if grant.revoked {
                return Ok(false);
            }
            grant.revoked = true;
            Ok(true)
        })
    }
}

impl NotificationAuthorization for ConfiguredNotificationAuthority {
    fn check(&self, grant: &NotificationGrantV1, now: u64) -> araphor_data::Result<()> {
        let state = self
            .store
            .authority_state()
            .map_err(|_| notification_denied("notification grant store"))?;
        if now >= grant.expires_utc_ns
            || !state
                .notification_grants
                .get(&(grant.tenant_id, grant.principal_id))
                .is_some_and(|current| !current.revoked && current.grant == *grant)
        {
            return Err(notification_denied("notification current authorization"));
        }
        Ok(())
    }
}

pub struct UnavailableNotificationSink;

impl NotificationSink for UnavailableNotificationSink {
    fn deliver(&self, _request: &araphor_data::NotificationDeliveryV1) -> NotificationSinkResultV1 {
        NotificationSinkResultV1::Failed {
            reason: NotificationFailureV1::SinkUnavailable,
        }
    }
}

pub struct ControlNotificationOwner {
    pub(crate) router: Arc<NotificationRouter>,
    authority: Arc<ConfiguredNotificationAuthority>,
    pub(crate) sink: Arc<dyn NotificationSink>,
}

impl ControlNotificationOwner {
    pub fn new(
        store: crate::ControlStore,
        data: Arc<AnalysisStore>,
        config: NotificationControlConfigV1,
        now: u64,
    ) -> Result<Self> {
        config.validate()?;
        let authority = Arc::new(ConfiguredNotificationAuthority::new(
            store,
            &config.grants,
            config.grant_limit,
        )?);
        let router = Arc::new(NotificationRouter::new(data, authority.clone())?);
        for route in config.routes {
            let grant = config
                .grants
                .iter()
                .find(|grant| {
                    grant.allows(
                        route.tenant_id,
                        &route.route_id,
                        araphor_data::NotificationOperationV1::Configure,
                        now,
                    )
                })
                .ok_or_else(|| notification_denied("notification configured route approval"))?;
            router.configure(grant, route, now)?;
        }
        Ok(Self {
            router,
            authority,
            sink: Arc::new(UnavailableNotificationSink),
        })
    }

    pub fn with_sink(mut self, sink: Arc<dyn NotificationSink>) -> Self {
        self.sink = sink;
        self
    }
    pub fn router(&self) -> &NotificationRouter {
        &self.router
    }
    pub fn authority(&self) -> &ConfiguredNotificationAuthority {
        &self.authority
    }
    pub fn route_finding(
        &self,
        tenant: [u8; 16],
        reference: &araphor_data::NotificationFindingRefV1,
        now: u64,
    ) -> Result<usize> {
        Ok(self.router.route_finding(tenant, reference, now)?)
    }

    pub fn deliver_obligation(
        &self,
        key: araphor_data::NotificationKeyV1,
        now: u64,
    ) -> Result<usize> {
        Ok(self
            .router
            .deliver_obligation(key, self.sink.as_ref(), now)?)
    }
}

fn notification_denied(field: &'static str) -> araphor_data::Error {
    araphor_data::Error::Notification {
        code: araphor_data::NotificationErrorCodeV1::Denied,
        field,
        location: snafu::Location::default(),
    }
}

#[cfg(test)]
pub(crate) mod tests;
