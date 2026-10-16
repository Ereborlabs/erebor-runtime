use std::collections::BTreeSet;

use araphor_data::PackageAuthorization;
use araphor_data::{AnalysisSelectionV1, PackageActionV1, PackageGrantV1};

use super::*;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageTrustPinV1 {
    pub tenant_id: String,
    pub bundle_digest: String,
}

impl PackageTrustPinV1 {
    pub(super) fn validate(pins: &[Self]) -> Result<BTreeSet<([u8; 16], String)>> {
        ensure!(
            pins.len() <= MAX_ENTRIES,
            InvalidConfigurationSnafu {
                reason: "package trust pins exceed 4096",
            }
        );
        let mut result = BTreeSet::new();
        for pin in pins {
            let digest = pin.bundle_digest.strip_prefix("sha256:");
            let tenant = Uuid::parse_str(&pin.tenant_id)
                .ok()
                .filter(|tenant| !tenant.is_nil() && tenant.to_string() == pin.tenant_id);
            ensure!(
                tenant.is_some()
                    && digest.is_some_and(|digest| digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))),
                InvalidConfigurationSnafu {
                    reason: "package trust requires a canonical tenant UUID and OCI sha256 digest"
                }
            );
            let tenant = tenant.ok_or_else(|| {
                InvalidConfigurationSnafu {
                    reason: "package trust tenant is absent",
                }
                .build()
            })?;
            ensure!(
                result.insert((*tenant.as_bytes(), pin.bundle_digest.clone())),
                InvalidConfigurationSnafu {
                    reason: "a package trust pin is repeated"
                }
            );
        }
        Ok(result)
    }
}

impl ClientAuth {
    pub fn replace_package_managers(&self, grants: Vec<InvestigateGrant>) -> Result<()> {
        let mut grants = ClientState::grants(&grants)?;
        let mut state = self.state()?;
        if state.package_managers.keys().eq(grants.keys()) {
            return Ok(());
        }
        let revision = state.next_revision()?;
        for (key, value) in &mut grants {
            *value = state.package_managers.get(key).copied().unwrap_or(revision);
        }
        state.package_managers = grants;
        state.revision = revision;
        self.changes.send_replace(revision);
        Ok(())
    }

    pub fn replace_package_trust(&self, pins: Vec<PackageTrustPinV1>) -> Result<()> {
        let pins = PackageTrustPinV1::validate(&pins)?;
        let mut state = self.state()?;
        if state.package_trust == pins {
            return Ok(());
        }
        let revision = state.next_revision()?;
        state.package_trust = pins;
        state.revision = revision;
        self.changes.send_replace(revision);
        Ok(())
    }

    fn check_package(&self, grant: &PackageGrantV1, action: PackageActionV1) -> Result<()> {
        self.package_state(grant, action).map(|_| ())
    }

    fn package_state(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
    ) -> Result<MutexGuard<'_, ClientState>> {
        let state = self.state()?;
        let now = Self::now()?;
        state.check_package(grant, action, now)?;
        Ok(state)
    }

    fn package_denied(_: Error) -> araphor_data::Error {
        araphor_data::Error::Package {
            code: araphor_data::PackageErrorCodeV1::Denied,
            field: "package authority",
            location: snafu::Location::default(),
        }
    }
}

impl ClientState {
    fn check_package(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        now: u64,
    ) -> Result<()> {
        ensure!(
            grant.expires_utc_ns.is_some_and(|expiry| now < expiry),
            ClientDeniedSnafu
        );
        let key = (grant.principal.clone(), grant.selection.tenant_id);
        let investigator = self
            .grants
            .get(&key)
            .ok_or_else(|| ClientDeniedSnafu.build())?;
        let manager = self.package_managers.get(&key);
        ensure!(
            matches!(action, PackageActionV1::Inspect) || manager.is_some(),
            ClientDeniedSnafu
        );
        let revision = (*investigator).max(manager.copied().unwrap_or(*investigator));
        ensure!(grant.revision == revision, ClientDeniedSnafu);
        if let Some(id) = &grant.authorization_id {
            ensure!(
                self.sessions
                    .values()
                    .any(|session| session.authorization_id == *id
                        && session.subject == grant.principal
                        && now < session.expires_ns),
                ClientDeniedSnafu
            );
        }
        Ok(())
    }
}

impl ClientAccess {
    pub fn package_grant(
        &self,
        selection: AnalysisSelectionV1,
        action: PackageActionV1,
    ) -> Result<PackageGrantV1> {
        self.check()?;
        ensure!(selection.tenant_id == self.tenant_id, ClientDeniedSnafu);
        let state = self.owner.state()?;
        let manager = state
            .package_managers
            .get(&(self.subject.clone(), self.tenant_id));
        ensure!(
            matches!(action, PackageActionV1::Inspect) || manager.is_some(),
            ClientDeniedSnafu
        );
        let revision = self.revision.max(manager.copied().unwrap_or(self.revision));
        let authorization_id = self
            .session
            .as_ref()
            .map(|token| {
                state
                    .sessions
                    .get(token)
                    .map(|session| session.authorization_id.clone())
                    .ok_or_else(|| ClientDeniedSnafu.build())
            })
            .transpose()?;
        Ok(PackageGrantV1 {
            principal: self.subject.clone(),
            revision,
            selection,
            expires_utc_ns: Some(self.expires_ns),
            authorization_id,
        })
    }
}

impl PackageAuthorization for ClientAuth {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        self.check_package(grant, action)
            .map_err(Self::package_denied)
    }

    fn admit(
        &self,
        grant: &PackageGrantV1,
        bundle: &araphor_data::PackageBundleRef<'_>,
    ) -> araphor_data::Result<()> {
        let digest = bundle.digest().to_owned();
        let state = self
            .package_state(grant, PackageActionV1::Run)
            .map_err(Self::package_denied)?;
        if !state
            .package_trust
            .contains(&(grant.selection.tenant_id, digest))
        {
            return Err(araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Denied,
                field: "package authority",
                location: snafu::Location::default(),
            });
        }
        Ok(())
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &araphor_data::PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(&[(grant, bundle)], action, operation)
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, &araphor_data::PackageBundleRef<'_>)],
        action: PackageActionV1,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        let state = self.state().map_err(Self::package_denied)?;
        let now = Self::now().map_err(Self::package_denied)?;
        for (grant, bundle) in grants {
            state
                .check_package(grant, action, now)
                .map_err(Self::package_denied)?;
            if action != PackageActionV1::Remove
                && !state
                    .package_trust
                    .contains(&(grant.selection.tenant_id, bundle.digest().to_owned()))
            {
                return Err(araphor_data::Error::Package {
                    code: araphor_data::PackageErrorCodeV1::Denied,
                    field: "package authority",
                    location: snafu::Location::default(),
                });
            }
        }
        let result = operation();
        drop(state);
        result
    }
}

#[cfg(test)]
mod tests;
