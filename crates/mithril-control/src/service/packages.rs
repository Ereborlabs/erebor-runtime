use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use araphor_analysis::{AnalysisPackageOwner, InstalledAnalysis};
use araphor_data::PackageAuthorization;
use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, PackageActionV1, PackageBundleV1, PackageGrantV1,
};
use araphor_query::execution::{Engine, Limits};

use super::ControlPlane;

pub(crate) struct ControlPackages {
    pub(crate) owner: Arc<AnalysisPackageOwner>,
    pub(crate) query: Arc<Engine>,
    authority: Arc<ControlPackageAuthority>,
    limits: Limits,
}

struct ControlPackageAuthority {
    tenants: BTreeSet<[u8; 16]>,
    pins: BTreeSet<String>,
    client: RwLock<Option<Arc<crate::ClientAuth>>>,
    changes: tokio::sync::watch::Sender<u64>,
}

impl ControlPlane {
    pub(crate) fn analysis_packages(
        &self,
        limits: Option<Limits>,
    ) -> crate::Result<Arc<ControlPackages>> {
        let mut installed = self.packages.lock().map_err(|_| {
            crate::error::InvalidConfigurationSnafu {
                reason: "analysis package registry lock failed",
            }
            .build()
        })?;
        if let Some(installed) = installed.as_ref() {
            if limits
                .as_ref()
                .is_some_and(|limits| *limits != installed.limits)
            {
                return Err(crate::error::InvalidConfigurationSnafu {
                    reason: "analysis packages already use different query limits",
                }
                .build());
            }
            return Ok(installed.clone());
        }
        let data = self.analysis_store().ok_or_else(|| {
            crate::error::InvalidConfigurationSnafu {
                reason: "analysis packages require retained data storage",
            }
            .build()
        })?;
        let tenants = self
            .allowed_nodes
            .values()
            .map(|node| {
                uuid::Uuid::parse_str(&node.tenant_id)
                    .map(|tenant| *tenant.as_bytes())
                    .map_err(|_| {
                        crate::error::InvalidConfigurationSnafu {
                            reason: "analysis package tenant is invalid",
                        }
                        .build()
                    })
            })
            .collect::<crate::Result<BTreeSet<_>>>()?;
        let pins = AnalysisPackageOwner::required_bundles()
            .iter()
            .map(PackageBundleV1::digest)
            .collect::<araphor_data::Result<BTreeSet<_>>>()?;
        let authority = Arc::new(ControlPackageAuthority {
            tenants,
            pins,
            client: RwLock::new(None),
            changes: tokio::sync::watch::channel(1).0,
        });
        let limits = limits.unwrap_or_default();
        let mut query = Engine::new(data, limits.clone())?;
        Arc::get_mut(&mut query)
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    reason: "query engine is shared before package registration",
                }
                .build()
            })?
            .register_relation_planner(Arc::new(araphor_discovery_effects::ObservedEffects))?;
        let owner = AnalysisPackageOwner::new(query.clone(), authority.clone())?;
        #[cfg(test)]
        let owner = {
            let mut owner = owner;
            owner.prepare_test_code()?;
            owner
        };
        let owner = Arc::new(owner);
        for tenant in &authority.tenants {
            owner.ensure_required(
                &authority.grant(*tenant),
                &AnalysisReadControl::with_timeout(std::time::Duration::from_secs(120))?,
            )?;
        }
        let runtime = Arc::new(ControlPackages {
            owner,
            query,
            authority,
            limits,
        });
        *installed = Some(runtime.clone());
        Ok(runtime)
    }

    pub fn installed_analysis(&self) -> crate::Result<InstalledAnalysis> {
        InstalledAnalysis::new(
            self.analysis_packages(None)?.owner.clone(),
            AnalysisPackageOwner::DOMAIN_SCOPE,
        )
        .map_err(Into::into)
    }
}

impl ControlPackages {
    pub(crate) fn bind_client(&self, auth: Arc<crate::ClientAuth>) -> crate::Result<()> {
        let mut client = self.authority.client.write().map_err(|_| {
            crate::error::InvalidConfigurationSnafu {
                reason: "package client authority lock failed",
            }
            .build()
        })?;
        if client
            .as_ref()
            .is_some_and(|current| !Arc::ptr_eq(current, &auth))
        {
            return Err(crate::error::InvalidConfigurationSnafu {
                reason: "analysis packages already use another client authority",
            }
            .build());
        }
        *client = Some(auth);
        Ok(())
    }
}

impl ControlPackageAuthority {
    fn grant(&self, tenant: [u8; 16]) -> PackageGrantV1 {
        PackageGrantV1 {
            principal: "mithril-control".into(),
            revision: 1,
            selection: AnalysisSelectionV1::tenant(tenant),
            expires_utc_ns: None,
            authorization_id: None,
        }
    }

    fn internal(&self, grant: &PackageGrantV1) -> bool {
        self.tenants.contains(&grant.selection.tenant_id)
            && *grant == self.grant(grant.selection.tenant_id)
    }

    fn denied() -> araphor_data::Error {
        araphor_data::Error::Package {
            code: araphor_data::PackageErrorCodeV1::Denied,
            field: "package authority",
            location: snafu::Location::default(),
        }
    }
}

impl PackageAuthorization for ControlPackageAuthority {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        if self.internal(grant) {
            return if action == PackageActionV1::Remove {
                Err(Self::denied())
            } else {
                Ok(())
            };
        }
        self.client
            .read()
            .map_err(|_| Self::denied())?
            .as_ref()
            .ok_or_else(Self::denied)?
            .check(grant, action)
    }

    fn admit(
        &self,
        grant: &PackageGrantV1,
        bundle: &araphor_data::PackageBundleRef<'_>,
    ) -> araphor_data::Result<()> {
        if self.internal(grant) {
            return if self.pins.contains(bundle.digest()) {
                Ok(())
            } else {
                Err(Self::denied())
            };
        }
        self.client
            .read()
            .map_err(|_| Self::denied())?
            .as_ref()
            .ok_or_else(Self::denied)?
            .admit(grant, bundle)
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

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, &araphor_data::PackageBundleRef<'_>)],
        action: PackageActionV1,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        let mut external = Vec::new();
        for (grant, bundle) in grants {
            if self.internal(grant) {
                self.check(grant, action)?;
                self.admit(grant, bundle)?;
            } else {
                external.push((*grant, *bundle));
            }
        }
        if external.is_empty() {
            return operation();
        }
        self.client
            .read()
            .map_err(|_| Self::denied())?
            .as_ref()
            .ok_or_else(Self::denied)?
            .commit_many(&external, action, operation)
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.client
            .read()
            .ok()
            .and_then(|client| client.as_ref().map(|client| client.changes()))
            .unwrap_or_else(|| self.changes.subscribe())
    }
}
