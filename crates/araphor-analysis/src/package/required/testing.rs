use snafu::IntoError as _;
use std::sync::Arc;
use std::time::Duration;

use crate::package::{
    AnalysisPackageOwner, InstalledAnalysis, PackageActionV1, PackageAuthorization, PackageGrantV1,
};
use crate::{AnalysisSelectionV1, AnalysisStore, Engine, Result};
use araphor_query::execution::Limits;

struct FixtureAuthority {
    tenants: std::collections::BTreeSet<[u8; 16]>,
    changes: tokio::sync::watch::Sender<u64>,
}

impl PackageAuthorization for FixtureAuthority {
    fn check(&self, grant: &PackageGrantV1, _action: PackageActionV1) -> araphor_data::Result<()> {
        if self.tenants.contains(&grant.selection.tenant_id)
            && grant.selection == AnalysisSelectionV1::tenant(grant.selection.tenant_id)
        {
            Ok(())
        } else {
            Err(araphor_data::Error::AnalysisReadDenied {
                location: snafu::Location::default(),
            })
        }
    }

    fn admit(
        &self,
        grant: &PackageGrantV1,
        _bundle: &crate::package::PackageBundleRef<'_>,
    ) -> araphor_data::Result<()> {
        self.check(grant, PackageActionV1::Run)
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &crate::package::PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(&[(grant, bundle)], action, operation)
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, &crate::package::PackageBundleRef<'_>)],
        action: PackageActionV1,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        for (grant, bundle) in grants {
            self.check(grant, action)?;
            self.admit(grant, bundle)?;
        }
        operation()
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

impl InstalledAnalysis {
    pub fn testing_owner(&self) -> Arc<AnalysisPackageOwner> {
        self.owner.clone()
    }

    pub fn testing(store: Option<Arc<AnalysisStore>>, tenant: [u8; 16]) -> Result<Self> {
        Self::testing_tenants(store, &[tenant])
    }

    pub fn testing_existing(store: Arc<AnalysisStore>, tenant: [u8; 16]) -> Result<Self> {
        let owner = Arc::new(Self::fixture_owner(store, &[tenant])?);
        Self::new(owner, AnalysisPackageOwner::DOMAIN_SCOPE)
    }

    fn fixture_owner(
        store: Arc<AnalysisStore>,
        tenants: &[[u8; 16]],
    ) -> Result<AnalysisPackageOwner> {
        let query = Engine::new(
            store,
            Limits {
                evaluate_timeout: Some(Duration::from_secs(30)),
                ..Default::default()
            },
        )?;
        let authority = Arc::new(FixtureAuthority {
            tenants: tenants.iter().copied().collect(),
            changes: tokio::sync::watch::channel(1).0,
        });
        AnalysisPackageOwner::new(query, authority)
    }

    pub fn testing_tenants(
        store: Option<Arc<AnalysisStore>>,
        tenants: &[[u8; 16]],
    ) -> Result<Self> {
        if tenants.is_empty() {
            return Err(crate::package::PackageErrorCodeV1::Invalid
                .error("fixture tenants")
                .into());
        }
        let (store, directory) = match store {
            Some(store) => (store, None),
            None => {
                let directory = tempfile::tempdir().map_err(|source| {
                    crate::IoSnafu {
                        path: std::env::temp_dir(),
                    }
                    .into_error(source)
                })?;
                let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
                (store, Some(Arc::new(directory)))
            }
        };
        let mut owner = Self::fixture_owner(store, tenants)?;
        owner.prepare_test_code()?;
        let owner = Arc::new(owner);
        for tenant in tenants {
            let grant = PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant(*tenant),
                expires_utc_ns: None,
                authorization_id: None,
            };
            owner.ensure_required(
                &grant,
                &crate::AnalysisReadControl::with_timeout(Duration::from_secs(120))?,
            )?;
        }
        let mut installed = Self::new(owner, AnalysisPackageOwner::DOMAIN_SCOPE)?;
        installed._directory = directory;
        Ok(installed)
    }
}
