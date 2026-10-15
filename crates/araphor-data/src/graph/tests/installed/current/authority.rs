use std::sync::atomic::{AtomicBool, Ordering};

use super::super::super::notices::NoticeInputs;
use super::*;

struct CacheAuthority {
    revoked: AtomicBool,
    blocked: AtomicBool,
    changes: tokio::sync::watch::Sender<u64>,
}

impl PackageAuthorization for CacheAuthority {
    fn check(&self, grant: &PackageGrantV1, _: PackageActionV1) -> Result<()> {
        if self.revoked.load(Ordering::SeqCst) || grant.selection != self::grant().selection {
            return Err(PackageErrorCodeV1::Denied.error("cache fixture grant"));
        }
        Ok(())
    }

    fn admit(
        &self,
        grant: &PackageGrantV1,
        _: &crate::package::PackageBundleRef<'_>,
    ) -> Result<()> {
        self.check(grant, PackageActionV1::Run)
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &crate::package::PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.commit_many(&[(grant, bundle)], action, operation)
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, &crate::package::PackageBundleRef<'_>)],
        action: PackageActionV1,
        operation: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        for (grant, bundle) in grants {
            self.check(grant, action)?;
            self.admit(grant, bundle)?;
        }
        if self.blocked.load(Ordering::SeqCst) {
            return Err(PackageErrorCodeV1::Denied.error("cache fixture commit"));
        }
        operation()
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

#[test]
fn cache_checks_commit_authority() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let execution = InstalledAnalysis::testing(Some(store.clone()), source().tenant_id)?;
    let provider = Arc::new(NoticeInputs::default());
    let owner = GraphAndFindingOwner::new(store.clone(), provider.clone(), execution)?;
    accept(
        &store,
        &[record(1, &wire(1, DeniedBeforeEffect, 2, 2, [20; 16]))?],
    )?;
    coverage(&store, 1, 1, "HEALTHY")?;
    super::super::super::window_expiry::process_to(&owner, &store, 1, 10)?;
    let original = store
        .processor_result(&GraphAndFindingOwner::scope(&source()))?
        .ok_or("original head")?;
    let saved = owner
        .snapshot_result(source().tenant_id, &original.result_id)?
        .ok_or("original graph")?;
    drop(owner);
    let authority = Arc::new(CacheAuthority {
        revoked: AtomicBool::new(false),
        blocked: AtomicBool::new(false),
        changes: tokio::sync::watch::channel(1).0,
    });
    let query = Arc::new(QueryOwner::new(store.clone(), QueryLimits::default())?);
    let mut packages = AnalysisPackageOwner::new(store.clone(), query, authority.clone())?;
    packages.prepare_test_code()?;
    let owner = GraphAndFindingOwner::new(
        store.clone(),
        provider.clone(),
        InstalledAnalysis::new(Arc::new(packages), AnalysisPackageOwner::DOMAIN_SCOPE)?,
    )?;
    assert_eq!(process_twice(&owner, 11)?, 0);
    authority.blocked.store(true, Ordering::SeqCst);
    authority.check(&grant(), PackageActionV1::Run)?;
    provider.revision.store(1, Ordering::SeqCst);
    assert!(matches!(
        process_twice(&owner, 12),
        Err(Error::Package {
            code: PackageErrorCodeV1::Denied,
            field: "cache fixture commit",
            ..
        })
    ));
    assert_eq!(
        store
            .processor_health(&GraphAndFindingOwner::scope(&source()))?
            .ok_or("processor health")?
            .state,
        ProcessorStateV1::ProcessingFailed
    );
    assert_eq!(
        owner.snapshot_result(source().tenant_id, &original.result_id)?,
        Some(saved.clone())
    );
    assert_eq!(
        store.graph_notice(&saved.scope, &original.result_id, original.commit_revision)?,
        Some((0, 1))
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    authority.blocked.store(false, Ordering::SeqCst);
    assert_eq!(process_twice(&owner, 13)?, 0);
    assert_eq!(
        store.graph_notice(&saved.scope, &original.result_id, original.commit_revision)?,
        Some((1, 1))
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    authority.blocked.store(true, Ordering::SeqCst);
    assert!(matches!(
        process_twice(&owner, 14),
        Err(Error::Package {
            code: PackageErrorCodeV1::Denied,
            field: "cache fixture commit",
            ..
        })
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    authority.blocked.store(false, Ordering::SeqCst);
    assert_eq!(process_twice(&owner, 15)?, 0);
    authority.revoked.store(true, Ordering::SeqCst);
    assert!(matches!(
        process_twice(&owner, 16),
        Err(Error::Package {
            code: PackageErrorCodeV1::Denied,
            field: "cache fixture grant",
            ..
        })
    ));
    assert_eq!(
        owner.snapshot_result(source().tenant_id, &original.result_id)?,
        Some(saved)
    );
    Ok(())
}
