use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::package::tests::{Authority, Fixture, TestResult};
use crate::package::{PackageAuthorization, PackageGrantV1, PackageRequestV1};
use crate::{AnalysisReadControl, Engine, Limits};

use super::*;

mod changes;

struct SelectiveAuthority {
    base: Arc<Authority>,
    denied: AtomicBool,
    changes: tokio::sync::watch::Sender<u64>,
}

impl PackageAuthorization for SelectiveAuthority {
    fn check(&self, grant: &PackageGrantV1, action: Action) -> araphor_data::Result<()> {
        self.base.check(grant, action)?;
        if self.denied.load(Ordering::SeqCst) && grant.principal == "second" {
            return Err(Code::Denied.error("second fixture grant"));
        }
        Ok(())
    }

    fn admit(
        &self,
        grant: &PackageGrantV1,
        bundle: &crate::package::PackageBundleRef<'_>,
    ) -> araphor_data::Result<()> {
        self.base.admit(grant, bundle)?;
        self.check(grant, Action::Run)
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: Action,
        bundle: &crate::package::PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(&[(grant, bundle)], action, operation)
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, &crate::package::PackageBundleRef<'_>)],
        action: Action,
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

#[test]
fn shared_root_checks_grants() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.owner.ensure_required(
        &fixture.grant,
        &AnalysisReadControl::with_timeout(Duration::from_secs(120))?,
    )?;
    let package = araphor_analysis_builtins::discovery::Discovery::package();
    let active = fixture
        .store
        .package_activations(
            [1; 16],
            AnalysisPackageOwner::DOMAIN_SCOPE,
            Some(&package.id),
        )?
        .pop()
        .ok_or("discovery activation")?;
    let mut context: InstalledContext = AnalysisPackageOwner::decode(&active.metadata)?;
    context.grant.principal = "second".into();
    fixture.store.renew_package(
        &active,
        &AnalysisPackageOwner::encode(&context)?,
        "second",
        || Ok(()),
    )?;
    let authority = Arc::new(SelectiveAuthority {
        base: fixture.authority.clone(),
        denied: AtomicBool::new(false),
        changes: tokio::sync::watch::channel(0).0,
    });
    let query = Engine::new(fixture.store.clone(), Limits::default())?;
    let owner = Arc::new(AnalysisPackageOwner::new(query, authority.clone())?);
    let execution =
        InstalledAnalysis::new(owner, AnalysisPackageOwner::DOMAIN_SCOPE)?.snapshot([1; 16])?;
    let expected = [(package.id, package.revision)];
    let mut commits = 0;
    execution.authorize([1; 16], &expected, || {
        commits += 1;
        Ok(())
    })?;
    assert_eq!(commits, 1);
    authority.denied.store(true, Ordering::SeqCst);
    authority.changes.send_replace(1);
    authority.check(&fixture.grant, Action::Run)?;
    assert!(execution
        .authorize([1; 16], &expected, || {
            commits += 1;
            Ok(())
        })
        .is_err());
    assert_eq!(commits, 1);
    Ok(())
}

#[test]
fn shared_store_fences_removal() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.owner.ensure_required(
        &fixture.grant,
        &AnalysisReadControl::with_timeout(Duration::from_secs(120))?,
    )?;
    let query = Engine::new(fixture.store.clone(), Limits::default())?;
    let other = Arc::new(AnalysisPackageOwner::new(query, fixture.authority.clone())?);
    assert!(Arc::ptr_eq(&fixture.owner.lifecycle, &other.lifecycle));
    let package = araphor_analysis_builtins::discovery::Discovery::package();
    let expected = [(package.id.clone(), package.revision)];
    let execution =
        InstalledAnalysis::new(fixture.owner.clone(), AnalysisPackageOwner::DOMAIN_SCOPE)?
            .snapshot([1; 16])?;
    let (started, start) = std::sync::mpsc::channel();
    let (finished, finish) = std::sync::mpsc::channel();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
    let grant = fixture.grant.clone();
    let request = PackageRequestV1::Remove {
        scope_id: AnalysisPackageOwner::DOMAIN_SCOPE.into(),
        package_id: package.id.clone(),
    };
    let mut worker = None;
    execution.authorize([1; 16], &expected, || {
        let owner = other.clone();
        worker = Some(std::thread::spawn(move || {
            let _started = started.send(());
            let result = runtime.block_on(owner.execute(grant, request, control));
            let _finished = finished.send(result);
        }));
        start
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| Code::Conflict.error("second owner did not start"))?;
        assert!(matches!(
            other.lifecycle.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        assert!(matches!(
            finish.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(!fixture
            .store
            .package_activations(
                [1; 16],
                AnalysisPackageOwner::DOMAIN_SCOPE,
                Some(&package.id)
            )?
            .is_empty());
        Ok(())
    })?;
    finish.recv_timeout(Duration::from_secs(35))??;
    worker
        .ok_or("second owner worker")?
        .join()
        .map_err(|_| "second owner panic")?;
    assert!(fixture
        .store
        .package_activations(
            [1; 16],
            AnalysisPackageOwner::DOMAIN_SCOPE,
            Some(&package.id)
        )?
        .is_empty());
    let mut committed = false;
    assert!(execution
        .authorize([1; 16], &expected, || {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    Ok(())
}

#[test]
fn constructor_fences_admission_cleanup() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.owner.ensure_required(
        &fixture.grant,
        &AnalysisReadControl::with_timeout(Duration::from_secs(120))?,
    )?;
    let package = araphor_analysis_builtins::discovery::Discovery::package();
    let admitted = fixture
        .store
        .package_revision([1; 16], &package.id, &package.revision)?
        .ok_or("discovery revision")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(fixture.execute(PackageRequestV1::Remove {
        scope_id: AnalysisPackageOwner::DOMAIN_SCOPE.into(),
        package_id: package.id.clone(),
    }))?;
    assert!(fixture
        .store
        .package_revision([1; 16], &package.id, &package.revision)?
        .is_none());
    let query = Engine::new(fixture.store.clone(), Limits::default())?;
    let lifecycle = fixture
        .owner
        .lifecycle
        .lock()
        .map_err(|_| "package lifecycle lock")?;
    fixture.store.install_package(&[admitted], || Ok(()))?;
    let authority = fixture.authority.clone();
    let (started, start) = std::sync::mpsc::channel();
    let (finished, finish) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _started = started.send(());
        let _finished = finished.send(AnalysisPackageOwner::new(query, authority));
    });
    start.recv_timeout(Duration::from_secs(2))?;
    assert!(matches!(
        finish.recv_timeout(Duration::from_millis(100)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    assert!(fixture
        .store
        .package_revision([1; 16], &package.id, &package.revision)?
        .is_some());
    drop(lifecycle);
    let other = finish.recv_timeout(Duration::from_secs(5))??;
    worker.join().map_err(|_| "second owner panic")?;
    assert!(Arc::ptr_eq(&fixture.owner.lifecycle, &other.lifecycle));
    assert!(fixture
        .store
        .package_revision([1; 16], &package.id, &package.revision)?
        .is_none());
    Ok(())
}
