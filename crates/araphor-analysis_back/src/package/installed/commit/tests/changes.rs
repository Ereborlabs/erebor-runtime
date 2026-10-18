use super::*;

struct ChangingAuthority {
    base: Arc<Authority>,
    renew: bool,
    started: std::sync::mpsc::Sender<()>,
    proceed: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl ChangingAuthority {
    fn gate(&self) -> araphor_data::Result<()> {
        if let Some(proceed) = self
            .proceed
            .lock()
            .map_err(|_| Code::Conflict.error("fixture authority lock"))?
            .take()
        {
            let _started = self.started.send(());
            proceed
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| Code::Conflict.error("fixture authority gate"))?;
        }
        Ok(())
    }
}

impl PackageAuthorization for ChangingAuthority {
    fn check(&self, grant: &PackageGrantV1, action: Action) -> araphor_data::Result<()> {
        if self.renew {
            self.base.check(grant, action)
        } else {
            self.gate()?;
            Err(Code::Denied.error("suspended fixture grant"))
        }
    }

    fn admit(
        &self,
        grant: &PackageGrantV1,
        bundle: &crate::package::PackageBundleRef<'_>,
    ) -> araphor_data::Result<()> {
        self.check(grant, Action::Run)?;
        self.gate()?;
        self.base.admit(grant, bundle)
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: Action,
        bundle: &crate::package::PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.check(grant, action)?;
        self.base.commit(grant, action, bundle, operation)
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.base.changes()
    }
}

#[test]
fn domain_commit_fences_renewal() -> TestResult {
    fence_change(true)
}

#[test]
fn domain_commit_fences_suspension() -> TestResult {
    fence_change(false)
}

fn fence_change(renew: bool) -> TestResult {
    let fixture = Fixture::new()?;
    fixture.owner.ensure_required(
        &fixture.grant,
        &AnalysisReadControl::with_timeout(Duration::from_secs(120))?,
    )?;
    let (started, start) = std::sync::mpsc::channel();
    let (proceed, release) = std::sync::mpsc::channel();
    let authority = Arc::new(ChangingAuthority {
        base: fixture.authority.clone(),
        renew,
        started,
        proceed: std::sync::Mutex::new(Some(release)),
    });
    let other = Arc::new(AnalysisPackageOwner::new(
        Engine::new(fixture.store.clone(), Limits::default())?,
        authority,
    )?);
    let package = araphor_analysis_builtins::discovery::Discovery::package();
    let execution =
        InstalledAnalysis::new(fixture.owner.clone(), AnalysisPackageOwner::DOMAIN_SCOPE)?
            .snapshot([1; 16])?;
    let before = if renew {
        execution.active([1; 16], &package.id, "atoms")?
    } else {
        fixture
            .store
            .package_activation_page(None)?
            .into_iter()
            .find(|active| active.active)
            .ok_or("first active package")?
    };
    let expected = [(before.key.package_id.clone(), before.revision.clone())];
    let mut grant = fixture.grant.clone();
    grant.expires_utc_ns = None;
    let (finished, finish) = std::sync::mpsc::channel();
    let owner = other.clone();
    let package = package.id.clone();
    let worker = std::thread::spawn(move || {
        let result = if renew {
            owner
                .execute_sync(
                    grant,
                    PackageRequestV1::Run {
                        scope_id: AnalysisPackageOwner::DOMAIN_SCOPE.into(),
                        package_id: package,
                        export: Some("atoms".into()),
                        evaluation_id: "renewal".into(),
                        parameters: None,
                    },
                    &AnalysisReadControl::with_timeout(Duration::from_secs(30))?,
                )
                .map(|_| ())
                .or_else(|error| match error {
                    crate::Error::Query {
                        source:
                            araphor_query::Error::Data {
                                source:
                                    araphor_data::Error::Package {
                                        code: Code::Missing,
                                        field: "host-prepared inputs",
                                        ..
                                    },
                            },
                    } => Ok(()),
                    error => Err(error),
                })
        } else {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| Code::Incomplete.error("fixture runtime"))?
                .block_on(crate::package::tests::suspend(owner))
        };
        let _finished = finished.send(result);
        Ok::<_, crate::Error>(())
    });
    start.recv_timeout(Duration::from_secs(30))?;
    execution.authorize([1; 16], &expected, || {
        proceed
            .send(())
            .map_err(|_| Code::Conflict.error("fixture authority gate"))?;
        assert!(matches!(
            finish.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        let active = fixture
            .store
            .package_activation(&before.key)?
            .ok_or_else(|| Code::Missing.error("discovery activation"))?;
        assert_eq!(active.generation, before.generation);
        assert!(active.active);
        Ok(())
    })?;
    finish.recv_timeout(Duration::from_secs(35))??;
    worker.join().map_err(|_| "second owner panic")??;
    let after = fixture
        .store
        .package_activation(&before.key)?
        .ok_or("discovery activation")?;
    assert!(after.generation > before.generation);
    assert_eq!(after.active, renew);
    assert!(execution.authorize([1; 16], &expected, || Ok(())).is_err());
    Ok(())
}
