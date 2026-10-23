use super::*;
use araphor_data::{PackageRequestV1, PackageResponseV1};

#[tokio::test]
async fn public_control_keeps_identity() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture.admit("shared-control", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    let original = instance
        .run(request("original"), &AnalysisReadControl::default())
        .await?;
    let generation = instance.admitted().generation;
    let saved = instance.admitted().grant.clone();
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let mut operator = saved.clone();
    operator.principal = "operator".into();
    operator.revision = 2;
    let control = AnalysisReadControl::default();
    let run = PackageRequestV1::RunInstance {
        instance_id: "shared-control".into(),
        expected_lifecycle: instance.admitted().lifecycle,
        evaluation_id: "operator-step".into(),
        rebuild: false,
    };
    let PackageResponseV1::History(receipts) = host
        .execute(operator.clone(), run.clone(), &control)
        .await?
    else {
        return Err("finite receipt variant".into());
    };
    assert_eq!(receipts.len(), 1);
    assert_eq!(fixture.selected("shared-control", "operator-step")?, [6]);
    let attempt = fixture
        .query
        .store()
        .managed_attempt([1; 16], "shared-control", "operator-step", &control)?
        .ok_or("operator attempt")?;
    assert_eq!(attempt.instance().grant, saved);
    let before = fixture.query.store().meta()?;
    assert!(
        matches!(host.execute(operator.clone(), run, &control).await?, PackageResponseV1::History(repeated) if repeated == receipts)
    );
    assert_eq!(fixture.query.store().meta()?, before);
    let definition = fixture.query.admit_definition([1; 16], Fixture::definition(r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(4 AS BIGINT UNSIGNED) AS value))"#), Arc::new(control.operation()?)).await?;
    fixture
        .query
        .store()
        .admit_definition([1; 16], &definition, || Ok(()))?;
    let PackageResponseV1::Instance(updated) = host
        .execute(
            operator.clone(),
            PackageRequestV1::UpdateInstance {
                instance_id: "shared-control".into(),
                expected_lifecycle: instance.admitted().lifecycle,
                definition_name: definition.definition.name.clone(),
                definition_revision: definition.digest()?,
                rebuild: true,
            },
            &control,
        )
        .await?
    else {
        return Err("updated status".into());
    };
    assert_ne!(updated.generation, generation);
    let PackageResponseV1::Instance(rolled) = host
        .execute(
            operator.clone(),
            PackageRequestV1::RollbackInstance {
                instance_id: "shared-control".into(),
                expected_lifecycle: updated.lifecycle,
                generation,
                rebuild: true,
            },
            &control,
        )
        .await?
    else {
        return Err("rollback status".into());
    };
    let PackageResponseV1::Instance(started) = host
        .execute(
            operator.clone(),
            PackageRequestV1::StartInstance {
                instance_id: "shared-control".into(),
                expected_lifecycle: rolled.lifecycle,
            },
            &control,
        )
        .await?
    else {
        return Err("started status".into());
    };
    assert!(started.running);
    let PackageResponseV1::Instance(stopped) = host
        .execute(
            operator.clone(),
            PackageRequestV1::StopInstance {
                instance_id: "shared-control".into(),
                expected_lifecycle: started.lifecycle,
            },
            &control,
        )
        .await?
    else {
        return Err("stopped status".into());
    };
    assert!(!stopped.running);
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "shared-control", &control)?
        .ok_or("current instance")?;
    assert_eq!(current.grant, saved);
    assert_eq!(fixture.selected("shared-control", "original")?, [3]);
    assert_eq!(fixture.selected("shared-control", "operator-step")?, [6]);
    let before = fixture.query.store().meta()?;
    let mut narrow = operator.clone();
    narrow.selection.nodes.push("other-node".into());
    let denied = PackageRequestV1::RunInstance {
        instance_id: "shared-control".into(),
        expected_lifecycle: stopped.lifecycle,
        evaluation_id: "denied".into(),
        rebuild: false,
    };
    let error = host
        .execute(narrow, denied.clone(), &control)
        .await
        .err()
        .ok_or("narrow caller controlled whole instance")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    fixture.authority.revoke(operator.revision);
    let error = host
        .execute(operator, denied, &control)
        .await
        .err()
        .ok_or("revoked operator ran instance")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance([1; 16], "shared-control", &control)?,
        Some(current.clone())
    );
    assert!(fixture
        .query
        .store()
        .managed_attempt([1; 16], "shared-control", "denied", &control)?
        .is_none());
    assert_eq!(
        fixture
            .query
            .store()
            .managed_attempt([1; 16], "shared-control", "original", &control)?
            .ok_or("original attempt")?
            .receipt(),
        Some(&original)
    );
    drop(instance);
    drop(host);
    fixture.authority.revoke(saved.revision);
    let Fixture {
        directory,
        query,
        authority,
        ..
    } = fixture;
    drop(query);
    let query = Engine::new(
        Arc::new(AnalysisStore::open(directory.path().join("data"))?),
        Default::default(),
    )?;
    let host = InstanceHost::new(Arc::clone(&query), authority.clone());
    let mut renewed = saved.clone();
    renewed.principal = "renewed-owner".into();
    renewed.revision = 3;
    let PackageResponseV1::Instance(renewed_status) = host
        .execute(
            renewed.clone(),
            PackageRequestV1::RenewInstance {
                instance_id: "shared-control".into(),
                expected_lifecycle: current.lifecycle,
            },
            &control,
        )
        .await?
    else {
        return Err("renewed status".into());
    };
    assert_eq!(renewed_status.progress, current.progress);
    assert_eq!(renewed_status.generation, current.generation);
    assert!(!renewed_status.running);
    assert_eq!(
        query
            .store()
            .managed_instance([1; 16], "shared-control", &control)?
            .ok_or("renewed instance")?
            .grant,
        renewed
    );
    assert_eq!(
        query
            .store()
            .managed_attempt([1; 16], "shared-control", "original", &control)?
            .ok_or("retained original")?
            .instance()
            .grant,
        saved
    );
    assert_eq!(
        query
            .store()
            .managed_attempt([1; 16], "shared-control", "original", &control)?
            .ok_or("retained receipt")?
            .receipt(),
        Some(&original)
    );
    Ok(())
}

struct PublicationAuthority {
    inner: Arc<Authority>,
    store: Arc<AnalysisStore>,
    rejected: AtomicBool,
}

impl PackageAuthorization for PublicationAuthority {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        self.inner.check(grant, action)
    }
    fn admit(
        &self,
        grant: &PackageGrantV1,
        bundle: &PackageBundleRef<'_>,
    ) -> araphor_data::Result<()> {
        self.inner.admit(grant, bundle)
    }
    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &PackageBundleRef<'_>,
        work: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(&[(grant, action, Some(bundle))], work)
    }
    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.changes()
    }
    fn commit_many(
        &self,
        grants: &[(
            &PackageGrantV1,
            PackageActionV1,
            Option<&PackageBundleRef<'_>>,
        )],
        work: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        if grants
            .iter()
            .any(|(grant, _, _)| grant.principal == "operator")
            && self
                .store
                .managed_attempt(
                    [1; 16],
                    "operator-fence",
                    "rejected",
                    &AnalysisReadControl::default(),
                )?
                .is_some_and(|attempt| attempt.receipt().is_none() && attempt.terminal().is_none())
        {
            self.rejected.store(true, Ordering::SeqCst);
            self.inner.revoke(2);
        }
        self.inner.commit_many(grants, work)
    }
}

#[tokio::test]
async fn operator_revocation_fences_publication() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture.admit("operator-fence", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    let original = instance
        .run(request("original"), &AnalysisReadControl::default())
        .await?;
    let control = AnalysisReadControl::default();
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "operator-fence", &control)?
        .ok_or("original instance")?;
    let authority = Arc::new(PublicationAuthority {
        inner: Arc::clone(&fixture.authority),
        store: Arc::clone(fixture.query.store()),
        rejected: AtomicBool::new(false),
    });
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let mut operator = fixture.grant.clone();
    operator.principal = "operator".into();
    operator.revision = 2;
    let held = fixture.query.memory().input_reserved();
    let error = host
        .execute(
            operator,
            PackageRequestV1::RunInstance {
                instance_id: "operator-fence".into(),
                expected_lifecycle: current.lifecycle,
                evaluation_id: "rejected".into(),
                rebuild: false,
            },
            &control,
        )
        .await
        .err()
        .ok_or("revoked operator published")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert!(authority.rejected.load(Ordering::SeqCst));
    control.check()?;
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance([1; 16], "operator-fence", &control)?,
        Some(current)
    );
    assert_eq!(fixture.selected("operator-fence", "original")?, [3]);
    let attempt = fixture
        .query
        .store()
        .managed_attempt([1; 16], "operator-fence", "rejected", &control)?
        .ok_or("captured operator step")?;
    assert_eq!(attempt.instance().grant, fixture.grant);
    assert!(attempt.receipt().is_none());
    assert!(attempt.terminal().is_none());
    assert!(fixture
        .query
        .store()
        .managed_selected([1; 16], "operator-fence", "rejected", &control)?
        .is_none());
    assert_eq!(
        fixture.query.store().managed_history(
            &fixture.grant.selection,
            "operator-fence",
            &control
        )?,
        [original]
    );
    assert_eq!(fixture.query.memory().input_reserved(), held);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}
