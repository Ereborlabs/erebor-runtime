use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;

use super::*;

#[allow(
    clippy::type_complexity,
    reason = "The test retains exact action groups and gate channels."
)]
struct Actions {
    inner: Arc<Authority>,
    denied: Mutex<Option<PackageActionV1>>,
    blocked: Mutex<BTreeSet<String>>,
    checked: Mutex<Vec<PackageActionV1>>,
    committed: Mutex<Vec<Vec<(PackageActionV1, Option<String>)>>>,
    changes: tokio::sync::watch::Sender<u64>,
    updates: AtomicUsize,
    rejected: AtomicUsize,
    revoked: AtomicUsize,
    gate: Mutex<Option<(String, mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}

impl Actions {
    fn new(fixture: &Fixture) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::clone(&fixture.authority),
            denied: Mutex::new(None),
            blocked: Mutex::default(),
            checked: Mutex::default(),
            committed: Mutex::default(),
            changes: tokio::sync::watch::channel(0).0,
            updates: AtomicUsize::new(0),
            rejected: AtomicUsize::new(0),
            revoked: AtomicUsize::new(0),
            gate: Mutex::default(),
        })
    }

    fn deny(&self, action: Option<PackageActionV1>) -> TestResult {
        *self.denied.lock().map_err(|_| "version denied lock")? = action;
        self.changes.send_modify(|revision| *revision += 1);
        Ok(())
    }

    fn clear(&self) -> TestResult {
        self.checked
            .lock()
            .map_err(|_| "version checks lock")?
            .clear();
        self.committed
            .lock()
            .map_err(|_| "version commits lock")?
            .clear();
        self.updates.store(0, Ordering::SeqCst);
        self.rejected.store(0, Ordering::SeqCst);
        self.revoked.store(0, Ordering::SeqCst);
        Ok(())
    }
}

impl PackageAuthorization for Actions {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        self.checked
            .lock()
            .map_err(|_| Code::Incomplete.error("version checks lock"))?
            .push(action);
        self.inner.check(grant, action)?;
        if self
            .denied
            .lock()
            .map_err(|_| Code::Incomplete.error("version denied lock"))?
            .is_some_and(|denied| denied == action)
        {
            return Err(Code::Denied.error("version action"));
        }
        Ok(())
    }

    fn admit(&self, grant: &PackageGrantV1, image: &PackageBundle) -> araphor_data::Result<()> {
        if self
            .blocked
            .lock()
            .map_err(|_| Code::Incomplete.error("version trust lock"))?
            .contains(image.digest())
        {
            return Err(Code::Denied.error("version trust"));
        }
        let gate = {
            let mut gate = self
                .gate
                .lock()
                .map_err(|_| Code::Incomplete.error("version gate lock"))?;
            if gate
                .as_ref()
                .is_some_and(|(digest, _, _)| digest == image.digest())
            {
                gate.take()
            } else {
                None
            }
        };
        if let Some((_, entered, release)) = gate {
            entered
                .send(())
                .map_err(|_| Code::Incomplete.error("version gate entry"))?;
            release
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| Code::Incomplete.error("version gate release"))?;
        }
        self.inner.admit(grant, image)
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        image: &PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(
            &[(grant, action, None), (grant, action, Some(image))],
            operation,
        )
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, PackageActionV1, Option<&PackageBundle>)],
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.committed
            .lock()
            .map_err(|_| Code::Incomplete.error("version commits lock"))?
            .push(
                grants
                    .iter()
                    .map(|(_, action, image)| {
                        (*action, image.map(|image| image.digest().to_owned()))
                    })
                    .collect(),
            );
        let count = grants
            .iter()
            .any(|(_, action, _)| *action == PackageActionV1::Update)
            .then(|| self.updates.fetch_add(1, Ordering::SeqCst) + 1);
        if count.is_some_and(|count| count == self.revoked.load(Ordering::SeqCst)) {
            *self
                .denied
                .lock()
                .map_err(|_| Code::Incomplete.error("version denied lock"))? =
                Some(PackageActionV1::Run);
        }
        let denied = self
            .denied
            .lock()
            .map_err(|_| Code::Incomplete.error("version denied lock"))?;
        for (grant, action, image) in grants {
            self.checked
                .lock()
                .map_err(|_| Code::Incomplete.error("version checks lock"))?
                .push(*action);
            self.inner.check(grant, *action)?;
            if denied.is_some_and(|denied| denied == *action) {
                return Err(Code::Denied.error("version action"));
            }
            if let Some(image) = image {
                self.admit(grant, image)?;
            }
        }
        if count.is_some_and(|count| count == self.rejected.load(Ordering::SeqCst)) {
            return Err(Code::Denied.error("version switch guard"));
        }
        let result = self.inner.commit_many(grants, operation);
        drop(denied);
        result
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

async fn target(fixture: &Fixture, sql: &str, description: &str) -> TestResult<ResolvedDefinition> {
    let mut definition = Fixture::definition(sql);
    definition.description = description.into();
    let definition = fixture
        .query
        .admit_definition(
            [1; 16],
            definition,
            Arc::new(AnalysisReadControl::default()),
        )
        .await?;
    fixture
        .query
        .store()
        .admit_definition([1; 16], &definition, || Ok(()))?;
    Ok(definition)
}

fn image(target: &str, revision: &str) -> TestResult<PackageBundleV1> {
    let mut image = bundle(target)?;
    image.root.revision = revision.into();
    image.artifacts[0].descriptor.revision = revision.into();
    Ok(image)
}

async fn replaced_history(implementation: &str) -> TestResult {
    let limits = araphor_query::execution::Limits {
        global_evaluations: Some(4),
        tenant_evaluations: Some(4),
        ..Default::default()
    };
    let fixture = Fixture::new(limits.clone())?;
    let package = bundle(implementation)?;
    fixture.install(&package)?;
    let instance = fixture
        .admit(
            "versioned",
            r#"SELECT value FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value))"#,
        )
        .await?;
    let original = instance.admitted().spec.clone();
    let generation = instance.admitted().generation;
    assert_eq!(original.manifest.calls.len(), 1);
    let call = original
        .manifest
        .calls
        .values()
        .next()
        .ok_or("original call")?;
    assert_eq!(call.target, implementation);
    assert_eq!(call.package.revision, "1");
    let control = AnalysisReadControl::default();
    let first = instance.run(request("first"), &control).await?;
    let reference = first.results.values().next().ok_or("original result")?;
    let original_current = fixture
        .query
        .store()
        .managed_instance([1; 16], "versioned", &control)?
        .ok_or("original current")?;
    let saved = fixture.query.store().managed_result(
        &original_current,
        &reference.result_id,
        10,
        &control,
    )?;
    assert_eq!(first.results.len(), 1);
    assert_eq!(fixture.selected("versioned", "first")?, [7]);
    assert_eq!(saved.context.target, implementation);
    assert_eq!(values(&saved.output.datasets[0].batches)?, [7]);
    let status = Instance::read_status(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.grant.clone(),
        "versioned",
        &control,
    )
    .await?;
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    assert_eq!(status.status_progress, first.commit_revision);
    let installed = fixture
        .query
        .store()
        .package_revision([1; 16], "runtime-fixture", "1")?
        .ok_or("installed original revision")?;
    let before = fixture.query.store().meta()?;
    assert_eq!(instance.run(request("first"), &control).await?, first);
    assert_eq!(fixture.query.store().meta()?, before);
    fixture.install(&package)?;
    assert_eq!(
        fixture
            .query
            .store()
            .package_revision([1; 16], "runtime-fixture", "1")?,
        Some(installed)
    );
    assert_eq!(fixture.query.store().meta()?, before);
    let wasm_image = image("wasm", "2")?;
    fixture.install(&wasm_image)?;
    let definition = target(
        &fixture,
        r#"SELECT value FROM "runtime-fixture"."2".accumulate(input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value))"#,
        "",
    )
    .await?;
    let actions = Actions::new(&fixture);
    let host = InstanceHost::new(Arc::clone(&fixture.query), actions.clone());
    let before = fixture
        .query
        .store()
        .managed_instance([1; 16], "versioned", &control)?
        .ok_or("original current")?;
    assert!(host
        .update(
            Arc::clone(&instance),
            before.lifecycle,
            definition.clone(),
            false,
            u64::MAX,
            &control,
        )
        .await
        .is_err());
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance([1; 16], "versioned", &control)?,
        Some(before.clone())
    );
    actions.clear()?;
    let updated = host
        .update(
            Arc::clone(&instance),
            before.lifecycle,
            definition,
            true,
            u64::MAX,
            &control,
        )
        .await?;
    assert_eq!(updated.admitted().spec.manifest.calls.len(), 1);
    let call = updated
        .admitted()
        .spec
        .manifest
        .calls
        .values()
        .next()
        .ok_or("Wasm call")?;
    assert_eq!(call.target, "wasm");
    assert_eq!(call.package.revision, "2");
    let expected = vec![
        (PackageActionV1::Run, None),
        (PackageActionV1::Update, None),
        (
            PackageActionV1::Run,
            Some(updated.admitted().spec.definition.images[0].digest.clone()),
        ),
    ];
    let groups = actions
        .committed
        .lock()
        .map_err(|_| "version commits lock")?
        .clone();
    assert_eq!(groups.last(), Some(&expected));
    assert_eq!(
        groups
            .into_iter()
            .filter(|group| group
                .iter()
                .any(|(action, _)| *action == PackageActionV1::Update))
            .collect::<Vec<_>>(),
        vec![expected; 3]
    );
    assert_eq!(actions.updates.load(Ordering::SeqCst), 3);
    let frontier = fixture
        .query
        .store()
        .managed_resume([1; 16], "versioned", &control)?;
    assert_eq!(frontier.instance, *updated.admitted());
    assert!(frontier.frontier.is_some());
    let fence = fixture.query.store().meta()?;
    let error = updated
        .run(request("first"), &control)
        .await
        .err()
        .ok_or("old ID ran under Wasm")?;
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Conflict,
                field: "managed attempt identity",
                ..
            }
        }
    ));
    assert_eq!(fixture.query.store().meta()?, fence);
    let fence = fixture.query.store().meta()?;
    assert!(instance.run(request("stale"), &control).await.is_err());
    assert!(host
        .update(
            Arc::clone(&instance),
            before.lifecycle,
            updated.admitted().spec.definition.clone(),
            true,
            u64::MAX,
            &control,
        )
        .await
        .is_err());
    assert_eq!(fixture.query.store().meta()?, fence);
    let current = fixture.query.store().meta()?;
    let unchanged = host
        .update(
            Arc::clone(&updated),
            updated.admitted().lifecycle,
            updated.admitted().spec.definition.clone(),
            false,
            u64::MAX,
            &control,
        )
        .await?;
    assert_eq!(unchanged.admitted(), updated.admitted());
    assert_eq!(fixture.query.store().meta()?, current);
    actions.clear()?;
    let restored = host
        .rollback(
            Arc::clone(&updated),
            updated.admitted().lifecycle,
            generation,
            true,
            u64::MAX,
            &control,
        )
        .await?;
    assert_eq!(restored.admitted().spec, original);
    assert_eq!(restored.admitted().generation, generation);
    assert!(restored.admitted().lifecycle > updated.admitted().lifecycle);
    assert!(instance
        .run(request("stale-rollback"), &control)
        .await
        .is_err());
    let checked = actions
        .checked
        .lock()
        .map_err(|_| "version checks lock")?
        .clone();
    assert_eq!(checked.first(), Some(&PackageActionV1::Rollback));
    let expected = vec![
        (PackageActionV1::Run, None),
        (PackageActionV1::Update, None),
        (PackageActionV1::Rollback, None),
        (
            PackageActionV1::Run,
            Some(original.definition.images[0].digest.clone()),
        ),
    ];
    let groups = actions
        .committed
        .lock()
        .map_err(|_| "version commits lock")?
        .clone();
    assert_eq!(groups.last(), Some(&expected));
    assert_eq!(
        groups
            .into_iter()
            .filter(|group| group
                .iter()
                .any(|(action, _)| *action == PackageActionV1::Update))
            .collect::<Vec<_>>(),
        vec![expected; 3]
    );
    assert_eq!(actions.updates.load(Ordering::SeqCst), 3);
    let before = fixture.query.store().meta()?;
    assert_eq!(restored.run(request("first"), &control).await?, first);
    assert_eq!(fixture.query.store().meta()?, before);
    let retained = fixture.query.store().managed_result(
        restored.admitted(),
        &reference.result_id,
        10,
        &control,
    )?;
    assert_eq!(retained.context, saved.context);
    let model = &package.artifacts[0].descriptor.exports[0];
    assert_eq!(
        sdk::wire::Output::encode_model(&retained.output, model)?,
        sdk::wire::Output::encode_model(&saved.output, model)?
    );
    assert_eq!(retained.commit_revision, saved.commit_revision);
    let history =
        fixture
            .query
            .store()
            .managed_history(&fixture.grant.selection, "versioned", &control)?;
    assert_eq!(history.len(), 3);
    let wasm = host
        .update(
            Arc::clone(&restored),
            restored.admitted().lifecycle,
            updated.admitted().spec.definition.clone(),
            true,
            u64::MAX,
            &control,
        )
        .await?;
    let wasm_current = wasm.admitted().clone();
    let Fixture {
        directory,
        query,
        authority,
        grant,
    } = fixture;
    drop((instance, unchanged, updated, restored, wasm, host, query));

    let query = Engine::new(
        Arc::new(AnalysisStore::open(directory.path().join("data"))?),
        limits.clone(),
    )?;
    let host = InstanceHost::new(Arc::clone(&query), actions.clone());
    let crate::instance::Restored::Present(wasm) =
        host.restore([1; 16], "versioned", &control).await?
    else {
        return Err("recovered Wasm version".into());
    };
    assert_eq!(wasm.admitted(), &wasm_current);
    let second = wasm.run(request("second"), &control).await?;
    let wasm_id = second
        .results
        .values()
        .next()
        .ok_or("reopened Wasm result")?
        .result_id
        .clone();
    let wasm_saved = query
        .store()
        .managed_result(wasm.admitted(), &wasm_id, 10, &control)?;
    assert_eq!(wasm_saved.context.target, "wasm");
    let before = query.store().meta()?;
    let latest = Instance::query_result(
        Arc::clone(&query),
        authority.clone(),
        grant.clone(),
        "versioned",
        None,
        "SELECT value FROM selected",
        &control,
    )
    .await?;
    assert_eq!(
        values(&latest.data.batches)?,
        values(&wasm_saved.output.datasets[0].batches)?
    );
    drop(latest);
    assert_eq!(query.store().meta()?, before);
    let restored = host
        .rollback(
            Arc::clone(&wasm),
            wasm.admitted().lifecycle,
            generation,
            true,
            u64::MAX,
            &control,
        )
        .await?;
    assert_eq!(restored.admitted().spec, original);
    assert_eq!(restored.admitted().generation, generation);
    let before = query.store().meta()?;
    assert_eq!(restored.run(request("first"), &control).await?, first);
    assert_eq!(query.store().meta()?, before);
    let current = restored.admitted().clone();
    let history = query
        .store()
        .managed_history(&grant.selection, "versioned", &control)?;
    let latest = history
        .iter()
        .find(|receipt| receipt.commit_revision == current.progress)
        .ok_or("restored receipt")?;
    let current_id = latest
        .results
        .values()
        .next()
        .ok_or("restored result")?
        .result_id
        .clone();
    let current_saved = query
        .store()
        .managed_result(&current, &current_id, 10, &control)?;
    assert_eq!(current_saved.context.target, implementation);
    let before = query.store().meta()?;
    let latest = Instance::query_result(
        Arc::clone(&query),
        authority.clone(),
        grant.clone(),
        "versioned",
        None,
        "SELECT value FROM selected",
        &control,
    )
    .await?;
    assert_eq!(
        values(&latest.data.batches)?,
        values(&current_saved.output.datasets[0].batches)?
    );
    drop(latest);
    assert_eq!(query.store().meta()?, before);
    drop((wasm, restored, host, query));

    let query = Engine::new(
        Arc::new(AnalysisStore::open(directory.path().join("data"))?),
        limits,
    )?;
    let host = InstanceHost::new(Arc::clone(&query), actions);
    let crate::instance::Restored::Present(reopened) =
        host.restore([1; 16], "versioned", &control).await?
    else {
        return Err("recovered version".into());
    };
    assert_eq!(reopened.admitted(), &current);
    assert_eq!(reopened.admitted().spec, original);
    let before = query.store().meta()?;
    assert_eq!(reopened.run(request("first"), &control).await?, first);
    assert_eq!(query.store().meta()?, before);
    assert_eq!(
        query
            .store()
            .managed_history(&grant.selection, "versioned", &control)?,
        history,
    );
    let removed = host
        .remove(
            grant.clone(),
            "versioned".into(),
            reopened.admitted().lifecycle,
            &control,
        )
        .await?;
    assert!(removed.removed);
    assert!(!removed.running);
    assert_eq!(removed.spec, original);
    assert_eq!(removed.generation, generation);
    assert_eq!(removed.progress, current.progress);
    let before = query.store().meta()?;
    let latest = Instance::query_result(
        Arc::clone(&query),
        authority.clone(),
        grant.clone(),
        "versioned",
        None,
        "SELECT value FROM selected",
        &control,
    )
    .await?;
    assert_eq!(
        values(&latest.data.batches)?,
        values(&current_saved.output.datasets[0].batches)?
    );
    drop(latest);
    let status = Instance::read_status(
        Arc::clone(&query),
        authority.clone(),
        grant.clone(),
        "versioned",
        &control,
    )
    .await?;
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    assert_eq!(status.instance, removed);
    assert_eq!(query.store().meta()?, before);
    let error = reopened
        .run(request("removed"), &control)
        .await
        .err()
        .ok_or("removed instance ran")?;
    assert!(
        matches!(
            &error,
            crate::Error::Query {
                source: araphor_query::Error::Data {
                    source: araphor_data::Error::Package {
                        code: Code::Conflict,
                        field: "managed instance generation",
                        ..
                    }
                }
            }
        ),
        "{error:?}"
    );
    assert_eq!(query.store().meta()?, before);
    assert_eq!(
        Instance::read_history(
            Arc::clone(&query),
            authority.clone(),
            grant.clone(),
            "versioned",
            &control,
        )
        .await?,
        history
    );
    for (id, saved, model) in [
        (&reference.result_id, &saved, model),
        (
            &wasm_id,
            &wasm_saved,
            &wasm_image.artifacts[0].descriptor.exports[0],
        ),
        (&current_id, &current_saved, model),
    ] {
        let retained = Instance::read_result(
            Arc::clone(&query),
            authority.clone(),
            grant.clone(),
            "versioned",
            id,
            &control,
        )
        .await?;
        assert!(!retained.current);
        if id == &reference.result_id {
            assert_eq!(values(&retained.output.datasets[0].batches)?, [7]);
        }
        assert_eq!(retained.context, saved.context);
        assert_eq!(retained.commit_revision, saved.commit_revision);
        assert_eq!(
            sdk::wire::Output::encode_model(&retained.output, model)?,
            sdk::wire::Output::encode_model(&saved.output, model)?,
        );
    }
    drop((reopened, host));
    let permits = (0..4)
        .map(|_| query.reserve_evaluation([1; 16]))
        .collect::<araphor_query::Result<Vec<_>>>()?;
    assert!(query.reserve_evaluation([1; 16]).is_err());
    drop(permits);
    Ok(())
}

#[tokio::test]
async fn versions_keep_history() -> TestResult {
    replaced_history("sql").await
}

#[tokio::test]
#[ignore = "requires the native fixture artifacts"]
async fn native_versions_keep_history() -> TestResult {
    replaced_history("native").await
}

#[tokio::test]
async fn versions_check_actions() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture
        .admit(
            "actions",
            r#"SELECT value FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#,
        )
        .await?;
    let generation = instance.admitted().generation;
    let control = AnalysisReadControl::default();
    let first = instance.run(request("first"), &control).await?;
    fixture.install(&image("wasm", "2")?)?;
    let definition = target(
        &fixture,
        r#"SELECT value FROM "runtime-fixture"."2".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#,
        "",
    )
    .await?;
    let actions = Actions::new(&fixture);
    let host = InstanceHost::new(Arc::clone(&fixture.query), actions.clone());
    let original = fixture
        .query
        .store()
        .managed_instance([1; 16], "actions", &control)?
        .ok_or("original action owner")?;
    for denied in [PackageActionV1::Update, PackageActionV1::Run] {
        actions.deny(Some(denied))?;
        let before = fixture.query.store().meta()?;
        assert!(host
            .update(
                Arc::clone(&instance),
                original.lifecycle,
                definition.clone(),
                true,
                u64::MAX,
                &control,
            )
            .await
            .is_err());
        assert_eq!(fixture.query.store().meta()?, before);
        assert_eq!(
            fixture
                .query
                .store()
                .managed_instance([1; 16], "actions", &control)?,
            Some(original.clone())
        );
    }
    actions.deny(None)?;
    let updated = host
        .update(
            instance,
            original.lifecycle,
            definition,
            true,
            u64::MAX,
            &control,
        )
        .await?;
    for denied in [
        PackageActionV1::Rollback,
        PackageActionV1::Update,
        PackageActionV1::Run,
    ] {
        actions.deny(Some(denied))?;
        let before = fixture.query.store().meta()?;
        assert!(host
            .rollback(
                Arc::clone(&updated),
                updated.admitted().lifecycle,
                generation,
                true,
                u64::MAX,
                &control,
            )
            .await
            .is_err());
        assert_eq!(fixture.query.store().meta()?, before);
        assert_eq!(
            fixture
                .query
                .store()
                .managed_instance([1; 16], "actions", &control)?,
            Some(updated.admitted().clone())
        );
    }
    actions.deny(None)?;
    actions.clear()?;
    actions.rejected.store(2, Ordering::SeqCst);
    assert!(host
        .rollback(
            Arc::clone(&updated),
            updated.admitted().lifecycle,
            generation,
            true,
            u64::MAX,
            &control,
        )
        .await
        .is_err());
    assert_eq!(actions.updates.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance([1; 16], "actions", &control)?,
        Some(updated.admitted().clone())
    );
    assert_eq!(fixture.selected("actions", &first.attempt)?, [3]);
    Ok(())
}

#[tokio::test]
async fn versions_use_target_trust() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let old = bundle("sql")?;
    fixture.install(&old)?;
    let instance = fixture
        .admit(
            "trust",
            r#"SELECT value FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#,
        )
        .await?;
    let current = image("wasm", "2")?;
    fixture.install(&current)?;
    let definition = target(
        &fixture,
        r#"SELECT value FROM "runtime-fixture"."2".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#,
        "",
    )
    .await?;
    let actions = Actions::new(&fixture);
    let host = InstanceHost::new(Arc::clone(&fixture.query), actions.clone());
    actions
        .blocked
        .lock()
        .map_err(|_| "version trust lock")?
        .insert(current.digest()?);
    let before = fixture.query.store().meta()?;
    assert!(host
        .update(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            definition.clone(),
            true,
            u64::MAX,
            &AnalysisReadControl::default(),
        )
        .await
        .is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    {
        let mut blocked = actions.blocked.lock().map_err(|_| "version trust lock")?;
        blocked.clear();
        blocked.insert(old.digest()?);
    }
    let updated = host
        .update(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            definition,
            true,
            u64::MAX,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert_ne!(updated.admitted().spec, instance.admitted().spec);
    assert_eq!(
        updated.admitted().spec.definition.images[0].digest,
        current.digest()?
    );
    Ok(())
}

#[tokio::test]
async fn versions_fence_revoked_run() -> TestResult {
    for rollback in [false, true] {
        let fixture = Fixture::new(Default::default())?;
        fixture.install(&bundle("sql")?)?;
        let instance = fixture.admit(
            "final-run",
            r#"SELECT value FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#,
        ).await?;
        let control = AnalysisReadControl::default();
        let first = instance.run(request("first"), &control).await?;
        let generation = instance.admitted().generation;
        let definition = target(
            &fixture,
            r#"SELECT value FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(4 AS BIGINT UNSIGNED) AS value))"#,
            "",
        ).await?;
        let actions = Actions::new(&fixture);
        let host = InstanceHost::new(Arc::clone(&fixture.query), actions.clone());
        let current = if rollback {
            host.update(
                instance,
                fixture
                    .query
                    .store()
                    .managed_instance([1; 16], "final-run", &control)?
                    .ok_or("current final Run instance")?
                    .lifecycle,
                definition.clone(),
                true,
                u64::MAX,
                &control,
            )
            .await?
        } else {
            instance
        };
        let before = fixture
            .query
            .store()
            .managed_instance([1; 16], "final-run", &control)?
            .ok_or("original final Run instance")?;
        let history = fixture.query.store().managed_history(
            &fixture.grant.selection,
            "final-run",
            &control,
        )?;
        actions.clear()?;
        actions.revoked.store(2, Ordering::SeqCst);
        let result = if rollback {
            host.rollback(
                Arc::clone(&current),
                before.lifecycle,
                generation,
                true,
                u64::MAX,
                &control,
            )
            .await
        } else {
            host.update(
                Arc::clone(&current),
                before.lifecycle,
                definition,
                true,
                u64::MAX,
                &control,
            )
            .await
        };
        assert!(result.is_err());
        assert_eq!(actions.updates.load(Ordering::SeqCst), 2);
        assert_eq!(
            *actions.denied.lock().map_err(|_| "version denied lock")?,
            Some(PackageActionV1::Run)
        );
        assert_eq!(
            fixture
                .query
                .store()
                .managed_instance([1; 16], "final-run", &control)?,
            Some(before.clone())
        );
        assert_eq!(
            fixture.query.store().managed_history(
                &fixture.grant.selection,
                "final-run",
                &control
            )?,
            history
        );
        assert_eq!(fixture.selected("final-run", &first.attempt)?, [3]);
        let old = fixture
            .query
            .store()
            .managed_attempt([1; 16], "final-run", &first.attempt, &control)?
            .ok_or("retained final Run attempt")?;
        assert_eq!(old.receipt(), Some(&first));
    }
    Ok(())
}

async fn entered(receiver: mpsc::Receiver<()>) -> TestResult {
    tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(30))).await??;
    Ok(())
}

async fn progress(fixture: &Fixture, id: &str, after: u64) -> TestResult<u64> {
    let mut changes = fixture.query.store().subscribe_revision();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let current = fixture.progress(id)?;
            if current > after {
                return Ok(current);
            }
            changes.changed().await?;
        }
    })
    .await?
}

pub(in crate::instance) struct JoinedInput {
    pub(in crate::instance) schema: Arc<sdk::Schema>,
    pub(in crate::instance) wait: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}

impl std::fmt::Debug for JoinedInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JoinedInput")
            .finish_non_exhaustive()
    }
}

impl datafusion::physical_plan::streaming::PartitionStream for JoinedInput {
    fn schema(&self) -> &Arc<sdk::Schema> {
        &self.schema
    }

    fn execute(
        &self,
        _context: Arc<datafusion::execution::TaskContext>,
    ) -> datafusion::physical_plan::SendableRecordBatchStream {
        use datafusion::common::DataFusionError;
        use datafusion::physical_plan::stream::RecordBatchStreamAdapter;

        let wait = self
            .wait
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let schema = Arc::clone(&self.schema);
        let stream = futures_util::stream::once(async move {
            if let Some((entered, release)) = wait {
                entered.send(()).map_err(|_| {
                    DataFusionError::Execution("joined input observer closed".into())
                })?;
                release.await.map_err(|_| {
                    DataFusionError::Execution("joined input release closed".into())
                })?;
            }
            sdk::RecordBatch::try_new(schema, vec![Arc::new(UInt64Array::from(vec![3]))])
                .map_err(DataFusionError::from)
        });
        Box::pin(RecordBatchStreamAdapter::new(
            Arc::clone(&self.schema),
            stream,
        ))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_capture_joined_state() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let image = bundle("wasm")?;
    fixture.install(&image)?;
    let actions = Actions::new(&fixture);
    fixture.context(1)?;
    let sql = r#"SELECT value FROM "runtime-fixture"."1".accumulate(input => (SELECT value FROM joined_input)) WHERE EXISTS (SELECT 1 FROM context_versions)"#;
    let (entry, observed) = tokio::sync::oneshot::channel();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let input = Arc::new(JoinedInput {
        schema: Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "value",
            sdk::DataType::UInt64,
            false,
        )])),
        wait: Mutex::new(Some((entry, waiting))),
    });
    let control = AnalysisReadControl::default();
    let mut session = fixture
        .query
        .session(fixture.grant.selection.clone(), &control, 0)?;
    let partition: Arc<dyn datafusion::physical_plan::streaming::PartitionStream> = input.clone();
    session.register_table(
        "joined_input",
        Arc::new(datafusion::catalog::streaming::StreamingTable::try_new(
            Arc::clone(&input.schema),
            vec![partition],
        )?),
    )?;
    let prepared = session
        .prepare_definition(&Fixture::definition(sql))
        .await?;
    fixture
        .query
        .store()
        .admit_definition([1; 16], prepared.resolved(), || Ok(()))?;
    let instance = Instance::admit_prepared(
        session,
        actions.clone(),
        fixture.grant.clone(),
        "joined-state".into(),
        prepared,
        araphor_data::ManagedDestination::Selected,
    )
    .await?;
    let mut definition = Fixture::definition(sql);
    definition.description = "Retain the same program and state.".into();
    let definition = instance
        .session
        .prepare_definition(&definition)
        .await?
        .resolved()
        .clone();
    fixture
        .query
        .store()
        .admit_definition([1; 16], &definition, || Ok(()))?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), actions.clone());
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    let running = host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(30), observed).await??;
    assert_eq!(fixture.progress("joined-state")?, 0);
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    let (entry, observed) = mpsc::channel();
    let (prepared, waiting) = mpsc::channel();
    *actions.gate.lock().map_err(|_| "version gate lock")? =
        Some((image.digest()?, entry, waiting));
    let selected = Arc::clone(&host);
    let expected = running.admitted().lifecycle;
    let update = tokio::spawn(async move {
        selected
            .update(
                running,
                expected,
                definition,
                false,
                u64::MAX,
                &AnalysisReadControl::default(),
            )
            .await
    });
    entered(observed).await?;
    assert!(!update.is_finished());
    release
        .send(())
        .map_err(|_| "joined input release closed")?;
    let first = progress(&fixture, "joined-state", 0).await?;
    assert!(!update.is_finished());
    prepared.send(())?;
    let updated = tokio::time::timeout(Duration::from_secs(30), update).await???;
    assert!(updated.admitted().progress > first);
    let history = fixture.query.store().managed_history(
        &fixture.grant.selection,
        "joined-state",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(history.len(), 2);
    let original = history.first().ok_or("joined original")?;
    let current = history.last().ok_or("joined target")?;
    assert_eq!(fixture.selected("joined-state", &original.attempt)?, [3]);
    assert_eq!(fixture.selected("joined-state", &current.attempt)?, [6]);
    let reference = current.results.values().next().ok_or("joined result")?;
    let evaluation = fixture.query.store().managed_evaluation(
        updated.admitted(),
        &reference.result_id,
        &AnalysisReadControl::default(),
    )?;
    let checkpoint = evaluation.checkpoint.ok_or("joined consumed checkpoint")?;
    assert_eq!(values(&checkpoint.datasets[0].batches)?, [3]);
    let stopped = host
        .stop(
            Arc::clone(&updated),
            updated.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert!(!stopped.admitted().running);
    let updated = host
        .start(
            Arc::clone(&stopped),
            stopped.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert!(updated.admitted().running);
    fixture.context(2)?;
    progress(&fixture, "joined-state", updated.admitted().progress).await?;
    let history = fixture.query.store().managed_history(
        &fixture.grant.selection,
        "joined-state",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        fixture.selected(
            "joined-state",
            &history.last().ok_or("continued target")?.attempt
        )?,
        [9]
    );
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_versions_keep_running() -> TestResult {
    for mode in ["trap", "invalid-evidence"] {
        let fixture = Fixture::new(Default::default())?;
        fixture.install(&image("sql", "old")?)?;
        let template = fixture.terminal_instance("target-template", mode).await?;
        let instance = fixture
            .admit(
                "failed-version",
                r#"SELECT value FROM "runtime-fixture"."old".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value)) WHERE EXISTS (SELECT 1 FROM context_versions)"#,
            )
            .await?;
        let control = AnalysisReadControl::default();
        let first = instance.run(request("first"), &control).await?;
        let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
        let running = host
            .start(
                Arc::clone(&instance),
                instance.admitted().lifecycle,
                &control,
            )
            .await?;
        let original = fixture
            .query
            .store()
            .managed_instance([1; 16], "failed-version", &control)?
            .ok_or("running old version")?;
        assert!(host
            .update(
                running,
                original.lifecycle,
                template.admitted().spec.definition.clone(),
                true,
                u64::MAX,
                &control,
            )
            .await
            .is_err());
        assert_eq!(
            fixture
                .query
                .store()
                .managed_instance([1; 16], "failed-version", &control)?,
            Some(original)
        );
        let status = fixture.query.store().managed_status(
            &fixture.grant.selection,
            "failed-version",
            &control,
        )?;
        assert!(matches!(
            status.readiness,
            araphor_data::PackageReadinessV1::Ready
        ));
        assert_eq!(status.status_progress, first.commit_revision);
        assert_eq!(fixture.selected("failed-version", &first.attempt)?, [3]);
        fixture.context(2)?;
        progress(&fixture, "failed-version", first.commit_revision).await?;
        let history = fixture.query.store().managed_history(
            &fixture.grant.selection,
            "failed-version",
            &control,
        )?;
        assert_eq!(history.len(), 2);
        assert_eq!(
            fixture.selected(
                "failed-version",
                &history.last().ok_or("continued old")?.attempt
            )?,
            [6]
        );
        stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(30), worker).await???;
        drop(fixture.query.store().lease_managed()?);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_cancellation_joins_workers() -> TestResult {
    for mode in ["cancel", "drop", "shutdown"] {
        let fixture = Fixture::new(araphor_query::execution::Limits {
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            ..Default::default()
        })?;
        fixture.install(&image("sql", "old")?)?;
        let template = fixture
            .terminal_instance("cancel-template", "cancel")
            .await?;
        let instance = fixture
            .admit(
                "cancel-version",
                r#"SELECT value FROM "runtime-fixture"."old".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value)) WHERE EXISTS (SELECT 1 FROM context_versions)"#,
            )
            .await?;
        let first = instance
            .run(request("first"), &AnalysisReadControl::default())
            .await?;
        let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
        let running = host
            .start(
                Arc::clone(&instance),
                instance.admitted().lifecycle,
                &AnalysisReadControl::default(),
            )
            .await?;
        let original = fixture
            .query
            .store()
            .managed_instance([1; 16], "cancel-version", &AnalysisReadControl::default())?
            .ok_or("cancel old version")?;
        let (entry, observed) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        fixture.query.guest_entry(entry, Some(waiting))?;
        let selected = Arc::clone(&host);
        let control = Arc::new(AnalysisReadControl::default());
        let operation = Arc::clone(&control);
        let definition = template.admitted().spec.definition.clone();
        let expected = running.admitted().lifecycle;
        let update = tokio::spawn(async move {
            selected
                .update(running, expected, definition, true, u64::MAX, &operation)
                .await
        });
        entered(observed).await?;
        assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
        match mode {
            "drop" => update.abort(),
            "shutdown" => {
                stop.send_replace(true);
            }
            _ => control.cancel()?,
        }
        tokio::task::yield_now().await;
        assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
        assert!(!worker.is_finished());
        if mode != "drop" {
            assert!(!update.is_finished());
        }
        release.send(())?;
        if mode == "drop" {
            assert!(update.await.is_err_and(|error| error.is_cancelled()));
        } else {
            assert!(tokio::time::timeout(Duration::from_secs(30), update)
                .await??
                .is_err());
        }
        drop(
            tokio::time::timeout(
                Duration::from_secs(30),
                fixture.query.acquire_evaluation([1; 16]),
            )
            .await??,
        );
        assert_eq!(
            fixture.query.store().managed_instance(
                [1; 16],
                "cancel-version",
                &AnalysisReadControl::default()
            )?,
            Some(original)
        );
        assert_eq!(fixture.selected("cancel-version", &first.attempt)?, [3]);
        if mode != "shutdown" {
            fixture.context(2)?;
            progress(&fixture, "cancel-version", first.commit_revision).await?;
            let history = fixture.query.store().managed_history(
                &fixture.grant.selection,
                "cancel-version",
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(history.len(), 2);
            assert_eq!(
                fixture.selected(
                    "cancel-version",
                    &history.last().ok_or("cancelled target")?.attempt
                )?,
                [6]
            );
            stop.send_replace(true);
        }
        tokio::time::timeout(Duration::from_secs(30), worker).await???;
        drop(fixture.query.store().lease_managed()?);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_keeps_old_worker() -> TestResult {
    const CAPACITY: usize = 128 * 1024 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(CAPACITY),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let instance = fixture.terminal_instance("prepare-old", "cancel").await?;
    let definition = target(&fixture, "SELECT CAST(7 AS BIGINT UNSIGNED) AS value", "").await?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    fixture.query.guest_entry(entry, Some(waiting))?;
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    let running = host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    entered(observed).await?;
    let held = fixture.query.memory().input_reserved();
    let pressure = fixture
        .query
        .memory()
        .reserve_input(CAPACITY.checked_sub(held).ok_or("retained preparation")?)?;
    let before = fixture.query.store().meta()?;
    let original = fixture
        .query
        .store()
        .managed_instance([1; 16], "prepare-old", &AnalysisReadControl::default())?
        .ok_or("prepared old owner")?;
    assert!(tokio::time::timeout(
        Duration::from_secs(30),
        host.update(
            running,
            original.lifecycle,
            definition,
            true,
            u64::MAX,
            &AnalysisReadControl::default(),
        ),
    )
    .await?
    .is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(
        fixture.query.store().managed_instance(
            [1; 16],
            "prepare-old",
            &AnalysisReadControl::default()
        )?,
        Some(original)
    );
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    assert!(!worker.is_finished());
    drop(pressure);
    stop.send_replace(true);
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
async fn retained_replay_uses_generation() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let old = bundle("sql")?;
    fixture.install(&old)?;
    let instance = fixture.admit("retained-replay", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    let mut input = request("original");
    input.seed = Some(17);
    let receipt = instance
        .run(input.clone(), &AnalysisReadControl::default())
        .await?;
    let reference = receipt
        .results
        .values()
        .next()
        .ok_or("original replay result")?;
    let original = fixture.query.store().managed_result(
        instance.admitted(),
        &reference.result_id,
        10,
        &AnalysisReadControl::default(),
    )?;
    let next = image("sql", "2")?;
    fixture.install(&next)?;
    let definition = target(&fixture, r#"SELECT * FROM "runtime-fixture"."2".accumulate(input => (SELECT CAST(99 AS BIGINT UNSIGNED) AS value))"#, "").await?;
    let actions = Actions::new(&fixture);
    let host = InstanceHost::new(Arc::clone(&fixture.query), actions.clone());
    let updated = host
        .update(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            definition,
            true,
            u64::MAX,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert_ne!(
        updated.admitted().generation,
        instance.admitted().generation
    );
    actions
        .blocked
        .lock()
        .map_err(|_| "blocked images")?
        .insert(next.digest()?);
    assert!(host
        .restore([1; 16], "retained-replay", &AnalysisReadControl::default())
        .await
        .is_err());
    let removed = host
        .remove(
            fixture.grant.clone(),
            "retained-replay".into(),
            updated.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert!(removed.removed);
    assert!(!removed.running);
    drop((instance, updated));
    let before = fixture.query.store().meta()?;
    let history = fixture.query.store().managed_history(
        &fixture.grant.selection,
        "retained-replay",
        &AnalysisReadControl::default(),
    )?;
    let replayed = Instance::replay_result(
        Arc::clone(&fixture.query),
        actions,
        fixture.grant.clone(),
        "retained-replay",
        &reference.result_id,
        &AnalysisReadControl::default(),
    )
    .await?;
    assert_eq!(values(&replayed.batches)?, [3]);
    let call = replayed
        .calls
        .values()
        .next()
        .ok_or("historical replay call")?;
    assert_eq!(call.evaluation().context, original.context.context);
    assert_eq!(call.evaluation().context.id, input.id);
    assert_eq!(
        call.evaluation().context.time_utc_ns,
        input.time_utc_ns as i64
    );
    assert_eq!(call.evaluation().context.seed, input.seed);
    assert_eq!(
        sdk::wire::Output::encode_model(call.output(), &old.artifacts[0].descriptor.exports[0])?,
        sdk::wire::Output::encode_model(&original.output, &old.artifacts[0].descriptor.exports[0])?
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(
        fixture.query.store().managed_instance(
            [1; 16],
            "retained-replay",
            &AnalysisReadControl::default()
        )?,
        Some(removed)
    );
    assert_eq!(
        fixture.query.store().managed_history(
            &fixture.grant.selection,
            "retained-replay",
            &AnalysisReadControl::default()
        )?,
        history
    );
    Ok(())
}

#[tokio::test]
async fn retained_replay_checks_inspect() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture.admit("retained-inspect", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    let receipt = instance
        .run(request("original"), &AnalysisReadControl::default())
        .await?;
    let reference = receipt
        .results
        .values()
        .next()
        .ok_or("retained inspect result")?;
    fixture.query.store().fault_write(
        "UPDATE managed_arrow SET ipc = 'invalid'::BLOB WHERE result_id = ? AND role = 'input'",
        &[&reference.result_id],
    )?;
    let actions = Actions::new(&fixture);
    actions.deny(Some(PackageActionV1::Inspect))?;
    actions.clear()?;
    let before = fixture.query.store().meta()?;
    let held = fixture.query.memory().input_reserved();
    let error = Instance::replay_result(
        Arc::clone(&fixture.query),
        actions.clone(),
        fixture.grant.clone(),
        "retained-inspect",
        &reference.result_id,
        &AnalysisReadControl::default(),
    )
    .await
    .err()
    .ok_or("denied replay inspected payload")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(
        *actions.checked.lock().map_err(|_| "inspect checks")?,
        [PackageActionV1::Inspect]
    );
    assert_eq!(fixture.query.memory().input_reserved(), held);
    assert_eq!(fixture.query.store().meta()?, before);
    actions.deny(None)?;
    let error = Instance::replay_result(
        Arc::clone(&fixture.query),
        actions,
        fixture.grant.clone(),
        "retained-inspect",
        &reference.result_id,
        &AnalysisReadControl::default(),
    )
    .await
    .err()
    .ok_or("corrupt replay input accepted")?;
    assert_ne!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}

struct FinalInspector {
    inner: Arc<Actions>,
    inspections: AtomicUsize,
    image: String,
    trust: bool,
}

impl PackageAuthorization for FinalInspector {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        self.inner.check(grant, action)?;
        if action == PackageActionV1::Inspect
            && self.inspections.fetch_add(1, Ordering::SeqCst) == 1
        {
            if self.trust {
                self.inner
                    .blocked
                    .lock()
                    .map_err(|_| Code::Incomplete.error("final inspection trust"))?
                    .insert(self.image.clone());
            } else {
                *self
                    .inner
                    .denied
                    .lock()
                    .map_err(|_| Code::Incomplete.error("final inspection permission"))? =
                    Some(PackageActionV1::Run);
            }
        }
        Ok(())
    }

    fn admit(&self, grant: &PackageGrantV1, image: &PackageBundle) -> araphor_data::Result<()> {
        self.inner.admit(grant, image)
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        image: &PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.inner.commit(grant, action, image, operation)
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, PackageActionV1, Option<&PackageBundle>)],
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.inner.commit_many(grants, operation)
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.changes()
    }
}

#[tokio::test]
async fn replay_checks_final_authority() -> TestResult {
    for trust in [false, true] {
        let fixture = Fixture::new(Default::default())?;
        let image = bundle("sql")?;
        fixture.install(&image)?;
        let instance = fixture.admit("final-replay", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
        let receipt = instance
            .run(request("original"), &AnalysisReadControl::default())
            .await?;
        let reference = receipt
            .results
            .values()
            .next()
            .ok_or("final replay result")?;
        let actions = Actions::new(&fixture);
        let authority = Arc::new(FinalInspector {
            inner: Arc::clone(&actions),
            inspections: AtomicUsize::new(0),
            image: image.digest()?,
            trust,
        });
        let before = fixture.query.store().meta()?;
        let held = fixture.query.memory().input_reserved();
        let error = Instance::replay_result(
            Arc::clone(&fixture.query),
            authority.clone(),
            fixture.grant.clone(),
            "final-replay",
            &reference.result_id,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("final replay authority changed")?;
        assert_eq!(
            error.status_code(),
            erebor_runtime_error::StatusCode::PermissionDenied
        );
        assert_eq!(authority.inspections.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.query.store().meta()?, before);
        assert_eq!(fixture.query.memory().input_reserved(), held);
        let groups = actions
            .committed
            .lock()
            .map_err(|_| "final replay authority groups")?;
        let final_group = groups.last().ok_or("final replay authority snapshot")?;
        let digest = image.digest()?;
        assert!(final_group
            .iter()
            .any(|(action, image)| *action == PackageActionV1::Run && image.is_none()));
        assert!(final_group
            .iter()
            .any(|(action, image)| *action == PackageActionV1::Inspect && image.is_none()));
        assert!(final_group
            .iter()
            .any(|(action, pin)| *action == PackageActionV1::Run
                && pin.as_deref() == Some(digest.as_str())));
    }
    Ok(())
}

#[tokio::test]
async fn native_caps_keep_receipt() -> TestResult {
    let mut fixture = Fixture::new(Default::default())?;
    let mut native = image("wasm", "2")?;
    native.artifacts[0].implementations = vec![PackageImplementationV1::Native {
        export: "accumulate".into(),
        artifact: b"invalid".to_vec(),
        qualification: Some(araphor_package::Qualification {
            exports: vec!["accumulate".into()],
            target: "foreign-target".into(),
            cpu_features: Vec::new(),
            contract_version: sdk::CONTRACT_VERSION,
            system_libraries: Vec::new(),
            dependencies: Vec::new(),
        }),
    }];
    fixture.install(&native)?;
    let definition = target(
        &fixture,
        r#"SELECT value FROM "runtime-fixture"."2".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#,
        "",
    ).await?;
    let mut limits = araphor_query::execution::Limits {
        global_evaluations: Some(4),
        tenant_evaluations: Some(4),
        ..Default::default()
    };
    limits.package.native.memory_bytes = Some(1024);
    fixture.query = Engine::new(Arc::clone(fixture.query.store()), limits)?;
    let wasm = image("wasm", "1")?;
    fixture.install(&wasm)?;
    let instance = fixture.admit(
        "native-cap",
        r#"SELECT value FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#,
    ).await?;
    let control = AnalysisReadControl::default();
    let receipt = instance.run(request("prior-wasm"), &control).await?;
    let prior = fixture
        .query
        .store()
        .managed_instance([1; 16], "native-cap", &control)?
        .ok_or("prior Wasm instance")?;
    let reference = receipt.results.values().next().ok_or("prior Wasm result")?;
    let saved = fixture
        .query
        .store()
        .managed_result(&prior, &reference.result_id, 10, &control)?;
    assert_eq!(saved.context.target, "wasm");
    assert!(saved.output.checkpoint.is_some());
    assert_eq!(fixture.selected("native-cap", &receipt.attempt)?, [3]);
    let model = &wasm.artifacts[0].descriptor.exports[0];
    let packet = sdk::wire::Output::encode_model(&saved.output, model)?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let before = fixture.query.store().meta()?;
    let error = host
        .update(
            Arc::clone(&instance),
            prior.lifecycle,
            definition,
            true,
            u64::MAX,
            &control,
        )
        .await
        .err()
        .ok_or("capped Native replacement published")?;
    assert_eq!(
        Subscription::failure(&error),
        araphor_data::ManagedExit::Failed(Code::Unsupported),
        "{error:?}"
    );
    let mut cause: &dyn std::error::Error = &error;
    while let Some(next) = cause.source() {
        cause = next;
    }
    assert_eq!(
        cause.to_string(),
        Code::Unsupported
            .error("in-process native resource limits")
            .to_string(),
        "{error:?}"
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance([1; 16], "native-cap", &control)?,
        Some(prior.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .managed_history(&fixture.grant.selection, "native-cap", &control)?,
        std::slice::from_ref(&receipt)
    );
    assert_eq!(fixture.progress("native-cap")?, receipt.commit_revision);
    let unchanged =
        fixture
            .query
            .store()
            .managed_result(&prior, &reference.result_id, 10, &control)?;
    assert!(unchanged.current);
    assert_eq!(unchanged.context, saved.context);
    assert_eq!(unchanged.commit_revision, saved.commit_revision);
    assert_eq!(
        sdk::wire::Output::encode_model(&unchanged.output, model)?,
        packet
    );
    assert_eq!(
        instance.run(request("prior-wasm"), &control).await?,
        receipt
    );
    assert_eq!(fixture.query.store().meta()?, before);
    let mut permits = Vec::new();
    for _ in 0..4 {
        permits.push(fixture.query.reserve_evaluation([1; 16])?);
    }
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    drop(permits);
    Ok(())
}
