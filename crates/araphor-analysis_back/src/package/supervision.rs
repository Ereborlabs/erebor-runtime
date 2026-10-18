use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use erebor_runtime_error::{ErrorExt as _, StatusCode};
use snafu::IntoError as _;
use tokio::sync::watch;
use tokio::task::{Id, JoinSet};

use crate::analysis::{PackageActivationV1, PackageResultRefV1};
use crate::{AnalysisReadControl, Result};

use super::evaluation::RunPreparation;
use super::installed::snapshot::InstalledBundle;
use super::owner::InstalledContext;
use super::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code, PackageReadinessV1,
};

type TaskKey = ([u8; 16], String, String, String);
type BundleKey = ([u8; 16], String, String, String);
type TaskResult = (TaskKey, Result<()>);

struct Registered {
    active: PackageActivationV1,
    bundle: Arc<InstalledBundle>,
    stop: Option<watch::Sender<bool>>,
    task: Option<Id>,
}

impl Registered {
    fn key(active: &PackageActivationV1) -> TaskKey {
        let key = &active.key;
        (
            key.tenant_id,
            key.scope_id.clone(),
            key.package_id.clone(),
            key.export.clone(),
        )
    }

    fn bundle_key(&self) -> BundleKey {
        (
            self.active.key.tenant_id,
            self.active.key.scope_id.clone(),
            self.bundle.value.root.package_id.clone(),
            self.bundle.value.root.revision.clone(),
        )
    }

    fn stop(&self) {
        if let Some(stop) = &self.stop {
            stop.send_replace(true);
        }
    }
}

impl AnalysisPackageOwner {
    pub(super) async fn supervise(self: Arc<Self>, mut stop: watch::Receiver<bool>) -> Result<()> {
        let mut activations = self.store.subscribe_activations();
        let mut authority = self.authority.changes();
        let memory = self.query.memory().scope();
        let mut entries = BTreeMap::<TaskKey, Registered>::new();
        let mut tasks = JoinSet::<TaskResult>::new();
        let result = async {
            let mut refresh = true;
            let mut reauthorize = false;
            let mut blocked = None::<(crate::Error, u64)>;
            let mut expiry = None::<u64>;
            loop {
                if *stop.borrow() || stop.has_changed().is_err() {
                    return Ok(());
                }
                if reauthorize {
                    for entry in entries.values() { entry.stop(); }
                    while let Some(result) = tasks.join_next().await {
                        let (_, result) = result.map_err(|source| crate::AnalysisExecutionSnafu.into_error(source))?;
                        Self::task_result(result)?;
                    }
                    for entry in entries.values_mut() { entry.task = None; entry.stop = None; }
                    reauthorize = false;
                }
                if refresh {
                    refresh = false;
                    let owner = Arc::clone(&self);
                    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
                    let stage = Arc::clone(&control);
                    let mut worker = tokio::task::spawn_blocking(move || owner.registrations(&stage));
                    let selected = tokio::select! {
                        result = &mut worker => result.map_err(|source| crate::AnalysisExecutionSnafu.into_error(source))?,
                        _changed = stop.changed() => {
                            control.cancel()?;
                            let _result = worker.await;
                            return Ok(());
                        }
                        _changed = authority.changed() => {
                            control.cancel()?;
                            let _result = worker.await;
                            reauthorize = true;
                            refresh = true;
                            continue;
                        }
                    };
                    let epoch = memory.capacity_epoch();
                    let selected = match selected {
                        Ok(selected) => { blocked = None; selected }
                        Err(error) if error.is_busy() => {
                            blocked = Some((error, epoch));
                            Vec::new()
                        }
                        Err(error) => return Err(error),
                    };
                    if blocked.is_none() {
                        expiry = selected.iter().try_fold(None::<u64>, |expiry, active| {
                            let context: InstalledContext = Self::decode(&active.metadata)?;
                            Ok::<_, crate::Error>(match (expiry, context.grant.expires_utc_ns) {
                                (Some(previous), Some(next)) => Some(previous.min(next)),
                                (previous, next) => previous.or(next),
                            })
                        })?;
                        let mut retiring = BTreeSet::new();
                        for (key, entry) in &entries {
                            let current = selected.iter().find(|active| Registered::key(active) == *key);
                            if current.is_none_or(|active| active.generation != entry.active.generation
                                || active.revision != entry.active.revision
                                || active.metadata != entry.active.metadata) {
                                entry.stop();
                                retiring.insert(key.clone());
                            }
                        }
                        while retiring.iter().any(|key| entries.get(key).is_some_and(|entry| entry.task.is_some())) {
                            let Some(result) = tasks.join_next_with_id().await else { break; };
                            let (id, (key, result)) = result.map_err(|source| crate::AnalysisExecutionSnafu.into_error(source))?;
                            if entries.get(&key).is_some_and(|entry| entry.task == Some(id)) { entries.remove(&key); }
                            Self::task_result(result)?;
                        }
                        for key in retiring { entries.remove(&key); }
                        let selected = selected.into_iter().filter(|active|
                            entries.get(&Registered::key(active)).is_none_or(|entry| entry.task.is_none())).collect();
                        let cache = entries.values().map(|entry|
                            (entry.bundle_key(), Arc::clone(&entry.bundle))).collect();
                        let owner = Arc::clone(&self);
                        let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?);
                        let stage = Arc::clone(&control);
                        let budget = Arc::clone(&memory);
                        let epoch = memory.capacity_epoch();
                        let mut worker = tokio::task::spawn_blocking(move || owner.admit_registrations(selected, cache, &budget, &stage));
                        let admitted = tokio::select! {
                            result = &mut worker => result.map_err(|source| crate::AnalysisExecutionSnafu.into_error(source))?,
                            _changed = stop.changed() => {
                                control.cancel()?;
                                let _result = worker.await;
                                return Ok(());
                            }
                            _changed = authority.changed() => {
                                control.cancel()?;
                                let _result = worker.await;
                                reauthorize = true;
                                refresh = true;
                                continue;
                            }
                        };
                        match admitted {
                            Err(error) if error.is_busy() => blocked = Some((error, epoch)),
                            Err(error) => return Err(error),
                            Ok(values) => {
                                blocked = None;
                                for (active, bundle) in values {
                                    let key = Registered::key(&active);
                                    let context: InstalledContext = Self::decode(&active.metadata)?;
                                    let (sender, receiver) = watch::channel(false);
                                    let task = if context.prepared { None } else {
                                        let owner = Arc::clone(&self);
                                        let selected = active.clone();
                                        let retained = Arc::clone(&bundle);
                                        let task_key = key.clone();
                                        Some(tasks.spawn(async move {
                                            let result = owner.serve_activation(selected, retained, receiver).await;
                                            (task_key, result)
                                        }).id())
                                    };
                                    entries.insert(key, Registered { active, bundle, stop: task.map(|_| sender), task });
                                }
                            }
                        }
                    }
                }
                tokio::select! {
                    changed = stop.changed() => { if changed.is_err() || *stop.borrow() { return Ok(()); } refresh = true; }
                    changed = activations.changed() => {
                        if changed.is_err() { return Ok(()); }
                        activations.borrow_and_update();
                        blocked = None;
                        refresh = true;
                    }
                    changed = authority.changed() => {
                        if changed.is_err() { return Ok(()); }
                        reauthorize = true;
                        blocked = None;
                        refresh = true;
                    }
                    ready = async {
                        let Some((error, epoch)) = blocked.take() else {
                            return std::future::pending::<Result<()>>().await;
                        };
                        self.wait_capacity(error, &memory, epoch, None).await
                    } => { ready?; refresh = true; }
                    result = tasks.join_next_with_id(), if !tasks.is_empty() => {
                        if let Some(result) = result {
                            let (id, (key, result)) = result.map_err(|source| crate::AnalysisExecutionSnafu.into_error(source))?;
                            if entries.get(&key).is_some_and(|entry| entry.task == Some(id)) { entries.remove(&key); }
                            Self::task_result(result)?;
                            refresh = true;
                        }
                    }
                    () = Self::grant_expiry(expiry) => { expiry = None; blocked = None; refresh = true; },
                }
            }
        }.await;
        for entry in entries.values() {
            entry.stop();
        }
        while let Some(joined) = tasks.join_next().await {
            let _joined = joined;
        }
        result
    }

    fn task_result(result: Result<()>) -> Result<()> {
        match result {
            Err(error) if error.status_code() == StatusCode::PermissionDenied => Ok(()),
            result => result,
        }
    }

    fn registrations(&self, control: &AnalysisReadControl) -> Result<Vec<PackageActivationV1>> {
        let mut values = Vec::new();
        let mut after = None;
        loop {
            control.check()?;
            let page = self
                .store
                .package_activation_page_until(after.as_ref(), control)?;
            if page.is_empty() {
                return Ok(values);
            }
            after = page.last().map(|active| active.key.clone());
            values.extend(page.into_iter().filter(|active| active.active));
        }
    }

    fn admit_registrations(
        &self,
        selected: Vec<PackageActivationV1>,
        cache: BTreeMap<BundleKey, Arc<InstalledBundle>>,
        memory: &araphor_query::memory::Memory,
        control: &AnalysisReadControl,
    ) -> Result<Vec<(PackageActivationV1, Arc<InstalledBundle>)>> {
        let mut values = Vec::new();
        let mut cache = cache;
        for selected in selected {
            control.check()?;
            let Some(active) = self
                .store
                .package_activation_until(&selected.key, control)?
                .filter(|active| active.active)
            else {
                continue;
            };
            let context: InstalledContext = Self::decode(&active.metadata)?;
            let result = (|| -> Result<Arc<InstalledBundle>> {
                self.check(&context.grant, Action::Run)?;
                self.prune_orphans(&active, control)?;
                let _permit = self.operation()?;
                let key = (
                    active.key.tenant_id,
                    active.key.scope_id.clone(),
                    context.root.package_id.clone(),
                    context.root.revision.clone(),
                );
                let bundle = match cache.get(&key) {
                    Some(bundle) => Arc::clone(bundle),
                    None => {
                        let bundle = InstalledBundle::new(
                            &self.query,
                            self.load_bundle(active.key.tenant_id, &context.root, Some(control))?,
                            memory,
                        )?;
                        cache.insert(key, Arc::clone(&bundle));
                        bundle
                    }
                };
                self.authority.admit(&context.grant, &bundle.admission())?;
                let (artifact, model, _) =
                    bundle.export(&active.key.package_id, &active.revision, &active.key.export)?;
                if context.prepared != artifact.prepared(&active.key.export)
                    || context.clock != bundle.clock(artifact, model)?
                {
                    return Err(Code::Invalid.error("activation model flags").into());
                }
                control.check()?;
                Ok(bundle)
            })();
            match result {
                Ok(bundle) => values.push((active, bundle)),
                Err(error) if error.is_busy() => return Err(error),
                Err(error) => {
                    control.check()?;
                    self.failed(&active, &error, control)?;
                    if error.status_code() == StatusCode::PermissionDenied {
                        let _lifecycle = self
                            .lifecycle
                            .lock()
                            .map_err(|_| Code::Conflict.error("package lifecycle lock"))?;
                        self.store
                            .suspend_package(&active.key, active.generation, || control.check())?;
                    }
                }
            }
        }
        Ok(values)
    }

    async fn serve_activation(
        self: Arc<Self>,
        mut active: PackageActivationV1,
        bundle: Arc<InstalledBundle>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut authority = self.authority.changes();
        let (artifact, _, admitted) =
            bundle.export(&active.key.package_id, &active.revision, &active.key.export)?;
        let context: InstalledContext = Self::decode(&active.metadata)?;
        let model_clock =
            admitted.implementation(artifact)?.target() != "sql" || admitted.model_clock();
        let mut inputs = admitted.inputs.watch(
            Arc::clone(&self.query),
            active.clone(),
            Arc::new(araphor_query::follow::SystemClock::default()),
            model_clock,
        )?;
        loop {
            if *stop.borrow() || stop.has_changed().is_err() {
                return Ok(());
            }
            match self.check(&context.grant, Action::Run) {
                Ok(()) => {}
                Err(error) if error.status_code() == StatusCode::PermissionDenied => return Ok(()),
                Err(error) => return Err(error.into()),
            }
            let mut epoch = inputs.memory().capacity_epoch();
            let offered = {
                let control = Arc::clone(inputs.control());
                let offered = inputs.next();
                tokio::pin!(offered);
                tokio::select! {
                    result = &mut offered => result,
                    _changed = stop.changed() => { control.cancel()?; let _result = offered.await; return Ok(()); }
                    _changed = authority.changed() => { control.cancel()?; let _result = offered.await; return Ok(()); }
                    () = Self::grant_expiry(context.grant.expires_utc_ns) => { control.cancel()?; let _result = offered.await; return Ok(()); }
                }
            };
            let offered = match offered.map_err(crate::Error::from) {
                Ok(Some(offered)) => Ok(offered),
                Ok(None) => return Ok(()),
                Err(error) if error.is_busy() => {
                    if !self
                        .wait_inputs(
                            &mut inputs,
                            error,
                            epoch,
                            &mut stop,
                            &mut authority,
                            context.grant.expires_utc_ns,
                        )
                        .await?
                    {
                        return Ok(());
                    }
                    inputs.retry();
                    continue;
                }
                Err(error) => Err(error),
            };
            active = inputs.activation().clone();
            let now = inputs.now();
            let control = Arc::clone(inputs.control());
            let result = match offered {
                Err(error) => Err(error),
                Ok(offered) => {
                    let permit = tokio::select! {
                        permit = Arc::clone(&self.operations).acquire_owned() => permit.map_err(|_| Code::Incomplete.error("package operation capacity"))?,
                        _changed = stop.changed() => { control.cancel()?; return Ok(()); }
                        _changed = authority.changed() => { control.cancel()?; return Ok(()); }
                        () = Self::grant_expiry(context.grant.expires_utc_ns) => { control.cancel()?; return Ok(()); }
                    };
                    let control = Self::grant_control(
                        &context.grant,
                        Arc::new(inputs.control().stage(Duration::from_secs(30))?),
                    )?;
                    match self.check(&context.grant, Action::Run) {
                        Ok(()) => {}
                        Err(error) if error.status_code() == StatusCode::PermissionDenied => {
                            return Ok(())
                        }
                        Err(error) => return Err(error.into()),
                    }
                    let owner = Arc::clone(&self);
                    let retained = Arc::clone(&bundle);
                    let selected = active.clone();
                    let stage = Arc::clone(&control);
                    epoch = inputs.memory().capacity_epoch();
                    let mut worker = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        owner.evaluate_offer(&selected, &retained, offered, now, &stage)
                    });
                    tokio::select! {
                        result = &mut worker => result.map_err(|source| crate::AnalysisExecutionSnafu.into_error(source))?,
                        _changed = stop.changed() => { control.cancel()?; let _result = worker.await; return Ok(()); }
                        _changed = authority.changed() => { control.cancel()?; let _result = worker.await; return Ok(()); }
                        () = Self::grant_expiry(context.grant.expires_utc_ns) => { control.cancel()?; let _result = worker.await; return Ok(()); }
                    }
                }
            };
            match result {
                Ok(Some(receipt)) => loop {
                    let completion = {
                        let completion = inputs.complete(&receipt);
                        tokio::pin!(completion);
                        tokio::select! {
                            result = &mut completion => result.map_err(crate::Error::from),
                            _changed = stop.changed() => { control.cancel()?; let _result = completion.await; return Ok(()); }
                            _changed = authority.changed() => { control.cancel()?; let _result = completion.await; return Ok(()); }
                            () = Self::grant_expiry(context.grant.expires_utc_ns) => { control.cancel()?; let _result = completion.await; return Ok(()); }
                        }
                    };
                    match completion {
                        Ok(()) => break,
                        Err(error) if error.is_busy() => {
                            let memory = Arc::clone(inputs.memory());
                            tokio::select! {
                                result = self.wait_capacity(error, &memory, epoch, Some(active.key.tenant_id)) => result?,
                                _changed = stop.changed() => { control.cancel()?; return Ok(()); }
                                _changed = authority.changed() => { control.cancel()?; return Ok(()); }
                                () = Self::grant_expiry(context.grant.expires_utc_ns) => { control.cancel()?; return Ok(()); }
                            }
                        }
                        Err(error) if error.package_code() == Code::Conflict => return Ok(()),
                        Err(error) => return Err(error),
                    }
                },
                Ok(None) => {
                    return Err(Code::Conflict
                        .error("live input completion is absent")
                        .into())
                }
                Err(error) if error.is_busy() => {
                    if !self
                        .wait_inputs(
                            &mut inputs,
                            error,
                            epoch,
                            &mut stop,
                            &mut authority,
                            context.grant.expires_utc_ns,
                        )
                        .await?
                    {
                        return Ok(());
                    }
                    inputs.retry();
                }
                Err(error) if error.package_code() == Code::Conflict => {
                    inputs.retry();
                }
                Err(error) => {
                    let control = Self::grant_control(
                        &context.grant,
                        Arc::new(inputs.control().stage(Duration::from_secs(30))?),
                    )?;
                    let owner = Arc::clone(&self);
                    let selected = active.clone();
                    let stage = Arc::clone(&control);
                    let mut worker = tokio::task::spawn_blocking(move || -> Result<_> {
                        owner.failed(&selected, &error, &stage)?;
                        if error.status_code() == StatusCode::PermissionDenied {
                            let _lifecycle = owner
                                .lifecycle
                                .lock()
                                .map_err(|_| Code::Conflict.error("package lifecycle lock"))?;
                            owner.store.suspend_package(
                                &selected.key,
                                selected.generation,
                                || stage.check(),
                            )?;
                            return Ok(None);
                        }
                        owner
                            .store
                            .package_activation_until(&selected.key, &stage)
                            .map_err(Into::into)
                    });
                    let current = tokio::select! {
                        result = &mut worker => result.map_err(|source| crate::AnalysisExecutionSnafu.into_error(source))??,
                        _changed = stop.changed() => { control.cancel()?; let _result = worker.await; return Ok(()); }
                        _changed = authority.changed() => { control.cancel()?; let _result = worker.await; return Ok(()); }
                        () = Self::grant_expiry(context.grant.expires_utc_ns) => { control.cancel()?; let _result = worker.await; return Ok(()); }
                    };
                    let Some(current) = current.filter(|active| active.active) else {
                        return Ok(());
                    };
                    tokio::select! {
                        result = inputs.changed() => result?,
                        _changed = stop.changed() => { control.cancel()?; return Ok(()); }
                        _changed = authority.changed() => { control.cancel()?; return Ok(()); }
                        () = Self::grant_expiry(context.grant.expires_utc_ns) => { control.cancel()?; return Ok(()); }
                    }
                    active = current;
                    inputs = admitted.inputs.watch(
                        Arc::clone(&self.query),
                        active.clone(),
                        Arc::new(araphor_query::follow::SystemClock::default()),
                        model_clock,
                    )?;
                }
            }
        }
    }

    async fn wait_inputs(
        &self,
        inputs: &mut araphor_query::inputs::InputOperation,
        error: crate::Error,
        epoch: u64,
        stop: &mut watch::Receiver<bool>,
        authority: &mut watch::Receiver<u64>,
        expiry: Option<u64>,
    ) -> Result<bool> {
        let control = Arc::clone(inputs.control());
        let memory = Arc::clone(inputs.memory());
        let tenant = inputs.activation().key.tenant_id;
        tokio::select! {
            result = inputs.changed() => { result?; Ok(true) }
            result = self.wait_capacity(error, &memory, epoch, Some(tenant)) => { result?; Ok(true) }
            _changed = stop.changed() => { control.cancel()?; Ok(false) }
            _changed = authority.changed() => { control.cancel()?; Ok(false) }
            () = Self::grant_expiry(expiry) => { control.cancel()?; Ok(false) }
        }
    }

    pub(crate) async fn wait_capacity(
        &self,
        error: crate::Error,
        memory: &araphor_query::memory::Memory,
        epoch: u64,
        tenant: Option<[u8; 16]>,
    ) -> Result<()> {
        match error.busy_resource() {
            Some(("shared input" | "shared output", _)) => memory.capacity_changed(epoch).await?,
            Some(("reader", _)) => self.store.wait_capacity().await?,
            Some(("evaluation", _)) if tenant.is_some() => {
                let tenant = tenant.ok_or_else(|| Code::Invalid.error("evaluation tenant"))?;
                drop(self.query.acquire_evaluation(tenant).await?);
            }
            Some(("package operation capacity", _)) => {
                drop(
                    Arc::clone(&self.operations)
                        .acquire_owned()
                        .await
                        .map_err(|_| Code::Incomplete.error("package operation capacity"))?,
                );
            }
            Some((
                resource @ ("component evaluations"
                | "component compiler"
                | "component cache capacity"),
                requested,
            )) => {
                self.wasm.wait_capacity(resource, requested).await?;
            }
            _ => return Err(error),
        }
        Ok(())
    }

    async fn grant_expiry(expiry: Option<u64>) {
        match expiry {
            Some(expiry) => {
                tokio::time::sleep(Duration::from_nanos(expiry.saturating_sub(Self::now()))).await
            }
            None => std::future::pending::<()>().await,
        }
    }

    fn evaluate_offer(
        &self,
        active: &PackageActivationV1,
        bundle: &Arc<InstalledBundle>,
        inputs: Arc<araphor_query::inputs::InputSet>,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageResultRefV1>> {
        let context: InstalledContext = Self::decode(&active.metadata)?;
        self.check(&context.grant, Action::Run)?;
        let admission = bundle.admission();
        self.authority.admit(&context.grant, &admission)?;
        let prepared = self.prepare_model(
            active,
            &context,
            bundle,
            RunPreparation {
                inputs: Some(&inputs),
                id: "automatic",
                rebuild: false,
                now,
            },
            Action::Run,
            control,
        )?;
        prepared
            .map(|prepared| {
                self.authorize_commit(&context.grant, Action::Run, &admission, || {
                    self.store.commit_package(&prepared, || control.check())
                })
            })
            .transpose()
    }

    pub(super) fn failed(
        &self,
        active: &PackageActivationV1,
        error: &crate::Error,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let mut context: InstalledContext = Self::decode(&active.metadata)?;
        let code = error.package_code();
        if matches!(context.readiness, PackageReadinessV1::Failed { code: previous, .. } if previous == code)
            && context.status_checkpoint == active.checkpoint_revision
        {
            return Ok(());
        }
        context.readiness = PackageReadinessV1::Failed {
            code,
            field: "model evaluation".into(),
        };
        context.status_checkpoint = active.checkpoint_revision;
        self.store
            .fail_package(active, &Self::encode(&context)?, || control.check())
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
