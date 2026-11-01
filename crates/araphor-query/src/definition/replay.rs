use super::*;

use araphor_data::analysis::PackageResultRefV1;
use araphor_data::{ManagedAttempt, ManagedInstance};
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::logical_expr::Extension;
use futures_util::future::{BoxFuture, FutureExt};

impl PreparedDefinition {
    fn replay_call(&self, id: u64) -> Result<PackageCall> {
        let mut selected = None;
        PackageCall::any(&self.plan, &mut |call| {
            if call.id() == id {
                selected = Some(call.clone());
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .context(SqlSnafu)?;
        selected.ok_or_else(|| {
            PackageErrorCodeV1::Missing
                .error("replay package call")
                .into()
        })
    }
}

impl Session {
    async fn replay_owner(
        &self,
        instance: &ManagedInstance,
        call: u64,
        expected: &PackageResultRefV1,
        now: u64,
    ) -> Result<ManagedAttempt> {
        let store = Arc::clone(self.engine().store());
        let instance = instance.clone();
        let expected = expected.clone();
        let control = Arc::clone(self.control());
        Engine::blocking(Arc::clone(&control), self.token()?, move || {
            let (reference, actual, _) =
                store.managed_reference(&instance, &expected.result_id, now, &control)?;
            if actual != Some(call)
                || reference.receipt().is_none_or(|receipt| {
                    receipt.commit_revision != expected.commit_revision
                        || receipt.results.get(&call) != Some(&expected)
                })
            {
                return Err(PackageErrorCodeV1::Conflict
                    .error("replay call reference")
                    .into());
            }
            Ok(reference)
        })
        .await
    }

    async fn replay_definition(&self, reference: &ManagedAttempt) -> Result<PreparedDefinition> {
        if let Some(prepared) = self.definition.as_ref().filter(|prepared| {
            prepared.admission.tenant == reference.instance().spec.tenant
                && prepared.resolved() == &reference.instance().spec.definition
        }) {
            for pin in &prepared.resolved().images {
                if !prepared
                    .images()
                    .any(|image| image.bundle().root == pin.image && image.digest() == pin.digest)
                {
                    return Err(PackageErrorCodeV1::Conflict
                        .error("replay image admission")
                        .into());
                }
            }
            PackageCall::check_admission(&prepared.plan).context(SqlSnafu)?;
            return Ok(prepared.as_ref().clone());
        }
        self.prepare_resolved(&reference.instance().spec.definition)
            .await
    }

    fn seed_before<'a>(
        &'a self,
        physical: &'a Arc<dyn datafusion::physical_plan::ExecutionPlan>,
        before: u64,
    ) -> BoxFuture<'a, Result<()>> {
        async move {
            use datafusion::common::tree_node::TreeNode;
            let reference = self
                .reference
                .as_ref()
                .ok_or_else(|| PackageErrorCodeV1::Missing.error("historical reference"))?;
            let receipt = reference
                .receipt()
                .ok_or_else(|| PackageErrorCodeV1::Invalid.error("replay publication"))?;
            let owner = self
                .calls
                .as_ref()
                .ok_or_else(|| PackageErrorCodeV1::Invalid.error("replay call context"))?;
            let mut needed = BTreeMap::new();
            physical
                .apply(|plan| {
                    if let Some(plan) = plan.as_any().downcast_ref::<physical::PackageExec>() {
                        let call = plan.logical_call();
                        if before == call.id() {
                            return Err(datafusion::common::DataFusionError::Execution(
                                "the historical input contains its package call".into(),
                            ));
                        }
                        if owner.cached(call)? {
                            return Ok(TreeNodeRecursion::Jump);
                        }
                        if let Some(saved) = receipt.results.get(&call.id()) {
                            if saved.commit_revision != receipt.commit_revision {
                                return Err(datafusion::common::DataFusionError::Execution(
                                    "the historical child publication differs".into(),
                                ));
                            }
                            needed.insert(call.id(), (call.clone(), saved.clone()));
                            return Ok(TreeNodeRecursion::Jump);
                        }
                    }
                    Ok(TreeNodeRecursion::Continue)
                })
                .context(SqlSnafu)?;
            for (id, (call, saved)) in needed {
                self.control().check()?;
                let historical = self
                    .replay_owner(reference.instance(), id, &saved, 0)
                    .await?;
                if historical.instance().spec.definition != reference.instance().spec.definition
                    || historical.instance().spec.manifest.calls.get(&id)
                        != reference.instance().spec.manifest.calls.get(&id)
                {
                    return Err(PackageErrorCodeV1::Conflict
                        .error("retained replay reference")
                        .into());
                }
                let prepared = self.replay_definition(&historical).await?;
                let mut result = self
                    .replay_reference(&prepared, &historical, Some(id))
                    .await?;
                let returned = result
                    .calls
                    .remove(&id)
                    .ok_or_else(|| PackageErrorCodeV1::Missing.error("retained replay output"))?;
                self.control().check()?;
                owner.seed(&call, returned, &saved).context(SqlSnafu)?;
            }
            self.control().check()?;
            Ok(())
        }
        .boxed()
    }

    pub(crate) fn replay_before<'a>(
        &'a self,
        call: &'a PackageCall,
        slot: usize,
        prior: &'a araphor_data::ManagedPrior,
        context: &'a Arc<datafusion::execution::TaskContext>,
    ) -> BoxFuture<'a, Result<sdk::Input>> {
        async move {
            use crate::sources::{SourceOrigin, SourceSnapshot};

            self.control().check()?;
            let invalid = || PackageErrorCodeV1::Invalid.error("historical change input");
            let changes = call.changes.as_ref().ok_or_else(invalid)?;
            let pair = changes
                .ports
                .iter()
                .find(|pair| pair.before == slot)
                .ok_or_else(invalid)?;
            let model = call.model().ok_or_else(invalid)?;
            let port = model.inputs.get(slot).ok_or_else(invalid)?;
            let revision = prior.context.inputs.get(pair.after).ok_or_else(invalid)?;
            let coverage = prior
                .context
                .input_coverage
                .get(pair.after)
                .ok_or_else(invalid)?;
            let source = context
                .session_config()
                .get_extension::<SourceSnapshot>()
                .ok_or_else(invalid)?;
            let snapshot = source.snapshot().context(SqlSnafu)?;
            let instance = snapshot.managed().ok_or_else(invalid)?.instance().clone();
            let id = call.id();
            let now = snapshot.time_utc_ns();
            let reference = self
                .replay_owner(
                    &instance,
                    id,
                    &PackageResultRefV1 {
                        result_id: prior.result.clone(),
                        commit_revision: prior.revision,
                    },
                    now,
                )
                .await?;
            if reference.instance().spec.definition != instance.spec.definition
                || reference.instance().spec.manifest.calls.get(&id)
                    != instance.spec.manifest.calls.get(&id)
            {
                return Err(PackageErrorCodeV1::Conflict
                    .error("historical change reference")
                    .into());
            }
            let definition = self.replay_definition(&reference).await?;
            let plan = call.admitted.get(slot).ok_or_else(invalid)?;
            let request = reference.request();
            let mut session = self.at(
                reference
                    .instance()
                    .spec
                    .destination
                    .selection(&reference.instance().grant.selection)?,
                request.time_utc_ns,
            );
            session.control = Arc::new(self.control().within(None)?);
            session.reference = Some(reference.clone());
            session.definition = Some(Arc::new(definition));
            session.calls = Some(session.call_context(Invocation {
                id: request.id.clone(),
                seed: request.seed,
                time_utc_ns: Some(i64::try_from(request.time_utc_ns).map_err(|_| invalid())?),
                ..Default::default()
            }));
            let calls = Arc::clone(session.calls.as_ref().ok_or_else(invalid)?);
            let result = async {
                let permit = session.evaluation_permit()?;
                let mut state = session.state()?;
                state
                    .config_mut()
                    .set_extension(Arc::clone(session.control()));
                state.config_mut().set_extension(Arc::clone(&permit));
                state.config_mut().set_extension(Arc::clone(&calls));
                let physical = session.physical(plan, &state).await?;
                session.seed_before(&physical, id).await?;
                let mut requests = session
                    .definition
                    .as_ref()
                    .ok_or_else(invalid)?
                    .sources()
                    .clone();
                let bounds = SourceSnapshot::requests(
                    &mut requests,
                    std::slice::from_ref(&physical),
                    None,
                    Some(&calls),
                )
                .context(SqlSnafu)?;
                requests.retain(|_, columns| columns.is_some());
                let limits = session.engine().limits();
                let historical = SourceSnapshot::new(
                    Arc::clone(session.engine().store()),
                    session.selection().clone(),
                    araphor_data::AnalysisExtractLimits {
                        scan_bytes: limits.scan_bytes,
                        input_bytes: limits.input_bytes,
                        keys: limits.extract_keys,
                        ..Default::default()
                    },
                    session.control().within(session.control().remaining()?)?,
                    limits.extract_timeout,
                    request.time_utc_ns,
                    Arc::clone(session.memory()),
                    None,
                );
                let old = Arc::clone(&historical);
                let current = Arc::clone(&source);
                let saved = reference.clone();
                Engine::blocking(Arc::clone(session.control()), session.token()?, move || {
                    old.capture_before(&saved, &current, &requests, bounds)
                        .context(SqlSnafu)
                })
                .await?;
                let physical = historical
                    .bind_before_keys(physical, Some(&calls))
                    .context(SqlSnafu)?;
                for origin in Planner::sources(plan)? {
                    if let SourceOrigin::Port(port) = origin {
                        if changes.lookups.bindings.iter().any(|(id, _)| *id == port) {
                            source.copy_port(port, &historical).context(SqlSnafu)?;
                        }
                    }
                }
                state.config_mut().set_extension(Arc::clone(&historical));
                let mut replay = session.at(session.selection().clone(), request.time_utc_ns);
                replay.reference = None;
                state.config_mut().set_extension(Arc::new(replay));
                session.initialize_context(state.config_mut());
                let memory = session.memory().reserve_input(0).context(SqlSnafu)?;
                let batches = physical::PackageExec::collect_plan(
                    &physical,
                    &port.port.schema,
                    &calls,
                    &state.task_ctx(),
                    &memory,
                    true,
                )
                .await
                .context(SqlSnafu)?;
                session
                    .check_read(&historical.snapshot().context(SqlSnafu)?)
                    .await?;
                Ok(sdk::Input {
                    data: sdk::Dataset {
                        name: port.port.name.clone(),
                        batches,
                    },
                    revision: revision.clone(),
                    coverage: coverage.clone(),
                })
            }
            .await;
            if result.is_err() {
                let _cancelled = session.control().cancel();
            }
            calls.finish().await;
            self.control().check()?;
            result
        }
        .boxed()
    }

    pub(crate) fn hydrate_source<'a>(
        &'a self,
        source: &'a Arc<crate::sources::SourceSnapshot>,
        physical: &'a Arc<dyn datafusion::physical_plan::ExecutionPlan>,
    ) -> BoxFuture<'a, Result<()>> {
        async move {
            use datafusion::common::tree_node::TreeNode;
            let mut calls = BTreeMap::new();
            physical
                .apply(|plan| {
                    if let Some(plan) = plan.as_any().downcast_ref::<physical::PackageExec>() {
                        let call = plan.logical_call();
                        if self
                            .calls
                            .as_ref()
                            .map(|calls| calls.cached(call))
                            .transpose()?
                            .unwrap_or(false)
                        {
                            return Ok(TreeNodeRecursion::Jump);
                        }
                        calls.entry(call.id()).or_insert_with(|| call.clone());
                    }
                    Ok(TreeNodeRecursion::Continue)
                })
                .context(SqlSnafu)?;
            if let Some(reference) = &self.reference {
                for (&id, call) in &calls {
                    let model = call
                        .model()
                        .ok_or_else(|| PackageErrorCodeV1::Missing.error("prior package model"))?;
                    if model.change_inputs.is_none() {
                        if self
                            .replay_frontier
                            .as_ref()
                            .is_some_and(|(active, ready)| *active == id && ready.is_none())
                        {
                            source.discard_prior(id).context(SqlSnafu)?;
                        }
                        continue;
                    }
                    let store = Arc::clone(self.engine().store());
                    let reference = reference.clone();
                    let control = Arc::clone(self.control());
                    let changes =
                        Engine::blocking(Arc::clone(&control), self.token()?, move || {
                            store
                                .managed_changes(&reference, id, &control)
                                .map_err(Into::into)
                        })
                        .await?;
                    let changes = changes.ok_or_else(|| {
                        PackageErrorCodeV1::Invalid.error("replay change contract")
                    })?;
                    if changes.base.is_none() {
                        source.discard_prior(id).context(SqlSnafu)?;
                    }
                }
            }
            let captured = source.snapshot().context(SqlSnafu)?;
            let Some(managed) = captured.managed().filter(|managed| !managed.rebuild()) else {
                return Ok(());
            };
            let instance = managed.instance().clone();
            let view = source.source_view().context(SqlSnafu)?;
            let now = captured.time_utc_ns();
            let mut needed = Vec::new();
            for (id, call) in calls {
                let Some(prior) = managed.prior(id).filter(|prior| prior.retained.is_none()) else {
                    continue;
                };
                let model = call
                    .model()
                    .ok_or_else(|| PackageErrorCodeV1::Missing.error("prior package model"))?;
                if model.change_inputs.is_some()
                    && view
                        .as_ref()
                        .is_none_or(|view| view.version() != prior.revision)
                {
                    continue;
                }
                let outputs = prior.checkpoint.is_some()
                    && (model.change_inputs.is_some()
                        || model
                            .checkpoint
                            .as_ref()
                            .is_some_and(|state| state.resume_input_changes));
                if outputs || (prior.checkpoint.is_some() && !model.parameters.fields().is_empty())
                {
                    needed.push((
                        id,
                        model.clone(),
                        prior.result.clone(),
                        prior.revision,
                        outputs,
                    ));
                }
            }
            drop(captured);
            for (call, model, id, revision, outputs) in needed {
                self.control().check()?;
                let expected = PackageResultRefV1 {
                    result_id: id,
                    commit_revision: revision,
                };
                let saved = if outputs {
                    if let Some((_, ready)) = self
                        .replay_frontier
                        .as_ref()
                        .filter(|(active, _)| *active == call)
                    {
                        let (published, saved) = ready.as_ref().ok_or_else(|| {
                            PackageErrorCodeV1::Missing.error("replay state frontier")
                        })?;
                        if *published != revision {
                            return Err(PackageErrorCodeV1::Conflict
                                .error("replay state reference")
                                .into());
                        }
                        Some(Arc::clone(saved))
                    } else {
                        let reference = self.replay_owner(&instance, call, &expected, now).await?;
                        let prepared = self.replay_definition(&reference).await?;
                        let result = self
                            .replay_reference(&prepared, &reference, Some(call))
                            .await?;
                        Some(Arc::clone(result.calls.get(&call).ok_or_else(|| {
                            PackageErrorCodeV1::Missing.error("prior package output")
                        })?))
                    }
                } else {
                    None
                };
                let (parameters, retained) = if let Some(saved) = saved {
                    let parameters =
                        saved
                            .evaluation()
                            .parameters
                            .as_ref()
                            .map(|batch| sdk::Dataset {
                                name: "parameters".into(),
                                batches: vec![batch.clone()],
                            });
                    (
                        parameters,
                        Some(Arc::new(araphor_data::RetainedCall {
                            evaluation: saved.evaluation().clone(),
                            output: saved.output().clone(),
                            changes: saved.changes().cloned(),
                        })),
                    )
                } else {
                    let reference = self.replay_owner(&instance, call, &expected, now).await?;
                    let prepared = self.replay_definition(&reference).await?;
                    (
                        Some(
                            self.replay_parameters(&prepared, &reference, call, &model)
                                .await?,
                        ),
                        None,
                    )
                };
                source
                    .hydrate_prior(call, &model, parameters, retained)
                    .context(SqlSnafu)?;
            }
            Ok(())
        }
        .boxed()
    }

    pub fn replay_reference<'a>(
        &'a self,
        definition: &'a PreparedDefinition,
        reference: &'a ManagedAttempt,
        call: Option<u64>,
    ) -> BoxFuture<'a, Result<DefinitionOutput>> {
        async move {
            self.control().check()?;
            PackageCall::check_admission(&definition.plan).context(SqlSnafu)?;
            let instance = reference.instance();
            if instance.spec.tenant != self.selection().tenant_id
                || definition.resolved() != &instance.spec.definition
                || reference.receipt().is_none()
            {
                return Err(PackageErrorCodeV1::Denied
                    .error("replay reference scope")
                    .into());
            }
            let plan = match call {
                Some(id) => LogicalPlan::Extension(Extension {
                    node: Arc::new(definition.replay_call(id)?),
                }),
                None => definition.plan.clone(),
            };
            if let (Some(id), LogicalPlan::Extension(extension)) = (call, &plan) {
                let selected = extension
                    .node
                    .as_any()
                    .downcast_ref::<PackageCall>()
                    .ok_or_else(|| PackageErrorCodeV1::Invalid.error("replay call plan"))?;
                let model = selected
                    .model()
                    .ok_or_else(|| PackageErrorCodeV1::Missing.error("replay call model"))?;
                if model.checkpoint.as_ref().is_some_and(|state| {
                    state.resume_input_changes || model.change_inputs.is_some()
                }) {
                    let memory = self.memory().reserve_input(0).context(SqlSnafu)?;
                    let header = self.memory().reserve_input(0).context(SqlSnafu)?;
                    let mut work = Vec::new();
                    let mut string_bytes = 0usize;
                    let mut current = Arc::new(reference.clone());
                    let mut parameters = None;
                    loop {
                        self.control().check()?;
                        if current.instance().spec.manifest.calls.get(&id)
                            != instance.spec.manifest.calls.get(&id)
                        {
                            return Err(PackageErrorCodeV1::Conflict
                                .error("replay state declaration")
                                .into());
                        }
                        header
                            .try_resize(current.allocation_bytes().ok_or_else(|| {
                                PackageErrorCodeV1::Limit.error("replay reference memory")
                            })?)
                            .context(SqlSnafu)?;
                        let receipt = current.receipt().ok_or_else(|| {
                            PackageErrorCodeV1::Invalid.error("replay state publication")
                        })?;
                        let result = receipt.results.get(&id).ok_or_else(|| {
                            PackageErrorCodeV1::Missing.error("replay state result")
                        })?;
                        if result.commit_revision != receipt.commit_revision {
                            return Err(PackageErrorCodeV1::Conflict
                                .error("replay state publication")
                                .into());
                        }
                        let owned = result.clone();
                        string_bytes = string_bytes
                            .checked_add(owned.result_id.capacity())
                            .ok_or_else(|| {
                                PackageErrorCodeV1::Limit.error("replay reference memory")
                            })?;
                        work.push(owned);
                        let bytes = work
                            .capacity()
                            .checked_mul(std::mem::size_of::<PackageResultRefV1>())
                            .and_then(|bytes| bytes.checked_add(string_bytes))
                            .ok_or_else(|| {
                                PackageErrorCodeV1::Limit.error("replay reference memory")
                            })?;
                        memory.try_resize(bytes).context(SqlSnafu)?;
                        if current.request().rebuild {
                            break;
                        }
                        let base = if model.change_inputs.is_some() {
                            let store = Arc::clone(self.engine().store());
                            let owned = Arc::clone(&current);
                            let control = Arc::clone(self.control());
                            Engine::blocking(Arc::clone(&control), self.token()?, move || {
                                store
                                    .managed_changes(&owned, id, &control)
                                    .map_err(Into::into)
                            })
                            .await?
                            .ok_or_else(|| {
                                PackageErrorCodeV1::Invalid.error("replay change contract")
                            })?
                            .base
                        } else {
                            current.prior_result(id).cloned()
                        };
                        let Some(base) = base else { break };
                        if current.prior_result(id) != Some(&base)
                            || base.commit_revision >= result.commit_revision
                        {
                            return Err(PackageErrorCodeV1::Conflict
                                .error("replay state lineage")
                                .into());
                        }
                        let prior = self.replay_owner(instance, id, &base, 0).await?;
                        header
                            .try_grow(prior.allocation_bytes().ok_or_else(|| {
                                PackageErrorCodeV1::Limit.error("replay reference memory")
                            })?)
                            .context(SqlSnafu)?;
                        if model.change_inputs.is_none() && !model.parameters.fields().is_empty() {
                            let saved = match parameters.take() {
                                Some(parameters) => parameters,
                                None => {
                                    let prepared = self.replay_definition(&current).await?;
                                    self.replay_parameters(&prepared, &current, id, model)
                                        .await?
                                }
                            };
                            let prepared = self.replay_definition(&prior).await?;
                            let previous =
                                self.replay_parameters(&prepared, &prior, id, model).await?;
                            if saved.batches != previous.batches {
                                break;
                            }
                            parameters = Some(previous);
                        }
                        current = Arc::new(prior);
                    }
                    drop(current);
                    header.free();
                    let mut session = self.clone();
                    session.replay_frontier = Some((id, None));
                    while let Some(expected) = work.pop() {
                        self.control().check()?;
                        let current = self.replay_owner(instance, id, &expected, 0).await?;
                        let published = expected.commit_revision;
                        string_bytes -= expected.result_id.capacity();
                        drop(expected);
                        let bytes = work
                            .capacity()
                            .checked_mul(std::mem::size_of::<PackageResultRefV1>())
                            .and_then(|bytes| bytes.checked_add(string_bytes))
                            .ok_or_else(|| {
                                PackageErrorCodeV1::Limit.error("replay reference memory")
                            })?;
                        memory.try_resize(bytes).context(SqlSnafu)?;
                        header
                            .try_resize(current.allocation_bytes().ok_or_else(|| {
                                PackageErrorCodeV1::Limit.error("replay reference memory")
                            })?)
                            .context(SqlSnafu)?;
                        let prepared = Arc::new(session.replay_definition(&current).await?);
                        let own = LogicalPlan::Extension(Extension {
                            node: Arc::new(prepared.replay_call(id)?),
                        });
                        session.definition = Some(Arc::clone(&prepared));
                        let mut result = session.replay_plan(&prepared, &current, own).await?;
                        if work.is_empty() {
                            return Ok(result);
                        }
                        let saved = result.calls.remove(&id).ok_or_else(|| {
                            PackageErrorCodeV1::Missing.error("replay state output")
                        })?;
                        session.replay_frontier = Some((id, Some((published, saved))));
                    }
                    return Err(PackageErrorCodeV1::Missing
                        .error("replay state work")
                        .into());
                }
            }
            self.replay_plan(definition, reference, plan).await
        }
        .boxed()
    }

    async fn replay_parameters(
        &self,
        definition: &PreparedDefinition,
        reference: &ManagedAttempt,
        id: u64,
        model: &sdk::Model,
    ) -> Result<sdk::Dataset> {
        let call = definition.replay_call(id)?;
        let result = self
            .replay_plan(
                definition,
                reference,
                call.admitted
                    .get(model.inputs.len())
                    .cloned()
                    .ok_or_else(|| PackageErrorCodeV1::Missing.error("replay parameter plan"))?,
            )
            .await?;
        let batch = physical::PackageExec::parameters(result.batches).context(SqlSnafu)?;
        Ok(sdk::Dataset {
            name: "parameters".into(),
            batches: vec![batch],
        })
    }

    async fn replay_plan(
        &self,
        definition: &PreparedDefinition,
        reference: &ManagedAttempt,
        plan: LogicalPlan,
    ) -> Result<DefinitionOutput> {
        let mut session = self.at(
            reference
                .instance()
                .spec
                .destination
                .selection(&reference.instance().grant.selection)?,
            reference.request().time_utc_ns,
        );
        session.control = Arc::new(self.control().within(None)?);
        session.reference = Some(reference.clone());
        session.managed = None;
        session.source_index = None;
        let replay = PreparedDefinition {
            plan,
            admission: Arc::clone(&definition.admission),
        };
        let request = reference.request();
        session
            .execute_definition(
                &replay,
                Invocation {
                    id: request.id.clone(),
                    seed: request.seed,
                    time_utc_ns: Some(
                        i64::try_from(request.time_utc_ns)
                            .map_err(|_| PackageErrorCodeV1::Invalid.error("replay time"))?,
                    ),
                    ..Default::default()
                },
            )
            .await
    }
}
