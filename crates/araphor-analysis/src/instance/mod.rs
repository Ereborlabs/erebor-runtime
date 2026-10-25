use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use araphor_data::{
    AnalysisReadControl, ManagedInstance, ManagedReceipt, ManagedRequest, ManagedSpec,
    PackageActionV1, PackageAuthorization, PackageErrorCodeV1 as Code, PackageGrantV1,
};
use araphor_discovery_definition::ResolvedDefinition;
use araphor_query::definition::PreparedDefinition;
use araphor_query::execution::{Engine, Session};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::LogicalPlan;

use crate::Result;

mod host;
mod lifecycle;
mod manifest;
mod read;
mod replay;
mod sink;
mod subscription;

pub use host::InstanceHost;
pub(crate) use host::Restored;
pub(crate) use host::Shutdown;
pub use subscription::Subscription;

#[cfg(test)]
mod tests;

pub struct Instance {
    query: Arc<Engine>,
    authority: Arc<dyn PackageAuthorization>,
    admitted: ManagedInstance,
    prepared: PreparedDefinition,
    session: Session,
    graph: Option<Arc<crate::GraphPublication>>,
    calls: BTreeMap<u64, LogicalPlan>,
    _metadata: MemoryReservation,
}

impl Instance {
    pub async fn admit(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        id: String,
        definition: ResolvedDefinition,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Self>> {
        Self::admit_on(query, authority, grant, id, definition, control, None).await
    }

    async fn admit_on(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        id: String,
        definition: ResolvedDefinition,
        control: &AnalysisReadControl,
        replacement: Option<ManagedInstance>,
    ) -> Result<Arc<Self>> {
        control.check()?;
        let read = Arc::new(control.within(grant.remaining()?)?);
        let checked = Arc::clone(&authority);
        let checked_grant = grant.clone();
        Engine::blocking(Arc::clone(&read), (), move || {
            checked
                .check(&checked_grant, PackageActionV1::Run)
                .map_err(Into::into)
        })
        .await?;
        definition.validate().map_err(araphor_data::Error::from)?;
        let memory = query.memory().scope();
        let session = query.session_on(grant.selection.clone(), &read, 0, memory)?;
        let prepared = if replacement.is_some() {
            session.prepare_definition(&definition.definition).await?
        } else {
            session.prepare_resolved(&definition).await?
        };
        if *prepared.resolved() != definition {
            return Err(Code::Conflict.error("managed definition pin").into());
        }
        Self::admit_prepared_on(
            session,
            authority,
            grant,
            id,
            prepared,
            araphor_data::ManagedDestination::Selected,
            None,
            replacement,
        )
        .await
    }

    pub(crate) async fn admit_prepared(
        session: Session,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        id: String,
        prepared: PreparedDefinition,
        destination: araphor_data::ManagedDestination,
    ) -> Result<Arc<Self>> {
        Self::admit_prepared_on(
            session,
            authority,
            grant,
            id,
            prepared,
            destination,
            None,
            None,
        )
        .await
    }

    pub(crate) async fn admit_graph(
        session: Session,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        id: String,
        prepared: PreparedDefinition,
        destination: araphor_data::ManagedDestination,
        graph: Arc<crate::GraphPublication>,
    ) -> Result<Arc<Self>> {
        Self::admit_prepared_on(
            session,
            authority,
            grant,
            id,
            prepared,
            destination,
            Some(graph),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn admit_prepared_on(
        session: Session,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        id: String,
        prepared: PreparedDefinition,
        destination: araphor_data::ManagedDestination,
        graph: Option<Arc<crate::GraphPublication>>,
        replacement: Option<ManagedInstance>,
    ) -> Result<Arc<Self>> {
        if session.selection() != &destination.selection(&grant.selection)? {
            return Err(Code::Denied.error("managed prepared selection").into());
        }
        let query = Arc::clone(session.engine());
        let memory = Arc::clone(session.memory());
        let read = Arc::new(session.control().within(grant.remaining()?)?);
        let store = Arc::clone(query.store());
        let check = Arc::clone(&authority);
        let stage = Arc::clone(&read);
        let definition = prepared.resolved().clone();
        definition.validate().map_err(araphor_data::Error::from)?;
        let (admitted, prepared, calls, metadata) =
            Engine::blocking(read, (), move || {
                for bundle in prepared.images() {
                    check.admit(&grant, bundle)?;
                }
                let (manifest, calls) = Self::manifest(&prepared)?;
                if destination == araphor_data::ManagedDestination::Notification {
                    Self::validate_notification(&prepared, &grant, &id)?;
                }
                let spec = ManagedSpec {
                    tenant: grant.selection.tenant_id,
                    id,
                    definition,
                    manifest,
                    destination,
                };
                let candidate = ManagedInstance {
                    spec,
                    grant,
                    generation: 0,
                    progress: 0,
                    running: false,
                    removed: false,
                    lifecycle: 0,
                };
                let bytes = Self::metadata_bytes(&candidate, &calls)?;
                let metadata = memory
                    .reserve_input(bytes)
                    .map_err(|source| araphor_query::Error::Sql { source })?;
                let mut admitted =
                    Self::authorize(check.as_ref(), &candidate.grant, &prepared, || {
                        match replacement {
                            Some(ref expected) if !expected.removed => {
                                if expected.spec != candidate.spec {
                                    return Err(Code::Conflict.error("managed renewal program pin"));
                                }
                                store.renew_managed(expected, &candidate.grant, || stage.check())
                            }
                            Some(ref expected) => store.recreate_managed(
                                expected,
                                &candidate.spec,
                                &candidate.grant,
                                || stage.check(),
                            ),
                            None => store
                                .admit_managed(&candidate.spec, &candidate.grant, || stage.check()),
                        }
                    })
                    .map_err(araphor_query::Error::from)?;
                admitted.spec = candidate.spec;
                admitted.grant = candidate.grant;
                Ok((admitted, prepared, calls, metadata))
            })
            .await?;
        Ok(Arc::new(Self {
            query,
            authority,
            admitted,
            prepared,
            session,
            graph,
            calls,
            _metadata: metadata,
        }))
    }

    pub fn admitted(&self) -> &ManagedInstance {
        &self.admitted
    }

    pub async fn run(
        self: &Arc<Self>,
        request: ManagedRequest,
        control: &AnalysisReadControl,
    ) -> Result<ManagedReceipt> {
        self.run_for(request, None, control).await
    }

    async fn run_for(
        self: &Arc<Self>,
        request: ManagedRequest,
        caller: Option<PackageGrantV1>,
        control: &AnalysisReadControl,
    ) -> Result<ManagedReceipt> {
        if self.admitted.spec.destination == araphor_data::ManagedDestination::Notification {
            return Err(Code::Unsupported.error("notification managed run").into());
        }
        self.authorized(
            Arc::clone(&self.authority),
            control,
            |operation| async move { self.execute(request, caller, &operation).await },
        )
        .await
    }

    async fn authorized<T, F>(
        &self,
        authority: Arc<dyn PackageAuthorization>,
        control: &AnalysisReadControl,
        work: impl FnOnce(Arc<AnalysisReadControl>) -> F,
    ) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        Self::authorized_on(
            authority,
            &self.admitted.grant,
            &self.prepared,
            control,
            work,
        )
        .await
    }

    async fn authorized_on<T, F>(
        authority: Arc<dyn PackageAuthorization>,
        grant: &PackageGrantV1,
        prepared: &PreparedDefinition,
        control: &AnalysisReadControl,
        work: impl FnOnce(Arc<AnalysisReadControl>) -> F,
    ) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        let mut changes = authority.changes_for(grant);
        Self::check_prepared(authority.as_ref(), grant, prepared)?;
        let operation = Arc::new(control.operation()?.within(grant.remaining()?)?);
        let execution = work(Arc::clone(&operation));
        tokio::pin!(execution);
        let result = loop {
            tokio::select! {
                result = &mut execution => break result,
                changed = changes.changed() => {
                    let checked = if changed.is_ok() {
                        let authority = Arc::clone(&authority);
                        let grant = grant.clone();
                        let prepared = prepared.clone();
                        let stage = Arc::clone(&operation);
                        let pending = Engine::blocking(Arc::clone(&operation), (), move || {
                            stage.check()?;
                            Self::check_prepared(authority.as_ref(), &grant, &prepared)?;
                            stage.check()?;
                            Ok(())
                        });
                        tokio::pin!(pending);
                        tokio::select! {
                            checked = &mut pending => checked,
                            stopped = control.query_async(std::future::pending::<Result<T>>()) => {
                                operation.cancel()?;
                                let _checked = pending.await;
                                break match execution.await {
                                    Ok(receipt) => Ok(receipt),
                                    Err(_) => stopped,
                                };
                            }
                        }
                    } else {
                        Err(Code::Denied.error("managed authority change").into())
                    };
                    if checked.is_err() {
                        operation.cancel()?;
                        break match execution.await {
                            Ok(receipt) => Ok(receipt),
                            Err(_) => Err(Code::Denied.error("managed authority change").into()),
                        };
                    }
                }
                stopped = control.query_async(std::future::pending::<Result<T>>()) => {
                    operation.cancel()?;
                    break match execution.await {
                        Ok(receipt) => Ok(receipt),
                        Err(_) => stopped,
                    };
                }
            }
        };
        if result.is_err() && grant.remaining().is_err() {
            return Err(Code::Denied.error("managed grant expiry").into());
        }
        let receipt = result?;
        Self::authorize(authority.as_ref(), grant, prepared, || {
            control.check()?;
            Ok(receipt)
        })
        .map_err(Into::into)
    }

    async fn execute(
        self: &Arc<Self>,
        mut request: ManagedRequest,
        caller: Option<PackageGrantV1>,
        control: &AnalysisReadControl,
    ) -> Result<ManagedReceipt> {
        control.check()?;
        let spec = &self.admitted.spec;
        let owner = Arc::clone(self);
        let read = Arc::new(control.within(None)?);
        let stage = Arc::clone(&read);
        let id = request.id.clone();
        let (current, previous) = Engine::blocking(read, (), move || {
            let spec = &owner.admitted.spec;
            let current = owner
                .query
                .store()
                .managed_instance(spec.tenant, &spec.id, &stage)?
                .filter(|current| {
                    current.spec == *spec
                        && current.grant == owner.admitted.grant
                        && current.generation == owner.admitted.generation
                        && current.lifecycle == owner.admitted.lifecycle
                })
                .ok_or_else(|| Code::Conflict.error("managed instance generation"))?;
            let previous =
                owner
                    .query
                    .store()
                    .managed_attempt(spec.tenant, &spec.id, &id, &stage)?;
            Ok((current, previous))
        })
        .await?;
        if request.frontier.is_some() {
            return Err(Code::Invalid.error("finite managed frontier").into());
        }
        if let Some(previous) = previous {
            if caller.is_some() {
                request.time_utc_ns = previous.request().time_utc_ns;
            }
            let mut recorded = request.clone();
            recorded.frontier = previous.request().frontier.clone();
            if previous.request() != &recorded || previous.instance().spec != *spec {
                return Err(Code::Conflict.error("managed attempt identity").into());
            }
            if previous.terminal().is_some() {
                return Err(Code::Conflict.error("managed attempt terminated").into());
            }
            return previous
                .receipt()
                .cloned()
                .ok_or_else(|| Code::Incomplete.error("managed pending attempt").into());
        }
        self.check()?;
        let time = request.time_utc_ns;
        let witness_expiry = request.witness_expiry;
        self.execute_step(
            sink::Operation::Once {
                current,
                request,
                caller,
            },
            time,
            witness_expiry,
            control,
        )
        .await
    }

    async fn execute_step(
        self: &Arc<Self>,
        mode: sink::Operation,
        time: u64,
        witness_expiry: u64,
        control: &AnalysisReadControl,
    ) -> Result<ManagedReceipt> {
        let spec = &self.admitted.spec;
        let state = Arc::new(Mutex::new(sink::Step::default()));
        let schema = Arc::clone(self.prepared.plan.schema().inner());
        let target = Arc::new(sink::Publication {
            owner: Arc::clone(self),
            schema,
            mode: sink::Mode::Managed {
                operation: Box::new(mode),
                state: Arc::clone(&state),
                witness_expiry,
            },
        });
        let binding = spec
            .definition
            .digest()
            .map_err(araphor_data::Error::from)?;
        let session = self.session.operation(control, time)?;
        if let Err(error) = session
            .run_managed(self.prepared.clone(), target, binding.as_bytes())
            .await
        {
            let busy = araphor_query::Failure::from(&error) == araphor_query::Failure::Busy;
            let error = crate::Error::from(error);
            if !busy && control.check().is_ok() {
                let attempt = state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .attempt
                    .clone();
                if let Some(attempt) = attempt {
                    let exit = Subscription::failure(&error);
                    let read = Arc::new(control.within(None)?);
                    let stage = Arc::clone(&read);
                    let store = Arc::clone(self.query.store());
                    let _terminal = Engine::blocking(read, (), move || {
                        store
                            .finish_managed(&attempt, exit, || stage.check())
                            .map_err(Into::into)
                    })
                    .await?;
                }
            }
            return Err(error);
        }
        let receipt = state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .receipt
            .take();
        if let Some(receipt) = receipt {
            return Ok(receipt);
        }
        Err(Code::Incomplete.error("managed publication receipt").into())
    }

    fn check(&self) -> araphor_data::Result<()> {
        self.check_authority(self.authority.as_ref())
    }

    fn check_authority(&self, authority: &dyn PackageAuthorization) -> araphor_data::Result<()> {
        Self::check_prepared(authority, &self.admitted.grant, &self.prepared)
    }

    fn check_prepared(
        authority: &dyn PackageAuthorization,
        grant: &PackageGrantV1,
        prepared: &PreparedDefinition,
    ) -> araphor_data::Result<()> {
        grant.remaining()?;
        authority.check(grant, PackageActionV1::Run)?;
        for bundle in prepared.images() {
            authority.admit(grant, bundle)?;
        }
        Ok(())
    }

    fn metadata_bytes(
        instance: &ManagedInstance,
        calls: &BTreeMap<u64, LogicalPlan>,
    ) -> araphor_data::Result<usize> {
        instance
            .allocation_bytes()
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<ManagedInstance>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| {
                calls
                    .len()
                    .checked_mul(std::mem::size_of::<(u64, LogicalPlan)>())
                    .and_then(|slots| bytes.checked_add(slots))
            })
            .ok_or_else(|| Code::Limit.error("managed instance memory"))
    }

    fn authorize<T>(
        authority: &dyn PackageAuthorization,
        grant: &PackageGrantV1,
        prepared: &PreparedDefinition,
        operation: impl FnOnce() -> araphor_data::Result<T>,
    ) -> araphor_data::Result<T> {
        Self::authorize_actions(
            authority,
            grant,
            prepared,
            &[PackageActionV1::Run],
            operation,
        )
    }

    pub(crate) fn authorize_actions<T>(
        authority: &dyn PackageAuthorization,
        grant: &PackageGrantV1,
        prepared: &PreparedDefinition,
        actions: &[PackageActionV1],
        operation: impl FnOnce() -> araphor_data::Result<T>,
    ) -> araphor_data::Result<T> {
        Self::authorize_actions_for(authority, grant, prepared, actions, None, operation)
    }

    fn authorize_actions_for<T>(
        authority: &dyn PackageAuthorization,
        grant: &PackageGrantV1,
        prepared: &PreparedDefinition,
        actions: &[PackageActionV1],
        caller: Option<(&PackageGrantV1, PackageActionV1, &AnalysisReadControl)>,
        operation: impl FnOnce() -> araphor_data::Result<T>,
    ) -> araphor_data::Result<T> {
        grant.remaining()?;
        if let Some((caller, action, control)) = caller {
            if let Err(error) = caller
                .remaining()
                .and_then(|_| authority.check(caller, action))
            {
                let _cancelled = control.cancel();
                return Err(error);
            }
            grant.permitted_by(&caller.selection)?;
        }
        let Some(&action) = actions.first() else {
            return Err(Code::Invalid.error("managed authority actions"));
        };
        let grants = actions
            .iter()
            .map(|action| (grant, *action, None))
            .chain(
                prepared
                    .images()
                    .map(|bundle| (grant, action, Some(bundle))),
            )
            .chain(caller.map(|(grant, action, _)| (grant, action, None)))
            .collect::<Vec<_>>();
        let mut operation = Some(operation);
        let mut result = None;
        let checked = authority.commit_many(&grants, &mut || {
            grant.remaining()?;
            result = Some(operation
                .take()
                .ok_or_else(|| Code::Invalid.error("managed authority callback"))?(
            )?);
            Ok(())
        });
        if checked.is_err() {
            if let Some((caller, action, control)) = caller {
                if caller
                    .remaining()
                    .and_then(|_| authority.check(caller, action))
                    .is_err()
                {
                    let _cancelled = control.cancel();
                }
            }
        }
        checked?;
        result.ok_or_else(|| Code::Denied.error("managed publication authority"))
    }
}
