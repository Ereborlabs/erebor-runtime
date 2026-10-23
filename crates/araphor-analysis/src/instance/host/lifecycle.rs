use std::future::Future;
use std::sync::{Arc, Mutex};

use araphor_data::{AnalysisReadControl, ManagedInstance, ManagedMember, PackageGrantV1};
use araphor_query::execution::Engine;
use datafusion::execution::memory_pool::MemoryReservation;
use snafu::ResultExt as _;
use tokio::sync::{oneshot, watch};

use super::{Code, Instance, InstanceHost, Member, Restored, Shutdown};
use crate::Result;

pub(super) type PreparedMember = (
    Option<Arc<Instance>>,
    MemoryReservation,
    oneshot::Sender<()>,
);

pub(super) enum PauseLease {
    Member {
        release: oneshot::Sender<PreparedMember>,
        _memory: MemoryReservation,
    },
    Idle {
        _lease: araphor_data::ManagedLease,
    },
}

impl PauseLease {
    pub(super) async fn resume(self, owner: Arc<Instance>) {
        self.release(Some(owner)).await;
    }

    pub(super) async fn release(self, owner: Option<Arc<Instance>>) {
        if let Self::Member { release, _memory } = self {
            let (accepted, ready) = oneshot::channel();
            if release.send((owner, _memory, accepted)).is_ok() {
                let _accepted = ready.await;
            }
        }
    }
}

pub(super) struct PauseRequest {
    member: ManagedMember,
    operation: Arc<AnalysisReadControl>,
    reply: oneshot::Sender<Result<PauseLease>>,
    memory: MemoryReservation,
}

impl PauseRequest {
    pub(super) fn fail(self, error: crate::Error) {
        let _sent = self.reply.send(Err(error));
    }
}

#[derive(Default)]
pub(super) struct PauseState {
    active: bool,
    waiting: Option<PauseWait>,
}

struct PauseWait {
    operation: Arc<AnalysisReadControl>,
    reply: oneshot::Sender<Result<PauseLease>>,
    lease: oneshot::Sender<PreparedMember>,
    released: oneshot::Receiver<PreparedMember>,
    memory: MemoryReservation,
}

impl Member {
    pub(super) fn allocation_bytes(member: &ManagedMember) -> araphor_data::Result<usize> {
        std::mem::size_of::<ManagedMember>()
            .checked_add(member.id.capacity())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Mutex<PauseState>>()))
            .ok_or_else(|| Code::Limit.error("managed membership memory"))
    }

    fn pause(&self, request: PauseRequest) {
        let mut state = self.pause.lock().unwrap_or_else(|error| error.into_inner());
        if state.active {
            request.fail(Code::Conflict.error("managed member pause").into());
            return;
        }
        let (lease, released) = oneshot::channel();
        state.active = true;
        state.waiting = Some(PauseWait {
            operation: request.operation,
            reply: request.reply,
            lease,
            released,
            memory: request.memory,
        });
        if let Err(error) = self.control.cancel() {
            state.active = false;
            if let Some(waiting) = state.waiting.take() {
                let _sent = waiting.reply.send(Err(error.into()));
            }
        }
    }

    pub(super) async fn joined_pause(
        state: &Mutex<PauseState>,
        mut serving: watch::Receiver<bool>,
    ) -> Option<PreparedMember> {
        let waiting = state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .waiting
            .take();
        let waiting = waiting?;
        let PauseWait {
            operation,
            reply,
            lease,
            mut released,
            memory,
        } = waiting;
        if reply
            .send(Ok(PauseLease::Member {
                release: lease,
                _memory: memory,
            }))
            .is_err()
        {
            return None;
        }
        if !*serving.borrow() {
            let _cancelled = operation.cancel();
            let _released = released.await;
            return None;
        }
        tokio::select! {
            retained = &mut released => retained.ok(),
            _ = serving.changed() => {
                let _cancelled = operation.cancel();
                let _released = released.await;
                None
            }
        }
    }
}

impl InstanceHost {
    pub(crate) async fn restore(
        self: &Arc<Self>,
        tenant: [u8; 16],
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<Restored> {
        let operation = Arc::new(control.within(None)?);
        let stage = Arc::clone(&operation);
        let store = Arc::clone(self.query.store());
        let id = id.to_owned();
        let current = Engine::blocking(Arc::clone(&operation), (), move || {
            store
                .managed_instance(tenant, &id, &stage)
                .map_err(Into::into)
        })
        .await?;
        let Some(current) = current else {
            return Ok(Restored::Absent);
        };
        if current.removed {
            return Ok(Restored::Removed(Box::new(current)));
        }
        self.restore_current(current, &operation)
            .await
            .map(Restored::Present)
    }

    pub(super) async fn restore_current(
        self: &Arc<Self>,
        current: ManagedInstance,
        operation: &Arc<AnalysisReadControl>,
    ) -> Result<Arc<Instance>> {
        let member = ManagedMember {
            tenant: current.spec.tenant,
            id: current.spec.id,
            generation: current.generation,
            lifecycle: current.lifecycle,
        };
        let memory = self
            .query
            .memory()
            .reserve_input(Member::allocation_bytes(&member)?)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let expected = Arc::new((member, memory));
        self.restore_member(&expected, operation, false).await
    }

    pub(super) async fn current_for(
        &self,
        grant: &PackageGrantV1,
        id: &str,
        expected: u64,
        control: &Arc<AnalysisReadControl>,
    ) -> Result<ManagedInstance> {
        let store = Arc::clone(self.query.store());
        let selected = grant.selection.clone();
        let id = id.to_owned();
        let stage = Arc::clone(control);
        Ok(Engine::blocking(Arc::clone(control), (), move || {
            let current = store
                .managed_instance(selected.tenant_id, &id, &stage)?
                .ok_or_else(|| Code::Missing.error("managed request instance"))?;
            current.grant.permitted_by(&selected)?;
            if current.lifecycle != expected || current.removed {
                return Err(Code::Conflict.error("managed request lifecycle").into());
            }
            Ok(current)
        })
        .await?)
    }

    pub(crate) async fn admit_current(
        &self,
        current: &ManagedInstance,
        renewal: Option<PackageGrantV1>,
        control: &Arc<AnalysisReadControl>,
        memory: Arc<araphor_query::memory::Memory>,
    ) -> Result<Arc<Instance>> {
        let grant = renewal.as_ref().unwrap_or(&current.grant).clone();
        let authority = Arc::clone(&self.authority);
        let checked = grant.clone();
        Engine::blocking(Arc::clone(control), (), move || {
            authority
                .check(&checked, araphor_data::PackageActionV1::Run)
                .map_err(Into::into)
        })
        .await?;
        let (session, prepared, destination, graph) = if matches!(
            &current.spec.destination,
            araphor_data::ManagedDestination::Graph { .. }
        ) {
            crate::GraphPublication::prepare_managed(
                Arc::clone(&self.query),
                Arc::clone(&self.authority),
                self.graph_facts.clone(),
                &grant,
                current.spec.definition.clone(),
                current.spec.destination.clone(),
                control,
            )
            .await?
        } else {
            if current.spec.destination == araphor_data::ManagedDestination::Notification
                && self.notifications.is_none()
            {
                return Err(Code::Incomplete
                    .error("notification execution owner")
                    .into());
            }
            let session = self.query.session_on(
                current.spec.destination.selection(&grant.selection)?,
                control,
                0,
                memory,
            )?;
            let prepared = session.prepare_resolved(&current.spec.definition).await?;
            if prepared.resolved() != &current.spec.definition {
                return Err(Code::Conflict
                    .error("managed restored definition pin")
                    .into());
            }
            (session, prepared, current.spec.destination.clone(), None)
        };
        let owner = Instance::admit_prepared_on(
            session,
            Arc::clone(&self.authority),
            grant.clone(),
            current.spec.id.clone(),
            prepared,
            destination,
            graph,
            renewal.map(|_| current.clone()),
        )
        .await?;
        if owner.admitted.spec != current.spec || owner.admitted.grant != grant {
            return Err(Code::Conflict.error("managed restored manifest").into());
        }
        Ok(owner)
    }

    pub async fn renew(
        self: &Arc<Self>,
        grant: PackageGrantV1,
        id: String,
        expected: u64,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        self.run_lifecycle(grant.clone(), control, move |host, operation| async move {
            host.authority
                .check(&grant, araphor_data::PackageActionV1::Run)?;
            let current = host.current_for(&grant, &id, expected, &operation).await?;
            if current.running || current.grant.selection != grant.selection {
                return Err(Code::Conflict.error("managed renewal lifecycle").into());
            }
            let pause = host
                .pause_and_join(&current, Arc::clone(&operation))
                .await?;
            let owner = host
                .admit_current(
                    &current,
                    Some(grant),
                    &operation,
                    host.query.memory().scope(),
                )
                .await;
            pause.release(None).await;
            owner
        })
        .await
    }

    pub async fn start(
        self: &Arc<Self>,
        instance: Arc<Instance>,
        expected_lifecycle: u64,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        self.set_running(instance, expected_lifecycle, true, None, control)
            .await
    }

    pub async fn stop(
        self: &Arc<Self>,
        instance: Arc<Instance>,
        expected_lifecycle: u64,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        self.set_running(instance, expected_lifecycle, false, None, control)
            .await
    }

    pub(super) async fn set_running(
        self: &Arc<Self>,
        instance: Arc<Instance>,
        expected_lifecycle: u64,
        running: bool,
        caller_grant: Option<PackageGrantV1>,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        if !Arc::ptr_eq(&instance.query, &self.query) {
            return Err(Code::Conflict.error("managed host query owner").into());
        }
        if running
            && instance.admitted.spec.destination == araphor_data::ManagedDestination::Notification
            && !self
                .notifications
                .as_ref()
                .is_some_and(|owner| owner.enabled)
        {
            return Err(Code::Denied.error("notification start disabled").into());
        }
        self.run_lifecycle(
            instance.admitted.grant.clone(),
            control,
            move |host, operation| async move {
                let authority = Arc::clone(&host.authority);
                let owner = Arc::clone(&instance);
                let final_authority = Arc::clone(&authority);
                instance
                    .authorized(authority.as_ref(), &operation, move |stage| async move {
                        let selected = Arc::clone(&owner);
                        let read = Arc::clone(&stage);
                        let current = Engine::blocking(Arc::clone(&stage), (), move || {
                            Ok(selected.current_lifecycle(expected_lifecycle, &read)?)
                        })
                        .await?;
                        let bound = owner.graph.as_ref().is_none_or(|graph| {
                            host.graph_facts
                                .as_ref()
                                .is_some_and(|facts| graph.uses_facts(facts))
                        });
                        let pause =
                            if !running || !current.running && *host.serving.borrow() && bound {
                                Some(host.pause_and_join(&current, Arc::clone(&stage)).await?)
                            } else {
                                None
                            };
                        let result = owner
                            .set_running(
                                final_authority,
                                expected_lifecycle,
                                running,
                                caller_grant,
                                &stage,
                            )
                            .await;
                        if let (Some(pause), Ok(retained)) = (pause, &result) {
                            if running && Arc::ptr_eq(&retained.authority, &host.authority) {
                                pause.resume(Arc::clone(retained)).await;
                            } else {
                                pause.release(None).await;
                            }
                        }
                        result
                    })
                    .await
            },
        )
        .await
    }

    pub(super) async fn run_lifecycle<T, F, W>(
        self: &Arc<Self>,
        grant: PackageGrantV1,
        control: &AnalysisReadControl,
        work: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Self>, Arc<AnalysisReadControl>) -> W + Send + 'static,
        W: Future<Output = Result<T>> + Send + 'static,
    {
        let operation = Arc::new(control.operation()?.within(grant.remaining()?)?);
        let shutdown = Shutdown(Arc::clone(&operation));
        let caller = Arc::new(control.within(None)?);
        let host = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut changes = host.authority.changes_for(&grant);
            grant.remaining()?;
            let work = work(Arc::clone(&host), Arc::clone(&operation));
            tokio::pin!(work);
            let result = tokio::select! {
                result = &mut work => result,
                _ = changes.changed() => {
                    let _cancelled = operation.cancel();
                    match work.await {
                        Ok(value) => Ok(value),
                        Err(_) => Err(Code::Denied.error("managed authority change").into()),
                    }
                }
                stopped = caller.query_async(std::future::pending::<Result<T>>()) => {
                    let _cancelled = operation.cancel();
                    match work.await {
                        Ok(value) => Ok(value),
                        Err(_) => stopped,
                    }
                }
            };
            if result.is_err() && grant.remaining().is_err() {
                return Err(Code::Denied.error("managed grant expiry").into());
            }
            let value = result?;
            caller.check()?;
            Ok(value)
        });
        let result = task.await.context(crate::error::TaskSnafu)?;
        drop(shutdown);
        result
    }

    pub(super) async fn pause_and_join(
        self: &Arc<Self>,
        expected: &ManagedInstance,
        operation: Arc<AnalysisReadControl>,
    ) -> Result<PauseLease> {
        operation.check()?;
        let sender = self
            .commands
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let Some(sender) = sender else {
            let lease = self.query.store().lease_managed()?;
            operation.check()?;
            return Ok(PauseLease::Idle { _lease: lease });
        };
        let member = ManagedMember {
            tenant: expected.spec.tenant,
            id: expected.spec.id.clone(),
            generation: expected.generation,
            lifecycle: expected.lifecycle,
        };
        let bytes = std::mem::size_of::<PauseRequest>()
            .checked_add(expected.spec.id.capacity())
            .ok_or_else(|| Code::Limit.error("managed pause memory"))?
            .max(Member::allocation_bytes(&member)?);
        let memory = self
            .query
            .memory()
            .reserve_input(bytes)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let (reply, joined) = oneshot::channel();
        sender
            .send(PauseRequest {
                member,
                operation: Arc::clone(&operation),
                reply,
                memory,
            })
            .map_err(|_| Code::Incomplete.error("managed host stopped"))?;
        let pause = joined
            .await
            .map_err(|_| Code::Incomplete.error("managed member join reply"))??;
        operation.check()?;
        Ok(pause)
    }

    pub(super) fn pause_member(
        self: &Arc<Self>,
        members: &futures_util::stream::FuturesUnordered<Member>,
        request: PauseRequest,
        witness_expiry: u64,
    ) {
        if let Err(error) = request.operation.check() {
            request.fail(error.into());
            return;
        }
        if let Some(member) = members.iter().find(|member| {
            member.key.0.tenant == request.member.tenant && member.key.0.id == request.member.id
        }) {
            if member.key.0.lifecycle > request.member.lifecycle
                || member.key.0.lifecycle == request.member.lifecycle
                    && member.key.0 != request.member
            {
                request.fail(Code::Conflict.error("managed member lifecycle").into());
                return;
            }
            member.pause(request);
            return;
        }
        let memory: Result<MemoryReservation> = (|| {
            let bytes = Member::allocation_bytes(&request.member)?;
            Ok(self
                .query
                .memory()
                .reserve_input(bytes)
                .map_err(|source| araphor_query::Error::Sql { source })?)
        })();
        let memory = match memory {
            Ok(memory) => memory,
            Err(error) => {
                request.fail(error);
                return;
            }
        };
        let member = Member::new(
            Arc::clone(self),
            ManagedMember {
                tenant: request.member.tenant,
                id: request.member.id.clone(),
                generation: request.member.generation,
                lifecycle: request.member.lifecycle,
            },
            memory,
            witness_expiry,
            None,
        );
        member.pause(request);
        members.push(member);
    }
}
