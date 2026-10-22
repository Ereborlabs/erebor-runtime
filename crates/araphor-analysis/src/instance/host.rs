use std::future::{pending, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use araphor_data::{
    AnalysisReadControl, ManagedExit, ManagedMember, ManagedSpec, PackageAuthorization,
};
use araphor_query::execution::Engine;
use araphor_query::memory::Memory;
use datafusion::execution::memory_pool::MemoryReservation;
use erebor_runtime_error::{ErrorExt as _, StatusCode};
use futures_util::{future::BoxFuture, stream::FuturesUnordered, FutureExt as _, StreamExt as _};
use snafu::ResultExt as _;
use tokio::sync::watch;

use super::{Code, Instance, Subscription};
use crate::Result;

pub struct InstanceHost {
    query: Arc<Engine>,
    authority: Arc<dyn PackageAuthorization>,
}

struct Shutdown(Arc<AnalysisReadControl>);

impl Drop for Shutdown {
    fn drop(&mut self) {
        let _cancelled = self.0.cancel();
    }
}

struct Member {
    key: Arc<(ManagedMember, MemoryReservation)>,
    control: Arc<AnalysisReadControl>,
    future: BoxFuture<'static, ()>,
}

impl Future for Member {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(context)
    }
}

impl Member {
    fn new(
        host: Arc<InstanceHost>,
        expected: ManagedMember,
        memory: MemoryReservation,
        witness_expiry: u64,
    ) -> Self {
        let control = Arc::new(AnalysisReadControl::default());
        let operation = Arc::clone(&control);
        let expected = Arc::new((expected, memory));
        Self {
            key: Arc::clone(&expected),
            control,
            future: async move {
                let mut result = host.member(&expected, &operation, witness_expiry).await;
                if result
                    .as_ref()
                    .is_err_and(|error| error.status_code() == StatusCode::PermissionDenied)
                {
                    if let Err(error) = host
                        .suspend(Arc::clone(&expected), Arc::clone(&operation))
                        .await
                    {
                        result = Err(error);
                    }
                }
                if result.is_err() {
                    operation.cancelled().await;
                }
            }
            .boxed(),
        }
    }
}

impl InstanceHost {
    pub fn new(query: Arc<Engine>, authority: Arc<dyn PackageAuthorization>) -> Arc<Self> {
        Arc::new(Self { query, authority })
    }

    /// Drop cancels the host. The task retains its lease until all workers join.
    pub async fn serve(
        self: Arc<Self>,
        stop: watch::Receiver<bool>,
        witness_expiry: u64,
    ) -> Result<()> {
        let control = Arc::new(AnalysisReadControl::default());
        let shutdown = Shutdown(Arc::clone(&control));
        let task = tokio::spawn(self.drive(control, stop, witness_expiry));
        let result = task.await.context(crate::error::TaskSnafu)?;
        drop(shutdown);
        result
    }

    async fn drive(
        self: Arc<Self>,
        control: Arc<AnalysisReadControl>,
        mut stop: watch::Receiver<bool>,
        witness_expiry: u64,
    ) -> Result<()> {
        control.check()?;
        if *stop.borrow() {
            return Ok(());
        }
        let lease = self.query.store().lease_managed()?;
        let mut notices = self.query.store().subscribe_activations();
        let reader = Arc::new(control.operation()?);
        let mut metadata = Some(self.membership(Arc::clone(&reader)).boxed());
        let mut members = FuturesUnordered::new();
        let result = loop {
            if *stop.borrow() {
                break Ok(());
            }
            tokio::select! {
                _ = control.cancelled() => break Ok(()),
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        break Ok(());
                    }
                }
                changed = notices.changed(), if metadata.is_none() => {
                    if changed.is_err() {
                        break Err(Code::Incomplete.error("managed lifecycle notices").into());
                    }
                    metadata = Some(self.membership(Arc::clone(&reader)).boxed());
                }
                result = async {
                    match metadata.as_mut() {
                        Some(read) => read.await,
                        None => pending().await,
                    }
                } => {
                    metadata = None;
                    match result {
                        Ok((revision, active)) => {
                            let memory = self.query.memory().scope();
                            let epoch = memory.capacity_epoch();
                            let reserved = memory.reserve_input(0)
                                .map_err(|source| araphor_query::Error::Sql { source });
                            let result: Result<()> = reserved.map_err(Into::into).and_then(|reserved| {
                                self.reconcile(&members, revision, active, reserved, witness_expiry)
                            });
                            if let Err(error) = result {
                                if !matches!(&error, crate::Error::Query { source }
                                    if araphor_query::Failure::from(source) == araphor_query::Failure::Busy) {
                                    break Err(error);
                                }
                                metadata = Some(if *notices.borrow_and_update() > revision {
                                    self.membership(Arc::clone(&reader)).boxed()
                                } else {
                                    self.wait_membership(
                                        Arc::clone(&reader), memory, epoch, notices.clone(),
                                    ).boxed()
                                });
                            }
                        }
                        Err(error) => break Err(error),
                    }
                }
                _ = members.next(), if !members.is_empty() => {
                    if metadata.is_none() {
                        metadata = Some(self.membership(Arc::clone(&reader)).boxed());
                    }
                }
            }
        };
        let _cancelled = reader.cancel();
        for member in members.iter() {
            let _cancelled = member.control.cancel();
        }
        if let Some(read) = metadata {
            let _joined = read.await;
        }
        while members.next().await.is_some() {}
        drop(lease);
        result
    }

    async fn membership(
        &self,
        control: Arc<AnalysisReadControl>,
    ) -> Result<(u64, Vec<ManagedMember>)> {
        let store = Arc::clone(self.query.store());
        loop {
            let reader = Arc::clone(&store);
            let stage = Arc::clone(&control);
            let result = Engine::blocking(Arc::clone(&control), (), move || {
                reader.active_managed(&stage).map_err(Into::into)
            })
            .await;
            match result {
                Err(araphor_query::Error::Data {
                    source:
                        araphor_data::Error::AnalysisBusy {
                            resource: "reader", ..
                        },
                }) => control.query_async(store.wait_capacity()).await?,
                result => return result.map_err(Into::into),
            }
        }
    }

    async fn wait_membership(
        &self,
        control: Arc<AnalysisReadControl>,
        memory: Arc<Memory>,
        epoch: u64,
        mut notices: watch::Receiver<u64>,
    ) -> Result<(u64, Vec<ManagedMember>)> {
        tokio::select! {
            changed = notices.changed() => {
                if changed.is_err() {
                    return Err(Code::Incomplete.error("managed lifecycle notices").into());
                }
            }
            result = control.query_async(memory.capacity_changed(epoch)) => result?,
        }
        self.membership(control).await
    }

    fn reconcile(
        self: &Arc<Self>,
        members: &FuturesUnordered<Member>,
        revision: u64,
        active: Vec<ManagedMember>,
        memory: MemoryReservation,
        witness_expiry: u64,
    ) -> Result<()> {
        for member in members.iter() {
            let expected = &member.key.0;
            let current = active
                .iter()
                .find(|current| current.tenant == expected.tenant && current.id == expected.id);
            if expected.lifecycle <= revision
                && current.is_none_or(|current| {
                    current.generation > expected.generation
                        || current.lifecycle > expected.lifecycle
                })
            {
                member.control.cancel()?;
            }
        }
        let bytes = active
            .capacity()
            .checked_mul(std::mem::size_of::<ManagedMember>())
            .and_then(|bytes| {
                active.iter().try_fold(bytes, |bytes, member| {
                    bytes.checked_add(member.id.capacity())
                })
            })
            .ok_or_else(|| Code::Limit.error("managed membership memory"))?;
        memory
            .try_grow(bytes)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        for current in active {
            if !members.iter().any(|member| {
                current.tenant == member.key.0.tenant && current.id == member.key.0.id
            }) {
                let bytes = std::mem::size_of::<ManagedMember>()
                    .checked_add(current.id.capacity())
                    .ok_or_else(|| Code::Limit.error("managed membership memory"))?;
                members.push(Member::new(
                    Arc::clone(self),
                    current,
                    memory.split(bytes),
                    witness_expiry,
                ));
            }
        }
        Ok(())
    }

    async fn open_member(
        self: &Arc<Self>,
        expected: &Arc<(ManagedMember, MemoryReservation)>,
        control: &Arc<AnalysisReadControl>,
    ) -> Result<Arc<Instance>> {
        let memory = self.query.memory().scope();
        let mut notices = self.authority.changes();
        loop {
            control.check()?;
            let epoch = memory.capacity_epoch();
            let store = Arc::clone(self.query.store());
            let selected = Arc::clone(expected);
            let stage = Arc::clone(control);
            let current = Engine::blocking(Arc::clone(control), Arc::clone(expected), move || {
                let current = store
                    .managed_instance(selected.0.tenant, &selected.0.id, &stage)?
                    .ok_or_else(|| Code::Missing.error("managed member instance"))?;
                if !current.running
                    || current.generation != selected.0.generation
                    || current.lifecycle != selected.0.lifecycle
                {
                    return Err(Code::Conflict.error("managed member fence").into());
                }
                Ok(current)
            })
            .await;
            let current = match current {
                Ok(current) => current,
                Err(error) => {
                    let error = error.into();
                    tokio::select! {
                        ready = self.wait_open(&error, control, &memory, epoch) => {
                            if !ready? { return Err(error); }
                        }
                        changed = notices.changed() => {
                            if changed.is_err() {
                                return Err(Code::Denied.error("managed admission authority notice").into());
                            }
                        }
                    }
                    continue;
                }
            };
            let ManagedSpec {
                id,
                definition,
                manifest,
                ..
            } = current.spec;
            let grant = current.grant;
            drop(manifest);
            let mut changes = self.authority.changes_for(&grant);
            let admission = Arc::new(control.operation()?.within(grant.remaining()?)?);
            let result = {
                let opening = Instance::admit_on(
                    Arc::clone(&self.query),
                    Arc::clone(&self.authority),
                    grant.clone(),
                    id,
                    definition,
                    &admission,
                    Arc::clone(&memory),
                );
                tokio::pin!(opening);
                loop {
                    tokio::select! {
                        result = &mut opening => break result,
                        _ = control.cancelled() => {
                            let _cancelled = admission.cancel();
                            let _joined = opening.await;
                            return Err(Code::Incomplete.error("managed admission stopped").into());
                        }
                        changed = changes.changed() => {
                            let authority = Arc::clone(&self.authority);
                            let checked_grant = grant.clone();
                            let checked = Engine::blocking(Arc::clone(&admission), (), move || {
                                authority.check(&checked_grant, araphor_data::PackageActionV1::Run).map_err(Into::into)
                            }).await;
                            if changed.is_err() || checked.is_err() {
                                let _cancelled = admission.cancel();
                                let _joined = opening.await;
                                checked?;
                                return Err(Code::Denied.error("managed admission authority notice").into());
                            }
                        }
                    }
                }
            };
            if control.check().is_ok() {
                grant.remaining()?;
            }
            let error = match result {
                Ok(owner) => return Ok(owner),
                Err(error) => error,
            };
            let ready = tokio::select! {
                _ = control.cancelled() => {
                    let _cancelled = admission.cancel();
                    return Err(Code::Incomplete.error("managed admission stopped").into());
                }
                ready = self.wait_open(&error, &admission, &memory, epoch) => ready,
                changed = changes.changed() => {
                    if changed.is_err() {
                        return Err(Code::Denied.error("managed admission authority notice").into());
                    }
                    Ok(true)
                }
            };
            if control.check().is_ok() {
                grant.remaining()?;
            }
            if !ready? {
                return Err(error);
            }
        }
    }

    async fn wait_open(
        &self,
        error: &crate::Error,
        control: &AnalysisReadControl,
        memory: &Memory,
        epoch: u64,
    ) -> Result<bool> {
        let resource = {
            let mut resource = None;
            let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
            while let Some(error) = current {
                if matches!(
                    error.downcast_ref::<araphor_data::Error>(),
                    Some(araphor_data::Error::AnalysisBusy {
                        resource: "reader",
                        ..
                    })
                ) {
                    resource = Some("reader");
                    break;
                }
                if let Some(araphor_query::Error::Capacity {
                    resource: capacity @ ("shared input" | "shared output"),
                    ..
                }) = error.downcast_ref::<araphor_query::Error>()
                {
                    resource = Some(*capacity);
                    break;
                }
                current = match error.downcast_ref::<crate::Error>() {
                    Some(crate::Error::Data { source }) => Some(source),
                    Some(crate::Error::Query { source }) => Some(source),
                    _ => match error.downcast_ref::<araphor_query::Error>() {
                        Some(araphor_query::Error::Data { source }) => Some(source),
                        _ => error.source(),
                    },
                };
            }
            resource
        };
        match resource {
            Some("reader") => {
                control
                    .query_async(self.query.store().wait_capacity())
                    .await?
            }
            Some(_) => control.query_async(memory.capacity_changed(epoch)).await?,
            None => return Ok(false),
        }
        Ok(true)
    }

    async fn member(
        self: &Arc<Self>,
        expected: &Arc<(ManagedMember, MemoryReservation)>,
        control: &Arc<AnalysisReadControl>,
        witness_expiry: u64,
    ) -> Result<()> {
        let owner = match self.open_member(expected, control).await {
            Ok(owner) => owner,
            Err(_) if control.check().is_err() => return Ok(()),
            Err(error) => return Err(error),
        };
        let expected = &expected.0;
        loop {
            control.check()?;
            let operation = Arc::new(
                control
                    .operation()?
                    .within(owner.admitted.grant.remaining()?)?,
            );
            let mut changes = self.authority.changes_for(&owner.admitted.grant);
            let opened = Arc::clone(&owner);
            let lifecycle = expected.lifecycle;
            let stage = Arc::clone(&operation);
            let opening = Engine::blocking(Arc::clone(&operation), (), move || {
                Ok(opened.subscribe(stage, witness_expiry, lifecycle))
            });
            tokio::pin!(opening);
            let result = tokio::select! {
                result = &mut opening => result?,
                _ = control.cancelled() => {
                    let _cancelled = operation.cancel();
                    if let Ok(Ok(stream)) = opening.await {
                        stream.cancel_and_join(&AnalysisReadControl::default()).await?;
                    }
                    return Ok(());
                }
            };
            let mut stream = match result {
                Ok(stream) => stream,
                Err(error) => {
                    let memory = self.query.memory().scope();
                    let epoch = memory.capacity_epoch();
                    let ready = tokio::select! {
                        _ = control.cancelled() => {
                            let _cancelled = operation.cancel();
                            return Ok(());
                        }
                        ready = self.wait_open(&error, &operation, &memory, epoch) => ready,
                        changed = changes.changed() => {
                            if changed.is_err() {
                                return Err(Code::Denied.error("managed admission authority notice").into());
                            }
                            Ok(true)
                        }
                    };
                    if control.check().is_ok() {
                        owner.admitted.grant.remaining()?;
                    }
                    if !ready? {
                        return Err(error);
                    }
                    continue;
                }
            };
            let failure = loop {
                tokio::select! {
                    _ = control.cancelled() => {
                        stream.cancel_and_join(&AnalysisReadControl::default()).await?;
                        return Ok(());
                    }
                    next = stream.next() => match next {
                        Some(Ok(_receipt)) => {}
                        Some(Err(error)) => break error,
                        None => break Code::Incomplete.error("managed subscription ended").into(),
                    }
                }
            };
            let terminal = stream
                .cancel_and_join(&AnalysisReadControl::default())
                .await?;
            if control.check().is_err() {
                return Ok(());
            }
            let checked = Arc::clone(&owner);
            Engine::blocking(Arc::clone(control), (), move || Ok(checked.check())).await??;
            match terminal.map(|terminal| terminal.exit) {
                Some(ManagedExit::Failed(
                    Code::Invalid | Code::Unsupported | Code::Missing | Code::Conflict,
                ))
                | Some(ManagedExit::Cancelled) => {}
                None if Subscription::failure(&failure) == ManagedExit::Cancelled => {}
                _ => return Err(failure),
            }
        }
    }

    async fn suspend(
        &self,
        expected: Arc<(ManagedMember, MemoryReservation)>,
        control: Arc<AnalysisReadControl>,
    ) -> Result<()> {
        loop {
            let store = Arc::clone(self.query.store());
            let selected = Arc::clone(&expected);
            let stage = Arc::clone(&control);
            let result = Engine::blocking(Arc::clone(&control), Arc::clone(&expected), move || {
                let expected = &selected.0;
                let current = store
                    .managed_instance(expected.tenant, &expected.id, &stage)?
                    .ok_or_else(|| Code::Missing.error("managed suspension instance"))?;
                if current.generation == expected.generation
                    && current.lifecycle == expected.lifecycle
                    && current.running
                {
                    store.suspend_managed(&current, || stage.check())?;
                }
                Ok(())
            })
            .await;
            match result {
                Err(araphor_query::Error::Data {
                    source:
                        araphor_data::Error::AnalysisBusy {
                            resource: "reader", ..
                        },
                }) => {
                    control
                        .query_async(self.query.store().wait_capacity())
                        .await?;
                }
                result => return result.map_err(Into::into),
            }
        }
    }
}

#[cfg(test)]
mod tests;
