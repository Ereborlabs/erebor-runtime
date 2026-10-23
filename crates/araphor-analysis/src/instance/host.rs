use std::future::{pending, Future};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use araphor_data::{
    AnalysisReadControl, ManagedDestination, ManagedExit, ManagedMember, ManagedResume,
    PackageAuthorization,
};
use araphor_query::execution::Engine;
use araphor_query::memory::Memory;
use datafusion::execution::memory_pool::MemoryReservation;
use erebor_runtime_error::{ErrorExt as _, StatusCode};
use futures_util::{future::BoxFuture, stream::FuturesUnordered, FutureExt as _, StreamExt as _};
use snafu::ResultExt as _;
use tokio::sync::{mpsc, watch};

use super::{Code, Instance, Subscription};
use crate::Result;

mod lifecycle;
mod notification;
mod removal;
mod request;
mod version;

use lifecycle::{PauseRequest, PauseState, PreparedMember};

pub struct InstanceHost {
    query: Arc<Engine>,
    authority: Arc<dyn PackageAuthorization>,
    graph_facts: Option<Arc<dyn crate::GraphFacts>>,
    notifications: Option<notification::Notifications>,
    commands: Mutex<Option<mpsc::UnboundedSender<PauseRequest>>>,
    serving: watch::Sender<bool>,
}

pub(crate) enum Restored {
    Absent,
    Removed(Box<araphor_data::ManagedInstance>),
    Present(Arc<Instance>),
}

pub(crate) struct Shutdown(Arc<AnalysisReadControl>);

struct Registration {
    host: Arc<InstanceHost>,
    _lease: araphor_data::ManagedLease,
}

impl Drop for Registration {
    fn drop(&mut self) {
        *self
            .host
            .commands
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
        self.host.serving.send_replace(false);
    }
}

impl Drop for Shutdown {
    fn drop(&mut self) {
        let _cancelled = self.0.cancel();
    }
}

impl Shutdown {
    pub(crate) async fn join(
        control: Arc<AnalysisReadControl>,
        mut stop: watch::Receiver<bool>,
        work: impl Future<Output = Result<()>> + Send + 'static,
    ) -> Result<()> {
        let shutdown = Self(Arc::clone(&control));
        let task = tokio::spawn(async move {
            let result = {
                tokio::pin!(work);
                loop {
                    tokio::select! {
                        result = &mut work => break result,
                        changed = stop.changed() => {
                            if changed.is_err() || *stop.borrow_and_update() {
                                let cancelled = control.cancel();
                                let joined = work.await;
                                cancelled?;
                                break joined;
                            }
                        }
                    }
                }
            };
            drop(stop);
            result
        });
        let result = task.await.context(crate::error::TaskSnafu)?;
        drop(shutdown);
        result
    }
}

enum MemberStream {
    Managed(Subscription),
    Notification(araphor_query::follow::Subscription),
}

impl MemberStream {
    fn failed(&mut self, error: &crate::Error) {
        if let Self::Managed(stream) = self {
            stream.failed(error);
        }
    }

    async fn next(&mut self) -> Option<Result<()>> {
        match self {
            Self::Managed(stream) => stream.next().await.map(|result| result.map(|_| ())),
            Self::Notification(stream) => stream
                .next()
                .await
                .map(|result| result.map(|_| ()).map_err(Into::into)),
        }
    }

    async fn cancel_and_join(
        self,
        diagnostic: &AnalysisReadControl,
    ) -> Result<Option<araphor_data::ManagedTerminal>> {
        match self {
            Self::Managed(stream) => stream.cancel_and_join(diagnostic).await,
            Self::Notification(stream) => {
                stream.cancel_and_join().await?;
                Ok(None)
            }
        }
    }
}

struct Member {
    key: Arc<(ManagedMember, MemoryReservation)>,
    control: Arc<AnalysisReadControl>,
    pause: Arc<Mutex<PauseState>>,
    future: BoxFuture<'static, Option<PreparedMember>>,
}

impl Future for Member {
    type Output = Option<PreparedMember>;

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
        prepared: Option<Arc<Instance>>,
    ) -> Self {
        let control = Arc::new(AnalysisReadControl::default());
        let operation = Arc::clone(&control);
        let expected = Arc::new((expected, memory));
        let pause = Arc::new(Mutex::new(PauseState::default()));
        let joined = Arc::clone(&pause);
        let serving = host.serving.subscribe();
        Self {
            key: Arc::clone(&expected),
            control,
            pause,
            future: async move {
                let mut result = host
                    .member(&expected, &operation, witness_expiry, prepared)
                    .await;
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
                if let Err(error) = &result {
                    if operation.check().is_ok() {
                        erebor_telemetry::warn!(error; "Managed instance subscription ended", instance_id = %expected.0.id);
                    }
                    operation.cancelled().await;
                }
                Self::joined_pause(&joined, serving).await
            }
            .boxed(),
        }
    }
}

impl InstanceHost {
    pub fn new(query: Arc<Engine>, authority: Arc<dyn PackageAuthorization>) -> Arc<Self> {
        Arc::new(Self {
            query,
            authority,
            graph_facts: None,
            notifications: None,
            commands: Mutex::default(),
            serving: watch::channel(false).0,
        })
    }

    pub fn with_graph_facts(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        facts: Arc<dyn crate::GraphFacts>,
    ) -> Arc<Self> {
        Arc::new(Self {
            query,
            authority,
            graph_facts: Some(facts),
            notifications: None,
            commands: Mutex::default(),
            serving: watch::channel(false).0,
        })
    }

    pub fn with_notifications(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        graph_facts: Option<Arc<dyn crate::GraphFacts>>,
        router: Arc<crate::NotificationRouter>,
        sink: Arc<dyn araphor_data::NotificationSink>,
        enabled: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            query,
            authority,
            graph_facts,
            notifications: Some(notification::Notifications {
                router,
                sink,
                enabled,
            }),
            commands: Mutex::default(),
            serving: watch::channel(false).0,
        })
    }

    pub(crate) fn check_query(&self, query: &Arc<Engine>) -> Result<()> {
        if !Arc::ptr_eq(query, &self.query) {
            return Err(Code::Conflict.error("managed host query owner").into());
        }
        Ok(())
    }

    pub(crate) async fn admit_prepared(
        &self,
        session: araphor_query::execution::Session,
        grant: araphor_data::PackageGrantV1,
        id: String,
        prepared: araphor_query::definition::PreparedDefinition,
        destination: ManagedDestination,
    ) -> Result<Arc<Instance>> {
        self.check_query(session.engine())?;
        if session.selection() != &destination.selection(&grant.selection)? {
            return Err(Code::Denied.error("managed prepared selection").into());
        }
        let read = Arc::new(session.control().within(grant.remaining()?)?);
        let control = Arc::clone(&read);
        let store = Arc::clone(self.query.store());
        let check = Arc::clone(&self.authority);
        let retained = prepared.clone();
        let authorized = grant.clone();
        Engine::blocking(read, (), move || {
            let definition = retained.resolved();
            let digest = definition.digest().map_err(araphor_data::Error::from)?;
            let saved = store.definition(
                authorized.selection.tenant_id,
                &definition.definition.name,
                Some(&digest),
                &control,
            )?;
            if let Some(saved) = saved {
                if saved != *definition {
                    return Err(Code::Conflict.error("managed definition pin").into());
                }
                return Ok(());
            }
            Instance::authorize_actions(
                check.as_ref(),
                &authorized,
                &retained,
                &[araphor_data::PackageActionV1::Install],
                || {
                    store
                        .admit_definition(authorized.selection.tenant_id, definition, || {
                            control.check()
                        })
                        .map(|_| ())
                },
            )
            .map_err(Into::into)
        })
        .await?;
        Instance::admit_prepared(
            session,
            Arc::clone(&self.authority),
            grant,
            id,
            prepared,
            destination,
        )
        .await
    }

    pub(crate) async fn admit_graph(
        &self,
        grant: araphor_data::PackageGrantV1,
        id: String,
        source: araphor_data::EvidenceIntakeIdentityV1,
        events_sql: String,
        definition: araphor_discovery_definition::ResolvedDefinition,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        let facts = self
            .graph_facts
            .as_ref()
            .ok_or_else(|| Code::Incomplete.error("managed graph facts"))?;
        crate::GraphPublication::admit(
            Arc::clone(&self.query),
            Arc::clone(&self.authority),
            Arc::clone(facts),
            grant,
            id,
            source,
            events_sql,
            definition,
            control,
        )
        .await
    }

    pub(crate) async fn admit_graph_expiry(
        &self,
        grant: araphor_data::PackageGrantV1,
        id: String,
        source: araphor_data::EvidenceIntakeIdentityV1,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        crate::GraphPublication::admit_expiry(
            Arc::clone(&self.query),
            Arc::clone(&self.authority),
            grant,
            id,
            source,
            control,
        )
        .await
    }

    /// Drop cancels the host. The task retains its lease until all workers join.
    pub fn serve(
        self: Arc<Self>,
        stop: watch::Receiver<bool>,
        witness_expiry: u64,
    ) -> impl Future<Output = Result<()>> + Send {
        let prepared = (|| -> Result<_> {
            if *stop.borrow() {
                return Ok(None);
            }
            let control = Arc::new(AnalysisReadControl::default());
            let shutdown = Shutdown(Arc::clone(&control));
            let reader = Arc::new(control.operation()?);
            let registration = Registration {
                host: Arc::clone(&self),
                _lease: self.query.store().lease_managed()?,
            };
            let (commands, requests) = mpsc::unbounded_channel();
            *self
                .commands
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(commands);
            self.serving.send_replace(true);
            Ok(Some((control, shutdown, reader, registration, requests)))
        })();
        async move {
            let Some((control, shutdown, reader, registration, requests)) = prepared? else {
                return Ok(());
            };
            let task = tokio::spawn(self.drive(
                control,
                reader,
                stop,
                witness_expiry,
                registration,
                requests,
            ));
            let result = task.await.context(crate::error::TaskSnafu)?;
            drop(shutdown);
            result
        }
    }

    async fn drive(
        self: Arc<Self>,
        control: Arc<AnalysisReadControl>,
        reader: Arc<AnalysisReadControl>,
        mut stop: watch::Receiver<bool>,
        witness_expiry: u64,
        registration: Registration,
        mut requests: mpsc::UnboundedReceiver<PauseRequest>,
    ) -> Result<()> {
        let mut notices = self.query.store().subscribe_activations();
        let mut metadata = Some(self.membership(Arc::clone(&reader)).boxed());
        let mut members = FuturesUnordered::new();
        let result = loop {
            if *stop.borrow() {
                break Ok(());
            }
            tokio::select! {
                _ = control.cancelled() => break Ok(()),
                request = requests.recv() => {
                    if let Some(request) = request {
                        self.pause_member(&members, request, witness_expiry);
                    }
                }
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
                joined = members.next(), if !members.is_empty() => {
                    if let Some(Some((owner, memory, accepted))) = joined {
                        if let Some(owner) = owner {
                            let admitted = owner.admitted();
                            members.push(Member::new(
                                Arc::clone(&self),
                                ManagedMember {
                                    tenant: admitted.spec.tenant,
                                    id: admitted.spec.id.clone(),
                                    generation: admitted.generation,
                                    lifecycle: admitted.lifecycle,
                                },
                                memory,
                                witness_expiry,
                                Some(owner),
                            ));
                        }
                        let _accepted = accepted.send(());
                    }
                    if metadata.is_none() {
                        metadata = Some(self.membership(Arc::clone(&reader)).boxed());
                    }
                }
            }
        };
        *self
            .commands
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
        requests.close();
        while let Ok(request) = requests.try_recv() {
            request.fail(Code::Incomplete.error("managed host stopped").into());
        }
        self.serving.send_replace(false);
        let _cancelled = reader.cancel();
        for member in members.iter() {
            let _cancelled = member.control.cancel();
        }
        if let Some(read) = metadata {
            let _joined = read.await;
        }
        while members.next().await.is_some() {}
        drop(registration);
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
                    bytes
                        .checked_add(member.id.capacity())?
                        .checked_add(std::mem::size_of::<Mutex<PauseState>>())
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
                let bytes = Member::allocation_bytes(&current)?;
                members.push(Member::new(
                    Arc::clone(self),
                    current,
                    memory.split(bytes),
                    witness_expiry,
                    None,
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
        self.restore_member(expected, control, true).await
    }

    async fn restore_member(
        self: &Arc<Self>,
        expected: &Arc<(ManagedMember, MemoryReservation)>,
        control: &Arc<AnalysisReadControl>,
        require_running: bool,
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
                let resume = if require_running {
                    store.managed_resume(selected.0.tenant, &selected.0.id, &stage)?
                } else {
                    ManagedResume {
                        instance: store
                            .managed_instance(selected.0.tenant, &selected.0.id, &stage)?
                            .ok_or_else(|| Code::Missing.error("managed member instance"))?,
                        frontier: None,
                        completed: 0,
                    }
                };
                let current = &resume.instance;
                if require_running && !current.running
                    || current.generation != selected.0.generation
                    || current.lifecycle != selected.0.lifecycle
                {
                    return Err(Code::Conflict.error("managed member fence").into());
                }
                Ok(resume)
            })
            .await;
            let resume = match current {
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
            let current = &resume.instance;
            let grant = current.grant.clone();
            let mut changes = self.authority.changes_for(&grant);
            let admission = Arc::new(control.operation()?.within(grant.remaining()?)?);
            let result = {
                let opening = async {
                    self.admit_current(current, None, &admission, Arc::clone(&memory))
                        .await
                };
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
                if require_running {
                    if let Some(code) = Subscription::admission(&error) {
                        let store = Arc::clone(self.query.store());
                        let stage = Arc::clone(control);
                        Engine::blocking(Arc::clone(control), (), move || {
                            Subscription::record_admission(&store, &resume, code, || stage.check())
                                .map_err(Into::into)
                        })
                        .await?;
                    }
                }
                return Err(error);
            }
        }
    }

    fn open_resource(error: &crate::Error) -> Option<(&'static str, usize)> {
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
                resource = Some(("reader", 0));
                break;
            }
            if let Some(araphor_query::Error::Capacity {
                resource: capacity @ ("shared input" | "shared output"),
                ..
            }) = error.downcast_ref::<araphor_query::Error>()
            {
                resource = Some((*capacity, 0));
                break;
            }
            if let Some(araphor_query::PackageRuntimeError::AnalysisBusy {
                resource: capacity @ ("component compiler" | "component cache capacity"),
                requested,
                ..
            }) = error.downcast_ref::<araphor_query::PackageRuntimeError>()
            {
                resource = Some((*capacity, *requested));
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
    }

    async fn wait_open(
        &self,
        error: &crate::Error,
        control: &AnalysisReadControl,
        memory: &Memory,
        epoch: u64,
    ) -> Result<bool> {
        match Self::open_resource(error) {
            Some(("reader", _)) => {
                control
                    .query_async(self.query.store().wait_capacity())
                    .await?
            }
            Some(("shared input" | "shared output", _)) => {
                control.query_async(memory.capacity_changed(epoch)).await?
            }
            Some((resource, requested)) => {
                control
                    .query_async(self.query.wait_package_capacity(resource, requested))
                    .await?
            }
            None => return Ok(false),
        }
        Ok(true)
    }

    async fn member(
        self: &Arc<Self>,
        expected: &Arc<(ManagedMember, MemoryReservation)>,
        control: &Arc<AnalysisReadControl>,
        witness_expiry: u64,
        prepared: Option<Arc<Instance>>,
    ) -> Result<()> {
        let opened = match prepared {
            Some(owner) => Ok(owner),
            None => self.open_member(expected, control).await,
        };
        let owner = match opened {
            Ok(owner) => owner,
            Err(_) if control.check().is_err() => return Ok(()),
            Err(error) => return Err(error),
        };
        let expected = &expected.0;
        let memory = Arc::clone(owner.session.memory());
        let mut retry_after_capacity = None;
        let mut capacity: Option<(crate::Error, u64, u64)> = None;
        'member: loop {
            control.check()?;
            let epoch = memory.capacity_epoch();
            let operation = Arc::new(
                control
                    .operation()?
                    .within(owner.admitted.grant.remaining()?)?,
            );
            let mut changes = self.authority.changes_for(&owner.admitted.grant);
            let opened = Arc::clone(&owner);
            let lifecycle = expected.lifecycle;
            let stage = Arc::clone(&operation);
            let notifications = self.notifications.clone();
            let opening = Engine::blocking(Arc::clone(&operation), (), move || {
                Ok(
                    if opened.admitted.spec.destination == ManagedDestination::Notification {
                        opened
                            .subscribe_notifications(
                                notifications.as_ref().ok_or_else(|| {
                                    Code::Incomplete.error("notification execution owner")
                                })?,
                                stage,
                                lifecycle,
                            )
                            .map(MemberStream::Notification)
                    } else {
                        opened
                            .subscribe_on(stage, witness_expiry, lifecycle, retry_after_capacity)
                            .map(MemberStream::Managed)
                    },
                )
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
                Ok(stream) => {
                    retry_after_capacity = None;
                    stream
                }
                Err(error) => {
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
                    ready = async {
                        match &capacity {
                            Some((error, epoch, _)) => self.wait_open(error, &operation, &memory, *epoch).await,
                            None => std::future::pending::<Result<bool>>().await,
                        }
                    } => {
                        let (failure, _, completed) = capacity.take().ok_or_else(|| {
                            Code::Incomplete.error("managed capacity cause")
                        })?;
                        stream.cancel_and_join(&AnalysisReadControl::default()).await?;
                        if control.check().is_err() {
                            return Ok(());
                        }
                        owner.admitted.grant.remaining()?;
                        if !ready? {
                            return Err(failure);
                        }
                        retry_after_capacity = Some(completed);
                        continue 'member;
                    }
                    next = stream.next() => match next {
                        Some(Ok(_receipt)) => { capacity = None; }
                        Some(Err(error)) => break error,
                        None => break Code::Incomplete.error("managed subscription ended").into(),
                    }
                }
            };
            stream.failed(&failure);
            let terminal = stream
                .cancel_and_join(&AnalysisReadControl::default())
                .await?;
            if control.check().is_err() {
                return Ok(());
            }
            if owner.admitted.spec.destination == ManagedDestination::Notification {
                if let Some(code) = Subscription::admission(&failure) {
                    let expected = ManagedResume {
                        instance: owner.admitted.clone(),
                        frontier: None,
                        completed: 0,
                    };
                    let store = Arc::clone(self.query.store());
                    let stage = Arc::clone(control);
                    Engine::blocking(Arc::clone(control), (), move || {
                        Subscription::record_admission(&store, &expected, code, || stage.check())
                            .map_err(Into::into)
                    })
                    .await?;
                }
            }
            let checked = Arc::clone(&owner);
            Engine::blocking(Arc::clone(control), (), move || Ok(checked.check())).await??;
            if terminal.is_none() {
                if let Some(recovery) = araphor_query::follow::SourceRecovery::take(&failure) {
                    let waiting = control
                        .operation()?
                        .within(owner.admitted.grant.remaining()?)?;
                    let changed = recovery.changed(&waiting);
                    tokio::pin!(changed);
                    tokio::select! {
                        result = &mut changed => result?,
                        _ = control.cancelled() => {
                            let _cancelled = waiting.cancel();
                            let _joined = changed.await;
                            return Ok(());
                        }
                        notice = changes.changed() => {
                            let _cancelled = waiting.cancel();
                            let _joined = changed.await;
                            if notice.is_err() {
                                return Err(Code::Denied.error("managed recovery authority notice").into());
                            }
                        }
                    }
                    continue;
                }
            }
            let busy = matches!(
                &failure,
                crate::Error::Data {
                    source: araphor_data::Error::AnalysisBusy { .. }
                }
            ) || matches!(
                &failure,
                crate::Error::Query { source }
                    if araphor_query::Failure::from(source) == araphor_query::Failure::Busy
            );
            if busy {
                if let Some(terminal) = terminal
                    .as_ref()
                    .filter(|_| Self::open_resource(&failure).is_some())
                {
                    capacity = Some((failure, epoch, terminal.revision));
                    continue;
                }
                capacity = None;
                let waiting = Arc::new(
                    control
                        .operation()?
                        .within(owner.admitted.grant.remaining()?)?,
                );
                let ready = loop {
                    tokio::select! {
                        _ = control.cancelled() => {
                            let _cancelled = waiting.cancel();
                            return Ok(());
                        }
                        ready = self.wait_open(&failure, &waiting, &memory, epoch) => break ready,
                        changed = changes.changed() => {
                            if changed.is_err() {
                                return Err(Code::Denied.error("managed admission authority notice").into());
                            }
                            let checked = Arc::clone(&owner);
                            let checked = Engine::blocking(Arc::clone(&waiting), (), move || Ok(checked.check())).await;
                            if control.check().is_ok() {
                                owner.admitted.grant.remaining()?;
                            }
                            checked??;
                        }
                    }
                };
                if control.check().is_ok() {
                    owner.admitted.grant.remaining()?;
                }
                if ready? {
                    continue;
                }
            }
            if terminal.is_some() || Subscription::failure(&failure) != ManagedExit::Cancelled {
                capacity = None;
            }
            match terminal.map(|terminal| terminal.exit) {
                Some(ManagedExit::Failed(
                    Code::Invalid | Code::Unsupported | Code::Missing | Code::Conflict,
                ))
                | Some(ManagedExit::Cancelled) => {}
                Some(ManagedExit::Failed(Code::Incomplete | Code::Limit)) if !busy => {}
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
