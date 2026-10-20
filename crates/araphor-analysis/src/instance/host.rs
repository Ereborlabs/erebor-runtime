use std::future::{pending, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use araphor_data::{AnalysisReadControl, ManagedExit, ManagedInstance, PackageAuthorization};
use araphor_query::execution::Engine;
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
    key: ([u8; 16], String),
    lifecycle: u64,
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
    fn new(host: Arc<InstanceHost>, expected: ManagedInstance, witness_expiry: u64) -> Self {
        let control = Arc::new(AnalysisReadControl::default());
        let operation = Arc::clone(&control);
        Self {
            key: (expected.spec.tenant, expected.spec.id.clone()),
            lifecycle: expected.lifecycle,
            control,
            future: async move {
                let mut result = host.member(&expected, &operation, witness_expiry).await;
                if result
                    .as_ref()
                    .is_err_and(|error| error.status_code() == StatusCode::PermissionDenied)
                {
                    if let Err(error) = host.suspend(&expected).await {
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
                            if let Err(error) = self.reconcile(&members, revision, active, witness_expiry) {
                                break Err(error);
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
    ) -> Result<(u64, Vec<ManagedInstance>)> {
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

    fn reconcile(
        self: &Arc<Self>,
        members: &FuturesUnordered<Member>,
        revision: u64,
        active: Vec<ManagedInstance>,
        witness_expiry: u64,
    ) -> Result<()> {
        for member in members.iter() {
            let current = active.iter().find(|current| {
                current.spec.tenant == member.key.0 && current.spec.id == member.key.1
            });
            if member.lifecycle <= revision
                && current.is_none_or(|current| current.lifecycle > member.lifecycle)
            {
                member.control.cancel()?;
            }
        }
        for current in active {
            if !members.iter().any(|member| {
                current.spec.tenant == member.key.0 && current.spec.id == member.key.1
            }) {
                members.push(Member::new(Arc::clone(self), current, witness_expiry));
            }
        }
        Ok(())
    }

    async fn member(
        self: &Arc<Self>,
        expected: &ManagedInstance,
        control: &Arc<AnalysisReadControl>,
        witness_expiry: u64,
    ) -> Result<()> {
        let grant = &expected.spec.grant;
        let mut changes = self.authority.changes_for(grant);
        let admission = Arc::new(control.operation()?.within(grant.remaining()?)?);
        let opening = Instance::admit(
            Arc::clone(&self.query),
            Arc::clone(&self.authority),
            grant.clone(),
            expected.spec.id.clone(),
            expected.spec.definition.clone(),
            &admission,
        );
        tokio::pin!(opening);
        let owner = loop {
            tokio::select! {
                result = &mut opening => match result {
                    Ok(owner) => break owner,
                    Err(error) => {
                        if control.check().is_ok() {
                            if let Err(expired @ araphor_data::Error::Package {
                                code: Code::Denied,
                                field: "package grant",
                                ..
                            }) = grant.remaining() {
                                return Err(expired.into());
                            }
                        }
                        return Err(error);
                    }
                },
                _ = control.cancelled() => {
                    let _cancelled = admission.cancel();
                    let _joined = opening.await;
                    return Ok(());
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
        };
        loop {
            control.check()?;
            let operation = Arc::new(control.operation()?);
            let opened = Arc::clone(&owner);
            let lifecycle = expected.lifecycle;
            let stage = Arc::clone(&operation);
            let opening = Engine::blocking(Arc::clone(&operation), (), move || {
                Ok(opened.subscribe(stage, witness_expiry, lifecycle))
            });
            tokio::pin!(opening);
            let mut stream = tokio::select! {
                result = &mut opening => result??,
                _ = control.cancelled() => {
                    let _cancelled = operation.cancel();
                    if let Ok(Ok(stream)) = opening.await {
                        stream.cancel_and_join(&AnalysisReadControl::default()).await?;
                    }
                    return Ok(());
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

    async fn suspend(&self, expected: &ManagedInstance) -> Result<()> {
        let store = Arc::clone(self.query.store());
        let expected = expected.clone();
        let control = Arc::new(AnalysisReadControl::default());
        let stage = Arc::clone(&control);
        Engine::blocking(control, (), move || {
            let current = store
                .managed_instance(expected.spec.tenant, &expected.spec.id, &stage)?
                .ok_or_else(|| Code::Missing.error("managed suspension instance"))?;
            if current.generation == expected.generation
                && current.lifecycle == expected.lifecycle
                && current.running
            {
                store.suspend_managed(&current, || stage.check())?;
            }
            Ok(())
        })
        .await
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
