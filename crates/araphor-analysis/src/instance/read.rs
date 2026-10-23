use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use araphor_data::{
    AnalysisReadControl, AnalysisStore, ManagedInstance, ManagedOutput, ManagedReceipt,
    ManagedResult, ManagedStatus, PackageActionV1, PackageAuthorization,
    PackageErrorCodeV1 as Code, PackageGrantV1, PackageResponseV1,
};
use araphor_query::execution::{Engine, LocalOutput};

use super::Instance;
use crate::Result;

struct Inspection(Arc<AnalysisReadControl>);

impl Drop for Inspection {
    fn drop(&mut self) {
        let _cancelled = self.0.cancel();
    }
}

impl Instance {
    pub async fn read_status(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        instance: &str,
        control: &AnalysisReadControl,
    ) -> Result<ManagedStatus> {
        Self::inspect(authority.as_ref(), &grant, control, |read| {
            let store = Arc::clone(query.store());
            let selection = grant.selection.clone();
            let instance = instance.to_owned();
            let control = Arc::clone(&read);
            async move {
                Ok(Engine::blocking(read, (), move || {
                    Ok(store.managed_status(&selection, &instance, &control)?)
                })
                .await?)
            }
        })
        .await
    }

    pub async fn read_history(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        instance: &str,
        control: &AnalysisReadControl,
    ) -> Result<Vec<ManagedReceipt>> {
        Self::inspect(authority.as_ref(), &grant, control, |read| {
            let store = Arc::clone(query.store());
            let selection = grant.selection.clone();
            let instance = instance.to_owned();
            let control = Arc::clone(&read);
            async move {
                Ok(Engine::blocking(read, (), move || {
                    Ok(store.managed_history(&selection, &instance, &control)?)
                })
                .await?)
            }
        })
        .await
    }

    pub async fn read_result(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        instance: &str,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<ManagedResult> {
        let (query, grant) = (&query, &grant);
        Self::inspect(authority.as_ref(), grant, control, |read| async move {
            Self::retained(
                query,
                grant,
                instance,
                id,
                Self::read_time()?,
                read,
                AnalysisStore::managed_result,
            )
            .await
        })
        .await
    }

    pub async fn read_output(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        instance: &str,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<PackageResponseV1> {
        let (query, grant) = (&query, &grant);
        Self::inspect(authority.as_ref(), grant, control, |read| async move {
            let retained = Self::retained(
                query,
                grant,
                instance,
                id,
                Self::read_time()?,
                read,
                AnalysisStore::managed_output,
            )
            .await?;
            Ok(match retained {
                ManagedOutput::Call { result, .. } => PackageResponseV1::Result(result),
                ManagedOutput::Selected { packet, .. } => PackageResponseV1::Output(packet),
            })
        })
        .await
    }

    pub async fn query_result(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        instance: &str,
        id: Option<&str>,
        sql: &str,
        control: &AnalysisReadControl,
    ) -> Result<LocalOutput> {
        let (query, grant) = (&query, &grant);
        Self::inspect(authority.as_ref(), grant, control, |read| async move {
            let now = Self::read_time()?;
            let store = Arc::clone(query.store());
            let selection = grant.selection.clone();
            let instance = instance.to_owned();
            let id = id.map(str::to_owned);
            let stage = Arc::clone(&read);
            let retained =
                Engine::blocking(Arc::clone(&read), (), move || {
                    Ok(store.managed_query_output(
                        &selection,
                        &instance,
                        id.as_deref(),
                        now,
                        &stage,
                    )?)
                })
                .await?;
            let datasets = match retained {
                ManagedOutput::Call { data, .. } => data.datasets,
                ManagedOutput::Selected { data, .. } => vec![data],
            };
            let session = query.session(grant.selection.clone(), &read, now)?;
            Ok(session.query_local(&datasets, sql).await?)
        })
        .await
    }

    async fn retained<T: Send + 'static>(
        query: &Arc<Engine>,
        grant: &PackageGrantV1,
        instance: &str,
        id: &str,
        now: u64,
        control: Arc<AnalysisReadControl>,
        output: fn(
            &AnalysisStore,
            &ManagedInstance,
            &str,
            u64,
            &AnalysisReadControl,
        ) -> araphor_data::Result<T>,
    ) -> Result<T> {
        let store = Arc::clone(query.store());
        let grant = grant.clone();
        let instance = instance.to_owned();
        let id = id.to_owned();
        let read = Arc::clone(&control);
        Ok(Engine::blocking(control, (), move || {
            let mut stored = store
                .managed_instance(grant.selection.tenant_id, &instance, &read)?
                .ok_or_else(|| Code::Missing.error("managed instance"))?;
            stored.grant = grant;
            Ok(output(&store, &stored, &id, now, &read)?)
        })
        .await?)
    }

    pub(crate) async fn inspect<T, F: Future<Output = Result<T>>>(
        authority: &dyn PackageAuthorization,
        grant: &PackageGrantV1,
        control: &AnalysisReadControl,
        execute: impl FnOnce(Arc<AnalysisReadControl>) -> F,
    ) -> Result<T> {
        let mut changes = authority.changes_for(grant);
        grant.remaining()?;
        authority.check(grant, PackageActionV1::Inspect)?;
        let operation = Inspection(Arc::new(control.operation()?.within(grant.remaining()?)?));
        let execution = execute(Arc::clone(&operation.0));
        tokio::pin!(execution);
        let result = loop {
            tokio::select! {
                biased;
                stopped = control.query_async(std::future::pending::<Result<T>>()) => {
                    let _cancelled = operation.0.cancel();
                    let _finished = execution.await;
                    break stopped;
                }
                changed = changes.changed() => {
                    let checked = changed
                        .map_err(|_| Code::Denied.error("retained authority watch"))
                        .and_then(|()| grant.remaining().map(|_| ()))
                        .and_then(|()| authority.check(grant, PackageActionV1::Inspect));
                    if let Err(error) = checked {
                        let _cancelled = operation.0.cancel();
                        let _finished = execution.await;
                        break Err(error.into());
                    }
                }
                result = &mut execution => break result,
            }
        };
        control.check()?;
        grant.remaining()?;
        authority.check(grant, PackageActionV1::Inspect)?;
        result
    }

    fn read_time() -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_nanos()).ok())
            .ok_or_else(|| Code::Incomplete.error("system time").into())
    }
}
