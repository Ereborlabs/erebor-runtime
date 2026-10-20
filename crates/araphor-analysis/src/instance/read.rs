use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use araphor_data::{
    AnalysisReadControl, ManagedResult, PackageActionV1, PackageAuthorization,
    PackageErrorCodeV1 as Code, PackageGrantV1,
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
            Self::retained(query, grant, instance, id, Self::read_time()?, read).await
        })
        .await
    }

    pub async fn query_result(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        instance: &str,
        id: &str,
        sql: &str,
        control: &AnalysisReadControl,
    ) -> Result<LocalOutput> {
        let (query, grant) = (&query, &grant);
        Self::inspect(authority.as_ref(), grant, control, |read| async move {
            let now = Self::read_time()?;
            let retained =
                Self::retained(query, grant, instance, id, now, Arc::clone(&read)).await?;
            let session = query.session(grant.selection.clone(), &read, now)?;
            Ok(session
                .query_local(&retained.output.datasets, sql, retained.limits)
                .await?)
        })
        .await
    }

    async fn retained(
        query: &Arc<Engine>,
        grant: &PackageGrantV1,
        instance: &str,
        id: &str,
        now: u64,
        control: Arc<AnalysisReadControl>,
    ) -> Result<ManagedResult> {
        let store = Arc::clone(query.store());
        let grant = grant.clone();
        let instance = instance.to_owned();
        let id = id.to_owned();
        let read = Arc::clone(&control);
        Ok(Engine::blocking(control, (), move || {
            let stored = store
                .managed_instance(grant.selection.tenant_id, &instance, &read)?
                .ok_or_else(|| Code::Missing.error("managed instance"))?;
            stored.spec.grant.permitted_by(&grant.selection)?;
            Ok(store.managed_result(&stored, &id, now, &read)?)
        })
        .await?)
    }

    async fn inspect<T, F: Future<Output = Result<T>>>(
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
