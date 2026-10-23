use std::sync::Arc;

use araphor_data::{
    AnalysisReadControl, ManagedInstance, PackageActionV1, PackageErrorCodeV1 as Code,
    PackageGrantV1,
};
use araphor_query::execution::Engine;

use super::{Instance, InstanceHost};
use crate::Result;

impl InstanceHost {
    pub async fn recreate(
        self: &Arc<Self>,
        grant: PackageGrantV1,
        id: String,
        expected: u64,
        definition: araphor_discovery_definition::ResolvedDefinition,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        let store = Arc::clone(self.query.store());
        let read = Arc::new(control.within(grant.remaining()?)?);
        let stage = Arc::clone(&read);
        let selected = grant.clone();
        let identity = id.clone();
        let current = Engine::blocking(Arc::clone(&read), (), move || {
            let current = store
                .managed_instance(selected.selection.tenant_id, &identity, &stage)?
                .ok_or_else(|| Code::Missing.error("managed recreation instance"))?;
            if !current.removed || current.lifecycle != expected {
                return Err(Code::Conflict.error("managed recreation lifecycle").into());
            }
            Ok(current)
        })
        .await?;
        Instance::admit_on(
            Arc::clone(&self.query),
            Arc::clone(&self.authority),
            grant,
            id,
            definition,
            &read,
            Some(current),
        )
        .await
    }

    pub async fn remove(
        self: &Arc<Self>,
        grant: PackageGrantV1,
        id: String,
        expected: u64,
        control: &AnalysisReadControl,
    ) -> Result<ManagedInstance> {
        self.run_lifecycle(grant.clone(), control, move |host, operation| async move {
            host.authority.check(&grant, PackageActionV1::Remove)?;
            let store = Arc::clone(host.query.store());
            let read = Arc::clone(&operation);
            let selected = grant.clone();
            let current = Engine::blocking(Arc::clone(&operation), (), move || {
                let current = store
                    .managed_instance(selected.selection.tenant_id, &id, &read)?
                    .ok_or_else(|| Code::Missing.error("managed removal instance"))?;
                current.grant.permitted_by(&selected.selection)?;
                if current.lifecycle != expected {
                    return Err(Code::Conflict.error("managed removal lifecycle").into());
                }
                Ok(current)
            })
            .await?;
            let pause = host
                .pause_and_join(&current, Arc::clone(&operation))
                .await?;
            let read = Arc::clone(&operation);
            let store = Arc::clone(host.query.store());
            let check = Arc::clone(&host.authority);
            let selected = grant.clone();
            let (removed, pause) = Engine::blocking(Arc::clone(&operation), (), move || {
                let mut removed = None;
                check.commit_many(&[(&selected, PackageActionV1::Remove, None)], &mut || {
                    selected.remaining()?;
                    let joined = store
                        .managed_instance(current.spec.tenant, &current.spec.id, &read)?
                        .filter(|joined| {
                            joined.spec == current.spec
                                && joined.grant == current.grant
                                && joined.generation == current.generation
                                && joined.lifecycle == current.lifecycle
                                && joined.running == current.running
                                && joined.removed == current.removed
                        })
                        .ok_or_else(|| Code::Conflict.error("managed removal join fence"))?;
                    removed = Some(store.remove_managed(&joined, || read.check())?);
                    Ok(())
                })?;
                let removed =
                    removed.ok_or_else(|| Code::Denied.error("managed removal authority"))?;
                Ok((removed, pause))
            })
            .await?;
            pause.release(None).await;
            host.authority.check(&grant, PackageActionV1::Remove)?;
            operation.check()?;
            Ok(removed)
        })
        .await
    }
}
