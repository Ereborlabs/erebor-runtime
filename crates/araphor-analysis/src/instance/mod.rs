use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use araphor_data::{
    AnalysisReadControl, ManagedInstance, ManagedRead, ManagedReceipt, ManagedRequest, ManagedSpec,
    PackageActionV1, PackageAuthorization, PackageBundleRef, PackageBundleV1,
    PackageErrorCodeV1 as Code, PackageGrantV1,
};
use araphor_discovery_definition::ResolvedDefinition;
use araphor_query::definition::{Invocation, PackageCall, PreparedDefinition};
use araphor_query::execution::Engine;
use datafusion::datasource::provider_as_source;
use datafusion::logical_expr::{dml::InsertOp, LogicalPlanBuilder};

use crate::Result;

mod manifest;
mod read;
mod sink;
mod subscription;

pub use subscription::Subscription;

#[cfg(test)]
mod tests;

pub struct Instance {
    query: Arc<Engine>,
    authority: Arc<dyn PackageAuthorization>,
    admitted: ManagedInstance,
    prepared: PreparedDefinition,
    calls: BTreeMap<u64, PackageCall>,
    images: Arc<[(PackageBundleV1, String)]>,
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
        control.check()?;
        grant.remaining()?;
        authority.check(&grant, PackageActionV1::Run)?;
        definition.validate().map_err(araphor_data::Error::from)?;
        let read = Arc::new(control.within(grant.remaining()?)?);
        let store = Arc::clone(query.store());
        let pins = definition.images.clone();
        let tenant = grant.selection.tenant_id;
        let stage = Arc::clone(&read);
        let images: Arc<[(PackageBundleV1, String)]> =
            Engine::blocking(Arc::clone(&read), (), move || {
                pins.into_iter()
                    .map(|pin| {
                        let bundle = store
                            .package_image(
                                tenant,
                                &pin.image.package_id,
                                Some(&pin.image.revision),
                                &stage,
                            )?
                            .ok_or_else(|| Code::Missing.error("managed image"))?;
                        if bundle.digest().map_err(araphor_data::Error::from)? != pin.digest {
                            return Err(Code::Conflict.error("managed image pin").into());
                        }
                        Ok((bundle, pin.digest))
                    })
                    .collect::<araphor_query::Result<Vec<_>>>()
                    .map(Into::into)
            })
            .await?;
        for (bundle, digest) in images.iter() {
            authority.admit(&grant, &PackageBundleRef::retained(bundle, digest))?;
        }
        let prepared = query
            .prepare_definition(
                grant.selection.tenant_id,
                &definition.definition,
                Arc::new(control.within(grant.remaining()?)?),
            )
            .await?;
        if prepared.resolved != definition {
            return Err(Code::Conflict.error("managed definition pin").into());
        }
        let store = Arc::clone(query.store());
        let check = Arc::clone(&authority);
        let checked = Arc::clone(&images);
        let stage = Arc::clone(&read);
        let (admitted, prepared, calls) = Engine::blocking(read, (), move || {
            let (manifest, calls) = Self::manifest(&prepared, &checked)?;
            let spec = ManagedSpec {
                tenant: grant.selection.tenant_id,
                id,
                grant,
                definition,
                manifest,
            };
            let admitted = Self::authorize(check.as_ref(), &spec.grant, &checked, || {
                store.admit_managed(&spec, || stage.check())
            })
            .map_err(araphor_query::Error::from)?;
            Ok((admitted, prepared, calls))
        })
        .await?;
        Ok(Arc::new(Self {
            query,
            authority,
            admitted,
            prepared,
            calls,
            images,
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
        if request.frontier.is_some() {
            return Err(Code::Invalid.error("finite managed frontier").into());
        }
        let grant = &self.admitted.spec.grant;
        let mut changes = self.authority.changes_for(grant);
        self.check()?;
        let operation = control.operation()?.within(grant.remaining()?)?;
        let execution = self.execute(request, &operation);
        tokio::pin!(execution);
        let result = tokio::select! {
            result = &mut execution => result,
            _ = changes.changed() => {
                operation.cancel()?;
                match execution.await {
                    Ok(receipt) => Ok(receipt),
                    Err(_) => Err(Code::Denied.error("managed authority change").into()),
                }
            }
            stopped = control.query_async(std::future::pending::<Result<ManagedReceipt>>()) => {
                operation.cancel()?;
                match execution.await {
                    Ok(receipt) => Ok(receipt),
                    Err(_) => stopped,
                }
            }
        };
        if result.is_err() && grant.remaining().is_err() {
            return Err(Code::Denied.error("managed grant expiry").into());
        }
        let receipt = result?;
        Self::authorize(self.authority.as_ref(), grant, &self.images, || {
            control.check()?;
            Ok(receipt)
        })
        .map_err(Into::into)
    }

    async fn execute(
        self: &Arc<Self>,
        request: ManagedRequest,
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
                    current.spec == *spec && current.generation == owner.admitted.generation
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
        if let Some(previous) = previous {
            if previous.request() != &request || previous.instance().spec != *spec {
                return Err(Code::Conflict.error("managed attempt identity").into());
            }
            return previous
                .receipt()
                .cloned()
                .ok_or_else(|| Code::Incomplete.error("managed pending attempt").into());
        }
        self.check()?;
        let state = Arc::new(Mutex::new(sink::Step::default()));
        let schema = Arc::clone(self.prepared.plan.schema().inner());
        let target = Arc::new(sink::Publication {
            owner: Arc::clone(self),
            schema,
            state: Arc::clone(&state),
            witness_expiry: request.witness_expiry,
            lifecycle: None,
        });
        let mut definition = self.prepared.clone();
        definition.plan = LogicalPlanBuilder::insert_into(
            definition.plan,
            "__araphor_managed_output",
            provider_as_source(target),
            InsertOp::Append,
        )
        .and_then(LogicalPlanBuilder::build)
        .map_err(|source| araphor_query::Error::Sql { source })?;
        let session =
            self.query
                .session(spec.grant.selection.clone(), control, request.time_utc_ns)?;
        let captured = session
            .capture_managed(
                &definition,
                Invocation {
                    id: request.id.clone(),
                    seed: request.seed,
                    ..Default::default()
                },
                ManagedRead {
                    instance: current,
                    rebuild: request.rebuild,
                },
            )
            .await?;
        let owner = Arc::clone(self);
        let registration = request.clone();
        let registered = captured
            .blocking(move |snapshot, control| {
                let captured = snapshot
                    .managed()
                    .ok_or_else(|| Code::Incomplete.error("managed captured state"))?;
                Self::authorize(
                    owner.authority.as_ref(),
                    &owner.admitted.spec.grant,
                    &owner.images,
                    || {
                        owner.query.store().register_managed_attempt(
                            captured,
                            &registration,
                            || control.check(),
                        )
                    },
                )
                .map_err(araphor_query::Error::from)
            })
            .await;
        let attempt = match registered {
            Ok(attempt) => attempt,
            Err(error) => {
                captured.cancel_and_join().await?;
                return Err(error.into());
            }
        };
        if let Some(receipt) = attempt.receipt() {
            let receipt = receipt.clone();
            captured.cancel_and_join().await?;
            return Ok(receipt);
        }
        state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .attempt = Some(attempt);
        let result = captured.execute().await;
        let receipt = state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .receipt
            .take();
        if let Some(receipt) = receipt {
            return Ok(receipt);
        }
        result?;
        Err(Code::Incomplete.error("managed publication receipt").into())
    }

    fn check(&self) -> araphor_data::Result<()> {
        let grant = &self.admitted.spec.grant;
        grant.remaining()?;
        self.authority.check(grant, PackageActionV1::Run)?;
        for (bundle, digest) in self.images.iter() {
            self.authority
                .admit(grant, &PackageBundleRef::retained(bundle, digest))?;
        }
        Ok(())
    }

    fn authorize<T>(
        authority: &dyn PackageAuthorization,
        grant: &PackageGrantV1,
        images: &[(PackageBundleV1, String)],
        operation: impl FnOnce() -> araphor_data::Result<T>,
    ) -> araphor_data::Result<T> {
        grant.remaining()?;
        let bundles = images
            .iter()
            .map(|(bundle, digest)| PackageBundleRef::retained(bundle, digest))
            .collect::<Vec<_>>();
        let mut grants = Vec::with_capacity(bundles.len() + 1);
        grants.push((grant, None));
        grants.extend(bundles.iter().map(|bundle| (grant, Some(bundle))));
        let mut operation = Some(operation);
        let mut result = None;
        authority.commit_many(&grants, PackageActionV1::Run, &mut || {
            grant.remaining()?;
            result = Some(operation
                .take()
                .ok_or_else(|| Code::Invalid.error("managed authority callback"))?(
            )?);
            Ok(())
        })?;
        result.ok_or_else(|| Code::Denied.error("managed publication authority"))
    }
}
