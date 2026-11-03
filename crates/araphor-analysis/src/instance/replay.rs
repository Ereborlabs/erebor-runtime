use araphor_analysis_sdk as sdk;
use araphor_query::definition::DefinitionOutput;
use futures_util::{future::BoxFuture, FutureExt as _};
use snafu::ResultExt as _;

use super::*;

type Replayed = (
    DefinitionOutput,
    PreparedDefinition,
    Option<u64>,
    MemoryReservation,
);

impl Instance {
    pub async fn replay_response(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        facts: Option<Arc<dyn crate::GraphFacts>>,
        grant: PackageGrantV1,
        instance: &str,
        result: &str,
        control: &AnalysisReadControl,
    ) -> Result<araphor_data::PackageResponseV1> {
        let (output, prepared, call, _metadata) = Self::replay_retained(
            &query,
            Arc::clone(&authority),
            facts,
            &grant,
            instance,
            result,
            control,
        )
        .await?;
        let response = match call {
            Some(call) => {
                let returned = output
                    .calls
                    .get(&call)
                    .ok_or_else(|| Code::Missing.error("replayed package call"))?;
                let (manifest, _) = Self::manifest(&prepared)?;
                let package = &manifest
                    .calls
                    .get(&call)
                    .ok_or_else(|| Code::Missing.error("replayed package declaration"))?
                    .package;
                let descriptor = prepared
                    .images()
                    .flat_map(|bundle| &bundle.bundle().artifacts)
                    .map(|artifact| &artifact.descriptor)
                    .find(|descriptor| {
                        descriptor.id == package.package_id
                            && descriptor.revision == package.revision
                    })
                    .ok_or_else(|| Code::Missing.error("replayed package descriptor"))?;
                araphor_data::PackageResponseV1::Replayed(
                    sdk::wire::Output::encode(descriptor, returned.evaluation(), returned.output())
                        .context(araphor_data::AnalysisContractSnafu)?,
                )
            }
            None => araphor_data::PackageResponseV1::Output(
                sdk::wire::Dataset::encode(
                    &sdk::Dataset {
                        name: "selected".into(),
                        batches: output.batches,
                    },
                    prepared.plan().schema().as_arrow(),
                )
                .context(araphor_data::AnalysisContractSnafu)?,
            ),
        };
        Self::authorize_actions(
            authority.as_ref(),
            &grant,
            &prepared,
            &[PackageActionV1::Run, PackageActionV1::Inspect],
            || {
                control.check()?;
                Ok(response)
            },
        )
        .map_err(Into::into)
    }

    pub async fn replay(
        self: &Arc<Self>,
        result: &str,
        control: &AnalysisReadControl,
    ) -> Result<DefinitionOutput> {
        self.check()?;
        let (output, prepared, _call, _metadata) = Self::inspect(
            self.authority.as_ref(),
            &self.admitted.grant,
            control,
            |operation| async move {
                Self::replay_bound(
                    &self.query,
                    Arc::clone(&self.authority),
                    None,
                    &self.admitted.grant,
                    &self.admitted.spec.id,
                    result,
                    Some(self),
                    operation,
                )
                .await
            },
        )
        .await?;
        Self::authorize_actions(
            self.authority.as_ref(),
            &self.admitted.grant,
            &prepared,
            &[PackageActionV1::Run, PackageActionV1::Inspect],
            || {
                control.check()?;
                Ok(output)
            },
        )
        .map_err(Into::into)
    }

    pub async fn replay_result(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        facts: Option<Arc<dyn crate::GraphFacts>>,
        grant: PackageGrantV1,
        instance: &str,
        result: &str,
        control: &AnalysisReadControl,
    ) -> Result<DefinitionOutput> {
        let (output, prepared, _call, _metadata) = Self::replay_retained(
            &query,
            Arc::clone(&authority),
            facts,
            &grant,
            instance,
            result,
            control,
        )
        .await?;
        Self::authorize_actions(
            authority.as_ref(),
            &grant,
            &prepared,
            &[PackageActionV1::Run, PackageActionV1::Inspect],
            || {
                control.check()?;
                Ok(output)
            },
        )
        .map_err(Into::into)
    }

    pub(crate) async fn replay_retained(
        query: &Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        facts: Option<Arc<dyn crate::GraphFacts>>,
        grant: &PackageGrantV1,
        instance: &str,
        result: &str,
        control: &AnalysisReadControl,
    ) -> Result<Replayed> {
        Self::inspect(authority.as_ref(), grant, control, |read| {
            Self::replay_bound(
                query,
                Arc::clone(&authority),
                facts,
                grant,
                instance,
                result,
                None,
                read,
            )
        })
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Replay binds the historical source, provider, definition, and current authority."
    )]
    fn replay_bound<'a>(
        query: &'a Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        facts: Option<Arc<dyn crate::GraphFacts>>,
        grant: &'a PackageGrantV1,
        instance: &'a str,
        result: &'a str,
        expected: Option<&'a Instance>,
        control: Arc<AnalysisReadControl>,
    ) -> BoxFuture<'a, Result<Replayed>> {
        async move {
            authority.check(grant, PackageActionV1::Run)?;
            let store = Arc::clone(query.store());
            let instance = instance.to_owned();
            let id = result.to_owned();
            let pinned = expected.map(|owner| owner.admitted.clone());
            let selected = grant.clone();
            let stage = Arc::clone(&control);
            let memory = query.memory().scope();
            let now = Self::read_time()?;
            let (reference, call, metadata) =
                Engine::blocking(Arc::clone(&control), (), move || {
                    let mut current = store
                        .managed_instance(selected.selection.tenant_id, &instance, &stage)?
                        .ok_or_else(|| Code::Missing.error("managed replay instance"))?;
                    if pinned.as_ref().is_some_and(|pinned| {
                        current.spec != pinned.spec
                            || current.grant != pinned.grant
                            || current.generation != pinned.generation
                            || current.lifecycle != pinned.lifecycle
                    }) {
                        return Err(Code::Conflict.error("managed replay lifecycle").into());
                    }
                    current.grant = selected;
                    let (reference, call, _) =
                        store.managed_reference(&current, &id, now, &stage)?;
                    let bytes = reference
                        .allocation_bytes()
                        .ok_or_else(|| Code::Limit.error("managed replay metadata"))?;
                    let metadata = memory
                        .reserve_input(bytes)
                        .map_err(|source| araphor_query::Error::Sql { source })?;
                    Ok((reference, call, metadata))
                })
                .await?;
            let spec = &reference.instance().spec;
            if spec.destination == araphor_data::ManagedDestination::Notification {
                return Err(Code::Unsupported
                    .error("notification managed replay")
                    .into());
            }
            let (session, prepared, graph) = match expected
                .filter(|owner| owner.admitted.spec == *spec)
            {
                Some(owner) => (
                    owner.session.operation(&control, 0)?,
                    owner.prepared.clone(),
                    owner.graph.clone(),
                ),
                None => {
                    if matches!(
                        &spec.destination,
                        araphor_data::ManagedDestination::Graph { .. }
                    ) {
                        let facts = facts.or_else(|| {
                            expected
                                .and_then(|owner| owner.graph.as_ref().map(|graph| graph.facts()))
                        });
                        let (session, prepared, destination, graph) =
                            crate::GraphPublication::prepare_managed(
                                Arc::clone(query),
                                Arc::clone(&authority),
                                facts,
                                grant,
                                (spec.definition.clone(), Some(spec.manifest.definition)),
                                spec.destination.clone(),
                                &control,
                            )
                            .await?;
                        if destination != spec.destination {
                            return Err(Code::Conflict
                                .error("managed historical destination pin")
                                .into());
                        }
                        (session, prepared, graph)
                    } else {
                        let session = query.session(
                            spec.destination.selection(&grant.selection)?,
                            &control,
                            0,
                        )?;
                        let prepared = session
                            .prepare_resolved(
                                &spec.definition,
                                Some(spec.manifest.definition),
                                None,
                            )
                            .await?;
                        (session, prepared, None)
                    }
                }
            };
            let (manifest, _) = Self::manifest(&prepared)?;
            if prepared.resolved() != &spec.definition || manifest != spec.manifest {
                return Err(Code::Conflict
                    .error("managed historical definition pin")
                    .into());
            }
            let replay = &prepared;
            let output = Self::authorized_on(
                authority,
                grant,
                &prepared,
                &control,
                |operation| async move {
                    let session = session.operation(&operation, reference.request().time_utc_ns)?;
                    Ok(session.replay_reference(replay, &reference, call).await?)
                },
            )
            .await?;
            drop(graph);
            Ok((output, prepared, call, metadata))
        }
        .boxed()
    }
}
