use araphor_query::definition::DefinitionOutput;

use super::*;

impl Instance {
    pub async fn replay(
        self: &Arc<Self>,
        result: &str,
        control: &AnalysisReadControl,
    ) -> Result<DefinitionOutput> {
        self.check()?;
        let (output, prepared, _saved) = Self::inspect(
            self.authority.as_ref(),
            &self.admitted.grant,
            control,
            |operation| async move {
                Self::replay_saved(
                    &self.query,
                    Arc::clone(&self.authority),
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
        grant: PackageGrantV1,
        instance: &str,
        result: &str,
        control: &AnalysisReadControl,
    ) -> Result<DefinitionOutput> {
        let (output, prepared, _saved) = Self::replay_retained(
            &query,
            Arc::clone(&authority),
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

    // The caller keeps this admission for the final combined permission check.
    pub(crate) async fn replay_retained(
        query: &Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: &PackageGrantV1,
        instance: &str,
        result: &str,
        control: &AnalysisReadControl,
    ) -> Result<(DefinitionOutput, PreparedDefinition, MemoryReservation)> {
        Self::inspect(authority.as_ref(), grant, control, |read| {
            Self::replay_saved(
                query,
                Arc::clone(&authority),
                grant,
                instance,
                result,
                None,
                read,
            )
        })
        .await
    }

    async fn replay_saved(
        query: &Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: &PackageGrantV1,
        instance: &str,
        result: &str,
        expected: Option<&Instance>,
        control: Arc<AnalysisReadControl>,
    ) -> Result<(DefinitionOutput, PreparedDefinition, MemoryReservation)> {
        authority.check(grant, PackageActionV1::Run)?;
        let store = Arc::clone(query.store());
        let instance = instance.to_owned();
        let id = result.to_owned();
        let pinned = expected.map(|owner| owner.admitted.clone());
        let selected = grant.clone();
        let stage = Arc::clone(&control);
        let memory = query.memory().scope();
        let retained = Arc::clone(&memory);
        let (current, call, spec, saved) = Engine::blocking(Arc::clone(&control), (), move || {
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
            let (call, generation, bound) =
                store.managed_evaluation_bytes(&current, &id, &stage)?;
            let spec =
                store.managed_version(current.spec.tenant, &current.spec.id, generation, &stage)?;
            let bytes = bound
                .checked_add(
                    spec.allocation_bytes()
                        .ok_or_else(|| Code::Limit.error("managed replay metadata"))?,
                )
                .ok_or_else(|| Code::Limit.error("managed replay metadata"))?;
            let saved = retained
                .reserve_input(bytes)
                .map_err(|source| araphor_query::Error::Sql { source })?;
            Ok((current, call, spec, saved))
        })
        .await?;
        if spec.destination == araphor_data::ManagedDestination::Notification {
            return Err(Code::Unsupported
                .error("notification managed replay")
                .into());
        }
        let mut session = match expected {
            Some(owner) => owner.session.operation(&control, 0)?,
            None => query.session(spec.destination.selection(&grant.selection)?, &control, 0)?,
        };
        if expected.is_none()
            && matches!(
                &spec.destination,
                araphor_data::ManagedDestination::Graph {
                    operation: araphor_data::ManagedGraphOperation::Evaluate,
                    ..
                }
            )
        {
            crate::GraphPublication::replay_tables(&mut session)?;
        }
        let prepared = match expected.filter(|owner| owner.admitted.spec == spec) {
            Some(owner) => owner.prepared.clone(),
            None => {
                let prepared = session.prepare_resolved(&spec.definition).await?;
                let (manifest, _) = Self::manifest(&prepared)?;
                if prepared.resolved() != &spec.definition || manifest != spec.manifest {
                    return Err(Code::Conflict
                        .error("managed historical definition pin")
                        .into());
                }
                prepared
            }
        };
        drop(spec);
        let replay = &prepared;
        let (output, saved) = Self::authorized_on(
            authority,
            grant,
            &prepared,
            &control,
            |operation| async move {
                let store = Arc::clone(query.store());
                let id = result.to_owned();
                let stage = Arc::clone(&operation);
                let retained = Arc::clone(&memory);
                let evaluation = Engine::blocking(Arc::clone(&operation), (), move || {
                    let evaluation = store.managed_evaluation(&current, &id, &stage)?;
                    saved
                        .try_resize(evaluation.allocated_bytes())
                        .map_err(|source| araphor_query::Error::Sql { source })?;
                    for batch in evaluation
                        .inputs
                        .iter()
                        .flat_map(|input| &input.data.batches)
                        .chain(evaluation.parameters.iter())
                        .chain(evaluation.checkpoint.iter().flat_map(|checkpoint| {
                            checkpoint.datasets.iter().flat_map(|data| &data.batches)
                        }))
                    {
                        stage.check()?;
                        retained
                            .retain_input(batch, &saved)
                            .map_err(|source| araphor_query::Error::Sql { source })?;
                    }
                    Ok((evaluation, saved))
                })
                .await?;
                let (evaluation, saved) = evaluation;
                let time = u64::try_from(evaluation.context.time_utc_ns)
                    .map_err(|_| Code::Invalid.error("managed replay time"))?;
                let session = session.operation(&operation, time)?;
                let output = session.replay_call(replay, call, evaluation).await?;
                Ok((output, saved))
            },
        )
        .await?;
        Ok((output, prepared, saved))
    }
}
