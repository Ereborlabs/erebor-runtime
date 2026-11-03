use super::*;

impl PackageExec {
    pub(super) async fn change_inputs(
        &self,
        evaluation: &mut sdk::Evaluation,
        prior: Option<&araphor_data::ManagedPrior>,
        owner: &CallContext,
        context: &Arc<TaskContext>,
        memory: &MemoryReservation,
    ) -> Result<Option<araphor_data::ManagedChanges>> {
        let Some(call) = &self.call.changes else {
            return Ok(None);
        };
        let model = self
            .call
            .model()
            .ok_or_else(|| internal("change model is absent"))?;
        let contract = model
            .change_inputs
            .as_ref()
            .ok_or_else(|| internal("change contract is absent"))?;
        let source = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| internal("change source is absent"))?;
        let view = source.source_view()?;
        if source.snapshot()?.managed().is_some() && view.is_none() {
            return Err(DataFusionError::Execution(
                "the managed change view is absent".into(),
            ));
        }
        let bind = |slot: usize, input: &sdk::Input| -> Result<()> {
            for (id, bound) in &call.lookups.bindings {
                if *bound == slot {
                    source.bind_port(
                        *id,
                        Arc::new(model.inputs[slot].port.schema.clone()),
                        input.data.batches.clone(),
                        Some(input),
                    )?;
                }
            }
            Ok(())
        };
        let mut inputs = (0..model.inputs.len()).map(|_| None).collect::<Vec<_>>();
        for &slot in &call.lookups.order {
            let port = &model.inputs[slot];
            if contract.generated(&port.port.name)
                || call.ports.iter().any(|pair| pair.after == slot)
                || matches!(&port.source, sdk::InputSource::Lookup(_))
            {
                continue;
            }
            let input = self
                .read_input((slot, slot), port, owner, context, memory, &source)
                .await?;
            bind(slot, &input)?;
            inputs[slot] = Some(input);
        }
        let retained = match (prior, view.as_ref()) {
            (Some(prior), Some(view)) => view.has_call(self.call.id, prior)?,
            _ => false,
        };
        let compatible = retained
            && prior.is_some_and(|prior| {
                prior
                    .parameters
                    .as_ref()
                    .map(|data| data.batches.as_slice())
                    == evaluation.parameters.as_ref().map(std::slice::from_ref)
                    && inputs.iter().enumerate().all(|(slot, input)| {
                        input.as_ref().is_none_or(|input| {
                            prior.context.inputs.get(slot) == Some(&input.revision)
                                && prior.context.input_coverage.get(slot) == Some(&input.coverage)
                        })
                    })
            })
            && source
                .snapshot()?
                .managed()
                .is_none_or(|managed| !managed.rebuild())
            && (model.checkpoint.is_none() || evaluation.checkpoint.is_some());
        let reset = !compatible;
        if reset {
            evaluation.checkpoint = None;
            evaluation.previous_outputs.clear();
        }
        for &slot in &call.lookups.order {
            if inputs[slot].is_some() {
                continue;
            }
            if let Some(pair) = call
                .ports
                .iter()
                .find(|pair| pair.before == slot || pair.after == slot || pair.affected == slot)
            {
                if reset {
                    let after = self
                        .read_input(
                            (pair.after, pair.reset),
                            &model.inputs[pair.after],
                            owner,
                            context,
                            memory,
                            &source,
                        )
                        .await?;
                    bind(pair.after, &after)?;
                    let mut before = after.clone();
                    before
                        .data
                        .name
                        .clone_from(&model.inputs[pair.before].port.name);
                    before.data.batches = vec![sdk::RecordBatch::new_empty(Arc::new(
                        model.inputs[pair.before].port.schema.clone(),
                    ))];
                    bind(pair.before, &before)?;
                    let keys = self
                        .collect(
                            pair.reset_keys,
                            &model.inputs[pair.affected].port.schema,
                            owner,
                            context,
                            memory,
                            true,
                        )
                        .await?;
                    let mut affected = after.clone();
                    affected
                        .data
                        .name
                        .clone_from(&model.inputs[pair.affected].port.name);
                    affected.data.batches = keys;
                    bind(pair.affected, &affected)?;
                    inputs[pair.before] = Some(before);
                    inputs[pair.after] = Some(after);
                    inputs[pair.affected] = Some(affected);
                    continue;
                }
                if pair.before == slot || (pair.after == slot && pair.difference.is_some()) {
                    let prior = prior.ok_or_else(|| internal("change base is absent"))?;
                    let session = context
                        .session_config()
                        .get_extension::<crate::execution::Session>()
                        .ok_or_else(|| internal("change replay session is absent"))?;
                    let mut before = session
                        .replay_before(&self.call, pair.before, prior, context)
                        .await
                        .map_err(external)?;
                    if let Some(difference) = &pair.difference {
                        let mut after = self
                            .read_input(
                                (pair.after, pair.after),
                                &model.inputs[pair.after],
                                owner,
                                context,
                                memory,
                                &source,
                            )
                            .await?;
                        let schema = Arc::new(model.inputs[pair.after].port.schema.clone());
                        source.bind_port(
                            difference.base,
                            Arc::clone(&schema),
                            before.data.batches.clone(),
                            None,
                        )?;
                        source.bind_port(
                            difference.target,
                            schema,
                            after.data.batches.clone(),
                            None,
                        )?;
                        before.data.batches = self
                            .collect(
                                difference.removed,
                                &model.inputs[pair.before].port.schema,
                                owner,
                                context,
                                memory,
                                true,
                            )
                            .await?;
                        after.data.batches = self
                            .collect(
                                difference.inserted,
                                &model.inputs[pair.after].port.schema,
                                owner,
                                context,
                                memory,
                                true,
                            )
                            .await?;
                        bind(pair.after, &after)?;
                        inputs[pair.after] = Some(after);
                    }
                    bind(pair.before, &before)?;
                    inputs[pair.before] = Some(before);
                    continue;
                }
            }
            let port = &model.inputs[slot];
            let mut input = self
                .read_input((slot, slot), port, owner, context, memory, &source)
                .await?;
            if port.port.name == contract.reset {
                input.data = contract.reset_input(reset).map_err(external)?;
            }
            bind(slot, &input)?;
            inputs[slot] = Some(input);
        }
        evaluation.inputs = inputs
            .into_iter()
            .map(|input| input.ok_or_else(|| internal("the change input was not executed")))
            .collect::<Result<_>>()?;
        Ok(Some(araphor_data::ManagedChanges {
            base: prior.filter(|_| !reset).map(|prior| {
                araphor_data::analysis::PackageResultRefV1 {
                    result_id: prior.result.clone(),
                    commit_revision: prior.revision,
                }
            }),
        }))
    }
}
