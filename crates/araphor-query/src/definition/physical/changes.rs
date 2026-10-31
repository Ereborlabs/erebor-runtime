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
            .descriptor()
            .exports
            .iter()
            .find(|model| model.name == self.call.export)
            .ok_or_else(|| internal("change model is absent"))?;
        let contract = model
            .change_inputs
            .as_ref()
            .ok_or_else(|| internal("change contract is absent"))?;
        let targets = evaluation
            .inputs
            .iter()
            .zip(&model.inputs)
            .filter(|(input, port)| {
                !contract.generated(&input.data.name)
                    && !matches!(&port.source, sdk::InputSource::Lookup(_))
            })
            .map(|(input, _)| input)
            .cloned()
            .collect::<Vec<_>>();
        let old = prior
            .and_then(|prior| prior.retained.as_ref())
            .and_then(|saved| saved.changes.as_ref());
        let source = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| internal("change source is absent"))?;
        let parameters = prior.is_some_and(|prior| {
            prior
                .parameters
                .as_ref()
                .map(|data| data.batches.as_slice())
                == evaluation.parameters.as_ref().map(std::slice::from_ref)
        });
        let compatible = parameters
            && source
                .snapshot()?
                .managed()
                .is_none_or(|managed| !managed.rebuild())
            && (model.checkpoint.is_none() || evaluation.checkpoint.is_some())
            && old.is_some_and(|old| {
                old.targets.len() == targets.len()
                    && targets.iter().all(|target| {
                        old.targets
                            .iter()
                            .find(|base| base.data.name == target.data.name)
                            .is_some_and(|base| {
                                let schema = model
                                    .inputs
                                    .iter()
                                    .find(|input| input.port.name == target.data.name)
                                    .map(|input| &input.port.schema);
                                base.data
                                    .batches
                                    .iter()
                                    .all(|batch| Some(batch.schema().as_ref()) == schema)
                                    && (contract
                                        .ports
                                        .iter()
                                        .any(|pair| pair.after == target.data.name)
                                        || (base.data.batches == target.data.batches
                                            && base.revision == target.revision
                                            && base.coverage == target.coverage))
                            })
                    })
            });
        let reset = !compatible;
        if reset {
            evaluation.checkpoint = None;
            evaluation.previous_outputs.clear();
        } else {
            let old = old.ok_or_else(|| internal("change base is absent"))?;
            for (index, port) in call.ports.iter().enumerate() {
                let after = &evaluation.inputs[port.after];
                let base = old
                    .targets
                    .iter()
                    .find(|base| base.data.name == after.data.name)
                    .ok_or_else(|| internal("change base port is absent"))?;
                let schema = Arc::new(model.inputs[port.after].port.schema.clone());
                source.bind_port(
                    port.base,
                    Arc::clone(&schema),
                    base.data.batches.clone(),
                    None,
                )?;
                source.bind_port(
                    port.target,
                    Arc::clone(&schema),
                    after.data.batches.clone(),
                    None,
                )?;
                let removed = self
                    .collect(
                        call.start + index * 2,
                        &schema,
                        owner,
                        context,
                        memory,
                        true,
                    )
                    .await?;
                let inserted = self
                    .collect(
                        call.start + index * 2 + 1,
                        &schema,
                        owner,
                        context,
                        memory,
                        true,
                    )
                    .await?;
                evaluation.inputs[port.before] = sdk::Input {
                    data: sdk::Dataset {
                        name: model.inputs[port.before].port.name.clone(),
                        batches: removed,
                    },
                    revision: base.revision.clone(),
                    coverage: base.coverage.clone(),
                };
                evaluation.inputs[port.after].data.batches = inserted;
            }
        }
        if reset {
            for port in &call.ports {
                let mut before = evaluation.inputs[port.after].clone();
                before.data = sdk::Dataset {
                    name: model.inputs[port.before].port.name.clone(),
                    batches: vec![sdk::RecordBatch::new_empty(Arc::new(
                        model.inputs[port.before].port.schema.clone(),
                    ))],
                };
                evaluation.inputs[port.before] = before;
            }
        }
        let reset_input = evaluation
            .inputs
            .iter_mut()
            .find(|input| input.data.name == contract.reset)
            .ok_or_else(|| internal("change reset port is absent"))?;
        reset_input.data = contract.reset_input(reset).map_err(external)?;
        for (id, slot) in &call.lookups.bindings {
            if !matches!(&model.inputs[*slot].source, sdk::InputSource::Lookup(_)) {
                let input = &evaluation.inputs[*slot];
                source.bind_port(
                    *id,
                    Arc::new(model.inputs[*slot].port.schema.clone()),
                    input.data.batches.clone(),
                    Some(input),
                )?;
            }
        }
        for slot in &call.lookups.order {
            let port = &model.inputs[*slot];
            let input = self
                .read_input(*slot, port, owner, context, memory, &source)
                .await?;
            for (id, bound) in &call.lookups.bindings {
                if bound == slot {
                    source.bind_port(
                        *id,
                        Arc::new(port.port.schema.clone()),
                        input.data.batches.clone(),
                        Some(&input),
                    )?;
                }
            }
            evaluation.inputs[*slot] = input;
        }
        Ok(Some(araphor_data::ManagedChanges {
            base: prior.filter(|_| !reset).map(|prior| {
                araphor_data::analysis::PackageResultRefV1 {
                    result_id: prior.result.clone(),
                    commit_revision: prior.revision,
                }
            }),
            targets,
        }))
    }
}
