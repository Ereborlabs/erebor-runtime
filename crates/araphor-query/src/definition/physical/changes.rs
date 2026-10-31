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
        let source = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| internal("change source is absent"))?;
        if source.snapshot()?.managed().is_some() && source.source_view()?.is_none() {
            return Err(DataFusionError::Execution(
                "the managed change view is absent".into(),
            ));
        }
        let compatible = prior.is_some_and(|prior| {
            prior
                .parameters
                .as_ref()
                .map(|data| data.batches.as_slice())
                == evaluation.parameters.as_ref().map(std::slice::from_ref)
        }) && source
            .snapshot()?
            .managed()
            .is_none_or(|managed| !managed.rebuild())
            && (model.checkpoint.is_none() || evaluation.checkpoint.is_some());
        let reset = !compatible;
        if reset {
            evaluation.checkpoint = None;
            evaluation.previous_outputs.clear();
        }
        let mut inputs = (0..model.inputs.len()).map(|_| None).collect::<Vec<_>>();
        for &slot in &call.lookups.order {
            let port = &model.inputs[slot];
            let mut input = self
                .read_input(slot, port, owner, context, memory, &source)
                .await?;
            if port.port.name == contract.reset {
                input.data = contract.reset_input(reset).map_err(external)?;
            }
            for (id, bound) in &call.lookups.bindings {
                if *bound == slot {
                    source.bind_port(
                        *id,
                        Arc::new(port.port.schema.clone()),
                        input.data.batches.clone(),
                        Some(&input),
                    )?;
                }
            }
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
