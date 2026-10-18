use araphor_analysis_sdk as sdk;
use araphor_query::execution::Session;
use snafu::ResultExt as _;

use super::operation::ModelRun;
use crate::Result;

impl ModelRun {
    pub(super) fn register(
        &mut self,
        model: &sdk::Model,
        evaluation: &sdk::Evaluation,
    ) -> Result<()> {
        self.session.check_input(
            evaluation
                .inputs
                .iter()
                .flat_map(|input| &input.data.batches)
                .chain(evaluation.parameters.iter())
                .chain(
                    evaluation
                        .checkpoint
                        .iter()
                        .flat_map(|state| &state.datasets)
                        .flat_map(|data| &data.batches),
                ),
        )?;
        if let Some(inputs) = self.inputs.clone() {
            inputs.register(&mut self.session)?;
        } else {
            for input in &model.inputs {
                let port = &input.port;
                self.table(
                    &port.name,
                    &port.schema,
                    &evaluation
                        .input(&port.name)
                        .context(crate::AnalysisContractSnafu)?
                        .data
                        .batches,
                )?;
            }
        }
        if let Some(parameters) = &evaluation.parameters {
            self.table(
                "parameters",
                &model.parameters,
                std::slice::from_ref(parameters),
            )?;
        }
        if let Some(spec) = &model.checkpoint {
            for port in &spec.datasets {
                let batches = evaluation
                    .checkpoint
                    .as_ref()
                    .and_then(|state| state.datasets.iter().find(|data| data.name == port.name))
                    .map_or(&[][..], |data| data.batches.as_slice());
                self.table(&format!("prior_{}", port.name), &port.schema, batches)?;
            }
        }
        Ok(())
    }

    pub(super) fn table(
        &mut self,
        name: &str,
        schema: &sdk::Schema,
        batches: &[sdk::RecordBatch],
    ) -> Result<()> {
        self.control.check()?;
        let schema = Session::indexed_schema(schema)?;
        let reservation = self.memory.reserve_input(0)?;
        let indexed = self
            .session
            .index_batches(schema.clone(), batches, &reservation, 0)?;
        drop(reservation);
        self.session.register(name, schema, &indexed)?;
        self.control.check()?;
        Ok(())
    }
}
