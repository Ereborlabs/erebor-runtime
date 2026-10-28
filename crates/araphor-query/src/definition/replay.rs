use super::*;

use araphor_analysis_sdk as sdk;
use datafusion::logical_expr::{Extension, LogicalPlanBuilder};

use crate::inputs::Inputs;
use crate::sources::SourceOrigin;

impl Session {
    pub async fn replay_call(
        &self,
        definition: &PreparedDefinition,
        id: u64,
        evaluation: sdk::Evaluation,
    ) -> Result<DefinitionOutput> {
        self.control().check()?;
        PackageCall::check_admission(&definition.plan).context(SqlSnafu)?;
        let mut selected = None;
        PackageCall::any(&definition.plan, &mut |call| {
            if call.id() == id {
                selected = Some(call.clone());
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .context(SqlSnafu)?;
        let mut call = selected.ok_or_else(|| PackageErrorCodeV1::Missing.error("replay call"))?;
        if call.tenant() != self.selection().tenant_id
            || call.export() != evaluation.export
            || !definition.admission.images.iter().any(|(bundle, image)| {
                Arc::ptr_eq(bundle, &call.bundle)
                    && Arc::ptr_eq(image, &call._image)
                    && bundle.bundle().root == call.pin.image
                    && bundle.digest() == call.pin.digest
            })
        {
            return Err(PackageErrorCodeV1::Denied.error("replay call scope").into());
        }
        let bundle = Arc::clone(&call.bundle);
        let descriptor = &bundle.bundle().artifacts[call.artifact].descriptor;
        let mut session = self.clone();
        session.tables = Arc::default();
        let replay = {
            let checked = descriptor
                .check_evaluation(&evaluation)
                .map_err(|source| datafusion::common::DataFusionError::External(Box::new(source)))
                .context(SqlSnafu)?;
            let model = checked.model();
            let mut plans = Vec::with_capacity(model.inputs.len());
            let mut origins = Vec::with_capacity(model.inputs.len());
            for (slot, input) in model.inputs.iter().enumerate() {
                let data = evaluation
                    .inputs
                    .iter()
                    .find(|value| value.data.name == input.port.name)
                    .ok_or_else(|| PackageErrorCodeV1::Invalid.error("replay input"))?;
                let name = format!("__replay_input_{slot}");
                session.register(
                    &name,
                    Arc::new(input.port.schema.clone()),
                    &data.data.batches,
                )?;
                let provider = session
                    .tables
                    .get(&name)
                    .ok_or_else(|| PackageErrorCodeV1::Missing.error("replay table"))?
                    .provider();
                plans.push(Inputs::scan(&name, provider, &input.port.schema)?);
                origins.push(BTreeSet::from([SourceOrigin::Local(name)]));
            }
            call.input_scope = Arc::new(Inputs::from_plans(model, &plans, origins)?);
            if let Some(parameters) = &evaluation.parameters {
                let name = "__replay_parameters";
                session.register(name, parameters.schema(), std::slice::from_ref(parameters))?;
                plans.push(
                    LogicalPlanBuilder::scan(
                        name,
                        datafusion::datasource::provider_as_source(
                            session
                                .tables
                                .get(name)
                                .ok_or_else(|| {
                                    PackageErrorCodeV1::Missing.error("replay parameters")
                                })?
                                .provider(),
                        ),
                        None,
                    )
                    .and_then(LogicalPlanBuilder::build)
                    .context(SqlSnafu)?,
                );
            }
            let count = model.inputs.len() + usize::from(!model.parameters.fields().is_empty());
            if plans.len() != count || count > call.children.len() {
                return Err(PackageErrorCodeV1::Invalid
                    .error("replay input plans")
                    .into());
            }
            call.children.splice(..count, plans);
            call.admitted = call.children.clone().into();
            call._metadata = PackageCall::metadata(
                session.memory(),
                model,
                &call.input_scope,
                call.children.len(),
            )?;
            let sources = AnalysisTableRequests::new();
            let resolved = definition.resolved().clone();
            let memory = session
                .memory()
                .reserve_input(DefinitionAdmission::allocation_bytes(&resolved, &sources)?)
                .context(SqlSnafu)?;
            PreparedDefinition {
                plan: LogicalPlan::Extension(Extension {
                    node: Arc::new(call),
                }),
                admission: Arc::new(DefinitionAdmission {
                    resolved,
                    sources,
                    tenant: self.selection().tenant_id,
                    images: Arc::clone(&definition.admission.images),
                    retained: None,
                    _memory: memory,
                }),
            }
        };
        session
            .execute_definition(
                &replay,
                Invocation {
                    id: evaluation.context.id,
                    seed: evaluation.context.seed,
                    time_utc_ns: Some(evaluation.context.time_utc_ns),
                    inputs: if evaluation.inputs.is_empty() {
                        BTreeMap::new()
                    } else {
                        BTreeMap::from([(id, evaluation.inputs)])
                    },
                    checkpoints: evaluation
                        .checkpoint
                        .into_iter()
                        .map(|checkpoint| (id, checkpoint))
                        .collect(),
                    previous_outputs: if evaluation.previous_outputs.is_empty() {
                        BTreeMap::new()
                    } else {
                        BTreeMap::from([(id, evaluation.previous_outputs)])
                    },
                },
            )
            .await
    }
}
