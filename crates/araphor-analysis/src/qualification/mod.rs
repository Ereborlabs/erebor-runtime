use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisReadControl, PackageActionV1, PackageAuthorization, PackageBundle,
    PackageErrorCodeV1 as Code, PackageFixtureV1, PackageGrantV1, PackageRefV1,
};
use araphor_query::definition::{Invocation, PackageCall};
use araphor_query::execution::Engine;
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::logical_expr::LogicalPlan;
use snafu::ResultExt as _;

use crate::Result;

mod query;
#[cfg(test)]
mod tests;

pub use araphor_data::FixtureResult;

pub struct Qualification {
    query: Arc<Engine>,
    authority: Arc<dyn PackageAuthorization>,
}

struct ReadOperation(Arc<AnalysisReadControl>);

impl Drop for ReadOperation {
    fn drop(&mut self) {
        let _cancelled = self.0.cancel();
    }
}

impl Qualification {
    pub fn new(query: Arc<Engine>, authority: Arc<dyn PackageAuthorization>) -> Self {
        Self { query, authority }
    }

    pub async fn run(
        &self,
        grant: &PackageGrantV1,
        image: &PackageRefV1,
        name: Option<&str>,
        control: &AnalysisReadControl,
    ) -> Result<Vec<FixtureResult>> {
        self.run_artifact(grant, image, image, name, control).await
    }

    pub async fn run_artifact(
        &self,
        grant: &PackageGrantV1,
        image: &PackageRefV1,
        artifact: &PackageRefV1,
        name: Option<&str>,
        control: &AnalysisReadControl,
    ) -> Result<Vec<FixtureResult>> {
        let mut changes = self.authority.changes_for(grant);
        self.authority.check(grant, PackageActionV1::Test)?;
        let operation = ReadOperation(Arc::new(control.operation()?.within(grant.remaining()?)?));
        let execution = self.run_inner(grant, image, artifact, name, &operation.0);
        tokio::pin!(execution);
        let result = tokio::select! {
            biased;
            stopped = control.query_async(std::future::pending::<Result<Vec<FixtureResult>>>()) => {
                let _cancelled = operation.0.cancel();
                let _finished = execution.await;
                stopped
            }
            _ = changes.changed() => {
                let _cancelled = operation.0.cancel();
                let _finished = execution.await;
                Err(Code::Denied.error("package authority changed").into())
            }
            result = &mut execution => result,
        };
        control.check()?;
        if result.is_ok() {
            self.authority.check(grant, PackageActionV1::Test)?;
        }
        result
    }

    async fn run_inner(
        &self,
        grant: &PackageGrantV1,
        image: &PackageRefV1,
        target: &PackageRefV1,
        name: Option<&str>,
        control: &Arc<AnalysisReadControl>,
    ) -> Result<Vec<FixtureResult>> {
        let bundle = self
            .image(grant.selection.tenant_id, image, control)
            .await?;
        self.check(grant, &bundle, control)?;
        let artifact = bundle.bundle().artifact(target)?;
        let fixtures = artifact
            .fixtures
            .iter()
            .filter(|fixture| name.is_none_or(|name| name == fixture.name))
            .collect::<Vec<_>>();
        if name.is_some() && fixtures.is_empty() {
            return Err(Code::Missing.error("package fixture").into());
        }
        let mut results = Vec::new();
        for fixture in fixtures {
            self.check(grant, &bundle, control)?;
            let model = artifact
                .descriptor
                .exports
                .iter()
                .find(|model| model.name == fixture.export)
                .ok_or_else(|| Code::Invalid.error("fixture export"))?;
            let mut session = self.query.session(grant.selection.clone(), control, 0)?;
            let mut inputs = Vec::new();
            for (index, input) in fixture.inputs.iter().enumerate() {
                let port = model
                    .inputs
                    .iter()
                    .map(|input| &input.port)
                    .find(|port| port.name == input.data.name)
                    .ok_or_else(|| Code::Invalid.error("fixture input"))?;
                let data = input
                    .data
                    .decode(&port.schema)
                    .context(araphor_data::AnalysisContractSnafu)?;
                session.register(
                    &format!("__fixture_input_{index}"),
                    Arc::new(port.schema.clone()),
                    &data.batches,
                )?;
                inputs.push(sdk::Input {
                    data,
                    revision: input.revision.clone(),
                    coverage: input.coverage.clone(),
                });
            }
            if let Some(parameters) =
                araphor_data::decode_parameters(&model.parameters, fixture.parameters.as_ref())?
            {
                session.register(
                    "__fixture_parameters",
                    Arc::new(model.parameters.clone()),
                    &[parameters],
                )?;
            }
            let definition = Self::definition(target, fixture, model)?;
            let prepared = session.prepare_image(&definition, image.clone()).await?;
            if prepared.resolved().images.len() != 1
                || prepared.resolved().images[0].image != *image
                || prepared.resolved().images[0].digest != bundle.digest()
            {
                return Err(Code::Denied.error("fixture image pin").into());
            }
            let mut calls = BTreeSet::new();
            prepared
                .plan
                .apply_with_subqueries(|plan| {
                    if let LogicalPlan::Extension(extension) = plan {
                        if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                            if call.image().image == *image
                                && call.package() == target
                                && call.export() == fixture.export
                            {
                                calls.insert(call.id());
                            }
                        }
                    }
                    Ok(TreeNodeRecursion::Continue)
                })
                .map_err(|source| araphor_query::Error::Sql { source })?;
            if calls.len() != 1 {
                return Err(Code::Invalid.error("fixture package call").into());
            }
            let id = *calls
                .first()
                .ok_or_else(|| Code::Invalid.error("fixture package call"))?;
            let checkpoint = fixture
                .checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.decode_model(model))
                .transpose()
                .context(araphor_data::AnalysisContractSnafu)?;
            let context = fixture.evaluation_context();
            let previous = fixture
                .previous_outputs
                .iter()
                .map(|data| {
                    let port = model
                        .outputs
                        .iter()
                        .find(|port| port.name == data.name)
                        .ok_or_else(|| Code::Invalid.error("fixture previous output"))?;
                    data.decode(&port.schema)
                        .context(araphor_data::AnalysisContractSnafu)
                })
                .collect::<araphor_data::Result<Vec<_>>>()?;
            let invocation = Invocation {
                id: context.id,
                seed: context.seed,
                time_utc_ns: Some(context.time_utc_ns),
                checkpoints: checkpoint
                    .into_iter()
                    .map(|checkpoint| (id, checkpoint))
                    .collect(),
                previous_outputs: if previous.is_empty() {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([(id, previous)])
                },
                inputs: if inputs.is_empty() {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([(id, inputs)])
                },
            };
            let output = session.execute_definition(&prepared, invocation).await?;
            let call = output
                .calls
                .get(&id)
                .ok_or_else(|| Code::Incomplete.error("fixture package return"))?;
            let passed =
                fixture.compare_output(&artifact.descriptor, call.evaluation(), call.output())?;
            self.check(grant, &bundle, control)?;
            results.push(FixtureResult {
                fixture: fixture.name.clone(),
                passed,
            });
        }
        self.check(grant, &bundle, control)?;
        Ok(results)
    }

    fn check(
        &self,
        grant: &PackageGrantV1,
        bundle: &PackageBundle,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        control.check()?;
        grant.remaining()?;
        self.authority.check(grant, PackageActionV1::Test)?;
        self.authority.admit(grant, bundle)?;
        Ok(())
    }

    async fn image(
        &self,
        tenant: [u8; 16],
        image: &PackageRefV1,
        control: &Arc<AnalysisReadControl>,
    ) -> Result<PackageBundle> {
        let store = Arc::clone(self.query.store());
        let image = image.clone();
        let operation = ReadOperation(Arc::new(control.operation()?));
        let read = Arc::clone(&operation.0);
        let mut worker = tokio::task::spawn_blocking(move || {
            store.package_image(tenant, &image.package_id, Some(&image.revision), &read)
        });
        let result = control
            .query_async(async {
                (&mut worker)
                    .await
                    .context(crate::error::TaskSnafu)?
                    .map_err(crate::Error::from)
            })
            .await;
        if result.is_err() && !worker.is_finished() {
            let _cancelled = operation.0.cancel();
            let _finished = worker.await;
        }
        result?.ok_or_else(|| Code::Missing.error("installed package image").into())
    }
}
