use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisReadControl, PackageActionV1, PackageAuthorization, PackageBundleRef, PackageBundleV1,
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

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct FixtureResult {
    pub fixture: String,
    pub passed: bool,
}

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
        let mut changes = self.authority.changes_for(grant);
        self.authority.check(grant, PackageActionV1::Test)?;
        let operation = ReadOperation(Arc::new(control.operation()?.within(grant.remaining()?)?));
        let execution = self.run_inner(grant, image, name, &operation.0);
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
        name: Option<&str>,
        control: &Arc<AnalysisReadControl>,
    ) -> Result<Vec<FixtureResult>> {
        let bundle = self
            .image(grant.selection.tenant_id, image, control)
            .await?;
        let retained = PackageBundleRef::new(&bundle)?;
        self.check(grant, &retained, control)?;
        let artifact = bundle.artifact(image)?;
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
            self.check(grant, &retained, control)?;
            let model = artifact
                .descriptor
                .exports
                .iter()
                .find(|model| model.name == fixture.export)
                .ok_or_else(|| Code::Invalid.error("fixture export"))?;
            let now = u64::try_from(fixture.time_utc_ns)
                .map_err(|_| Code::Unsupported.error("negative fixture time"))?;
            let mut session = self.query.session(grant.selection.clone(), control, now)?;
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
                    .decode(&port.schema, model.limits)
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
            let definition = Self::definition(image, fixture, model)?;
            let prepared = session.prepare_definition(&definition).await?;
            if prepared.resolved.images.len() != 1
                || prepared.resolved.images[0].image != *image
                || prepared.resolved.images[0].digest != retained.digest()
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
                                && call.package() == image
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
            let context = fixture.evaluation_context(model);
            let invocation = Invocation {
                id: context.id,
                seed: context.seed,
                checkpoints: checkpoint
                    .into_iter()
                    .map(|checkpoint| (id, checkpoint))
                    .collect(),
                inputs: if inputs.is_empty() {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([(id, inputs)])
                },
                limits: context.limits,
            };
            let output = session.execute_definition(&prepared, invocation).await?;
            let call = output
                .calls
                .get(&id)
                .ok_or_else(|| Code::Incomplete.error("fixture package return"))?;
            let passed =
                fixture.compare_output(&artifact.descriptor, call.evaluation(), call.output())?;
            self.check(grant, &retained, control)?;
            results.push(FixtureResult {
                fixture: fixture.name.clone(),
                passed,
            });
        }
        self.check(grant, &retained, control)?;
        Ok(results)
    }

    fn check(
        &self,
        grant: &PackageGrantV1,
        retained: &PackageBundleRef<'_>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        control.check()?;
        grant.remaining()?;
        self.authority.check(grant, PackageActionV1::Test)?;
        self.authority.admit(grant, retained)?;
        Ok(())
    }

    async fn image(
        &self,
        tenant: [u8; 16],
        image: &PackageRefV1,
        control: &Arc<AnalysisReadControl>,
    ) -> Result<PackageBundleV1> {
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
