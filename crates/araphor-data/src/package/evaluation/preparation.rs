use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::analysis::{PackageActivationV1, PackageCommitV1};
use crate::{AnalysisReadControl, QueryOwner, Result};

use super::ResultContext;
use crate::package::owner::{ClockDependency, InstalledContext};
use crate::package::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageArtifactV1, PackageBundleV1,
    PackageCheckpointV1, PackageErrorCodeV1 as Code, PackageOutputV1,
};
use crate::query::{ModelInputRequest, ModelInputs};

struct ModelRun<'a> {
    active: &'a PackageActivationV1,
    context: &'a InstalledContext,
    artifact: &'a PackageArtifactV1,
    model: &'a sdk::Model,
    clocked: bool,
    id: &'a str,
}

struct RunPreparation<'a> {
    id: &'a str,
    rebuild: bool,
    automatic: bool,
    now: u64,
}

impl AnalysisPackageOwner {
    pub(super) fn prepare_run(
        &self,
        active: &PackageActivationV1,
        bundle: &PackageBundleV1,
        id: &str,
        rebuild: bool,
        automatic: bool,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageCommitV1>> {
        self.prepare_at(
            active,
            bundle,
            RunPreparation {
                id,
                rebuild,
                automatic,
                now: Self::now(),
            },
            control,
        )
    }

    fn prepare_at(
        &self,
        active: &PackageActivationV1,
        bundle: &PackageBundleV1,
        request: RunPreparation<'_>,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageCommitV1>> {
        let RunPreparation {
            id,
            rebuild,
            automatic,
            now,
        } = request;
        control.check()?;
        let context: InstalledContext = Self::decode(&active.metadata)?;
        if bundle.root != context.root {
            return Err(Code::Conflict.error("activation package root"));
        }
        if automatic && self.inputs_current(active, context.clock, now, true, control)? {
            return Ok(None);
        }
        let run = ModelRun::new(active, &context, bundle, id)?;
        let implementation = run.artifact.implementation(&run.model.name)?;
        let now = if automatic {
            Self::clock_tick(now)
        } else {
            now
        };
        let (operation, inputs) = self.query.model_operation(active.key.tenant_id).inputs(
            ModelInputRequest {
                activation: active,
                model: run.model,
                grant: &context.grant,
                now,
            },
            control,
            || self.check(&context.grant, Action::Run),
        )?;
        let mut metadata = ResultContext::new(id, now, run.model, &inputs);
        metadata.target = implementation.target().into();
        metadata.artifact = implementation.identity()?;
        if metadata.target == "wasm" {
            metadata.context.limits = self.query.component_limits(metadata.context.limits);
        }
        let Some(evaluation) = run.evaluation(self, &inputs, &metadata, rebuild, automatic)? else {
            return Ok(None);
        };
        let evaluated = match implementation {
            crate::package::PackageImplementationV1::Sql { program, .. } => {
                operation.evaluate(&run.artifact.descriptor, program, &evaluation, control)?
            }
            _ => {
                drop(operation);
                self.evaluate_artifact(active.key.tenant_id, run.artifact, &evaluation, control)?
            }
        };
        run.commit(inputs, metadata, &evaluated.output, automatic)
            .map(Some)
    }

    pub(in crate::package) fn clock_tick(now: u64) -> u64 {
        let period = Self::RECONCILE_INTERVAL.as_nanos() as u64;
        now / period * period
    }

    pub(in crate::package) fn clock_changed(clocked: bool, prior: i64, now: u64) -> bool {
        clocked && Self::clock_tick(prior as u64) != Self::clock_tick(now)
    }

    pub(in crate::package) fn inputs_current(
        &self,
        active: &PackageActivationV1,
        clock: ClockDependency,
        now: u64,
        changed: bool,
        control: &AnalysisReadControl,
    ) -> Result<bool> {
        let Some(metadata) = self.store.package_current(active, now, changed, control)? else {
            return Ok(false);
        };
        let saved: ResultContext = Self::decode(&metadata)?;
        Ok(!Self::clock_changed(
            clock != ClockDependency::None,
            saved.context.time_utc_ns,
            now,
        ))
    }
}

impl<'a> ModelRun<'a> {
    fn new(
        active: &'a PackageActivationV1,
        context: &'a InstalledContext,
        bundle: &'a PackageBundleV1,
        id: &'a str,
    ) -> Result<Self> {
        let artifact = bundle
            .artifacts
            .iter()
            .find(|artifact| {
                artifact.descriptor.id == active.key.package_id
                    && artifact.descriptor.revision == active.revision
            })
            .ok_or_else(|| Code::Missing.error("active artifact"))?;
        let model = artifact
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == active.key.export)
            .ok_or_else(|| Code::Missing.error("active export"))?;
        let clocked = context.clock == ClockDependency::Model;
        Ok(Self {
            active,
            context,
            artifact,
            model,
            clocked,
            id,
        })
    }

    fn evaluation(
        &self,
        owner: &AnalysisPackageOwner,
        inputs: &ModelInputs,
        metadata: &ResultContext,
        rebuild: bool,
        automatic: bool,
    ) -> Result<Option<sdk::Evaluation>> {
        let previous = self
            .active
            .result_id
            .as_deref()
            .map(|id| owner.store.package_result(self.active.key.tenant_id, id))
            .transpose()?
            .flatten();
        let prior = previous
            .as_ref()
            .map(|previous| AnalysisPackageOwner::decode::<ResultContext>(&previous.metadata))
            .transpose()?;
        let unchanged = prior.as_ref().is_some_and(|prior| {
            prior.inputs == metadata.inputs && prior.input_coverage == metadata.input_coverage
        });
        let clock_changed = prior.as_ref().is_some_and(|prior| {
            AnalysisPackageOwner::clock_changed(
                self.clocked,
                prior.context.time_utc_ns,
                metadata.context.time_utc_ns as u64,
            )
        });
        if automatic
            && unchanged
            && !clock_changed
            && previous.as_ref().is_some_and(|previous| !previous.stale)
        {
            return Ok(None);
        }
        if (!unchanged || clock_changed)
            && self.active.generation != 0
            && self.active.result_id.is_some()
        {
            owner.store.mark_package_stale(self.active)?;
        }
        let checkpoint = if unchanged && !rebuild {
            previous
                .as_ref()
                .filter(|previous| !previous.checkpoint.is_empty())
                .map(|previous| {
                    AnalysisPackageOwner::decode::<PackageCheckpointV1>(&previous.checkpoint)?
                        .decode(self.model)
                })
                .transpose()?
        } else {
            None
        };
        let parameters = AnalysisPackageOwner::parameter_values(
            self.context.parameters.as_ref(),
            &self.active.key.package_id,
            &self.active.key.export,
        );
        Ok(Some(sdk::Evaluation {
            export: self.model.name.clone(),
            inputs: inputs.inputs.clone(),
            parameters: QueryOwner::model_parameters(&self.model.parameters, parameters)?,
            context: metadata.context.clone(),
            checkpoint,
        }))
    }

    fn commit(
        &self,
        inputs: ModelInputs,
        metadata: ResultContext,
        output: &sdk::Output,
        automatic: bool,
    ) -> Result<PackageCommitV1> {
        let mut packet = PackageOutputV1::encode(output, self.model)?;
        let checkpoint = packet
            .checkpoint
            .take()
            .map(|checkpoint| AnalysisPackageOwner::encode(&checkpoint))
            .transpose()?
            .unwrap_or_default();
        let result_id = if automatic {
            format!(
                "package-{}",
                crate::digest::InputRevision::of(&(
                    &self.active.key,
                    self.active.generation,
                    self.active.checkpoint_revision,
                    &metadata.inputs,
                    &metadata.input_coverage,
                    self.clocked.then_some(metadata.context.time_utc_ns),
                ))
                .context(crate::PackageEncodingSnafu)?
            )
        } else {
            AnalysisPackageOwner::result_id(self.active, self.id)?
        };
        Ok(PackageCommitV1 {
            activation: self.active.clone(),
            expected_checkpoint_revision: self.active.checkpoint_revision,
            window_id: "snapshot".into(),
            result_id,
            request: AnalysisPackageOwner::request(
                self.active,
                self.id,
                self.context,
                self.artifact,
            )?,
            metadata: AnalysisPackageOwner::encode(&metadata)?,
            datasets: AnalysisPackageOwner::encode(&packet)?,
            checkpoint,
            dependencies: inputs.dependencies,
            source_revisions: inputs.source_revisions,
            witnesses: inputs.witnesses,
            context_refs: inputs.contexts,
            created_utc_ns: metadata.context.time_utc_ns as u64,
        })
    }
}

#[cfg(test)]
mod tests;

impl ResultContext {
    fn new(id: &str, now: u64, model: &sdk::Model, inputs: &ModelInputs) -> Self {
        let input_coverage: Vec<_> = inputs
            .inputs
            .iter()
            .map(|input| input.coverage.clone())
            .collect();
        Self {
            target: "sql".into(),
            artifact: None,
            context: sdk::EvaluationContext {
                id: id.into(),
                time_utc_ns: now as i64,
                seed: None,
                limits: model.limits,
            },
            inputs: inputs
                .inputs
                .iter()
                .map(|input| input.revision.clone())
                .collect(),
            coverage: ModelInputs::coverage(input_coverage.iter()),
            input_coverage,
        }
    }
}
