use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::analysis::{PackageActivationV1, PackageCommitV1, PackageResultV1};
use crate::{AnalysisReadControl, QueryOwner, Result};

use super::{ResultContext, RunPreparation};
use crate::package::installed::snapshot::InstalledBundle;
use crate::package::owner::{ClockDependency, InstalledContext};
use crate::package::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageArtifactV1, PackageErrorCodeV1 as Code,
};
use crate::query::{AdmittedExport, ModelInputRequest, ModelInputs, ModelOperation};

pub(in crate::package) struct ModelRun<'a> {
    owner: &'a AnalysisPackageOwner,
    active: &'a PackageActivationV1,
    context: &'a InstalledContext,
    artifact: &'a PackageArtifactV1,
    model: &'a sdk::Model,
    admitted: &'a AdmittedExport,
    id: &'a str,
    now: u64,
    operation: ModelOperation<'a>,
    inputs: ModelInputs,
    previous: Option<PackageResultV1>,
    unchanged: bool,
}

impl AnalysisPackageOwner {
    pub(in crate::package) fn prepare_at(
        &self,
        active: &PackageActivationV1,
        bundle: &InstalledBundle,
        request: RunPreparation<'_>,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageCommitV1>> {
        control.check()?;
        let context: InstalledContext = Self::decode(&active.metadata)?;
        self.model_run(active, &context, bundle, request, Action::Run, control)?
            .map(|run| run.evaluate(request.rebuild, request.automatic, control))
            .transpose()
    }

    pub(in crate::package) fn model_run<'a>(
        &'a self,
        active: &'a PackageActivationV1,
        context: &'a InstalledContext,
        bundle: &'a InstalledBundle,
        request: RunPreparation<'a>,
        action: Action,
        control: &AnalysisReadControl,
    ) -> Result<Option<ModelRun<'a>>> {
        control.check()?;
        let mut now = if request.automatic {
            Self::clock_tick(request.now)
        } else {
            request.now
        };
        if action == Action::Run && bundle.value.root != context.root {
            return Err(Code::Conflict.error("activation package root"));
        }
        if request.automatic
            && self
                .inputs_current(active, context.clock, request.now, true, control)?
                .0
        {
            return Ok(None);
        }
        let (artifact, model, admitted) =
            bundle.export(&active.key.package_id, &active.revision, &active.key.export)?;
        let previous = active
            .result_id
            .as_deref()
            .map(|id| self.store.package_result(active.key.tenant_id, id))
            .transpose()?
            .flatten();
        if action == Action::Inspect && previous.as_ref().is_none_or(|previous| previous.stale) {
            return Ok(None);
        }
        let prior = previous
            .as_ref()
            .map(|previous| Self::decode::<ResultContext>(&previous.commit.metadata))
            .transpose()?;
        if action == Action::Inspect {
            if let Some(prior) = prior
                .as_ref()
                .filter(|prior| Self::clock_tick(prior.context.time_utc_ns as u64) == now)
            {
                now = prior.context.time_utc_ns as u64;
            }
        }
        let prepared = self
            .query
            .model_operation(active.key.tenant_id)
            .inputs_admitted(
                ModelInputRequest {
                    activation: active,
                    model,
                    grant: &context.grant,
                    now,
                },
                admitted,
                control,
                || self.check(&context.grant, action),
            );
        let (operation, inputs) = match prepared {
            Ok(prepared) => prepared,
            Err(crate::Error::Package {
                code: Code::Missing | Code::Incomplete,
                ..
            }) if action == Action::Inspect => {
                control.check()?;
                self.store.mark_package_stale(active)?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        control.check()?;
        let unchanged = prior.as_ref().is_some_and(|prior| prior.matches(&inputs));
        let current = unchanged
            && !prior.as_ref().is_some_and(|prior| {
                Self::clock_changed(
                    context.clock == ClockDependency::Model,
                    prior.context.time_utc_ns,
                    now,
                )
            });
        if !current && active.generation != 0 && active.result_id.is_some() {
            self.store.mark_package_stale(active)?;
        }
        if action == Action::Inspect
            || (request.automatic
                && current
                && previous.as_ref().is_some_and(|previous| !previous.stale))
        {
            return Ok(None);
        }
        Ok(Some(ModelRun {
            owner: self,
            active,
            context,
            artifact,
            model,
            admitted,
            id: request.id,
            now,
            operation,
            inputs,
            previous,
            unchanged,
        }))
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
    ) -> Result<(bool, u64)> {
        let tick = Self::clock_tick(now).saturating_add(Self::RECONCILE_INTERVAL.as_nanos() as u64);
        let Some((metadata, deadline)) =
            self.store.package_current(active, now, changed, control)?
        else {
            return Ok((false, tick));
        };
        let saved: ResultContext = Self::decode(&metadata)?;
        Ok((
            !Self::clock_changed(
                clock != ClockDependency::None,
                saved.context.time_utc_ns,
                now,
            ),
            deadline.min(if clock == ClockDependency::None {
                u64::MAX
            } else {
                tick
            }),
        ))
    }
}

impl ModelRun<'_> {
    fn evaluate(
        self,
        rebuild: bool,
        automatic: bool,
        control: &AnalysisReadControl,
    ) -> Result<PackageCommitV1> {
        let implementation = self.artifact.implementation(&self.model.name)?;
        let mut metadata = ResultContext::new(self.id, self.now, self.model, &self.inputs);
        metadata.target = implementation.target().into();
        metadata.artifact = implementation.identity()?;
        if metadata.target == "wasm" {
            metadata.context.limits = self.owner.query.component_limits(metadata.context.limits);
        }
        let checkpoint = if self.unchanged && !rebuild {
            self.previous
                .as_ref()
                .filter(|previous| !previous.commit.checkpoint.is_empty())
                .map(|previous| {
                    AnalysisPackageOwner::decode_checkpoint(
                        &AnalysisPackageOwner::decode::<sdk::wire::Checkpoint>(
                            &previous.commit.checkpoint,
                        )?,
                        self.model,
                    )
                })
                .transpose()?
        } else {
            None
        };
        drop(self.previous);
        let evaluation = sdk::Evaluation {
            export: self.model.name.clone(),
            inputs: self.inputs.inputs.clone(),
            parameters: QueryOwner::model_parameters(
                &self.model.parameters,
                AnalysisPackageOwner::parameter_values(
                    self.context.parameters.as_ref(),
                    &self.active.key.package_id,
                    &self.active.key.export,
                ),
            )?,
            context: metadata.context.clone(),
            checkpoint,
        };
        let evaluated = match implementation {
            crate::PackageImplementationV1::Sql { program, .. } => {
                self.operation.evaluate_admitted(
                    &self.artifact.descriptor,
                    program,
                    self.admitted,
                    &evaluation,
                    control,
                )?
            }
            _ => {
                self.operation.release_inputs()?;
                self.owner.evaluate_artifact(
                    self.active.key.tenant_id,
                    self.artifact,
                    self.admitted,
                    &evaluation,
                    control,
                )?
            }
        };
        let mut packet = crate::AnalysisPackageOwner::encode_output(&evaluated.output, self.model)?;
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
                    (self.context.clock == ClockDependency::Model)
                        .then_some(metadata.context.time_utc_ns),
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
            dependencies: self.inputs.dependencies,
            source_revisions: self.inputs.source_revisions,
            witnesses: self.inputs.witnesses,
            context_refs: self.inputs.contexts,
            created_utc_ns: metadata.context.time_utc_ns as u64,
        })
    }
}

#[cfg(test)]
mod tests;

impl ResultContext {
    fn matches(&self, inputs: &ModelInputs) -> bool {
        self.inputs
            .iter()
            .eq(inputs.inputs.iter().map(|input| &input.revision))
            && self
                .input_coverage
                .iter()
                .eq(inputs.inputs.iter().map(|input| &input.coverage))
    }

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
