use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::analysis::{PackageActivationV1, PackageCommitV1};
use crate::{AnalysisReadControl, Result};

use super::{ResultContext, RunPreparation};
use crate::package::installed::snapshot::InstalledBundle;
use crate::package::owner::{ClockDependency, InstalledContext};
use crate::package::{AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code};

impl AnalysisPackageOwner {
    pub(in crate::package) fn prepare_model(
        &self,
        active: &PackageActivationV1,
        context: &InstalledContext,
        bundle: &Arc<InstalledBundle>,
        request: RunPreparation<'_>,
        action: Action,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageCommitV1>> {
        control.check()?;
        let mut now = if action == Action::Inspect {
            Self::clock_tick(request.now)
        } else {
            request.now
        };
        if action == Action::Run && bundle.value.root != context.root {
            return Err(Code::Conflict.error("activation package root").into());
        }
        if action == Action::Inspect {
            if let Some((metadata, _)) =
                self.store
                    .package_current(active, request.now, true, control)?
            {
                let saved: ResultContext = Self::decode(&metadata)?;
                if !Self::clock_changed(
                    context.clock != ClockDependency::None,
                    saved.context.time_utc_ns,
                    request.now,
                ) {
                    return Ok(None);
                }
            }
        }
        let index =
            bundle.export_index(&active.key.package_id, &active.revision, &active.key.export)?;
        let (artifact, model, admitted) = bundle.export_at(index)?;
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
        if context.grant.selection.tenant_id != active.key.tenant_id {
            return Err(Code::Denied.error("model input tenant").into());
        }
        self.check(&context.grant, action)?;
        let prepared = match request.inputs {
            Some(inputs) => Ok(std::sync::Arc::clone(inputs)),
            None => admitted
                .inputs
                .read(
                    self.query.clone(),
                    context.grant.selection.clone(),
                    active.key.scope_id.clone(),
                    control,
                    now,
                )
                .map_err(crate::Error::from),
        };
        let inputs = match prepared {
            Ok(inputs) => inputs,
            Err(error) if action == Action::Inspect && error.missing_input().is_some() => {
                control.check()?;
                self.store.mark_package_stale(active)?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        self.check(&context.grant, action)?;
        control.check()?;
        let unchanged = prior
            .as_ref()
            .is_some_and(|prior| prior.matches(&inputs.inputs));
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
        if action == Action::Inspect {
            return Ok(None);
        }
        let implementation = admitted.implementation(artifact)?;
        let mut metadata = ResultContext::new(request.id, now, model, &inputs.inputs);
        metadata.target = implementation.target().into();
        metadata.artifact = implementation.identity()?;
        if metadata.target == "wasm" {
            metadata.context.limits = self.component_limits(metadata.context.limits);
        }
        let checkpoint = if unchanged && !request.rebuild {
            previous
                .as_ref()
                .filter(|previous| !previous.commit.checkpoint.is_empty())
                .map(|previous| {
                    AnalysisPackageOwner::decode_checkpoint(
                        &AnalysisPackageOwner::decode::<sdk::wire::Checkpoint>(
                            &previous.commit.checkpoint,
                        )?,
                        model,
                    )
                })
                .transpose()?
        } else {
            None
        };
        drop(previous);
        let evaluation = sdk::Evaluation {
            export: model.name.clone(),
            inputs: inputs.inputs.clone(),
            parameters: araphor_data::decode_parameters(
                &model.parameters,
                araphor_data::parameter_values(
                    context.parameters.as_ref(),
                    &active.key.package_id,
                    &active.key.export,
                ),
            )?,
            context: metadata.context.clone(),
            checkpoint,
        };
        let (evaluated, _) = self.evaluate_artifact(
            active.key.tenant_id,
            Arc::clone(bundle),
            index,
            evaluation,
            Some(Arc::clone(&inputs)),
            control,
        )?;
        let mut packet = crate::AnalysisPackageOwner::encode_output(&evaluated.output, model)?;
        let checkpoint = packet
            .checkpoint
            .take()
            .map(|checkpoint| AnalysisPackageOwner::encode(&checkpoint))
            .transpose()?
            .unwrap_or_default();
        let result_id = if request.inputs.is_some() {
            format!(
                "package-{}",
                crate::InputRevision::of(&(
                    &active.key,
                    active.generation,
                    active.checkpoint_revision,
                    &metadata.inputs,
                    &metadata.input_coverage,
                    (context.clock == ClockDependency::Model)
                        .then_some(metadata.context.time_utc_ns),
                ))
                .context(crate::PackageEncodingSnafu)?
            )
        } else {
            AnalysisPackageOwner::result_id(active, request.id)?
        };
        Ok(Some(PackageCommitV1 {
            activation: active.clone(),
            expected_checkpoint_revision: active.checkpoint_revision,
            window_id: "snapshot".into(),
            result_id,
            request: AnalysisPackageOwner::request(active, request.id, context, artifact)?,
            metadata: AnalysisPackageOwner::encode(&metadata)?,
            datasets: AnalysisPackageOwner::encode(&packet)?,
            checkpoint,
            dependencies: inputs.dependencies().cloned().collect(),
            source_revisions: inputs.source_revisions(),
            witnesses: inputs.witnesses().cloned().collect(),
            context_refs: inputs.contexts().cloned().collect(),
            created_utc_ns: metadata.context.time_utc_ns as u64,
        }))
    }

    pub(in crate::package) fn clock_tick(now: u64) -> u64 {
        let period = Self::RECONCILE_INTERVAL.as_nanos() as u64;
        now / period * period
    }

    pub(in crate::package) fn clock_changed(clocked: bool, prior: i64, now: u64) -> bool {
        clocked && Self::clock_tick(prior as u64) != Self::clock_tick(now)
    }
}

#[cfg(test)]
mod tests;
