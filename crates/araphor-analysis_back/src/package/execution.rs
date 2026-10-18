use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_query::inputs::InputSet;
use araphor_query::memory::Memory;
use snafu::ResultExt as _;

use crate::model::ModelRun;
use crate::{AnalysisReadControl, Result, SqlModelOutputV1};

use super::installed::snapshot::InstalledBundle;
use super::{
    AnalysisPackageOwner, PackageArtifactV1, PackageErrorCodeV1 as Code, PackageImplementationV1,
};

impl AnalysisPackageOwner {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn evaluate_artifact(
        &self,
        tenant: [u8; 16],
        bundle: Arc<InstalledBundle>,
        index: (usize, usize),
        mut evaluation: sdk::Evaluation,
        inputs: Option<Arc<InputSet>>,
        memory: &Arc<Memory>,
        control: &AnalysisReadControl,
    ) -> Result<(SqlModelOutputV1, sdk::Evaluation)> {
        let (artifact, _, admitted) = bundle.export_at(index)?;
        let implementation = admitted.implementation(artifact)?;
        if inputs
            .as_ref()
            .and_then(|inputs| inputs.snapshot.as_ref())
            .is_some_and(|snapshot| snapshot.selection.tenant_id != tenant)
        {
            return Err(Code::Denied.error("model input tenant").into());
        }
        control.check()?;
        if matches!(implementation, PackageImplementationV1::Sql { .. }) {
            let owner = Arc::clone(&self.query);
            let memory = Arc::clone(memory);
            let control = control.within(control.remaining()?)?;
            return self.query.wait(async move {
                let result: Result<_> = async {
                    let (artifact, _, admitted) = bundle.export_at(index)?;
                    let output = ModelRun::evaluate(
                        &owner,
                        &memory,
                        tenant,
                        &control,
                        &artifact.descriptor,
                        admitted,
                        &evaluation,
                        inputs,
                    )
                    .await?;
                    Ok((output, evaluation))
                }
                .await;
                Ok(result)
            })?;
        }
        let package = &artifact.descriptor;
        let preflight = self.exchange_preflight(package, &evaluation)?;
        if matches!(implementation, PackageImplementationV1::Wasm { .. }) {
            evaluation.context.limits = self.component_limits(evaluation.context.limits);
        }
        let checked = package
            .check_evaluation(&evaluation)
            .context(crate::AnalysisContractSnafu)?;
        let model = checked.model();
        let requested =
            evaluation
                .context
                .limits
                .max_bytes
                .saturating_add(if model.checkpoint.is_some() {
                    evaluation.context.limits.max_checkpoint_bytes
                } else {
                    0
                });
        let capacity = self
            .query
            .limits()
            .output_capacity
            .map_or(requested, |capacity| requested.min(capacity as u64));
        let capacity = usize::try_from(capacity)
            .map_err(|_| Code::Invalid.error("component output allocation"))?;
        let _permit = self.query.reserve_evaluation(tenant)?;
        let input_memory = memory.reserve_input(preflight)?;
        let output_memory = memory.reserve_output(capacity)?;
        control.check()?;
        let retained = evaluation.allocated_bytes();
        let (output, control) = match implementation {
            PackageImplementationV1::Wasm { artifact, .. } => {
                let prepared = self.wasm.prepare(artifact, control)?;
                let control = control.within(self.query.limits().evaluate_timeout)?;
                let input = checked.encode().context(crate::AnalysisContractSnafu)?;
                let bytes = retained
                    .checked_add(input.allocated_bytes())
                    .ok_or_else(|| {
                        crate::ModelLimitSnafu {
                            resource: "component input allocation",
                            limit: self.query.limits().input_bytes,
                        }
                        .build()
                    })?;
                input_memory.try_resize(bytes)?;
                control.check()?;
                if let Some(inputs) = &inputs {
                    inputs.check(&self.query, &control)?;
                }
                let output = self.wasm.invoke(&prepared, input.into(), &control)?;
                let decoded = sdk::wire::Output::from(output)
                    .decode(package, &evaluation)
                    .context(crate::AnalysisContractSnafu)?;
                control.check()?;
                (decoded, control)
            }
            PackageImplementationV1::Native {
                artifact,
                qualification: Some(qualification),
                ..
            } => {
                let control = control.within(self.query.limits().evaluate_timeout)?;
                let limits = sdk::Limits {
                    max_bytes: evaluation.context.limits.max_bytes.min(capacity as u64),
                    max_checkpoint_bytes: evaluation
                        .context
                        .limits
                        .max_checkpoint_bytes
                        .min(capacity as u64),
                    ..evaluation.context.limits
                };
                control.check()?;
                self.limits.native.validate()?;
                let loaded = super::native::NativeLibrary::load(artifact, qualification, &control);
                control.check()?;
                let loaded = loaded?;
                if let Some(inputs) = &inputs {
                    inputs.check(&self.query, &control)?;
                }
                let output = loaded.call(&checked, limits, &control)?;
                (output, control)
            }
            _ => return Err(Code::Unsupported.error("model target").into()),
        };
        input_memory.try_resize(retained)?;
        checked
            .validate_output(&output)
            .context(crate::AnalysisContractSnafu)?;
        let bytes = SqlModelOutputV1::owned_bytes(&output, output.allocated_bytes());
        if bytes > capacity {
            return crate::ModelLimitSnafu {
                resource: "query output bytes",
                limit: capacity,
            }
            .fail();
        }
        control.check()?;
        if let Some(inputs) = &inputs {
            inputs.check(&self.query, &control)?;
        }
        let output = SqlModelOutputV1::retain(output, memory, output_memory)?;
        Ok((output, evaluation))
    }

    pub(super) fn admit_artifact(
        &self,
        artifact: &PackageArtifactV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        for implementation in &artifact.implementations {
            control.check()?;
            match implementation {
                PackageImplementationV1::Wasm { artifact, .. } => {
                    self.wasm.admit(artifact, control)?;
                }
                PackageImplementationV1::Native {
                    artifact,
                    qualification: Some(qualification),
                    ..
                } => {
                    self.limits.native.validate()?;
                    super::native::NativeAdmission::validate(qualification, artifact)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}
