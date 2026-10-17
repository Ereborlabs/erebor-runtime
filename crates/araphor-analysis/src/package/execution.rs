use std::borrow::Cow;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::model::{AdmittedExport, ModelRun};
use crate::{AnalysisReadControl, Result, SqlModelOutputV1};

use super::{
    AnalysisPackageOwner, PackageArtifactV1, PackageErrorCodeV1 as Code, PackageImplementationV1,
};

impl AnalysisPackageOwner {
    pub(super) fn evaluate_artifact(
        &self,
        tenant: [u8; 16],
        artifact: &PackageArtifactV1,
        admitted: &AdmittedExport,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<SqlModelOutputV1> {
        let implementation = admitted.implementation(artifact)?;
        let run = ModelRun::new(&self.query, tenant, control)?;
        self.execute_model(
            run,
            &artifact.descriptor,
            implementation,
            admitted,
            evaluation,
            control,
        )
    }

    pub(super) fn execute_model(
        &self,
        run: ModelRun<'_>,
        package: &sdk::Package,
        implementation: &PackageImplementationV1,
        admitted: &AdmittedExport,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<SqlModelOutputV1> {
        if matches!(implementation, PackageImplementationV1::Sql { .. }) {
            return run.evaluate_admitted(package, admitted, evaluation);
        }
        let preflight = self.exchange_preflight(package, evaluation)?;
        let tenant = run.tenant();
        let inputs = run.inputs.clone();
        drop(run);
        let bounded = if matches!(implementation, PackageImplementationV1::Wasm { .. }) {
            let limits = self.component_limits(evaluation.context.limits);
            if limits == evaluation.context.limits {
                Cow::Borrowed(evaluation)
            } else {
                let mut bounded = evaluation.clone();
                bounded.context.limits = limits;
                Cow::Owned(bounded)
            }
        } else {
            Cow::Borrowed(evaluation)
        };
        let checked = package
            .check_evaluation(&bounded)
            .context(crate::AnalysisContractSnafu)?;
        let model = checked.model();
        let requested =
            bounded
                .context
                .limits
                .max_bytes
                .saturating_add(if model.checkpoint.is_some() {
                    bounded.context.limits.max_checkpoint_bytes
                } else {
                    0
                });
        let capacity = (requested as usize).min(self.query.limits().output_capacity);
        let _permit = self.query.reserve_evaluation(tenant)?;
        let input_memory = self.query.memory().reserve_input(preflight)?;
        let output_memory = self.query.memory().reserve_output(capacity)?;
        control.check()?;
        let retained = bounded.allocated_bytes();
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
                            limit: self.query.limits().input_capacity,
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
                    .decode(package, &bounded)
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
                    max_bytes: bounded.context.limits.max_bytes.min(capacity as u64),
                    max_checkpoint_bytes: bounded
                        .context
                        .limits
                        .max_checkpoint_bytes
                        .min(capacity as u64),
                    ..bounded.context.limits
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
        SqlModelOutputV1::retain(output, self.query.memory(), output_memory)
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
