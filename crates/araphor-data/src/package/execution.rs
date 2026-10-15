use std::borrow::Cow;

use araphor_analysis_sdk as sdk;

use crate::{AnalysisReadControl, Result, SqlModelOutputV1};

use super::{
    AnalysisPackageOwner, PackageArtifactV1, PackageErrorCodeV1 as Code, PackageImplementationV1,
};

impl AnalysisPackageOwner {
    pub(super) fn evaluate_artifact(
        &self,
        tenant: [u8; 16],
        artifact: &PackageArtifactV1,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<SqlModelOutputV1> {
        self.query.check_analysis_input(evaluation)?;
        match artifact.implementation(&evaluation.export)? {
            PackageImplementationV1::Sql { program, .. } => self.query.evaluate_model(
                tenant,
                &artifact.descriptor,
                program,
                evaluation,
                control,
            ),
            PackageImplementationV1::Wasm {
                artifact: bytes, ..
            } => {
                let prepared = self.wasm.prepare(bytes, control)?;
                let limits = self.query.component_limits(evaluation.context.limits);
                let bounded = if limits == evaluation.context.limits {
                    Cow::Borrowed(evaluation)
                } else {
                    let mut bounded = evaluation.clone();
                    bounded.context.limits = limits;
                    Cow::Owned(bounded)
                };
                self.query.evaluate_component(
                    tenant,
                    &artifact.descriptor,
                    &bounded,
                    control,
                    |control, _limits, input| {
                        let output = self.wasm.evaluate_prepared(
                            &artifact.descriptor,
                            &bounded,
                            prepared,
                            input,
                            control,
                        )?;
                        let bytes = output.allocated_bytes();
                        Ok((output, bytes))
                    },
                )
            }
            PackageImplementationV1::Native {
                artifact: bytes,
                qualification: Some(qualification),
                ..
            } => self.query.evaluate_native(
                tenant,
                &artifact.descriptor,
                evaluation,
                control,
                |control, limits| {
                    let output_limits = sdk::Limits {
                        max_bytes: evaluation
                            .context
                            .limits
                            .max_bytes
                            .min(limits.output_capacity as u64),
                        max_checkpoint_bytes: evaluation
                            .context
                            .limits
                            .max_checkpoint_bytes
                            .min(limits.output_capacity as u64),
                        ..evaluation.context.limits
                    };
                    let output = self.native.evaluate(
                        &artifact.descriptor,
                        evaluation,
                        bytes,
                        qualification,
                        output_limits,
                        control,
                    )?;
                    let bytes = output.allocated_bytes();
                    Ok((output, bytes))
                },
            ),
            _ => Err(Code::Unsupported.error("model target")),
        }
    }

    pub(super) fn admit_artifact(
        &self,
        artifact: &PackageArtifactV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let mut admitted = Vec::new();
        for model in &artifact.descriptor.exports {
            control.check()?;
            match artifact.implementation(&model.name) {
                Ok(PackageImplementationV1::Sql { program, .. }) => {
                    crate::QueryOwner::admit_model(model, program)?;
                }
                Ok(implementation @ PackageImplementationV1::Wasm { artifact, .. }) => {
                    if !admitted
                        .iter()
                        .any(|previous| std::ptr::eq(*previous, implementation))
                    {
                        self.wasm.admit(artifact, control)?;
                        admitted.push(implementation);
                    }
                }
                Ok(
                    implementation @ PackageImplementationV1::Native {
                        artifact,
                        qualification: Some(qualification),
                        ..
                    },
                ) => {
                    if !admitted
                        .iter()
                        .any(|previous| std::ptr::eq(*previous, implementation))
                    {
                        self.native.admit(artifact, qualification)?;
                        admitted.push(implementation);
                    }
                }
                Err(crate::Error::Package {
                    code: Code::Unsupported,
                    ..
                }) => continue,
                Err(error) => return Err(error),
                _ => return Err(Code::Unsupported.error("model target")),
            }
            crate::QueryOwner::admit_inputs(model)?;
        }
        Ok(())
    }
}
