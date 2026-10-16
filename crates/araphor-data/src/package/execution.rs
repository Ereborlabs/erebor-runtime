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
        admitted: &crate::query::AdmittedExport,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<SqlModelOutputV1> {
        self.query.check_analysis_input(evaluation)?;
        match artifact.implementation(&evaluation.export)? {
            PackageImplementationV1::Sql { .. } => self
                .query
                .model_operation(tenant)
                .evaluate_admitted(&artifact.descriptor, admitted, evaluation, control),
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
                    self.native.admit(artifact, qualification)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}
