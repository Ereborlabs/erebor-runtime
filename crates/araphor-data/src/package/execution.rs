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
                self.wasm.admit(bytes, control)?;
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
                        let output = self.wasm.evaluate_encoded(
                            &artifact.descriptor,
                            &bounded,
                            bytes,
                            input,
                            control,
                        )?;
                        let bytes = output.allocated_bytes();
                        Ok((output, bytes))
                    },
                )
            }
            _ => Err(Code::Unsupported.error("model target")),
        }
    }

    pub(super) fn admit_artifact(
        &self,
        artifact: &PackageArtifactV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        for model in &artifact.descriptor.exports {
            control.check()?;
            match artifact.implementation(&model.name) {
                Ok(PackageImplementationV1::Sql { program, .. }) => {
                    crate::QueryOwner::admit_model(model, program)?;
                }
                Ok(PackageImplementationV1::Wasm { artifact, .. }) => {
                    self.wasm.admit(artifact, control)?;
                }
                Err(crate::Error::Package {
                    code: Code::Unsupported,
                    ..
                }) => continue,
                Err(error) => return Err(error),
                _ => return Err(Code::Unsupported.error("model target")),
            }
            if let Some(inputs) = artifact.implementation(&model.name)?.bindings() {
                for sql in inputs.values() {
                    crate::QuerySql::admit(sql, Vec::new(), false)?;
                }
            }
        }
        Ok(())
    }
}
