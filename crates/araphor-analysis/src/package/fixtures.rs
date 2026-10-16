use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::{AnalysisReadControl, Result};

use super::owner::InstalledContext;
use super::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code, PackageGrantV1,
    PackageResponseV1, PackageTestResultV1,
};

mod comparison;
#[cfg(test)]
mod tests;

impl AnalysisPackageOwner {
    pub(super) fn test_package(
        &self,
        grant: &PackageGrantV1,
        scope: &str,
        package: &str,
        name: Option<&str>,
        control: &AnalysisReadControl,
    ) -> Result<PackageResponseV1> {
        self.check(grant, Action::Test)?;
        let activations = self.activations(grant.selection.tenant_id, scope, package)?;
        let active = activations
            .first()
            .ok_or_else(|| Code::Missing.error("installed package"))?;
        let context: InstalledContext = Self::decode(&active.metadata)?;
        let bundle = self.load_installed(grant.selection.tenant_id, &context.root)?;
        let admitted = bundle.admission();
        self.authority.admit(grant, &admitted)?;
        let mut response = self.inspect(grant, scope, package, Some(&bundle), control)?;
        for artifact in bundle
            .value
            .artifacts
            .iter()
            .filter(|artifact| artifact.descriptor.id == package)
        {
            for fixture in artifact
                .fixtures
                .iter()
                .filter(|fixture| name.is_none_or(|name| name == fixture.name))
            {
                let (_, model, program) = bundle.export(
                    &artifact.descriptor.id,
                    &artifact.descriptor.revision,
                    &fixture.export,
                )?;
                let mut inputs = Vec::new();
                for input in &fixture.inputs {
                    let port = model
                        .inputs
                        .iter()
                        .map(|input| &input.port)
                        .find(|port| port.name == input.data.name)
                        .ok_or_else(|| Code::Invalid.error("fixture input"))?;
                    inputs.push(sdk::Input {
                        data: input
                            .data
                            .decode(&port.schema, model.limits)
                            .context(crate::AnalysisContractSnafu)?,
                        revision: input.revision.clone(),
                        coverage: input.coverage.clone(),
                    });
                }
                let evaluation = sdk::Evaluation {
                    export: model.name.clone(),
                    inputs,
                    parameters: araphor_data::decode_parameters(
                        &model.parameters,
                        fixture.parameters.as_ref(),
                    )?,
                    context: sdk::EvaluationContext {
                        id: format!("fixture:{}", fixture.name),
                        time_utc_ns: fixture.time_utc_ns,
                        seed: fixture.seed,
                        limits: model.limits,
                    },
                    checkpoint: fixture
                        .checkpoint
                        .as_ref()
                        .map(|checkpoint| Self::decode_checkpoint(checkpoint, model))
                        .transpose()?,
                };
                control.check()?;
                self.check(grant, Action::Test)?;
                self.authority.admit(grant, &admitted)?;
                let output = self.evaluate_artifact(
                    grant.selection.tenant_id,
                    artifact,
                    program,
                    &evaluation,
                    control,
                )?;
                let expected = Self::decode_output(&fixture.expected, model)?;
                artifact
                    .descriptor
                    .validate_output(&evaluation, &expected)
                    .context(crate::AnalysisContractSnafu)?;
                response.tests.push(PackageTestResultV1 {
                    fixture: fixture.name.clone(),
                    passed: comparison::output(&output.output, &expected, model),
                });
            }
        }
        if name.is_some() && response.tests.is_empty() {
            return Err(Code::Missing.error("package fixture").into());
        }
        self.check(grant, Action::Test)?;
        Ok(response)
    }
}
