use std::collections::BTreeMap;

use crate::{Coverage, Evaluation, EvaluationContext, Output, Package, Result, Revision};

#[derive(Clone, Debug)]
pub struct Fixture {
    pub implementation: String,
    pub revision: String,
    pub evaluation: Evaluation,
}

#[derive(Debug)]
pub struct FixtureReport {
    pub package_id: String,
    pub package_revision: String,
    pub export: String,
    pub implementation: String,
    pub fixture_revision: String,
    pub context: EvaluationContext,
    pub inputs: BTreeMap<String, (Revision, Coverage)>,
    pub output: Output,
}

impl Package {
    pub fn test(
        &self,
        fixture: &Fixture,
        algorithm: impl FnOnce(&Evaluation) -> Result<Output>,
    ) -> Result<FixtureReport> {
        Self::text(&fixture.implementation)?;
        Self::text(&fixture.revision)?;
        let validator = self.validator(&fixture.evaluation)?;
        validator.input(&fixture.evaluation)?;
        let output = algorithm(&fixture.evaluation)?;
        validator.output(&fixture.evaluation, &output)?;
        Ok(FixtureReport {
            package_id: self.id.clone(),
            package_revision: self.revision.clone(),
            export: fixture.evaluation.export.clone(),
            implementation: fixture.implementation.clone(),
            fixture_revision: fixture.revision.clone(),
            context: fixture.evaluation.context.clone(),
            inputs: fixture
                .evaluation
                .inputs
                .iter()
                .map(|input| {
                    (
                        input.data.name.clone(),
                        (input.revision.clone(), input.coverage.clone()),
                    )
                })
                .collect(),
            output,
        })
    }
}
