use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Checkpoint, Dataset, Error, ErrorCode, Evaluation, Model, Output, Package, Port, Result,
    RowRef, Schema,
};

mod batch;

pub trait Guest {
    fn package() -> Package;
    fn compute(input: &CheckedEvaluation<'_>) -> Result<Output>;

    fn evaluate(evaluation: &Evaluation) -> Result<Output> {
        Self::package()
            .check_evaluation(evaluation)?
            .evaluate(Self::compute)
    }
}

impl Package {
    pub fn check_evaluation<'a>(
        &'a self,
        evaluation: &'a Evaluation,
    ) -> Result<CheckedEvaluation<'a>> {
        let model = self.validator(evaluation)?;
        model.input(evaluation)?;
        Ok(CheckedEvaluation::new(self, model, evaluation))
    }

    pub fn validate_evaluation(&self, evaluation: &Evaluation) -> Result<()> {
        self.check_evaluation(evaluation).map(|_| ())
    }

    pub fn validate_output(&self, evaluation: &Evaluation, output: &Output) -> Result<()> {
        self.check_evaluation(evaluation)?.validate_output(output)
    }

    pub fn validate_retained_output(
        &self,
        export: &str,
        inputs: &BTreeMap<String, u64>,
        output: &Output,
    ) -> Result<()> {
        let model = self.wire_validator(export)?;
        if inputs.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != model
                .inputs
                .iter()
                .map(|input| input.port.name.as_str())
                .collect()
        {
            return Err(Error::contract(ErrorCode::Invalid, "retained input names"));
        }
        model.output_rows(inputs, output)
    }

    pub(crate) fn validator(&self, evaluation: &Evaluation) -> Result<&Model> {
        self.validate()?;
        self.select_validator(&evaluation.export)
    }

    pub(crate) fn wire_validator(&self, export: &str) -> Result<&Model> {
        self.validate()?;
        self.select_validator(export)
    }

    fn select_validator(&self, export: &str) -> Result<&Model> {
        let model = self
            .exports
            .iter()
            .find(|model| model.name == export)
            .ok_or_else(|| Error::contract(ErrorCode::Incompatible, "export"))?;
        Ok(model)
    }
}

/// Borrowed package and input that passed the SDK contract checks.
pub struct CheckedEvaluation<'a> {
    evaluation: &'a Evaluation,
    package: &'a Package,
    model: &'a Model,
}

impl<'a> CheckedEvaluation<'a> {
    pub(crate) fn new(package: &'a Package, model: &'a Model, evaluation: &'a Evaluation) -> Self {
        Self {
            package,
            model,
            evaluation,
        }
    }

    pub fn package(&self) -> &Package {
        self.package
    }

    pub fn evaluation(&self) -> &Evaluation {
        self.evaluation
    }

    pub fn model(&self) -> &Model {
        self.model
    }

    pub fn validate_output(&self, output: &Output) -> Result<()> {
        self.model.output(self.evaluation, output)
    }

    pub fn evaluate(&self, compute: impl FnOnce(&Self) -> Result<Output>) -> Result<Output> {
        let output = compute(self)?;
        self.validate_output(&output)?;
        Ok(output)
    }
}

impl Model {
    pub(crate) fn input(&self, evaluation: &Evaluation) -> Result<()> {
        Package::text(&evaluation.context.id)?;
        match (&evaluation.parameters, self.parameters.fields().is_empty()) {
            (None, true) => {}
            (Some(parameters), false) if parameters.num_rows() == 1 => {
                batch::validate(parameters, &self.parameters)?;
            }
            _ => return Err(Error::contract(ErrorCode::Invalid, "parameters")),
        }
        Self::datasets(
            self.inputs.iter().map(|input| &input.port),
            evaluation.inputs.iter().map(|input| &input.data),
        )?;
        for input in &evaluation.inputs {
            Package::name(&input.revision.owner)?;
            Package::text(&input.revision.id)?;
            if let Some(window) = &input.revision.window {
                if window.source.is_empty() || window.start_utc_ns > window.end_utc_ns {
                    return Err(Error::contract(ErrorCode::Invalid, "source window"));
                }
            }
            for reason in &input.coverage.limits {
                Package::text(reason)?;
            }
        }
        self.checkpoint(evaluation.checkpoint.as_ref(), false)
    }

    pub(crate) fn output(&self, evaluation: &Evaluation, output: &Output) -> Result<()> {
        let inputs = evaluation
            .inputs
            .iter()
            .map(|input| (input.data.name.clone(), input.data.rows()))
            .collect();
        self.output_rows(&inputs, output)
    }

    fn output_rows(&self, inputs: &BTreeMap<String, u64>, output: &Output) -> Result<()> {
        let outputs = Self::datasets(self.outputs.iter(), output.datasets.iter())?;
        let inputs = inputs
            .iter()
            .map(|(name, rows)| (name.as_str(), *rows))
            .collect();
        let mut evidence = BTreeSet::new();
        for link in &output.evidence {
            Self::reference(&link.output, &outputs)?;
            Self::reference(&link.input, &inputs)?;
            if !evidence.insert(link) {
                return Err(Error::contract(ErrorCode::Invalid, "duplicate evidence"));
            }
        }
        let cited: BTreeSet<_> = evidence.iter().map(|link| &link.output).collect();
        for port in self.outputs.iter().filter(|port| port.evidence_required) {
            let count = cited
                .iter()
                .filter(|reference| reference.dataset == port.name)
                .count() as u64;
            if count != outputs[port.name.as_str()] {
                return Err(Error::contract(
                    ErrorCode::Incomplete,
                    "required output evidence",
                ));
            }
        }
        let mut reasons = BTreeSet::new();
        for value in &output.reasons {
            Self::reference(&value.output, &outputs)?;
            if !reasons.insert((&value.output, &value.code)) {
                return Err(Error::contract(ErrorCode::Invalid, "duplicate reason"));
            }
            let reason = self
                .reasons
                .iter()
                .find(|reason| reason.code == value.code)
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "reason code"))?;
            if value.details.num_rows() != 1 {
                return Err(Error::contract(ErrorCode::Invalid, "reason detail rows"));
            }
            batch::validate(&value.details, &reason.details)?;
        }
        self.checkpoint(output.checkpoint.as_ref(), true)
    }

    fn datasets<'a, 'p>(
        ports: impl Clone + ExactSizeIterator<Item = &'p Port>,
        datasets: impl Iterator<Item = &'a Dataset>,
    ) -> Result<BTreeMap<&'a str, u64>> {
        let mut seen = BTreeMap::new();
        for dataset in datasets {
            if seen.contains_key(dataset.name.as_str()) {
                return Err(Error::contract(ErrorCode::Invalid, "duplicate dataset"));
            }
            let port = ports
                .clone()
                .find(|port| port.name == dataset.name)
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "undeclared dataset"))?;
            let rows = dataset.validate_schema(&port.schema)?;
            seen.insert(dataset.name.as_str(), rows);
        }
        if seen.len() != ports.len() {
            return Err(Error::contract(ErrorCode::Incomplete, "missing dataset"));
        }
        Ok(seen)
    }

    fn reference(reference: &RowRef, rows: &BTreeMap<&str, u64>) -> Result<()> {
        if !rows
            .get(reference.dataset.as_str())
            .is_some_and(|count| reference.row < *count)
        {
            return Err(Error::contract(
                ErrorCode::Invalid,
                "evidence or reason reference",
            ));
        }
        Ok(())
    }

    fn checkpoint(&self, checkpoint: Option<&Checkpoint>, required: bool) -> Result<()> {
        match (&self.checkpoint, checkpoint) {
            (None, None) => Ok(()),
            (Some(_), None) if !required => Ok(()),
            (Some(spec), Some(checkpoint)) if spec.version == checkpoint.version => {
                Self::datasets(spec.datasets.iter(), checkpoint.datasets.iter())?;
                Ok(())
            }
            _ => Err(Error::contract(ErrorCode::Incompatible, "checkpoint")),
        }
    }
}

impl Dataset {
    pub fn validate(&self, port: &Port) -> Result<()> {
        Self::validate_all(std::slice::from_ref(self), std::slice::from_ref(port))
    }

    pub fn validate_all(datasets: &[Self], ports: &[Port]) -> Result<()> {
        Model::ports(ports.iter())?;
        Model::datasets(ports.iter(), datasets.iter())?;
        Ok(())
    }

    fn validate_schema(&self, schema: &Schema) -> Result<u64> {
        let mut rows = 0_u64;
        for batch in &self.batches {
            batch::validate(batch, schema)?;
            rows = rows
                .checked_add(batch.num_rows() as u64)
                .ok_or_else(|| Error::contract(ErrorCode::Limit, "dataset rows"))?;
        }
        Ok(rows)
    }

    pub fn rows(&self) -> u64 {
        self.batches
            .iter()
            .map(|batch| batch.num_rows() as u64)
            .sum()
    }
}

#[cfg(test)]
mod retained_tests;
