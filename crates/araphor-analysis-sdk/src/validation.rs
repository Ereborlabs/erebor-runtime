use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Checkpoint, Dataset, Error, ErrorCode, Evaluation, Limits, Model, Output, Package, Port,
    Result, RowRef, Schema,
};

mod batch;
use batch::BatchBudget;

impl Package {
    pub fn check_evaluation<'a>(
        &'a self,
        evaluation: &'a Evaluation,
    ) -> Result<CheckedEvaluation<'a>> {
        self.validator(evaluation)?.check(evaluation)
    }

    pub fn validate_evaluation(&self, evaluation: &Evaluation) -> Result<()> {
        self.check_evaluation(evaluation).map(|_| ())
    }

    pub fn validate_output(&self, evaluation: &Evaluation, output: &Output) -> Result<()> {
        self.check_evaluation(evaluation)?.validate_output(output)
    }

    pub(crate) fn validator(&self, evaluation: &Evaluation) -> Result<ContractValidator<'_>> {
        self.validate()?;
        self.select_validator(&evaluation.export, evaluation.context.limits)
    }

    pub(crate) fn wire_validator(
        &self,
        export: &str,
        limits: Limits,
    ) -> Result<ContractValidator<'_>> {
        self.validate()?;
        limits.validate()?;
        self.select_validator(export, limits)
    }

    fn select_validator(&self, export: &str, limits: Limits) -> Result<ContractValidator<'_>> {
        let model = self
            .exports
            .iter()
            .find(|model| model.name == export)
            .ok_or_else(|| Error::contract(ErrorCode::Incompatible, "export"))?;
        limits.validate()?;
        if !model.limits.permits(&limits) {
            return Err(Error::contract(ErrorCode::Limit, "evaluation limits"));
        }
        Ok(ContractValidator {
            package: self,
            model,
            limits,
        })
    }
}

/// Borrowed package and input that passed the SDK contract checks.
pub struct CheckedEvaluation<'a> {
    evaluation: &'a Evaluation,
    validator: ContractValidator<'a>,
}

impl CheckedEvaluation<'_> {
    pub fn package(&self) -> &Package {
        self.validator.package
    }

    pub fn evaluation(&self) -> &Evaluation {
        self.evaluation
    }

    pub fn model(&self) -> &Model {
        self.validator.model
    }

    pub fn validate_output(&self, output: &Output) -> Result<()> {
        self.validator.output(self.evaluation, output)
    }
}

pub(crate) struct ContractValidator<'a> {
    package: &'a Package,
    pub(crate) model: &'a Model,
    limits: Limits,
}

impl<'contract> ContractValidator<'contract> {
    pub(crate) fn check(
        self,
        evaluation: &'contract Evaluation,
    ) -> Result<CheckedEvaluation<'contract>> {
        self.input(evaluation)?;
        Ok(self.checked(evaluation))
    }

    pub(crate) fn checked(self, evaluation: &'contract Evaluation) -> CheckedEvaluation<'contract> {
        CheckedEvaluation {
            evaluation,
            validator: self,
        }
    }

    pub(crate) fn input(&self, evaluation: &Evaluation) -> Result<()> {
        Package::text(&evaluation.context.id)?;
        let mut budget = BatchBudget::new(self.limits.max_bytes, &self.limits);
        budget.bytes((evaluation.context.id.len() + evaluation.export.len() + 64) as u64)?;
        match (
            &evaluation.parameters,
            self.model.parameters.fields().is_empty(),
        ) {
            (None, true) => {}
            (Some(parameters), false) if parameters.num_rows() == 1 => {
                budget.batch(parameters, &self.model.parameters)?;
            }
            _ => return Err(Error::contract(ErrorCode::Invalid, "parameters")),
        }
        Self::datasets(
            self.model.inputs.iter().map(|input| &input.port),
            evaluation.inputs.iter().map(|input| &input.data),
            &mut budget,
        )?;
        for input in &evaluation.inputs {
            Package::name(&input.revision.owner)?;
            Package::text(&input.revision.id)?;
            if let Some(window) = &input.revision.window {
                if window.source.is_empty()
                    || window.source.len() > 4096
                    || window.start_utc_ns > window.end_utc_ns
                {
                    return Err(Error::contract(ErrorCode::Invalid, "source window"));
                }
                budget.bytes(window.source.len() as u64)?;
            }
            if input.coverage.limits.len() > 128 {
                return Err(Error::contract(ErrorCode::Limit, "coverage limits"));
            }
            budget.bytes((input.revision.owner.len() + input.revision.id.len()) as u64)?;
            for reason in &input.coverage.limits {
                Package::text(reason)?;
                budget.bytes(reason.len() as u64)?;
            }
        }
        self.checkpoint(evaluation.checkpoint.as_ref(), false)
    }

    pub(crate) fn output(&self, evaluation: &Evaluation, output: &Output) -> Result<()> {
        let mut budget = BatchBudget::new(self.limits.max_bytes, &self.limits);
        let outputs = Self::datasets(
            self.model.outputs.iter(),
            output.datasets.iter(),
            &mut budget,
        )?;
        let inputs: BTreeMap<_, _> = evaluation
            .inputs
            .iter()
            .map(|input| (input.data.name.as_str(), input.data.rows()))
            .collect();
        let mut evidence = BTreeSet::new();
        for link in &output.evidence {
            Self::reference(&link.output, &outputs)?;
            Self::reference(&link.input, &inputs)?;
            if !evidence.insert(link) {
                return Err(Error::contract(ErrorCode::Invalid, "duplicate evidence"));
            }
            budget.bytes((link.output.dataset.len() + link.input.dataset.len() + 16) as u64)?;
        }
        let cited: BTreeSet<_> = evidence.iter().map(|link| &link.output).collect();
        for port in self
            .model
            .outputs
            .iter()
            .filter(|port| port.evidence_required)
        {
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
                .model
                .reasons
                .iter()
                .find(|reason| reason.code == value.code)
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "reason code"))?;
            if value.details.num_rows() != 1 {
                return Err(Error::contract(ErrorCode::Invalid, "reason detail rows"));
            }
            budget.batch(&value.details, &reason.details)?;
            budget.bytes((value.output.dataset.len() + value.code.len() + 8) as u64)?;
        }
        self.checkpoint(output.checkpoint.as_ref(), true)
    }

    fn datasets<'a, 'p>(
        ports: impl Clone + ExactSizeIterator<Item = &'p Port>,
        datasets: impl Iterator<Item = &'a Dataset>,
        budget: &mut BatchBudget,
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
            let rows = dataset.validate_budget(&port.schema, budget)?;
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
        match (&self.model.checkpoint, checkpoint) {
            (None, None) => Ok(()),
            (Some(_), None) if !required => Ok(()),
            (Some(spec), Some(checkpoint)) if spec.version == checkpoint.version => {
                let mut budget = BatchBudget::new(self.limits.max_checkpoint_bytes, &self.limits);
                Self::datasets(
                    spec.datasets.iter(),
                    checkpoint.datasets.iter(),
                    &mut budget,
                )?;
                Ok(())
            }
            _ => Err(Error::contract(ErrorCode::Incompatible, "checkpoint")),
        }
    }
}

impl Dataset {
    pub fn validate(&self, port: &Port, limits: Limits) -> Result<()> {
        Self::validate_all(
            std::slice::from_ref(self),
            std::slice::from_ref(port),
            limits,
        )
    }

    pub fn validate_all(datasets: &[Self], ports: &[Port], limits: Limits) -> Result<()> {
        limits.validate()?;
        Model::ports(ports.iter())?;
        ContractValidator::datasets(
            ports.iter(),
            datasets.iter(),
            &mut BatchBudget::new(limits.max_bytes, &limits),
        )?;
        Ok(())
    }

    fn validate_budget(&self, schema: &Schema, budget: &mut BatchBudget) -> Result<u64> {
        let mut rows = 0_u64;
        budget.bytes(self.name.len() as u64)?;
        for batch in &self.batches {
            budget.batch(batch, schema)?;
            rows = rows
                .checked_add(batch.num_rows() as u64)
                .ok_or_else(|| Error::contract(ErrorCode::Limit, "dataset rows"))?;
        }
        Ok(rows)
    }

    pub(crate) fn rows(&self) -> u64 {
        self.batches
            .iter()
            .map(|batch| batch.num_rows() as u64)
            .sum()
    }
}
