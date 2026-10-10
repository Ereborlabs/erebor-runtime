use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Checkpoint, Dataset, Error, ErrorCode, Evaluation, Limits, Model, Output, Package, Port,
    Result, RowRef,
};

mod batch;
use batch::BatchBudget;

impl Package {
    pub fn validate_evaluation(&self, evaluation: &Evaluation) -> Result<()> {
        self.validator(evaluation)?.input(evaluation)
    }

    pub fn validate_output(&self, evaluation: &Evaluation, output: &Output) -> Result<()> {
        let validator = self.validator(evaluation)?;
        validator.input(evaluation)?;
        validator.output(evaluation, output)
    }

    pub(crate) fn validator(&self, evaluation: &Evaluation) -> Result<ContractValidator<'_>> {
        self.validate()?;
        let model = self
            .exports
            .iter()
            .find(|model| model.name == evaluation.export)
            .ok_or_else(|| Error::contract(ErrorCode::Incompatible, "export"))?;
        evaluation.context.limits.validate()?;
        if !model.limits.permits(&evaluation.context.limits) {
            return Err(Error::contract(ErrorCode::Limit, "evaluation limits"));
        }
        Ok(ContractValidator {
            model,
            limits: evaluation.context.limits,
        })
    }
}

pub(crate) struct ContractValidator<'a> {
    model: &'a Model,
    limits: Limits,
}

impl ContractValidator<'_> {
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
        self.datasets(
            &self.model.inputs,
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
        let outputs = self.datasets(&self.model.outputs, output.datasets.iter(), &mut budget)?;
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

    fn datasets<'a>(
        &self,
        ports: &[Port],
        datasets: impl Iterator<Item = &'a Dataset>,
        budget: &mut BatchBudget,
    ) -> Result<BTreeMap<&'a str, u64>> {
        let mut seen = BTreeMap::new();
        for dataset in datasets {
            if seen.contains_key(dataset.name.as_str()) {
                return Err(Error::contract(ErrorCode::Invalid, "duplicate dataset"));
            }
            let port = ports
                .iter()
                .find(|port| port.name == dataset.name)
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "undeclared dataset"))?;
            let mut rows = 0_u64;
            budget.bytes(dataset.name.len() as u64)?;
            for batch in &dataset.batches {
                budget.batch(batch, &port.schema)?;
                rows = rows
                    .checked_add(batch.num_rows() as u64)
                    .ok_or_else(|| Error::contract(ErrorCode::Limit, "dataset rows"))?;
            }
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
                self.datasets(&spec.datasets, checkpoint.datasets.iter(), &mut budget)?;
                Ok(())
            }
            _ => Err(Error::contract(ErrorCode::Incompatible, "checkpoint")),
        }
    }
}

impl Dataset {
    pub(crate) fn rows(&self) -> u64 {
        self.batches
            .iter()
            .map(|batch| batch.num_rows() as u64)
            .sum()
    }
}
