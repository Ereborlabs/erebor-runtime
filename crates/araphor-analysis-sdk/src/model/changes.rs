use std::collections::BTreeSet;
use std::sync::Arc;

use arrow_array::{Array, BooleanArray};
use serde::{Deserialize, Serialize};

use crate::{
    DataType, Error, ErrorCode, Evaluation, Field, InputSource, Model, Port, Result, Schema,
    TableRef,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeInput {
    pub before: String,
    pub after: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeInputs {
    pub reset: String,
    pub ports: Vec<ChangeInput>,
}

impl ChangeInputs {
    pub fn reset_port(name: impl Into<String>) -> Port {
        Port::new(
            name,
            Schema::new(vec![Field::new("reset", DataType::Boolean, false)]),
        )
    }

    pub fn generated(&self, name: &str) -> bool {
        self.reset == name || self.ports.iter().any(|port| port.before == name)
    }

    pub fn is_reset(&self, evaluation: &Evaluation) -> Result<bool> {
        let data = &evaluation.input(&self.reset)?.data;
        let mut batches = data.batches.iter().filter(|batch| batch.num_rows() != 0);
        let batch = batches
            .next()
            .filter(|batch| batch.num_rows() == 1)
            .ok_or_else(|| Self::invalid("change reset row"))?;
        if batches.next().is_some() || batch.num_columns() != 1 {
            return Err(Self::invalid("change reset row"));
        }
        let values = batch
            .column(0)
            .as_any()
            .downcast_ref::<BooleanArray>()
            .filter(|values| !values.is_null(0))
            .ok_or_else(|| Self::invalid("change reset value"))?;
        Ok(values.value(0))
    }

    pub fn reset_input(&self, reset: bool) -> Result<crate::Dataset> {
        Ok(crate::Dataset {
            name: self.reset.clone(),
            batches: vec![crate::RecordBatch::try_new(
                Arc::new(Self::reset_port(&self.reset).schema),
                vec![Arc::new(BooleanArray::from(vec![reset]))],
            )?],
        })
    }

    pub(crate) fn validate(&self, model: &Model) -> Result<()> {
        if self.ports.is_empty()
            || model
                .checkpoint
                .as_ref()
                .is_some_and(|checkpoint| !checkpoint.resume_input_changes)
        {
            return Err(Self::invalid("change checkpoint declaration"));
        }
        let input = |name: &str| {
            model
                .inputs
                .iter()
                .find(|input| input.port.name == name)
                .ok_or_else(|| Self::invalid("change input name"))
        };
        if input(&self.reset)?.port != Self::reset_port(&self.reset) {
            return Err(Self::invalid("change reset schema"));
        }
        let mut names = BTreeSet::from([self.reset.as_str()]);
        for port in &self.ports {
            if !names.insert(&port.before)
                || !names.insert(&port.after)
                || input(&port.before)?.port.schema != input(&port.after)?.port.schema
                || matches!(&input(&port.after)?.source, InputSource::Lookup(_))
            {
                return Err(Self::invalid("change input pair"));
            }
        }
        for port in model
            .inputs
            .iter()
            .filter(|input| self.generated(&input.port.name))
        {
            if !matches!(&port.source, InputSource::Table(TableRef::Named(name)) if name == &port.port.name)
            {
                return Err(Self::invalid("generated input source"));
            }
        }
        Ok(())
    }

    pub(crate) fn check_state(&self, evaluation: &Evaluation, stateful: bool) -> Result<()> {
        let reset = self.is_reset(evaluation)?;
        if stateful && reset == evaluation.checkpoint.is_some() {
            return Err(Self::invalid("change reset state"));
        }
        Ok(())
    }

    pub(crate) fn check_inputs(&self, evaluation: &Evaluation) -> Result<()> {
        if self.is_reset(evaluation)?
            && self.ports.iter().any(|port| {
                evaluation
                    .input(&port.before)
                    .is_ok_and(|input| input.data.rows() != 0)
            })
        {
            return Err(Self::invalid("change reset rows"));
        }
        Ok(())
    }

    fn invalid(field: &str) -> Error {
        Error::contract(ErrorCode::Invalid, field)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::*;
    use arrow_array::UInt64Array;

    fn fixture(reset: bool) -> (Package, Evaluation, Output) {
        let port = |name: &str| {
            Port::new(
                name,
                Schema::new(vec![Field::new("value", DataType::UInt64, false)]),
            )
        };
        let changes = ChangeInputs {
            reset: "reset".into(),
            ports: vec![ChangeInput {
                before: "before".into(),
                after: "after".into(),
            }],
        };
        let mut model = Model::new(
            "sum",
            vec![
                port("after"),
                port("before"),
                ChangeInputs::reset_port("reset"),
            ],
            vec![port("total")],
        );
        model.outputs[0].evidence_required = true;
        model.change_inputs = Some(changes.clone());
        model.checkpoint = Some(CheckpointSpec {
            version: 1,
            resume_input_changes: true,
            datasets: vec![port("state")],
        });
        let dataset = |name: &str, rows: Vec<u64>| Dataset {
            name: name.into(),
            batches: vec![RecordBatch::try_new(
                Arc::new(port(name).schema),
                vec![Arc::new(UInt64Array::from(rows))],
            )
            .unwrap()],
        };
        let revision = Revision {
            owner: "query".into(),
            id: "cut".into(),
            window: None,
        };
        let coverage = Coverage {
            state: CoverageState::Complete,
            limits: Vec::new(),
        };
        let input = |data| Input {
            data,
            revision: revision.clone(),
            coverage: coverage.clone(),
        };
        let output = Output {
            datasets: vec![dataset("total", vec![7])],
            evidence: vec![EvidenceLink {
                output: RowRef {
                    dataset: "total".into(),
                    row: 0,
                },
                input: RowRef {
                    dataset: "after".into(),
                    row: 0,
                },
            }],
            checkpoint: Some(Checkpoint {
                version: 1,
                datasets: vec![dataset("state", vec![7])],
            }),
            ..Default::default()
        };
        let evaluation = Evaluation {
            export: "sum".into(),
            inputs: vec![
                input(dataset("after", vec![7])),
                input(dataset("before", if reset { vec![] } else { vec![3] })),
                input(changes.reset_input(reset).unwrap()),
            ],
            context: EvaluationContext {
                id: "call".into(),
                time_utc_ns: 1,
                seed: None,
            },
            parameters: None,
            checkpoint: (!reset).then(|| output.checkpoint.clone().unwrap()),
            previous_outputs: if reset {
                vec![]
            } else {
                output.datasets.clone()
            },
        };
        (
            Package::new("fixture", "r1", vec![model]),
            evaluation,
            output,
        )
    }

    #[test]
    fn change_ports_share_contract() -> crate::Result<()> {
        for reset in [true, false] {
            let (package, evaluation, mut output) = fixture(reset);
            let checked = package.check_evaluation(&evaluation)?;
            checked.validate_output(&output)?;
            let decoded = checked.encode()?.decode(&package)?;
            if !reset {
                let mut stripped = checked.encode()?;
                stripped.checkpoint = None;
                stripped.previous_outputs.clear();
                assert!(stripped.decode(&package).is_err());
                let mut restored = stripped.decode_inputs(&package)?;
                assert!(package.check_evaluation(&restored).is_err());
                restored.checkpoint = evaluation.checkpoint.clone();
                restored.previous_outputs = evaluation.previous_outputs.clone();
                package.check_evaluation(&restored)?;
                assert!(checked.encode()?.decode_inputs(&package).is_err());
            }
            assert_eq!(
                decoded.inputs[1].data.batches,
                evaluation.inputs[1].data.batches
            );
            assert_eq!(
                decoded.inputs[2].data.batches,
                evaluation.inputs[2].data.batches
            );
            for name in ["before", "reset"] {
                output.evidence[0].input.dataset = name.into();
                assert!(checked.validate_output(&output).is_err());
                assert!(package
                    .validate_retained_output(
                        "sum",
                        &[
                            ("after".into(), 1),
                            ("before".into(), 1),
                            ("reset".into(), 1)
                        ]
                        .into(),
                        &output
                    )
                    .is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn invalid_changes_fail() {
        for case in 0..6 {
            let (mut package, _, _) = fixture(true);
            let model = &mut package.exports[0];
            match case {
                0 => model.change_inputs.as_mut().unwrap().ports.clear(),
                1 => model.change_inputs.as_mut().unwrap().ports[0].before = "after".into(),
                2 => model.change_inputs.as_mut().unwrap().ports[0].after = "missing".into(),
                3 => model.inputs[1].port.schema = Schema::empty(),
                4 => model.checkpoint.as_mut().unwrap().resume_input_changes = false,
                _ => model.inputs[2].port.schema = Schema::empty(),
            }
            assert!(package.validate().is_err(), "case {case}");
        }
        for case in 0..4 {
            let (package, mut evaluation, output) = fixture(true);
            match case {
                0 => evaluation.checkpoint = output.checkpoint,
                1 => evaluation.inputs[1].data.batches = evaluation.inputs[0].data.batches.clone(),
                2 => evaluation.inputs[2].data.batches.clear(),
                _ => {
                    evaluation.inputs[2].data.batches[0] = RecordBatch::try_new(
                        Arc::new(ChangeInputs::reset_port("reset").schema),
                        vec![Arc::new(BooleanArray::from(vec![false]))],
                    )
                    .unwrap()
                }
            }
            assert!(
                package.validate_evaluation(&evaluation).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn stateless_changes_keep_reset_rules() -> crate::Result<()> {
        for reset in [true, false] {
            let (mut package, mut evaluation, mut output) = fixture(reset);
            package.exports[0].checkpoint = None;
            evaluation.checkpoint = None;
            evaluation.previous_outputs.clear();
            output.checkpoint = None;
            package
                .check_evaluation(&evaluation)?
                .validate_output(&output)?;
            let model = &mut package.exports[0];
            model.input_mode = InputMode::Resolved;
            model.inputs[0].source = InputSource::Lookup("SELECT 7 AS value".into());
            assert!(package.validate().is_err());
            let model = &mut package.exports[0];
            model.inputs[0].source = InputSource::Table(TableRef::Named("after".into()));
            model.inputs.push(crate::InputPort {
                port: model.inputs[0].port.clone(),
                source: InputSource::Lookup("SELECT 7 AS value".into()),
            });
            model.inputs[3].port.name = "support".into();
            package.validate()?;
            package.exports[0].change_inputs = None;
            assert!(package.validate().is_err());
        }
        Ok(())
    }
}
