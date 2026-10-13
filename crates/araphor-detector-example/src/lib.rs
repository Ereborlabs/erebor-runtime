use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_builtins::{graph::*, Rows};
use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{cast::AsArray as _, types::UInt64Type, UInt64Array};

mod descriptor;

#[cfg(test)]
mod tests;

pub struct BurstDetector;

impl sdk::guest::Guest for BurstDetector {
    fn package() -> sdk::Package {
        Self::package()
    }
    fn evaluate(evaluation: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        Self::evaluate(evaluation)
    }
}

#[cfg(target_arch = "wasm32")]
sdk::export_component!(BurstDetector);

#[cfg(not(target_arch = "wasm32"))]
sdk::export_native!(BurstDetector);

impl BurstDetector {
    pub fn evaluate(evaluation: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        let package = Self::package();
        package.validate_evaluation(evaluation)?;
        let model = &package.exports[0];
        let threshold = Self::threshold(evaluation)?;
        let records: Vec<Observation> = Rows::decode(
            &model.inputs[0],
            &evaluation.input("records")?.data,
            evaluation.context.limits,
        )?;
        let mut groups = BTreeMap::new();
        for (row, record) in records.iter().enumerate() {
            groups
                .entry((&record.lifetime, record.task))
                .or_insert_with(Vec::new)
                .push(row as u64);
        }
        let findings: Vec<_> = groups
            .into_values()
            .filter(|rows| rows.len() as u64 >= threshold)
            .map(|rows| Finding {
                record: rows[0],
                context: None,
                reason: "THRESHOLD".into(),
                confirmed: false,
                evidence: rows,
                limits: vec!["CONTEXTUAL_ACTIVITY".into()],
            })
            .collect();
        let subjects: Vec<_> = findings
            .iter()
            .map(|finding| Subject {
                record: finding.record,
                context: None,
            })
            .collect();
        let mut output = sdk::Output {
            datasets: vec![
                Rows::encode(&model.outputs[0], &subjects, evaluation.context.limits)?,
                Rows::encode::<Relationship>(&model.outputs[1], &[], evaluation.context.limits)?,
                Rows::encode(&model.outputs[2], &findings, evaluation.context.limits)?,
            ],
            ..Default::default()
        };
        for (row, finding) in findings.iter().enumerate() {
            Self::reason(&mut output, model, finding, row as u64, threshold)?;
        }
        let spec = model.checkpoint.as_ref().ok_or_else(|| {
            sdk::Error::contract(sdk::ErrorCode::Invalid, "checkpoint declaration")
        })?;
        output.checkpoint = Some(sdk::Checkpoint {
            version: spec.version,
            datasets: vec![Rows::encode(
                &spec.datasets[0],
                &[State {
                    value: records.len().to_string(),
                }],
                evaluation.context.limits,
            )?],
        });
        package.validate_output(evaluation, &output)?;
        Ok(output)
    }

    fn threshold(evaluation: &sdk::Evaluation) -> sdk::Result<u64> {
        let value = evaluation
            .parameters
            .as_ref()
            .and_then(|batch| batch.column(0).as_primitive_opt::<UInt64Type>())
            .map(|values| values.value(0))
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "threshold"))?;
        if value < 2 {
            return Err(sdk::Error::contract(sdk::ErrorCode::Invalid, "threshold"));
        }
        Ok(value)
    }

    fn reason(
        output: &mut sdk::Output,
        model: &sdk::Model,
        finding: &Finding,
        row: u64,
        threshold: u64,
    ) -> sdk::Result<()> {
        let reference = sdk::RowRef {
            dataset: "findings".into(),
            row,
        };
        output
            .evidence
            .extend(finding.evidence.iter().map(|row| sdk::EvidenceLink {
                output: reference.clone(),
                input: sdk::RowRef {
                    dataset: "records".into(),
                    row: *row,
                },
            }));
        output.reasons.push(sdk::ReasonValue {
            output: reference,
            code: model.reasons[0].code.clone(),
            details: sdk::RecordBatch::try_new(
                Arc::new(model.reasons[0].details.clone()),
                vec![
                    Arc::new(UInt64Array::from(vec![threshold])),
                    Arc::new(UInt64Array::from(vec![finding.evidence.len() as u64])),
                ],
            )?,
        });
        Ok(())
    }
}
