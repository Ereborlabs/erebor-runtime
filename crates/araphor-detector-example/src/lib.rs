use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_builtins::graph::*;
use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{cast::AsArray as _, types::UInt64Type, UInt64Array};

mod descriptor;

#[cfg(test)]
mod tests;

pub struct BurstDetector;

impl sdk::Guest for BurstDetector {
    fn package() -> sdk::Package {
        Self::package()
    }
    fn compute(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        if checked.package() != Self::declaration() {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Incompatible,
                "detector package",
            ));
        }
        let evaluation = checked.evaluation();
        let model = checked.model();
        let threshold = Self::threshold(evaluation)?;
        let records = Observation::read(checked)?;
        let facts = Fact::read(checked)?;
        let mut groups = BTreeMap::new();
        for (row, record) in records.iter().enumerate() {
            groups
                .entry((
                    &record.id.stream.node_id,
                    record.id.stream.node_boot_id,
                    record.id.stream.label_epoch,
                    record.effect.task_cookie,
                ))
                .or_insert_with(Vec::new)
                .push(
                    u32::try_from(row).map_err(|_| {
                        sdk::Error::contract(sdk::ErrorCode::Invalid, "record count")
                    })?,
                );
        }
        let mut output = sdk::Output::default();
        let mut findings = Vec::new();
        for rows in groups
            .into_values()
            .filter(|rows| rows.len() as u64 >= threshold)
        {
            let row = findings.len() as u64;
            let reason = Self::reason(model, row, threshold, rows.len() as u64)?;
            let declared = FindingReasonV1::Declared(DeclaredFindingReasonV1::from_value(&reason)?);
            let value = FindingV1::resolve(
                &checked.package().id,
                declared.clone(),
                ReasonDetails {
                    record: rows[0],
                    context: None,
                    reason: "THRESHOLD".into(),
                    confirmed: false,
                    evidence: rows.clone(),
                    limits: vec!["CONTEXTUAL_ACTIVITY".into()],
                },
                &records,
                &facts,
            )?;
            let finding = Finding::from_finding(rows[0], None, value, reason.code.clone());
            findings.push(finding);
            for record in rows {
                output.evidence.push(sdk::EvidenceLink {
                    output: reason.output.clone(),
                    input: sdk::RowRef {
                        dataset: "records".into(),
                        row: u64::from(record),
                    },
                });
            }
            output.reasons.push(reason);
        }
        let record_ids = records
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>();
        let subjects = findings
            .iter()
            .map(|finding| {
                Ok((
                    finding.subject_id.clone(),
                    SubjectChange {
                        anchor: Anchor::from_positions(finding.record, None, &record_ids, &facts)?,
                        key: finding.subject_id.clone(),
                    },
                ))
            })
            .collect::<sdk::Result<BTreeMap<_, _>>>()?
            .into_values()
            .collect::<Vec<_>>();
        let findings = findings
            .into_iter()
            .map(|finding| {
                let anchor =
                    Anchor::from_positions(finding.record, finding.context, &record_ids, &facts)?;
                Ok(FindingChange::from_local(finding, anchor))
            })
            .collect::<sdk::Result<Vec<_>>>()?;
        let state = records.len().to_string();
        output.datasets = vec![
            SubjectChange::encode(&subjects)?,
            SubjectRemoval::encode(&[])?,
            RelationshipChange::encode(&[])?,
            RelationshipRemoval::encode(&[])?,
            FindingChange::encode(&findings)?,
            FindingRemoval::encode(&[])?,
            Progress::encode(&[])?,
            ProgressRemoval::encode(&[])?,
        ];
        let spec = model.checkpoint.as_ref().ok_or_else(|| {
            sdk::Error::contract(sdk::ErrorCode::Invalid, "checkpoint declaration")
        })?;
        output.checkpoint = Some(sdk::Checkpoint {
            version: spec.version,
            datasets: vec![GraphPackageStateV1::encode(&[
                GraphPackageStateV1::Declared(state),
            ])?],
        });
        Ok(output)
    }
}

#[cfg(target_arch = "wasm32")]
sdk::export_component!(BurstDetector);

#[cfg(not(target_arch = "wasm32"))]
sdk::export_native!(BurstDetector);

impl BurstDetector {
    pub fn evaluate(evaluation: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        Self::declaration()
            .check_evaluation(evaluation)?
            .evaluate(<Self as sdk::Guest>::compute)
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
        model: &sdk::Model,
        row: u64,
        threshold: u64,
        count: u64,
    ) -> sdk::Result<sdk::ReasonValue> {
        Ok(sdk::ReasonValue {
            output: sdk::RowRef {
                dataset: "findings".into(),
                row,
            },
            code: model.reasons[0].code.clone(),
            details: sdk::RecordBatch::try_new(
                Arc::new(model.reasons[0].details.clone()),
                vec![
                    Arc::new(UInt64Array::from(vec![threshold])),
                    Arc::new(UInt64Array::from(vec![count])),
                ],
            )?,
        })
    }
}
