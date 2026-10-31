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
        let record_ids = records
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>();
        let record_rows = record_ids
            .iter()
            .enumerate()
            .map(|(row, id)| (id, row))
            .collect::<BTreeMap<_, _>>();
        if record_rows.len() != records.len() {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "duplicate records",
            ));
        }
        let mut contributions = Vec::new();
        let mut owners = BTreeMap::new();
        for unit in Unit::decode(&evaluation.input("units")?.data)? {
            if !record_rows.contains_key(&unit.record)
                || owners
                    .insert(unit.record.clone(), (contributions.len(), unit.restricted))
                    .is_some()
            {
                return Err(sdk::Error::contract(
                    sdk::ErrorCode::Invalid,
                    "detector unit",
                ));
            }
            contributions.push(Contribution {
                record: unit.record,
                subjects: Vec::new(),
                relationships: Vec::new(),
                findings: Vec::new(),
                state: None,
            });
        }
        let mut output = sdk::Output::default();
        let mut subjects = Vec::new();
        let mut findings = Vec::new();
        for rows in groups
            .into_values()
            .filter(|rows| rows.len() as u64 >= threshold)
        {
            let anchor_row = rows
                .iter()
                .min_by_key(|&&row| &record_ids[row as usize])
                .copied()
                .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "record group"))?;
            let Some(&(owner, restricted)) = owners.get(&record_ids[anchor_row as usize]) else {
                continue;
            };
            let row = findings.len() as u64;
            let reason = Self::reason(model, row, threshold, rows.len() as u64)?;
            let declared = FindingReasonV1::Declared(DeclaredFindingReasonV1::from_value(&reason)?);
            let mut value = FindingV1::resolve(
                &checked.package().id,
                declared,
                ReasonDetails {
                    record: anchor_row,
                    context: None,
                    reason: "THRESHOLD".into(),
                    confirmed: false,
                    evidence: rows.clone(),
                    limits: vec!["CONTEXTUAL_ACTIVITY".into()],
                },
                &records,
                &facts,
            )?;
            value.sensitivity = if restricted {
                ContextSensitivityV1::HostRestricted
            } else {
                ContextSensitivityV1::Tenant
            };
            let finding = Finding::from_finding(anchor_row, None, value, reason.code.clone());
            let anchor = Anchor::from_positions(finding.record, None, &record_ids, &facts)?;
            contributions[owner].subjects.push(subjects.len() as u64);
            subjects.push(SubjectChange {
                anchor: anchor.clone(),
                key: finding.subject_id.clone(),
            });
            contributions[owner].findings.push(row);
            for record in &finding.evidence {
                let record = record_rows.get(record).ok_or_else(|| {
                    sdk::Error::contract(sdk::ErrorCode::Invalid, "record evidence")
                })?;
                output.evidence.push(sdk::EvidenceLink {
                    output: reason.output.clone(),
                    input: sdk::RowRef {
                        dataset: "records".into(),
                        row: *record as u64,
                    },
                });
            }
            findings.push(FindingChange::from_local(finding, anchor));
            output.reasons.push(reason);
        }
        if let Some(record) = records.iter().max_by_key(|record| &record.id) {
            if let Some(&(owner, _)) = owners.get(&record.id) {
                contributions[owner].state = Some(UnitState {
                    state: GraphPackageStateV1::Declared(records.len().to_string()),
                    position: record.position,
                    fact: None,
                });
            }
        }
        output.datasets = vec![
            SubjectChange::encode(&subjects)?,
            RelationshipChange::encode(&[])?,
            FindingChange::encode(&findings)?,
            Contribution::encode(&contributions)?,
            GraphPackageStateV1::encode(&[GraphPackageStateV1::Declared("0".into())])?,
        ];
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
