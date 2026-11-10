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
        let graph = checked.graph()?;
        if Unit::expired(&evaluation.input("window")?.data)? {
            return GraphCommands::expire(&graph);
        }
        let threshold = Self::threshold(evaluation)?;
        let units = Unit::decode(&evaluation.input("units")?.data)?;
        let removals = Unit::decode(&evaluation.input("unit_removals")?.data)?;
        let mut cleared = units
            .iter()
            .chain(&removals)
            .map(|unit| araphor_analysis_types::DomainRelations::key(&unit.record))
            .collect::<sdk::Result<std::collections::BTreeSet<_>>>()?;
        cleared.insert(araphor_analysis_types::DomainRelations::key(
            &Option::<araphor_analysis_types::source::DiscoveryRecordIdV1>::None,
        )?);
        if model
            .change_inputs
            .as_ref()
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "change inputs"))?
            .is_reset(evaluation)?
        {
            graph.clear_scope().map_err(sdk::Error::backend)?;
        } else {
            graph
                .clear_owners(sdk::arrow_array::BinaryArray::from_iter_values(
                    cleared.iter().map(Vec::as_slice),
                ))
                .map_err(sdk::Error::backend)?;
        }
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
        let mut owners = BTreeMap::new();
        for unit in units {
            if !record_rows.contains_key(&unit.record)
                || owners.insert(unit.record, unit.restricted).is_some()
            {
                return Err(sdk::Error::contract(
                    sdk::ErrorCode::Invalid,
                    "detector unit",
                ));
            }
        }
        let mut commands = GraphCommands::default();
        commands.state(
            &araphor_analysis_types::DomainRelations::key(
                &Option::<araphor_analysis_types::source::DiscoveryRecordIdV1>::None,
            )?,
            araphor_analysis_types::GraphStateMember {
                record: None,
                position: None,
                fact: None,
                state: GraphPackageStateV1::Declared("0".into()),
            },
        )?;
        let mut subjects = Vec::new();
        for rows in groups
            .into_values()
            .filter(|rows| rows.len() as u64 >= threshold)
        {
            let anchor_row = rows
                .iter()
                .min_by_key(|&&row| &record_ids[row as usize])
                .copied()
                .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "record group"))?;
            let Some(&restricted) = owners.get(&record_ids[anchor_row as usize]) else {
                continue;
            };
            let row = subjects.len() as u64;
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
            let anchor = Anchor::from_positions(anchor_row, None, &record_ids, &facts)?;
            let owner =
                araphor_analysis_types::DomainRelations::key(&record_ids[anchor_row as usize])?;
            let subject = SubjectChange {
                anchor: anchor.clone(),
                key: value.subject_id.clone(),
            };
            commands.subject(&owner, subject.clone())?;
            subjects.push(subject);
            commands.finding(
                &owner,
                araphor_analysis_types::FindingMember { anchor, value },
            )?;
        }
        if let Some(record) = records.iter().max_by_key(|record| &record.id) {
            if owners.contains_key(&record.id) {
                commands.state(
                    &araphor_analysis_types::DomainRelations::key(&record.id)?,
                    araphor_analysis_types::GraphStateMember {
                        record: Some(record.id.clone()),
                        position: Some(record.position),
                        fact: None,
                        state: GraphPackageStateV1::Declared(records.len().to_string()),
                    },
                )?;
            }
        }
        commands.stage(&graph)?;
        let output = sdk::Output {
            datasets: vec![SubjectChange::encode(&subjects)?],
            ..Default::default()
        };
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
