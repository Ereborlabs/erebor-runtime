use std::collections::BTreeSet;
use std::sync::Arc;

use araphor_analysis_sdk::arrow_array::cast::AsArray as _;
use araphor_analysis_sdk::arrow_array::types::UInt64Type;
use araphor_analysis_sdk::arrow_array::{Array, StringArray, UInt64Array};
use araphor_analysis_sdk::*;

#[path = "sensitive_access/fixture.rs"]
mod fixture;

pub struct SensitiveAccess;

struct Access<'a> {
    subject: &'a str,
    resource: &'a str,
    event_id: u64,
    row: u64,
}

impl SensitiveAccess {
    pub fn package() -> Package {
        let subject = Field::new("subject", DataType::Utf8, false);
        let resource = Field::new("resource", DataType::Utf8, false);
        let events = Schema::new(vec![
            subject.clone(),
            resource.clone(),
            Field::new("event_id", DataType::UInt64, false),
        ]);
        let baseline = Schema::new(vec![subject, resource]);
        let mut findings = Port::new("findings", events.clone());
        findings.kind = OutputKind::Findings;
        findings.evidence_required = true;
        let mut model = Model::new(
            "access.detect",
            vec![
                Port::new("sensitive_reads", events),
                Port::new("baseline", baseline),
            ],
            vec![findings],
        );
        model.reasons.push(Reason {
            code: "sensitive-access.OUTSIDE_BASELINE".into(),
            details: Schema::new(vec![
                Field::new("resource", DataType::Utf8, false),
                Field::new("baseline_revision", DataType::Utf8, false),
            ]),
        });
        Package::new("sensitive-access", "1", vec![model])
    }

    pub fn evaluate(evaluation: &Evaluation) -> Result<Output> {
        let baseline = evaluation.input("baseline")?;
        let allowed = Self::baseline(baseline)?;
        let events = evaluation.input("sensitive_reads")?;
        let accesses = Self::outside_baseline(events, &allowed)?;
        let package = Self::package();
        let model = &package.exports[0];
        let reason = &model.reasons[0];
        let batch = RecordBatch::try_new(
            Arc::new(model.outputs[0].schema.clone()),
            vec![
                Arc::new(StringArray::from_iter_values(
                    accesses.iter().map(|access| access.subject),
                )),
                Arc::new(StringArray::from_iter_values(
                    accesses.iter().map(|access| access.resource),
                )),
                Arc::new(UInt64Array::from_iter_values(
                    accesses.iter().map(|access| access.event_id),
                )),
            ],
        )?;
        let mut output = Output {
            datasets: vec![Dataset {
                name: "findings".into(),
                batches: vec![batch],
            }],
            ..Output::default()
        };
        for (row, access) in accesses.iter().enumerate() {
            let reference = RowRef {
                dataset: "findings".into(),
                row: row as u64,
            };
            output.evidence.push(EvidenceLink {
                output: reference.clone(),
                input: RowRef {
                    dataset: events.data.name.clone(),
                    row: access.row,
                },
            });
            output.reasons.push(ReasonValue {
                output: reference,
                code: reason.code.clone(),
                details: RecordBatch::try_new(
                    Arc::new(reason.details.clone()),
                    vec![
                        Arc::new(StringArray::from(vec![access.resource])),
                        Arc::new(StringArray::from(vec![baseline.revision.id.as_str()])),
                    ],
                )?,
            });
        }
        Ok(output)
    }

    fn baseline(input: &Input) -> Result<BTreeSet<(&str, &str)>> {
        if input.coverage.state != CoverageState::Complete || !input.coverage.limits.is_empty() {
            return Err(Error::contract(ErrorCode::Incomplete, "baseline coverage"));
        }
        let mut allowed = BTreeSet::new();
        for batch in &input.data.batches {
            let subjects = batch
                .column_by_name("subject")
                .and_then(|column| column.as_string_opt::<i32>())
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "baseline.subject"))?;
            let resources = batch
                .column_by_name("resource")
                .and_then(|column| column.as_string_opt::<i32>())
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "baseline.resource"))?;
            for row in 0..batch.num_rows() {
                if subjects.is_null(row)
                    || resources.is_null(row)
                    || subjects.value(row).is_empty()
                    || resources.value(row).is_empty()
                {
                    return Err(Error::contract(ErrorCode::Incomplete, "baseline identity"));
                }
                allowed.insert((subjects.value(row), resources.value(row)));
            }
        }
        Ok(allowed)
    }

    fn outside_baseline<'a>(
        events: &'a Input,
        allowed: &BTreeSet<(&str, &str)>,
    ) -> Result<Vec<Access<'a>>> {
        let mut accesses = Vec::new();
        let mut offset = 0_u64;
        for batch in &events.data.batches {
            let subjects = batch
                .column_by_name("subject")
                .and_then(|column| column.as_string_opt::<i32>())
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "sensitive_reads.subject"))?;
            let resources = batch
                .column_by_name("resource")
                .and_then(|column| column.as_string_opt::<i32>())
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "sensitive_reads.resource"))?;
            let ids = batch
                .column_by_name("event_id")
                .and_then(|column| column.as_primitive_opt::<UInt64Type>())
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "sensitive_reads.event_id"))?;
            for row in 0..batch.num_rows() {
                if subjects.is_null(row)
                    || resources.is_null(row)
                    || ids.is_null(row)
                    || subjects.value(row).is_empty()
                    || resources.value(row).is_empty()
                {
                    return Err(Error::contract(
                        ErrorCode::Incomplete,
                        "sensitive read identity",
                    ));
                }
                if !allowed.contains(&(subjects.value(row), resources.value(row))) {
                    accesses.push(Access {
                        subject: subjects.value(row),
                        resource: resources.value(row),
                        event_id: ids.value(row),
                        row: offset + row as u64,
                    });
                }
            }
            offset += batch.num_rows() as u64;
        }
        Ok(accesses)
    }
}

#[allow(dead_code)]
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let package = SensitiveAccess::package();
    let report = package.test(&SensitiveAccess::fixture()?, SensitiveAccess::evaluate)?;
    println!(
        "{}: {} findings",
        report.export,
        report.output.reasons.len()
    );
    Ok(())
}
