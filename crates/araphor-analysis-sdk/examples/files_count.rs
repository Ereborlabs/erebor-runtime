use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk::arrow_array::{Array, StringArray, UInt64Array};
use araphor_analysis_sdk::*;

pub struct FilesCount;

impl FilesCount {
    pub fn package() -> Package {
        let events = Schema::new(vec![
            Field::new("subject", DataType::Utf8, false),
            Field::new("event_id", DataType::UInt64, false),
        ]);
        let counts = Schema::new(vec![
            Field::new("subject", DataType::Utf8, false),
            Field::new("count", DataType::UInt64, false),
        ]);
        let mut output = Port::new("counts", counts);
        output.evidence_required = true;
        Package::new(
            "files",
            "1",
            vec![Model::new(
                "files.count",
                vec![Port::new("events", events)],
                vec![output],
            )],
        )
    }

    pub fn evaluate(input: &Evaluation) -> Result<Output> {
        let model = Self::package();
        let mut groups = BTreeMap::<String, BTreeSet<u64>>::new();
        let mut source_rows = Vec::new();
        let events = input
            .inputs
            .iter()
            .find(|input| input.data.name == "events")
            .ok_or_else(|| Error::contract(ErrorCode::Incomplete, "events"))?;
        for batch in &events.data.batches {
            let subjects = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "subjects"))?;
            let ids = batch
                .column(1)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "event IDs"))?;
            for row in 0..batch.num_rows() {
                if subjects.is_null(row) || subjects.value(row).is_empty() || ids.is_null(row) {
                    return Err(Error::contract(ErrorCode::Incomplete, "subject identity"));
                }
                groups
                    .entry(subjects.value(row).into())
                    .or_default()
                    .insert(ids.value(row));
                source_rows.push(subjects.value(row).to_owned());
            }
        }
        let subjects: Vec<_> = groups.keys().cloned().collect();
        let counts: Vec<_> = groups.values().map(|ids| ids.len() as u64).collect();
        let positions: BTreeMap<_, _> = subjects
            .iter()
            .enumerate()
            .map(|(row, subject)| (subject.as_str(), row as u64))
            .collect();
        let evidence = source_rows
            .iter()
            .enumerate()
            .map(|(row, subject)| EvidenceLink {
                output: RowRef {
                    dataset: "counts".into(),
                    row: positions[subject.as_str()],
                },
                input: RowRef {
                    dataset: "events".into(),
                    row: row as u64,
                },
            })
            .collect();
        let batch = RecordBatch::try_new(
            Arc::new(model.exports[0].outputs[0].schema.clone()),
            vec![
                Arc::new(StringArray::from(subjects)),
                Arc::new(UInt64Array::from(counts)),
            ],
        )
        .map_err(|_| Error::contract(ErrorCode::Invalid, "count batch"))?;
        Ok(Output {
            datasets: vec![Dataset {
                name: "counts".into(),
                batches: vec![batch],
            }],
            evidence,
            ..Output::default()
        })
    }

    pub fn fixture() -> Result<Fixture> {
        let package = Self::package();
        let batch = RecordBatch::try_new(
            Arc::new(package.exports[0].inputs[0].schema.clone()),
            vec![
                Arc::new(StringArray::from(vec!["subject.1"; 3])),
                Arc::new(UInt64Array::from(vec![1, 2, 3])),
            ],
        )
        .map_err(|_| Error::contract(ErrorCode::Invalid, "event batch"))?;
        Ok(Fixture {
            implementation: "portable-rust.1".into(),
            revision: "three-events.1".into(),
            evaluation: Evaluation {
                export: "files.count".into(),
                inputs: vec![Input {
                    data: Dataset {
                        name: "events".into(),
                        batches: vec![batch],
                    },
                    revision: Revision {
                        owner: "fixture".into(),
                        id: "events.1".into(),
                        window: Some(SourceWindow {
                            source: vec![1],
                            start_utc_ns: 0,
                            end_utc_ns: 10,
                        }),
                    },
                    coverage: Coverage {
                        state: CoverageState::Complete,
                        limits: vec![],
                    },
                }],
                parameters: None,
                context: EvaluationContext {
                    id: "run.1".into(),
                    time_utc_ns: 10,
                    seed: None,
                    limits: Limits::default(),
                },
                checkpoint: None,
            },
        })
    }
}

#[allow(dead_code)]
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let directory = arguments
        .next()
        .ok_or("Specify the declaration directory")?;
    if arguments.next().is_some() {
        return Err("Specify one declaration directory".into());
    }
    let package = FilesCount::package();
    package.build(std::path::Path::new(&directory))?;
    println!("{}", package.inspect()?);
    let report = package.test(&FilesCount::fixture()?, FilesCount::evaluate)?;
    let counts = report.output.datasets[0].batches[0]
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("Count column is invalid")?;
    if counts.value(0) != 3 {
        return Err("Expected count 3".into());
    }
    println!(
        "{} / {} / {}: count 3",
        report.export, report.implementation, report.fixture_revision
    );
    Ok(())
}
