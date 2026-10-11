use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use sdk::arrow_array::{BinaryArray, StringArray, UInt64Array};

use super::*;

pub(super) fn evaluate(inputs: &GraphAnalysisInputsV1) -> TestResult<Vec<(String, u64)>> {
    let schema = schema();
    let package = sdk::Package::new(
        "native.graph",
        "1",
        vec![sdk::Model::new(
            "joins",
            inputs
                .inputs()
                .iter()
                .map(|input| {
                    sdk::Port::new(
                        &input.data.name,
                        input.data.batches[0].schema().as_ref().clone(),
                    )
                })
                .collect(),
            vec![sdk::Port::new("counts", schema.as_ref().clone())],
        )],
    );
    let fixture = sdk::Fixture {
        implementation: "rust-native-graph-join".into(),
        revision: "1".into(),
        evaluation: sdk::Evaluation {
            export: "joins".into(),
            inputs: inputs.inputs().to_vec(),
            parameters: None,
            context: sdk::EvaluationContext {
                id: "native-graph-fixture".into(),
                time_utc_ns: 10,
                seed: Some(1),
                limits: sdk::Limits::default(),
            },
            checkpoint: None,
        },
    };
    let report = package.test(&fixture, join)?;
    let batch = &report.output.datasets[0].batches[0];
    let ids = column::<StringArray>(batch, "result_id")?;
    let counts = column::<UInt64Array>(batch, "joined_edges")?;
    Ok((0..batch.num_rows())
        .map(|row| (ids.value(row).into(), counts.value(row)))
        .collect())
}

fn schema() -> Arc<sdk::Schema> {
    Arc::new(sdk::Schema::new(vec![
        sdk::Field::new("result_id", sdk::DataType::Utf8, false),
        sdk::Field::new("joined_edges", sdk::DataType::UInt64, false),
    ]))
}

fn join(input: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
    let mut subjects = BTreeSet::new();
    for batch in &input.input("subjects")?.data.batches {
        let ids = column::<StringArray>(batch, "graph_result_id")?;
        let keys = column::<BinaryArray>(batch, "subject_id")?;
        for row in 0..batch.num_rows() {
            subjects.insert((ids.value(row), keys.value(row)));
        }
    }
    let mut counts = BTreeMap::new();
    for batch in &input.input("graph_manifest")?.data.batches {
        let ids = column::<StringArray>(batch, "graph_result_id")?;
        for row in 0..batch.num_rows() {
            counts.insert(ids.value(row), 0_u64);
        }
    }
    for batch in &input.input("relationships")?.data.batches {
        let ids = column::<StringArray>(batch, "graph_result_id")?;
        let from = column::<BinaryArray>(batch, "from_subject_id")?;
        let to = column::<BinaryArray>(batch, "to_subject_id")?;
        for row in 0..batch.num_rows() {
            let id = ids.value(row);
            if subjects.contains(&(id, from.value(row))) && subjects.contains(&(id, to.value(row)))
            {
                *counts.get_mut(id).ok_or_else(|| {
                    sdk::Error::contract(sdk::ErrorCode::Incomplete, "relationship manifest")
                })? += 1;
            }
        }
    }
    let batch = sdk::RecordBatch::try_new(
        schema(),
        vec![
            Arc::new(StringArray::from(
                counts.keys().copied().collect::<Vec<_>>(),
            )),
            Arc::new(UInt64Array::from(
                counts.values().copied().collect::<Vec<_>>(),
            )),
        ],
    )?;
    Ok(sdk::Output {
        datasets: vec![sdk::Dataset {
            name: "counts".into(),
            batches: vec![batch],
        }],
        ..Default::default()
    })
}
