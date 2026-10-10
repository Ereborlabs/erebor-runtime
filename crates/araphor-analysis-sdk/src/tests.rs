mod arrays;
mod boundaries;
mod graph;
mod semantics;

#[path = "../examples/files_count.rs"]
mod files_count;

use std::sync::Arc;

use arrow_array::{StringArray, UInt64Array};

use crate::*;
use files_count::FilesCount;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn count_fixture_builds() -> TestResult {
    let package = FilesCount::package();
    let report = package.test(&FilesCount::fixture()?, FilesCount::evaluate)?;
    assert_eq!(report.export, "files.count");
    assert_eq!(report.implementation, "portable-rust.1");
    assert_eq!(report.fixture_revision, "three-events.1");
    let counts = report.output.datasets[0].batches[0]
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("count column")?;
    assert_eq!(counts.values().as_ref(), &[3]);
    let directory = tempfile::tempdir()?;
    package.build(directory.path())?;
    assert_eq!(
        std::fs::read_to_string(directory.path().join("descriptor.json"))?,
        package.inspect()?
    );
    assert!(directory.path().join("analysis.wit").is_file());
    assert!(directory.path().join("analysis.h").is_file());
    Ok(())
}

#[test]
fn invalid_input_blocks_execution() -> TestResult {
    let package = FilesCount::package();
    let mut fixture = FilesCount::fixture()?;
    fixture.evaluation.inputs[0].data.batches = vec![RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new(
            "event_id",
            DataType::UInt64,
            false,
        )])),
        vec![Arc::new(UInt64Array::from(vec![1, 2, 3]))],
    )?];
    let mut executed = false;
    let result = package.test(&fixture, |_| {
        executed = true;
        Ok(Output::default())
    });
    assert_eq!(
        result.err().ok_or("accepted invalid input")?.code(),
        ErrorCode::Incompatible
    );
    assert!(!executed);
    Ok(())
}

#[test]
fn batches_keep_all_rows() -> TestResult {
    let package = FilesCount::package();
    let mut fixture = FilesCount::fixture()?;
    let schema = Arc::new(package.exports[0].inputs[0].schema.clone());
    let batches = (0..3)
        .map(|batch| {
            RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(StringArray::from(vec!["subject.1"; 100])),
                    Arc::new(UInt64Array::from_iter_values(
                        batch * 100..(batch + 1) * 100,
                    )),
                ],
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    fixture.evaluation.inputs[0].data.batches = batches;
    let report = package.test(&fixture, FilesCount::evaluate)?;
    let counts = report.output.datasets[0].batches[0]
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("count column")?;
    assert_eq!(counts.value(0), 300);
    assert_eq!(report.output.evidence.len(), 300);
    Ok(())
}

#[test]
fn multiple_inputs_variable_outputs() -> TestResult {
    let mut package = FilesCount::package();
    let mut extra = package.exports[0].inputs[0].clone();
    extra.name = "baseline".into();
    package.exports[0].inputs.push(extra);
    package.exports[0]
        .outputs
        .push(Port::new("removed", Schema::empty()));
    let mut fixture = FilesCount::fixture()?;
    let mut baseline = fixture.evaluation.inputs[0].clone();
    baseline.data.name = "baseline".into();
    baseline.revision.id = "baseline.1".into();
    fixture.evaluation.inputs.push(baseline);
    let report = package.test(&fixture, |input| {
        let mut output = FilesCount::evaluate(input)?;
        output.datasets.push(Dataset {
            name: "removed".into(),
            batches: vec![],
        });
        Ok(output)
    })?;
    assert_eq!(report.inputs.len(), 2);
    assert_eq!(report.output.datasets[0].batches[0].num_rows(), 1);
    assert!(report.output.datasets[1].batches.is_empty());
    Ok(())
}
