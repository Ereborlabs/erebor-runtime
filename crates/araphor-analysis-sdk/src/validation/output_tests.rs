use std::sync::Arc;

use crate::*;

use crate::tests::files_count::FilesCount;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn output_preserves_contract() -> TestResult {
    let mut package = FilesCount::package();
    let schema = Schema::new(vec![Field::new("value", DataType::UInt64, false)]);
    package.exports[0].checkpoint = Some(CheckpointSpec {
        resume_input_changes: false,
        version: 1,
        datasets: vec![Port::new("state", schema.clone())],
    });
    package.exports[0].reasons.push(Reason {
        code: "files.counted".into(),
        details: schema.clone(),
    });
    let evaluation = FilesCount::fixture()?.evaluation;
    let batch = RecordBatch::try_new(
        Arc::new(schema),
        vec![Arc::new(arrow_array::UInt64Array::from(vec![3]))],
    )?;
    let mut output = FilesCount::evaluate(&evaluation)?;
    output.checkpoint = Some(Checkpoint {
        version: 1,
        datasets: vec![Dataset {
            name: "state".into(),
            batches: vec![batch.clone()],
        }],
    });
    output.reasons.push(ReasonValue {
        output: RowRef {
            dataset: "counts".into(),
            row: 0,
        },
        code: "files.counted".into(),
        details: batch,
    });
    package.validate_output(&evaluation, &output)?;
    let packet = wire::Output::encode(&package, &evaluation, &output)?;
    let decoded = packet.decode(&package, &evaluation)?;
    assert_eq!(decoded.evidence, output.evidence);
    assert_eq!(decoded.datasets[0].batches, output.datasets[0].batches);
    assert_eq!(decoded.reasons[0].details, output.reasons[0].details);
    assert_eq!(
        decoded
            .checkpoint
            .as_ref()
            .map(|value| value.datasets[0].batches.clone()),
        output
            .checkpoint
            .as_ref()
            .map(|value| value.datasets[0].batches.clone())
    );
    for case in 0..5 {
        let mut invalid = output.clone();
        match case {
            0 => invalid.evidence[0].input.row = 3,
            1 => invalid.evidence.clear(),
            2 => invalid.reasons[0].output.row = 1,
            3 => {
                invalid
                    .checkpoint
                    .as_mut()
                    .ok_or("checkpoint absent")?
                    .version = 2
            }
            _ => {
                invalid.datasets[0].batches =
                    vec![RecordBatch::new_empty(Arc::new(Schema::empty()))]
            }
        }
        assert!(
            package.validate_output(&evaluation, &invalid).is_err(),
            "case {case}"
        );
    }
    Ok(())
}
