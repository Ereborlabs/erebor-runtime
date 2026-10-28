use std::collections::BTreeMap;
use std::sync::Arc;

use crate::*;

use crate::tests::files_count::FilesCount;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn retained_output_preserves_contract() -> TestResult {
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
    let inputs = BTreeMap::from([("events".into(), 3)]);
    let packet = wire::Output::encode(&package, &evaluation, &output)?;
    let retained = packet.decode_retained(&package, &evaluation.export, &inputs)?;
    assert_eq!(retained.evidence, output.evidence);
    assert_eq!(retained.datasets[0].batches, output.datasets[0].batches);
    assert_eq!(retained.reasons[0].details, output.reasons[0].details);
    assert_eq!(
        retained
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
        let live = package
            .validate_output(&evaluation, &invalid)
            .err()
            .ok_or("live contract accepted invalid output")?;
        let retained = package
            .validate_retained_output(&evaluation.export, &inputs, &invalid)
            .err()
            .ok_or("retained contract accepted invalid output")?;
        assert_eq!(retained.code(), live.code(), "case {case}");
        assert_eq!(retained.to_string(), live.to_string(), "case {case}");
    }
    for inputs in [
        BTreeMap::new(),
        BTreeMap::from([("other".into(), 3)]),
        BTreeMap::from([("events".into(), 3), ("other".into(), 0)]),
    ] {
        assert_eq!(
            package
                .validate_retained_output(&evaluation.export, &inputs, &output)
                .err()
                .ok_or("invalid names accepted")?
                .code(),
            ErrorCode::Invalid
        );
    }
    Ok(())
}
