use sdk::arrow_array::{Array, ArrayRef, FixedSizeListArray, NullArray, StructArray};

use super::*;

fn records(rows: usize) -> sdk::Result<StructArray> {
    StructArray::try_new(
        vec![sdk::Field::new("missing", sdk::DataType::Null, true)].into(),
        vec![Arc::new(NullArray::new(rows))],
        None,
    )
    .map_err(Into::into)
}

fn check_nested(array: ArrayRef, minimum: usize) -> TestResult {
    let fixture = QueryFixture::new()?;
    let query = fixture.owner(QueryLimits::default())?;
    let (mut package, mut evaluation) = input(schema())?;
    let schema = sdk::Schema::new(vec![sdk::Field::new(
        "value",
        array.data_type().clone(),
        false,
    )]);
    package.exports[0].inputs[0].port.schema = schema.clone();
    package.exports[0].outputs[0].schema = schema.clone();
    evaluation.inputs[0].data.batches =
        vec![sdk::RecordBatch::try_new(Arc::new(schema), vec![array])?];
    evaluation.context.limits = package.exports[0].limits;
    package.validate_evaluation(&evaluation)?;
    let retained = evaluation.allocated_bytes();
    assert!(retained < 32 * 1024);
    let capacity = QueryLimits::default().input_capacity;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let held = query.retain_analysis_input(capacity - 32 * 1024)?;
    let mut entered = false;
    let result = query.evaluate_component([1; 16], &package, &evaluation, &control, |_, _, _| {
        entered = true;
        Ok((sdk::Output::default(), 0))
    });
    assert!(
        matches!(
            &result,
            Err(crate::Error::AnalysisBusy {
                resource: "query input capacity",
                ..
            })
        ),
        "{:?}",
        result.as_ref().err()
    );
    assert!(!entered);
    drop(held);
    drop(query.retain_analysis_input(capacity)?);
    let output =
        query.evaluate_component([1; 16], &package, &evaluation, &control, |_, _, wire| {
            assert!(wire.inputs[0].data.arrow_ipc.len() >= minimum);
            let decoded = wire
                .decode(&package)
                .context(crate::AnalysisContractSnafu)?;
            assert_eq!(
                decoded.inputs[0].data.batches,
                evaluation.inputs[0].data.batches
            );
            assert_eq!(decoded.inputs[0].revision, evaluation.inputs[0].revision);
            assert_eq!(decoded.inputs[0].coverage, evaluation.inputs[0].coverage);
            assert_eq!(decoded.context, evaluation.context);
            let output = sdk::Output {
                datasets: vec![sdk::Dataset {
                    name: "data".into(),
                    batches: decoded.inputs[0].data.batches.clone(),
                }],
                ..Default::default()
            };
            let bytes = output.allocated_bytes();
            Ok((output, bytes))
        })?;
    assert_eq!(
        output.output.datasets[0].batches,
        evaluation.inputs[0].data.batches
    );
    let held = query.retain_analysis_input(capacity - retained)?;
    assert!(query.retain_analysis_input(1).is_err());
    drop(held);
    drop(output);
    drop(query.retain_analysis_input(capacity)?);
    Ok(())
}

#[test]
fn struct_reserves_encoding() -> TestResult {
    check_nested(Arc::new(records(1_000_000)?), 125_000)
}

#[test]
fn fixed_list_reserves_encoding() -> TestResult {
    let records = records(128 * 65_536)?;
    let field = Arc::new(sdk::Field::new("item", records.data_type().clone(), false));
    let array = FixedSizeListArray::try_new(field, 65_536, Arc::new(records), None)?;
    check_nested(Arc::new(array), 1024 * 1024)
}
