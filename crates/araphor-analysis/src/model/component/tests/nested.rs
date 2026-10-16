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
    let fixture = Fixture::new()?;
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
    assert!(evaluation.allocated_bytes() < 32 * 1024);
    assert!(evaluation.encoding_scratch_bytes()? >= minimum);
    let preflight = fixture.owner.exchange_preflight(&package, &evaluation)?;
    let memory = fixture.owner.query.memory();
    let capacity = fixture.owner.query.limits().input_capacity;
    let pressure = memory.reserve_input(capacity - 32 * 1024)?;
    assert!(memory.reserve_input(preflight).is_err());
    drop(pressure);
    let reservation = memory.reserve_input(preflight)?;
    let wire = package.check_evaluation(&evaluation)?.encode()?;
    assert!(wire.inputs[0].data.arrow_ipc.len() >= minimum);
    let decoded = wire.decode(&package)?;
    assert_eq!(
        decoded.inputs[0].data.batches,
        evaluation.inputs[0].data.batches
    );
    assert_eq!(decoded.inputs[0].revision, evaluation.inputs[0].revision);
    assert_eq!(decoded.inputs[0].coverage, evaluation.inputs[0].coverage);
    assert_eq!(decoded.context, evaluation.context);
    drop((wire, decoded, reservation));
    drop(memory.reserve_input(capacity)?);
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
