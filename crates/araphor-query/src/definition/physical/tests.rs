use super::*;
use sdk::arrow_array::{StringArray, UInt64Array};

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn parameters_keep_input_claim() -> TestResult {
    let capacity = 1024 * 1024;
    let memory = Memory::new(Some(capacity), None);
    let reservation = memory.reserve_input(0)?;
    let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
        "value",
        sdk::DataType::Utf8,
        false,
    )]));
    let text = "x".repeat(64 * 1024);
    let parameters = sdk::RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(StringArray::from(vec![text.as_str()]))],
    )?;
    let empty = sdk::RecordBatch::new_empty(schema);
    let scalar = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
        "value",
        sdk::DataType::UInt64,
        false,
    )]));
    let input = sdk::RecordBatch::try_new(
        Arc::clone(&scalar),
        vec![Arc::new(UInt64Array::from(vec![3]))],
    )?;
    let prior = sdk::RecordBatch::try_new(scalar, vec![Arc::new(UInt64Array::from(vec![7]))])?;
    for batch in [&input, &prior, &parameters, &empty] {
        memory.retain_input(batch, &reservation)?;
    }
    let buffers = |batch: &sdk::RecordBatch| {
        batch
            .columns()
            .iter()
            .map(|array| array.get_buffer_memory_size())
            .sum::<usize>()
    };
    let parameter_bytes = buffers(&parameters);
    let retained = [&input, &prior, &parameters, &empty]
        .into_iter()
        .map(buffers)
        .sum::<usize>();
    let held = memory.reserve_input(capacity - retained)?;
    assert!(memory.reserve_input(1).is_err());
    let parameters = PackageExec::parameters(vec![empty.clone(), parameters, empty.clone()])?;
    assert_eq!(parameters.num_rows(), 1);
    assert_eq!(
        parameters
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or("parameter type")?
            .value(0),
        text
    );
    assert!(memory.reserve_input(1).is_err());
    drop(parameters);
    let released = memory.reserve_input(parameter_bytes)?;
    drop((released, held, input, prior, empty, reservation));
    drop(memory.reserve_input(capacity)?);
    Ok(())
}

#[test]
fn parameters_require_one_row() -> TestResult {
    let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
        "value",
        sdk::DataType::UInt64,
        false,
    )]));
    let empty = sdk::RecordBatch::new_empty(Arc::clone(&schema));
    let one = sdk::RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(UInt64Array::from(vec![1]))],
    )?;
    let two = sdk::RecordBatch::try_new(schema, vec![Arc::new(UInt64Array::from(vec![1, 2]))])?;
    for batches in [Vec::new(), vec![empty], vec![two], vec![one.clone(), one]] {
        let error = PackageExec::parameters(batches)
            .err()
            .ok_or("invalid parameters accepted")?;
        assert!(matches!(error, DataFusionError::External(source)
            if source.downcast_ref::<sdk::Error>().is_some_and(|error| error.code() == sdk::ErrorCode::Invalid)));
    }
    Ok(())
}
