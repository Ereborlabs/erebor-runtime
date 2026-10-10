use arrow_array::{
    builder::{Float64Builder, ListBuilder},
    types::Float64Type,
    Array, ArrayRef, FixedSizeListArray, Float32Array, Float64Array, ListArray, NullArray,
    StructArray,
};

use super::*;

fn validate(array: ArrayRef) -> Result<()> {
    let mut package = FilesCount::package();
    let mut fixture = FilesCount::fixture()?;
    let schema = Schema::new(vec![Field::new("value", array.data_type().clone(), true)]);
    package.exports[0].inputs[0].schema = schema.clone();
    fixture.evaluation.inputs[0].data.batches =
        vec![RecordBatch::try_new(Arc::new(schema), vec![array])?];
    package.validate_evaluation(&fixture.evaluation)
}

#[test]
fn sliced_lists_skip_hidden() -> TestResult {
    let mut builder = ListBuilder::new(Float64Builder::new());
    for (value, valid) in [
        (f64::NAN, true),
        (1.0, true),
        (f64::INFINITY, false),
        (2.0, true),
        (f64::NEG_INFINITY, true),
    ] {
        builder.values().append_value(value);
        builder.append(valid);
    }
    let lists = builder.finish();
    validate(Arc::new(lists.slice(1, 3)))?;
    validate(Arc::new(lists.slice(2, 0)))?;
    for slice in [lists.slice(0, 1), lists.slice(3, 2)] {
        assert_eq!(
            validate(Arc::new(slice)).unwrap_err().code(),
            ErrorCode::Invalid
        );
    }
    Ok(())
}

#[test]
fn struct_masks_nested_list() -> TestResult {
    let lists = Arc::new(ListArray::from_iter_primitive::<Float64Type, _, _>([
        Some(vec![Some(f64::NAN)]),
        Some(vec![None, Some(1.0)]),
        Some(vec![Some(f64::INFINITY)]),
    ]));
    let fields = vec![Field::new("list", lists.data_type().clone(), false)].into();
    let structure =
        StructArray::try_new(fields, vec![lists], Some(vec![false, true, true].into()))?;
    validate(Arc::new(structure.slice(0, 2)))?;
    validate(Arc::new(structure.slice(1, 1)))?;
    assert_eq!(
        validate(Arc::new(structure)).unwrap_err().code(),
        ErrorCode::Invalid
    );
    Ok(())
}

#[test]
fn fixed_lists_skip_hidden() -> TestResult {
    let lists = FixedSizeListArray::try_new(
        Arc::new(Field::new("item", DataType::Float32, true)),
        2,
        Arc::new(Float32Array::from(vec![
            Some(f32::NAN),
            Some(f32::INFINITY),
            Some(1.0),
            None,
            Some(f32::NAN),
            Some(f32::NEG_INFINITY),
        ])),
        Some(vec![false, true, true].into()),
    )?;
    validate(Arc::new(lists.slice(0, 2)))?;
    validate(Arc::new(lists.slice(1, 1)))?;
    assert_eq!(
        validate(Arc::new(lists)).unwrap_err().code(),
        ErrorCode::Invalid
    );
    Ok(())
}

#[test]
fn floats_check_selected_values() -> TestResult {
    for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let values = Float64Array::from(vec![Some(invalid), None, Some(1.0)]);
        validate(Arc::new(values.slice(1, 2)))?;
        assert_eq!(
            validate(Arc::new(values)).unwrap_err().code(),
            ErrorCode::Invalid
        );
    }
    let values = Float32Array::from(vec![Some(f32::NAN), None, Some(1.0)]);
    validate(Arc::new(values.slice(1, 2)))?;
    assert_eq!(
        validate(Arc::new(values)).unwrap_err().code(),
        ErrorCode::Invalid
    );
    Ok(())
}

#[test]
fn null_type_requires_nullable() -> TestResult {
    validate(Arc::new(NullArray::new(1)))?;
    let required = Arc::new(Field::new("required", DataType::Null, false));
    for field in [
        required.clone(),
        Arc::new(Field::new("list", DataType::List(required.clone()), true)),
        Arc::new(Field::new(
            "fixed",
            DataType::FixedSizeList(required.clone(), 1),
            true,
        )),
        Arc::new(Field::new(
            "struct",
            DataType::Struct(vec![required].into()),
            true,
        )),
    ] {
        let mut package = FilesCount::package();
        package.exports[0].inputs[0].schema = Schema::new(vec![field]);
        assert_eq!(
            package.validate().unwrap_err().code(),
            ErrorCode::Incompatible
        );
    }
    Ok(())
}
