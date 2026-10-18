use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{cast::AsArray, types::Float32Type, types::Float64Type, Array};

pub(super) fn output(actual: &sdk::Output, expected: &sdk::Output, model: &sdk::Model) -> bool {
    let mut actual_evidence: Vec<_> = actual.evidence.iter().collect();
    let mut expected_evidence: Vec<_> = expected.evidence.iter().collect();
    actual_evidence.sort();
    expected_evidence.sort();
    datasets(&actual.datasets, &expected.datasets, model.tolerance)
        && actual_evidence == expected_evidence
        && reasons(&actual.reasons, &expected.reasons, model.tolerance)
        && match (&actual.checkpoint, &expected.checkpoint) {
            (None, None) => true,
            (Some(actual), Some(expected)) => {
                actual.version == expected.version
                    && datasets(&actual.datasets, &expected.datasets, model.tolerance)
            }
            _ => false,
        }
}

fn datasets(
    actual: &[sdk::Dataset],
    expected: &[sdk::Dataset],
    tolerance: sdk::NumericTolerance,
) -> bool {
    let expected: BTreeMap<_, _> = expected.iter().map(|data| (&data.name, data)).collect();
    actual.len() == expected.len()
        && actual.iter().all(|data| {
            expected
                .get(&data.name)
                .is_some_and(|expected| batches(&data.batches, &expected.batches, tolerance))
        })
}

fn batches(
    actual: &[sdk::RecordBatch],
    expected: &[sdk::RecordBatch],
    tolerance: sdk::NumericTolerance,
) -> bool {
    let mut left = actual.iter().filter(|batch| batch.num_rows() > 0);
    let mut right = expected.iter().filter(|batch| batch.num_rows() > 0);
    let (mut a, mut b) = (left.next(), right.next());
    let (mut ai, mut bi) = (0, 0);
    while let (Some(av), Some(bv)) = (a, b) {
        let count = (av.num_rows() - ai).min(bv.num_rows() - bi);
        if !batch(&av.slice(ai, count), &bv.slice(bi, count), tolerance) {
            return false;
        }
        ai += count;
        bi += count;
        if ai == av.num_rows() {
            a = left.next();
            ai = 0;
        }
        if bi == bv.num_rows() {
            b = right.next();
            bi = 0;
        }
    }
    a.is_none() && b.is_none()
}

fn batch(
    actual: &sdk::RecordBatch,
    expected: &sdk::RecordBatch,
    tolerance: sdk::NumericTolerance,
) -> bool {
    actual.schema() == expected.schema()
        && actual.num_rows() == expected.num_rows()
        && actual
            .columns()
            .iter()
            .zip(expected.columns())
            .all(|(a, b)| array(a.as_ref(), b.as_ref(), tolerance))
}

fn reasons(
    actual: &[sdk::ReasonValue],
    expected: &[sdk::ReasonValue],
    tolerance: sdk::NumericTolerance,
) -> bool {
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|reason| ((&reason.output, &reason.code), reason))
        .collect();
    actual.len() == expected.len()
        && actual.iter().all(|reason| {
            expected
                .get(&(&reason.output, &reason.code))
                .is_some_and(|expected| batch(&reason.details, &expected.details, tolerance))
        })
}

fn array(actual: &dyn Array, expected: &dyn Array, tolerance: sdk::NumericTolerance) -> bool {
    if actual.to_data() == expected.to_data() {
        return true;
    }
    if actual.data_type() != expected.data_type() || actual.len() != expected.len() {
        return false;
    }
    (0..actual.len()).all(|row| {
        if actual.is_null(row) || expected.is_null(row) {
            return actual.is_null(row) == expected.is_null(row);
        }
        match actual.data_type() {
            sdk::DataType::Float32 => actual
                .as_primitive_opt::<Float32Type>()
                .zip(expected.as_primitive_opt::<Float32Type>())
                .is_some_and(|(a, b)| {
                    number(f64::from(a.value(row)), f64::from(b.value(row)), tolerance)
                }),
            sdk::DataType::Float64 => actual
                .as_primitive_opt::<Float64Type>()
                .zip(expected.as_primitive_opt::<Float64Type>())
                .is_some_and(|(a, b)| number(a.value(row), b.value(row), tolerance)),
            sdk::DataType::List(_) => actual
                .as_list_opt::<i32>()
                .zip(expected.as_list_opt::<i32>())
                .is_some_and(|(a, b)| {
                    array(a.value(row).as_ref(), b.value(row).as_ref(), tolerance)
                }),
            sdk::DataType::FixedSizeList(_, _) => actual
                .as_fixed_size_list_opt()
                .zip(expected.as_fixed_size_list_opt())
                .is_some_and(|(a, b)| {
                    array(a.value(row).as_ref(), b.value(row).as_ref(), tolerance)
                }),
            sdk::DataType::Struct(_) => actual
                .as_struct_opt()
                .zip(expected.as_struct_opt())
                .is_some_and(|(a, b)| {
                    a.columns().iter().zip(b.columns()).all(|(a, b)| {
                        array(
                            a.slice(row, 1).as_ref(),
                            b.slice(row, 1).as_ref(),
                            tolerance,
                        )
                    })
                }),
            _ => actual.slice(row, 1).to_data() == expected.slice(row, 1).to_data(),
        }
    })
}

fn number(actual: f64, expected: f64, tolerance: sdk::NumericTolerance) -> bool {
    if actual == expected {
        return true;
    }
    if !actual.is_finite() || !expected.is_finite() {
        return false;
    }
    let scale = actual.abs().max(expected.abs());
    let difference = (actual - expected).abs();
    let limit = tolerance.absolute + tolerance.relative * scale;
    if difference.is_finite() && limit.is_finite() {
        difference <= limit
    } else {
        (actual / scale - expected / scale).abs() <= tolerance.absolute / scale + tolerance.relative
    }
}
