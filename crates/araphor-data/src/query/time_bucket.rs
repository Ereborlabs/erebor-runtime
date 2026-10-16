use std::any::Any;
use std::sync::Arc;

use datafusion::arrow::array::types::{Date32Type, IntervalMonthDayNanoType};
use datafusion::arrow::array::{ArrayRef, AsArray, Date32Array, TimestampMicrosecondArray};
use datafusion::arrow::datatypes::{DataType, IntervalUnit, TimeUnit};
use datafusion::common::{exec_err, plan_err, Result, ScalarValue};
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDFImpl, Signature, Volatility,
};

const MICROS_PER_DAY: i64 = 86_400_000_000;
const DEFAULT_ORIGIN: i64 = 10_959 * MICROS_PER_DAY;
const TIMESTAMP_TYPE: DataType = DataType::Timestamp(TimeUnit::Microsecond, None);
const INTERVAL_TYPE: DataType = DataType::Interval(IntervalUnit::MonthDayNano);

#[cfg(test)]
fn fixed_interval(micros: i64) -> Result<ScalarValue> {
    if micros <= 0 {
        return exec_err!("time_bucket requires a positive fixed interval");
    }
    Ok(ScalarValue::IntervalMonthDayNano(Some(
        IntervalMonthDayNanoType::make_value(
            0,
            (micros / MICROS_PER_DAY) as i32,
            (micros % MICROS_PER_DAY) * 1_000,
        ),
    )))
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct TimeBucket {
    signature: Signature,
}

impl TimeBucket {
    pub(super) fn new() -> Self {
        Self {
            signature: Signature::user_defined(Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for TimeBucket {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "time_bucket"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn coerce_types(&self, types: &[DataType]) -> Result<Vec<DataType>> {
        if !(2..=3).contains(&types.len())
            || !matches!(types[0], DataType::Interval(_) | DataType::Null)
        {
            return plan_err!("time_bucket requires an interval and a date or timestamp");
        }
        let mut result = types.to_vec();
        result[0] = INTERVAL_TYPE;
        if result[1] == DataType::Null {
            result[1] = if matches!(types.get(2), Some(DataType::Timestamp(..))) {
                TIMESTAMP_TYPE
            } else {
                DataType::Date32
            };
        }
        if !is_temporal(&result[1]) {
            return plan_err!("time_bucket requires a date or timestamp");
        }
        if result.len() == 3 {
            match &result[2] {
                DataType::Interval(_) => result[2] = INTERVAL_TYPE,
                DataType::Null if result[1] == DataType::Date32 => {
                    return plan_err!(
                        "time_bucket requires an explicit type for the null third argument"
                    );
                }
                DataType::Null => result[2] = result[1].clone(),
                value if is_temporal(value) => {}
                _ => {
                    return plan_err!("time_bucket requires an interval offset or temporal origin");
                }
            }
        }
        Ok(result)
    }

    fn return_type(&self, types: &[DataType]) -> Result<DataType> {
        let types = self.coerce_types(types)?;
        Ok(
            if types[1] == DataType::Date32
                && !matches!(types.get(2), Some(DataType::Timestamp(..)))
            {
                DataType::Date32
            } else {
                TIMESTAMP_TYPE
            },
        )
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> Result<ColumnarValue> {
        let arrays = ColumnarValue::values_to_arrays(&args.args)?;
        let offsets = arrays
            .get(2)
            .filter(|array| array.data_type() == &INTERVAL_TYPE);
        let date_result = args.return_type() == &DataType::Date32;
        let mut values = Vec::with_capacity(arrays[1].len());
        for row in 0..arrays[1].len() {
            if arrays
                .iter()
                .any(|array| array.data_type() == &DataType::Null || array.is_null(row))
            {
                values.push(None);
                continue;
            }
            let width = arrays[0]
                .as_primitive::<IntervalMonthDayNanoType>()
                .value(row);
            let micros = i64::from(width.days)
                .checked_mul(MICROS_PER_DAY)
                .and_then(|days| days.checked_add(width.nanoseconds / 1_000));
            let Some(micros) = micros.filter(|value| *value > 0 && width.months == 0) else {
                return exec_err!("time_bucket requires a positive fixed interval");
            };
            if let Some(origin) = arrays.get(2).filter(|_| date_result && offsets.is_none()) {
                let origin = origin.as_primitive::<Date32Type>().value(row);
                if origin == i32::MAX || origin == -i32::MAX {
                    values.push(None);
                    continue;
                }
            }
            let source = temporal_value(&arrays[1], row)?;
            let value = if let Some(offsets) = offsets {
                let offset = offsets
                    .as_primitive::<IntervalMonthDayNanoType>()
                    .value(row);
                if is_infinite(source) {
                    source
                } else {
                    let adjusted = shift(
                        source,
                        offset.months,
                        offset.days,
                        offset.nanoseconds / 1_000,
                        true,
                    )?;
                    let bucket = bucket(micros, adjusted, DEFAULT_ORIGIN)?;
                    shift(
                        bucket,
                        offset.months,
                        offset.days,
                        offset.nanoseconds / 1_000,
                        false,
                    )?
                }
            } else if date_result && is_infinite(source) {
                source
            } else {
                let origin = match arrays.get(2) {
                    Some(array) => temporal_value(array, row)?,
                    None => DEFAULT_ORIGIN,
                };
                if is_infinite(origin) {
                    values.push(None);
                    continue;
                }
                if is_infinite(source) {
                    source
                } else {
                    bucket(micros, source, origin)?
                }
            };
            values.push(Some(value));
        }
        let result: ArrayRef = if date_result {
            Arc::new(Date32Array::from(
                values
                    .into_iter()
                    .map(|value| {
                        value.map(|value| {
                            if is_infinite(value) {
                                if value < 0 {
                                    -i32::MAX
                                } else {
                                    i32::MAX
                                }
                            } else {
                                value.div_euclid(MICROS_PER_DAY) as i32
                            }
                        })
                    })
                    .collect::<Vec<_>>(),
            ))
        } else {
            Arc::new(TimestampMicrosecondArray::from(values))
        };
        if args
            .args
            .iter()
            .all(|value| matches!(value, ColumnarValue::Scalar(_)))
        {
            Ok(ColumnarValue::Scalar(ScalarValue::try_from_array(
                &result, 0,
            )?))
        } else {
            Ok(ColumnarValue::Array(result))
        }
    }
}

fn is_temporal(value: &DataType) -> bool {
    matches!(
        value,
        DataType::Date32 | DataType::Timestamp(TimeUnit::Microsecond | TimeUnit::Nanosecond, _)
    )
}

fn is_infinite(value: i64) -> bool {
    value == i64::MAX || value == -i64::MAX
}

fn temporal_value(array: &ArrayRef, row: usize) -> Result<i64> {
    match ScalarValue::try_from_array(array, row)? {
        ScalarValue::TimestampMicrosecond(Some(value), _) => Ok(value),
        ScalarValue::TimestampNanosecond(Some(value), _) => Ok(if is_infinite(value) {
            value
        } else {
            value / 1_000
        }),
        ScalarValue::Date32(Some(value)) => {
            if value == i32::MAX || value == -i32::MAX {
                Ok(if value < 0 { -i64::MAX } else { i64::MAX })
            } else {
                i64::from(value)
                    .checked_mul(MICROS_PER_DAY)
                    .ok_or_else(range_error)
            }
        }
        _ => exec_err!("time_bucket requires a date or timestamp"),
    }
}

fn bucket(width: i64, source: i64, origin: i64) -> Result<i64> {
    let origin = origin % width;
    let delta = source.checked_sub(origin).ok_or_else(range_error)?;
    let mut result = (delta / width) * width;
    if delta < 0 && delta % width != 0 {
        result = result.checked_sub(width).ok_or_else(range_error)?;
    }
    result.checked_add(origin).ok_or_else(range_error)
}

fn shift(
    value: i64,
    mut months: i32,
    mut days: i32,
    mut micros: i64,
    subtract: bool,
) -> Result<i64> {
    if is_infinite(value) {
        return Ok(value);
    }
    if subtract {
        months = months.checked_neg().ok_or_else(range_error)?;
        days = days.checked_neg().ok_or_else(range_error)?;
        micros = micros.checked_neg().ok_or_else(range_error)?;
    }
    let date = value.div_euclid(MICROS_PER_DAY);
    date.checked_mul(MICROS_PER_DAY).ok_or_else(range_error)?;
    // Map the date into one Gregorian cycle. This keeps Arrow month arithmetic in range.
    let date = if months == 0 {
        date
    } else {
        let mapped = Date32Type::add_year_months_opt(
            date.rem_euclid(146_097) as i32,
            months.rem_euclid(4_800),
        )
        .ok_or_else(range_error)?;
        i64::from(mapped)
            + (date.div_euclid(146_097) + i64::from(months.div_euclid(4_800))) * 146_097
    };
    let date = i32::try_from(date)
        .ok()
        .filter(|value| *value > -i32::MAX && *value < i32::MAX)
        .ok_or_else(range_error)?;
    let mut date = date
        .checked_add(days)
        .and_then(|value| value.checked_add((micros / MICROS_PER_DAY) as i32))
        .filter(|value| *value != i32::MAX && *value != -i32::MAX)
        .ok_or_else(range_error)?;
    let mut time = value.rem_euclid(MICROS_PER_DAY) + micros % MICROS_PER_DAY;
    if time >= MICROS_PER_DAY {
        date = date.checked_add(1).ok_or_else(range_error)?;
        time -= MICROS_PER_DAY;
    } else if time < 0 {
        date = date.checked_sub(1).ok_or_else(range_error)?;
        time += MICROS_PER_DAY;
    }
    i64::from(date)
        .checked_mul(MICROS_PER_DAY)
        .and_then(|value| value.checked_add(time))
        .filter(|value| !is_infinite(*value))
        .ok_or_else(range_error)
}

fn range_error() -> datafusion::common::DataFusionError {
    datafusion::common::DataFusionError::Execution("time_bucket timestamp is out of range".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::TimestampNanosecondArray;
    use datafusion::arrow::datatypes::Field;
    use datafusion::common::config::ConfigOptions;
    use duckdb::types::{TimeUnit as DuckTimeUnit, Value};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn timestamp(value: Option<i64>) -> ColumnarValue {
        ColumnarValue::Scalar(ScalarValue::TimestampMicrosecond(value, None))
    }

    fn interval(months: i32, days: i32, micros: i64) -> ColumnarValue {
        ColumnarValue::Scalar(ScalarValue::IntervalMonthDayNano(Some(
            IntervalMonthDayNanoType::make_value(months, days, micros * 1_000),
        )))
    }

    fn width(micros: i64) -> Result<ColumnarValue> {
        Ok(ColumnarValue::Scalar(fixed_interval(micros)?))
    }

    fn evaluate(args: Vec<ColumnarValue>) -> Result<(DataType, Vec<Value>)> {
        let function = TimeBucket::new();
        let types = args
            .iter()
            .map(ColumnarValue::data_type)
            .collect::<Vec<_>>();
        let number_rows = args
            .iter()
            .find_map(|arg| match arg {
                ColumnarValue::Array(array) => Some(array.len()),
                _ => None,
            })
            .unwrap_or(1);
        let output = function
            .invoke_with_args(ScalarFunctionArgs {
                arg_fields: types
                    .iter()
                    .map(|value| Arc::new(Field::new("arg", value.clone(), true)))
                    .collect(),
                return_field: Arc::new(Field::new("result", function.return_type(&types)?, true)),
                args,
                number_rows,
                config_options: Arc::new(ConfigOptions::default()),
            })?
            .into_array(number_rows)?;
        let values = (0..output.len())
            .map(|row| {
                Ok(match ScalarValue::try_from_array(&output, row)? {
                    value if value.is_null() => Value::Null,
                    ScalarValue::Date32(Some(value)) => Value::Date32(value),
                    ScalarValue::TimestampMicrosecond(Some(value), None) => {
                        Value::Timestamp(DuckTimeUnit::Microsecond, value)
                    }
                    value => return exec_err!("unexpected time_bucket output: {value:?}"),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((output.data_type().clone(), values))
    }

    fn compare(args: Vec<ColumnarValue>, sql: &str) -> TestResult {
        let db = duckdb::Connection::open_in_memory()?;
        let mut statement = db.prepare(sql)?;
        let expected = statement
            .query_map([], |row| row.get::<_, Value>(0))?
            .collect::<duckdb::Result<Vec<_>>>()?;
        assert_eq!(
            evaluate(args)?,
            (statement.column_type(0), expected),
            "{sql}"
        );
        Ok(())
    }

    #[test]
    fn time_bucket_default_anchor_and_negative_boundaries() -> TestResult {
        compare(
            vec![
                width(7 * MICROS_PER_DAY)?,
                timestamp(Some(10_958 * MICROS_PER_DAY)),
            ],
            "SELECT time_bucket(INTERVAL '7 days', TIMESTAMP '2000-01-02')",
        )?;
        for value in [
            -1_000_001, -1_000_000, -999_999, -1, 0, 1, 999_999, 1_000_000,
        ] {
            compare(
                vec![width(1_000_000)?, timestamp(Some(value)), timestamp(Some(0))],
                &format!(
                    "SELECT time_bucket(INTERVAL '1 second', make_timestamp({value}), TIMESTAMP '1970-01-01')"
                ),
            )?;
        }
        Ok(())
    }

    #[test]
    fn time_bucket_origins_and_offsets() -> TestResult {
        compare(
            vec![width(10)?, timestamp(Some(-2)), timestamp(Some(-1))],
            "SELECT time_bucket(INTERVAL '10 microseconds', make_timestamp(-2), make_timestamp(-1))",
        )?;
        compare(
            vec![
                width(MICROS_PER_DAY)?,
                timestamp(Some(0)),
                interval(0, 0, 7_200_000_000),
            ],
            "SELECT time_bucket(INTERVAL '1 day', TIMESTAMP '1970-01-01', INTERVAL '2 hours')",
        )?;
        compare(
            vec![
                width(7 * MICROS_PER_DAY)?,
                timestamp(Some(1_585_656_000_000_000)),
                interval(1, 2, -3_600_000_000),
            ],
            "SELECT time_bucket(INTERVAL '7 days', make_timestamp(1585656000000000), INTERVAL '1 month 2 days -1 hour')",
        )?;
        let origins = Arc::new(TimestampMicrosecondArray::from(vec![
            Some(1),
            Some(-1),
            None,
            Some(5),
        ]));
        let sources = Arc::new(TimestampMicrosecondArray::from(vec![
            Some(-1),
            Some(0),
            Some(20),
            None,
        ]));
        compare(
            vec![
                width(10)?,
                ColumnarValue::Array(sources),
                ColumnarValue::Array(origins),
            ],
            "SELECT time_bucket(INTERVAL '10 microseconds', make_timestamp(t), make_timestamp(o)) FROM (VALUES (-1, 1), (0, -1), (20, NULL), (NULL, 5)) input(t, o)",
        )?;
        Ok(())
    }

    #[test]
    fn time_bucket_dates_and_nulls() -> TestResult {
        let date = |value| ColumnarValue::Scalar(ScalarValue::Date32(value));
        compare(
            vec![width(7 * MICROS_PER_DAY)?, date(Some(10_958))],
            "SELECT time_bucket(INTERVAL '7 days', DATE '2000-01-02')",
        )?;
        compare(
            vec![width(7 * MICROS_PER_DAY)?, date(Some(-1)), date(Some(0))],
            "SELECT time_bucket(INTERVAL '7 days', DATE '1969-12-31', DATE '1970-01-01')",
        )?;
        compare(
            vec![
                width(MICROS_PER_DAY)?,
                date(Some(0)),
                interval(0, 0, 7_200_000_000),
            ],
            "SELECT time_bucket(INTERVAL '1 day', DATE '1970-01-01', INTERVAL '2 hours')",
        )?;
        compare(
            vec![width(MICROS_PER_DAY)?, date(Some(0)), timestamp(Some(1))],
            "SELECT time_bucket(INTERVAL '1 day', DATE '1970-01-01', make_timestamp(1))",
        )?;
        compare(
            vec![width(1_000_000)?, timestamp(None)],
            "SELECT time_bucket(INTERVAL '1 second', NULL::TIMESTAMP)",
        )?;
        compare(
            vec![width(1_000_000)?, timestamp(Some(0)), timestamp(None)],
            "SELECT time_bucket(INTERVAL '1 second', TIMESTAMP '1970-01-01', NULL::TIMESTAMP)",
        )?;
        compare(
            vec![width(MICROS_PER_DAY)?, date(None)],
            "SELECT time_bucket(INTERVAL '1 day', NULL::DATE)",
        )?;
        compare(
            vec![
                width(MICROS_PER_DAY)?,
                ColumnarValue::Scalar(ScalarValue::Null),
            ],
            "SELECT time_bucket(INTERVAL '1 day', NULL)",
        )?;
        compare(
            vec![
                width(MICROS_PER_DAY)?,
                ColumnarValue::Scalar(ScalarValue::Null),
                interval(1, 0, 0),
            ],
            "SELECT time_bucket(INTERVAL '1 day', NULL, INTERVAL '1 month')",
        )?;
        compare(
            vec![
                width(MICROS_PER_DAY)?,
                ColumnarValue::Array(Arc::new(datafusion::arrow::array::NullArray::new(2))),
            ],
            "SELECT time_bucket(INTERVAL '1 day', NULL) FROM (VALUES (1), (2)) input(value)",
        )?;
        compare(
            vec![ColumnarValue::Scalar(ScalarValue::Null), timestamp(Some(0))],
            "SELECT time_bucket(NULL, TIMESTAMP '1970-01-01')",
        )?;
        Ok(())
    }

    #[test]
    fn time_bucket_large_microseconds_and_model_nanoseconds() -> TestResult {
        for value in [-10_000_000_000_000_001, 10_000_000_000_000_001] {
            compare(
                vec![width(1_000_000)?, timestamp(Some(value))],
                &format!("SELECT time_bucket(INTERVAL '1 second', make_timestamp({value}))"),
            )?;
            compare(
                vec![width(i64::MAX)?, timestamp(Some(value))],
                &format!(
                    "SELECT time_bucket(INTERVAL '9223372036854775807 microseconds', make_timestamp({value}))"
                ),
            )?;
        }
        let source =
            TimestampNanosecondArray::from(vec![-1_999, -999, 999, 1_999]).with_timezone("UTC");
        compare(
            vec![width(1)?, ColumnarValue::Array(Arc::new(source))],
            "SELECT time_bucket(INTERVAL '1 microsecond', make_timestamp_ns(t)) FROM (VALUES (-1999), (-999), (999), (1999)) input(t)",
        )?;
        for value in [-9_000_000_000_000_000_000, 9_000_000_000_000_000_000] {
            compare(
                vec![
                    width(7 * MICROS_PER_DAY)?,
                    timestamp(Some(value)),
                    interval(1, 0, 0),
                ],
                &format!(
                    "SELECT time_bucket(INTERVAL '7 days', make_timestamp({value}), INTERVAL '1 month')"
                ),
            )?;
        }
        Ok(())
    }

    #[test]
    fn time_bucket_infinite_values_and_checked_overflow() -> TestResult {
        for (value, sql) in [(i64::MAX, "infinity"), (-i64::MAX, "-infinity")] {
            compare(
                vec![width(MICROS_PER_DAY)?, timestamp(Some(value))],
                &format!("SELECT time_bucket(INTERVAL '1 day', TIMESTAMP '{sql}')"),
            )?;
            compare(
                vec![
                    width(MICROS_PER_DAY)?,
                    timestamp(Some(0)),
                    timestamp(Some(value)),
                ],
                &format!(
                    "SELECT time_bucket(INTERVAL '1 day', TIMESTAMP '1970-01-01', TIMESTAMP '{sql}')"
                ),
            )?;
        }
        compare(
            vec![
                width(MICROS_PER_DAY)?,
                ColumnarValue::Scalar(ScalarValue::Date32(Some(i32::MAX - 1))),
                ColumnarValue::Scalar(ScalarValue::Date32(Some(i32::MAX))),
            ],
            "SELECT time_bucket(INTERVAL '1 day', DATE '5881580-07-10', DATE 'infinity')",
        )?;
        compare(
            vec![
                width(MICROS_PER_DAY)?,
                ColumnarValue::Scalar(ScalarValue::Date32(Some(i32::MAX))),
                ColumnarValue::Scalar(ScalarValue::Date32(Some(i32::MAX - 1))),
            ],
            "SELECT time_bucket(INTERVAL '1 day', DATE 'infinity', DATE '5881580-07-10')",
        )?;
        assert!(evaluate(vec![width(10)?, timestamp(Some(i64::MIN))]).is_err());
        let db = duckdb::Connection::open_in_memory()?;
        assert!(db.query_row("SELECT time_bucket(INTERVAL '10 microseconds', make_timestamp(CAST('-9223372036854775808' AS BIGINT)))", [], |row| row.get::<_, Value>(0)).is_err());
        Ok(())
    }

    #[test]
    fn time_bucket_null_origin_requires_a_type_for_date_source() -> TestResult {
        let db = duckdb::Connection::open_in_memory()?;
        for (source, sql) in [
            (ScalarValue::Date32(Some(0)), "DATE '1970-01-01'"),
            (ScalarValue::Null, "NULL"),
        ] {
            assert!(evaluate(vec![
                width(MICROS_PER_DAY)?,
                ColumnarValue::Scalar(source),
                ColumnarValue::Scalar(ScalarValue::Null)
            ])
            .is_err());
            assert!(db
                .query_row(
                    &format!("SELECT time_bucket(INTERVAL '1 day', {sql}, NULL)"),
                    [],
                    |row| row.get::<_, Value>(0)
                )
                .is_err());
        }
        Ok(())
    }
}
