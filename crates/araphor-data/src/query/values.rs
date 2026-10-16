use datafusion::arrow::array::{
    ArrayRef, BinaryArray, BinaryViewArray, BooleanArray, Date32Array, Decimal128Array,
    Decimal256Array, Decimal32Array, Decimal64Array, FixedSizeBinaryArray, Float16Array,
    Float32Array, Float64Array, Int16Array, Int32Array, Int64Array, Int8Array,
    IntervalDayTimeArray, IntervalMonthDayNanoArray, IntervalYearMonthArray, LargeBinaryArray,
    LargeStringArray, StringArray, StringViewArray, Time32MillisecondArray, Time32SecondArray,
    Time64MicrosecondArray, Time64NanosecondArray, TimestampMicrosecondArray,
    TimestampMillisecondArray, TimestampNanosecondArray, TimestampSecondArray, UInt16Array,
    UInt32Array, UInt64Array, UInt8Array,
};
use datafusion::arrow::datatypes::{DataType, IntervalUnit, Schema, TimeUnit as ArrowTime};
use duckdb::core::LogicalTypeId;
use duckdb::types::{Decimal, TimeUnit, ValueRef};

use super::Column;
use crate::Result;

pub(super) struct QueryValues;

impl QueryValues {
    pub(super) fn columns(schema: &Schema) -> Result<Vec<Column>> {
        schema
            .fields()
            .iter()
            .map(|field| {
                Ok(Column {
                    name: field.name().clone(),
                    data_type: format!("{:?}", Self::logical_type(field.data_type())?),
                })
            })
            .collect()
    }

    pub(super) fn logical_type(kind: &DataType) -> Result<LogicalTypeId> {
        use LogicalTypeId as Sql;

        Ok(match kind {
            DataType::Null | DataType::Int32 => Sql::Integer,
            DataType::Boolean => Sql::Boolean,
            DataType::Int8 => Sql::Tinyint,
            DataType::Int16 => Sql::Smallint,
            DataType::Int64 => Sql::Bigint,
            DataType::UInt8 => Sql::UTinyint,
            DataType::UInt16 => Sql::USmallint,
            DataType::UInt32 => Sql::UInteger,
            DataType::UInt64 => Sql::UBigint,
            DataType::Float16 | DataType::Float32 => Sql::Float,
            DataType::Float64 => Sql::Double,
            DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => Sql::Varchar,
            DataType::Binary
            | DataType::LargeBinary
            | DataType::BinaryView
            | DataType::FixedSizeBinary(_) => Sql::Blob,
            DataType::Decimal256(39, 0) => Sql::Hugeint,
            DataType::Decimal32(width, scale)
            | DataType::Decimal64(width, scale)
            | DataType::Decimal128(width, scale)
            | DataType::Decimal256(width, scale) => {
                Self::decimal(*width, *scale, 0)?;
                Sql::Decimal
            }
            DataType::Timestamp(_, Some(_)) => Sql::TimestampTZ,
            DataType::Timestamp(ArrowTime::Second, None) => Sql::TimestampS,
            DataType::Timestamp(ArrowTime::Millisecond, None) => Sql::TimestampMs,
            DataType::Timestamp(ArrowTime::Microsecond, None) => Sql::Timestamp,
            DataType::Timestamp(ArrowTime::Nanosecond, None) => Sql::TimestampNs,
            DataType::Date32 => Sql::Date,
            DataType::Time32(ArrowTime::Second | ArrowTime::Millisecond)
            | DataType::Time64(ArrowTime::Microsecond) => Sql::Time,
            DataType::Time64(ArrowTime::Nanosecond) => Sql::TimeNs,
            DataType::Interval(_) => Sql::Interval,
            _ => return Err(Self::unsupported()),
        })
    }

    pub(super) fn value<'a>(
        array: &'a ArrayRef,
        row: usize,
        kind: LogicalTypeId,
    ) -> Result<ValueRef<'a>> {
        macro_rules! read {
            ($array:ty) => {
                array
                    .as_any()
                    .downcast_ref::<$array>()
                    .ok_or_else(|| Self::invalid("query result array"))?
                    .value(row)
            };
        }

        if row >= array.len() {
            return Err(Self::invalid("query result row"));
        }
        if array.data_type() == &DataType::Null || array.is_null(row) {
            return Ok(ValueRef::Null);
        }
        if matches!(kind, LogicalTypeId::Hugeint | LogicalTypeId::UHugeint) {
            let value = match array.data_type() {
                DataType::Decimal128(_, 0) => {
                    datafusion::arrow::datatypes::i256::from_i128(read!(Decimal128Array))
                }
                DataType::Decimal256(_, 0) => read!(Decimal256Array),
                _ => return Err(Self::invalid("query result integer type")),
            };
            return Ok(if kind == LogicalTypeId::Hugeint {
                ValueRef::HugeInt(
                    value
                        .to_i128()
                        .ok_or_else(|| Self::invalid("query result integer range"))?,
                )
            } else {
                let (low, high) = value.to_parts();
                if high != 0 {
                    return Err(Self::invalid("query result integer range"));
                }
                ValueRef::UHugeInt(low)
            });
        }
        if Self::logical_type(array.data_type())? != kind {
            return Err(Self::invalid("query result logical type"));
        }
        Ok(match array.data_type() {
            DataType::Boolean => ValueRef::Boolean(read!(BooleanArray)),
            DataType::Int8 => ValueRef::TinyInt(read!(Int8Array)),
            DataType::Int16 => ValueRef::SmallInt(read!(Int16Array)),
            DataType::Int32 => ValueRef::Int(read!(Int32Array)),
            DataType::Int64 => ValueRef::BigInt(read!(Int64Array)),
            DataType::UInt8 => ValueRef::UTinyInt(read!(UInt8Array)),
            DataType::UInt16 => ValueRef::USmallInt(read!(UInt16Array)),
            DataType::UInt32 => ValueRef::UInt(read!(UInt32Array)),
            DataType::UInt64 => ValueRef::UBigInt(read!(UInt64Array)),
            DataType::Float16 => ValueRef::Float(read!(Float16Array).to_f32()),
            DataType::Float32 => ValueRef::Float(read!(Float32Array)),
            DataType::Float64 => ValueRef::Double(read!(Float64Array)),
            DataType::Utf8 => ValueRef::Text(read!(StringArray).as_bytes()),
            DataType::LargeUtf8 => ValueRef::Text(read!(LargeStringArray).as_bytes()),
            DataType::Utf8View => ValueRef::Text(read!(StringViewArray).as_bytes()),
            DataType::Binary => ValueRef::Blob(read!(BinaryArray)),
            DataType::LargeBinary => ValueRef::Blob(read!(LargeBinaryArray)),
            DataType::BinaryView => ValueRef::Blob(read!(BinaryViewArray)),
            DataType::FixedSizeBinary(_) => ValueRef::Blob(read!(FixedSizeBinaryArray)),
            DataType::Decimal32(width, scale) => ValueRef::Decimal(Self::decimal(
                *width,
                *scale,
                i128::from(read!(Decimal32Array)),
            )?),
            DataType::Decimal64(width, scale) => ValueRef::Decimal(Self::decimal(
                *width,
                *scale,
                i128::from(read!(Decimal64Array)),
            )?),
            DataType::Decimal128(width, scale) => {
                ValueRef::Decimal(Self::decimal(*width, *scale, read!(Decimal128Array))?)
            }
            DataType::Decimal256(width, scale) => ValueRef::Decimal(Self::decimal(
                *width,
                *scale,
                read!(Decimal256Array)
                    .to_i128()
                    .ok_or_else(|| Self::invalid("query result decimal range"))?,
            )?),
            DataType::Timestamp(ArrowTime::Second, _) => {
                ValueRef::Timestamp(TimeUnit::Second, read!(TimestampSecondArray))
            }
            DataType::Timestamp(ArrowTime::Millisecond, _) => {
                ValueRef::Timestamp(TimeUnit::Millisecond, read!(TimestampMillisecondArray))
            }
            DataType::Timestamp(ArrowTime::Microsecond, _) => {
                ValueRef::Timestamp(TimeUnit::Microsecond, read!(TimestampMicrosecondArray))
            }
            DataType::Timestamp(ArrowTime::Nanosecond, _) => {
                ValueRef::Timestamp(TimeUnit::Nanosecond, read!(TimestampNanosecondArray))
            }
            DataType::Date32 => ValueRef::Date32(read!(Date32Array)),
            DataType::Time32(ArrowTime::Second) => {
                ValueRef::Time64(TimeUnit::Second, i64::from(read!(Time32SecondArray)))
            }
            DataType::Time32(ArrowTime::Millisecond) => ValueRef::Time64(
                TimeUnit::Millisecond,
                i64::from(read!(Time32MillisecondArray)),
            ),
            DataType::Time64(ArrowTime::Microsecond) => {
                ValueRef::Time64(TimeUnit::Microsecond, read!(Time64MicrosecondArray))
            }
            DataType::Time64(ArrowTime::Nanosecond) => {
                ValueRef::Time64(TimeUnit::Nanosecond, read!(Time64NanosecondArray))
            }
            DataType::Interval(IntervalUnit::YearMonth) => ValueRef::Interval {
                months: read!(IntervalYearMonthArray),
                days: 0,
                nanos: 0,
            },
            DataType::Interval(IntervalUnit::DayTime) => {
                let value = read!(IntervalDayTimeArray);
                ValueRef::Interval {
                    months: 0,
                    days: value.days,
                    nanos: i64::from(value.milliseconds) * 1_000_000,
                }
            }
            DataType::Interval(IntervalUnit::MonthDayNano) => {
                let value = read!(IntervalMonthDayNanoArray);
                ValueRef::Interval {
                    months: value.months,
                    days: value.days,
                    nanos: value.nanoseconds,
                }
            }
            _ => return Err(Self::unsupported()),
        })
    }

    fn decimal(width: u8, scale: i8, value: i128) -> Result<Decimal> {
        let scale = u8::try_from(scale).map_err(|_| Self::invalid("query result decimal scale"))?;
        Decimal::new(width, scale, value).map_err(|_| Self::invalid("query result decimal range"))
    }

    fn invalid(field: &'static str) -> crate::Error {
        crate::QueryInvalidSnafu { field }.build()
    }

    fn unsupported() -> crate::Error {
        crate::QueryUnsupportedSnafu {
            relation: "query result value",
        }
        .build()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use datafusion::arrow::array::{Array, ListArray, NullArray};
    use datafusion::arrow::datatypes::{i256, Field, Int32Type, IntervalMonthDayNanoType};
    use duckdb::types::Value;

    use super::*;

    fn value(array: ArrayRef, kind: LogicalTypeId) -> Result<Value> {
        Ok(QueryValues::value(&array, 0, kind)?.to_owned())
    }

    #[test]
    fn integer_width_and_range() -> Result<()> {
        assert_eq!(
            value(
                Arc::new(Int64Array::from(vec![i64::MIN])),
                LogicalTypeId::Bigint
            )?,
            Value::BigInt(i64::MIN)
        );
        assert_eq!(
            value(
                Arc::new(UInt64Array::from(vec![u64::MAX])),
                LogicalTypeId::UBigint
            )?,
            Value::UBigInt(u64::MAX)
        );
        assert_eq!(
            value(
                Arc::new(UInt32Array::from(vec![u32::MAX])),
                LogicalTypeId::UInteger,
            )?,
            Value::UInt(u32::MAX)
        );
        for expected in [i128::MIN, i128::MAX] {
            let array = Decimal256Array::from(vec![i256::from_i128(expected)])
                .with_precision_and_scale(39, 0)
                .map_err(|_| QueryValues::invalid("test decimal"))?;
            assert_eq!(
                value(Arc::new(array), LogicalTypeId::Hugeint)?,
                Value::HugeInt(expected)
            );
        }
        let unsigned = Decimal256Array::from(vec![i256::from_parts(u128::MAX, 0)])
            .with_precision_and_scale(39, 0)
            .map_err(|_| QueryValues::invalid("test decimal"))?;
        assert_eq!(
            value(Arc::new(unsigned.clone()), LogicalTypeId::UHugeint)?,
            Value::UHugeInt(u128::MAX)
        );
        assert!(value(Arc::new(unsigned), LogicalTypeId::Hugeint).is_err());
        let negative: ArrayRef = Arc::new(
            Decimal256Array::from(vec![i256::from_i128(-1)])
                .with_precision_and_scale(39, 0)
                .map_err(|_| QueryValues::invalid("test decimal"))?,
        );
        assert!(QueryValues::value(&negative, 0, LogicalTypeId::UHugeint).is_err());
        let overflow: ArrayRef = Arc::new(
            Decimal256Array::from(vec![i256::from_parts(0, 1)])
                .with_precision_and_scale(39, 0)
                .map_err(|_| QueryValues::invalid("test decimal"))?,
        );
        assert!(QueryValues::value(&overflow, 0, LogicalTypeId::UHugeint).is_err());
        let underflow: ArrayRef = Arc::new(
            Decimal256Array::from(vec![i256::from_i128(i128::MIN) - i256::from_i128(1)])
                .with_precision_and_scale(39, 0)
                .map_err(|_| QueryValues::invalid("test decimal"))?,
        );
        assert!(QueryValues::value(&underflow, 0, LogicalTypeId::Hugeint).is_err());
        let wrong: ArrayRef = Arc::new(UInt64Array::from(vec![u64::MAX]));
        assert!(QueryValues::value(&wrong, 0, LogicalTypeId::Bigint).is_err());
        Ok(())
    }

    #[test]
    fn decimal_payload_and_metadata() -> Result<()> {
        let expected =
            Decimal::new(38, 5, -12345).map_err(|_| QueryValues::invalid("test decimal"))?;
        let array = Decimal128Array::from(vec![-12345])
            .with_precision_and_scale(38, 5)
            .map_err(|_| QueryValues::invalid("test decimal"))?;
        assert_eq!(
            value(Arc::new(array), LogicalTypeId::Decimal)?,
            Value::Decimal(expected)
        );
        let whole = Decimal128Array::from(vec![1])
            .with_precision_and_scale(38, 0)
            .map_err(|_| QueryValues::invalid("test decimal"))?;
        assert_eq!(
            QueryValues::logical_type(whole.data_type())?,
            LogicalTypeId::Decimal
        );
        assert_eq!(
            value(Arc::new(whole), LogicalTypeId::Decimal)?,
            Value::Decimal(
                Decimal::new(38, 0, 1).map_err(|_| QueryValues::invalid("test decimal"))?
            )
        );
        assert!(QueryValues::logical_type(&DataType::Decimal128(3, -1)).is_err());
        let invalid = Decimal128Array::from(vec![1000])
            .with_precision_and_scale(3, 0)
            .map_err(|_| QueryValues::invalid("test decimal"))?;
        assert!(value(Arc::new(invalid), LogicalTypeId::Decimal).is_err());
        Ok(())
    }

    #[test]
    fn borrowed_buffers_and_nulls() -> Result<()> {
        let text: ArrayRef = Arc::new(StringArray::from(vec![Some("a\0b"), None]));
        let borrowed = QueryValues::value(&text, 0, LogicalTypeId::Varchar)?;
        let ValueRef::Text(bytes) = borrowed else {
            return Err(QueryValues::invalid("test text"));
        };
        assert_eq!(
            bytes.as_ptr(),
            text.as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| QueryValues::invalid("test text type"))?
                .value(0)
                .as_ptr()
        );
        assert_eq!(borrowed.to_owned(), Value::Text("a\0b".into()));
        assert_eq!(
            QueryValues::value(&text, 1, LogicalTypeId::Varchar)?,
            ValueRef::Null
        );
        let binary: ArrayRef = Arc::new(BinaryArray::from(vec![b"\x00\x80\xff".as_slice()]));
        assert_eq!(
            QueryValues::value(&binary, 0, LogicalTypeId::Blob)?.to_owned(),
            Value::Blob(vec![0, 128, 255])
        );
        let null: ArrayRef = Arc::new(NullArray::new(1));
        assert_eq!(null.nulls(), None);
        assert!(!null.is_null(0));
        assert_eq!(null.logical_null_count(), 1);
        assert_eq!(
            QueryValues::logical_type(null.data_type())?,
            LogicalTypeId::Integer
        );
        assert_eq!(
            QueryValues::value(&null, 0, LogicalTypeId::Integer)?,
            ValueRef::Null
        );
        assert!(QueryValues::value(&null, 1, LogicalTypeId::Integer).is_err());
        Ok(())
    }

    #[test]
    fn timestamps_and_column_labels() -> Result<()> {
        for (array, expected, label) in [
            (
                Arc::new(TimestampSecondArray::from(vec![-1234])) as ArrayRef,
                TimeUnit::Second,
                LogicalTypeId::TimestampS,
            ),
            (
                Arc::new(TimestampMillisecondArray::from(vec![-1234])),
                TimeUnit::Millisecond,
                LogicalTypeId::TimestampMs,
            ),
            (
                Arc::new(TimestampMicrosecondArray::from(vec![-1234])),
                TimeUnit::Microsecond,
                LogicalTypeId::Timestamp,
            ),
            (
                Arc::new(TimestampNanosecondArray::from(vec![-1234])),
                TimeUnit::Nanosecond,
                LogicalTypeId::TimestampNs,
            ),
        ] {
            assert_eq!(QueryValues::logical_type(array.data_type())?, label);
            assert_eq!(
                QueryValues::value(&array, 0, label)?.to_owned(),
                Value::Timestamp(expected, -1234)
            );
        }
        let columns = QueryValues::columns(&Schema::new(vec![
            Field::new("source", DataType::UInt32, false),
            Field::new("whole", DataType::Decimal128(38, 0), true),
            Field::new("wide", DataType::Decimal256(39, 0), true),
        ]))?;
        assert_eq!(
            columns
                .iter()
                .map(|column| column.data_type.as_str())
                .collect::<Vec<_>>(),
            ["UInteger", "Decimal", "Hugeint"]
        );
        assert_eq!(columns[0].name, "source");
        let nested = DataType::List(Arc::new(Field::new("item", DataType::Int32, true)));
        assert!(matches!(
            QueryValues::logical_type(&nested),
            Err(crate::Error::QueryUnsupported { .. })
        ));
        let list: ArrayRef = Arc::new(ListArray::from_iter_primitive::<Int32Type, _, _>([Some([
            Some(1),
        ])]));
        assert!(QueryValues::value(&list, 0, LogicalTypeId::List).is_err());
        Ok(())
    }

    #[test]
    fn temporal_payload_and_nonfinite_output() -> Result<()> {
        let zoned: ArrayRef =
            Arc::new(TimestampNanosecondArray::from(vec![-1234]).with_timezone("UTC"));
        assert_eq!(
            QueryValues::logical_type(zoned.data_type())?,
            LogicalTypeId::TimestampTZ
        );
        assert_eq!(
            QueryValues::value(&zoned, 0, LogicalTypeId::TimestampTZ)?.to_owned(),
            Value::Timestamp(TimeUnit::Nanosecond, -1234)
        );
        let interval: ArrayRef = Arc::new(IntervalMonthDayNanoArray::from(vec![
            IntervalMonthDayNanoType::make_value(-2, 3, i64::MIN),
        ]));
        assert_eq!(
            QueryValues::value(&interval, 0, LogicalTypeId::Interval)?.to_owned(),
            Value::Interval {
                months: -2,
                days: 3,
                nanos: i64::MIN,
            }
        );
        let floating: ArrayRef = Arc::new(Float32Array::from(vec![f32::INFINITY]));
        assert_eq!(
            QueryValues::value(&floating, 0, LogicalTypeId::Float)?.to_owned(),
            Value::Float(f32::INFINITY)
        );
        Ok(())
    }
}
