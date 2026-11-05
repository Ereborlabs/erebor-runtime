use std::sync::Arc;

use araphor_data::{CoverageCounters, CoverageInterval, DiscoveryCoverageStateV1};
use datafusion::arrow::{
    array::{
        Array, BooleanArray, Int32Array, Int64Array, StringArray, StructArray, UInt64Array,
        UInt8Array,
    },
    datatypes::{DataType, Field},
};
use datafusion::common::{DataFusionError, Result};
use datafusion::logical_expr::{create_udf, ColumnarValue, ScalarUDF, Volatility};

pub(super) struct CoverageProof;

impl CoverageProof {
    const COUNTERS: [&'static str; 8] = [
        "attempted",
        "suppressed",
        "requested",
        "emitted",
        "lost",
        "classifier_miss_count",
        "unresolved",
        "next_sequence",
    ];

    pub(super) fn function() -> ScalarUDF {
        let mut fields = vec![
            Field::new("state", DataType::Utf8, true),
            Field::new("first_sequence", DataType::UInt64, true),
            Field::new("last_sequence", DataType::UInt64, true),
            Field::new("gap_reasons", DataType::Utf8, true),
        ];
        for prefix in ["opening", "closing"] {
            for name in Self::COUNTERS {
                fields.push(Field::new(
                    format!("{prefix}_{name}"),
                    DataType::UInt64,
                    true,
                ));
            }
        }
        create_udf(
            "araphor_temporal_coverage",
            vec![
                DataType::Int32,
                DataType::UInt64,
                DataType::Struct(fields.into()),
                DataType::Boolean,
                DataType::Int64,
            ],
            DataType::UInt8,
            Volatility::Immutable,
            Arc::new(Self::invoke),
        )
    }

    fn invoke(arguments: &[ColumnarValue]) -> Result<ColumnarValue> {
        let arrays = ColumnarValue::values_to_arrays(arguments)?;
        let [temporal, sequence, interval, gaps, counts] = arrays.as_slice() else {
            return Err(Self::invalid("coverage arguments"));
        };
        let temporal = temporal
            .as_any()
            .downcast_ref::<Int32Array>()
            .ok_or_else(|| Self::invalid("coverage temporal flag"))?;
        let sequence = sequence
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| Self::invalid("coverage sequence"))?;
        let interval = interval
            .as_any()
            .downcast_ref::<StructArray>()
            .ok_or_else(|| Self::invalid("coverage interval"))?;
        let gaps = gaps
            .as_any()
            .downcast_ref::<BooleanArray>()
            .ok_or_else(|| Self::invalid("coverage source gaps"))?;
        let counts = counts
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or_else(|| Self::invalid("coverage multiplicity"))?;
        let mut output = Vec::with_capacity(temporal.len());
        for row in 0..temporal.len() {
            if temporal.is_null(row)
                || gaps.is_null(row)
                || counts.is_null(row)
                || counts.value(row) != 1
            {
                return Err(Self::invalid("coverage event identity or multiplicity"));
            }
            let value = Self::interval(interval, row)?;
            let state = CoverageInterval::record_state(
                value.as_ref(),
                temporal.value(row),
                (!sequence.is_null(row)).then(|| sequence.value(row)),
            );
            output.push(
                if gaps.value(row) || state == DiscoveryCoverageStateV1::Gapped {
                    1
                } else if matches!(
                    state,
                    DiscoveryCoverageStateV1::Healthy | DiscoveryCoverageStateV1::Closed
                ) {
                    0
                } else {
                    2
                },
            );
        }
        Ok(ColumnarValue::Array(Arc::new(UInt8Array::from(output))))
    }

    fn number(array: &StructArray, name: &str, row: usize) -> Result<Option<u64>> {
        let values = array
            .column_by_name(name)
            .and_then(|array| array.as_any().downcast_ref::<UInt64Array>())
            .ok_or_else(|| Self::invalid("coverage interval number"))?;
        Ok((!values.is_null(row)).then(|| values.value(row)))
    }

    fn text<'a>(array: &'a StructArray, name: &str, row: usize) -> Result<Option<&'a str>> {
        let values = array
            .column_by_name(name)
            .and_then(|array| array.as_any().downcast_ref::<StringArray>())
            .ok_or_else(|| Self::invalid("coverage interval text"))?;
        Ok((!values.is_null(row)).then(|| values.value(row)))
    }

    fn counters(array: &StructArray, prefix: &str, row: usize) -> Result<Option<CoverageCounters>> {
        let values = Self::COUNTERS
            .map(|name| Self::number(array, &format!("{prefix}_{name}"), row))
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        let values = values
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| Self::invalid("coverage counter receipt"))?;
        Ok(Some(CoverageCounters {
            attempted: values[0],
            suppressed: values[1],
            requested: values[2],
            emitted: values[3],
            lost: values[4],
            classifier_miss_count: values[5],
            unresolved: values[6],
            next_sequence: values[7],
        }))
    }

    fn interval(array: &StructArray, row: usize) -> Result<Option<CoverageInterval>> {
        if array.is_null(row) {
            return Ok(None);
        }
        let Some(state) = Self::text(array, "state", row)? else {
            return Ok(None);
        };
        Ok(Some(CoverageInterval {
            state: state.into(),
            first_sequence: Self::number(array, "first_sequence", row)?
                .ok_or_else(|| Self::invalid("coverage first sequence"))?,
            last_sequence: Self::number(array, "last_sequence", row)?,
            gap_reasons: Self::text(array, "gap_reasons", row)?
                .filter(|value| !value.is_empty())
                .map_or_else(Vec::new, |value| vec![value.into()]),
            opening_counters: Self::counters(array, "opening", row)?,
            closing_counters: Self::counters(array, "closing", row)?,
            ..Default::default()
        }))
    }

    fn invalid(field: &str) -> DataFusionError {
        DataFusionError::Execution(field.into())
    }
}
