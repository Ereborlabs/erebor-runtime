use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{
    Array as _, ArrayRef, FixedSizeListArray, ListArray, NullArray, StructArray,
    TimestampNanosecondArray,
};
use snafu::ResultExt as _;

use crate::Result;

pub(super) struct ModelArrays;

impl ModelArrays {
    pub(super) fn cast(array: &ArrayRef, kind: &sdk::DataType) -> Result<ArrayRef> {
        let invalid = || {
            crate::QueryInvalidSnafu {
                field: "model array type",
            }
            .build()
        };
        Ok(match kind {
            sdk::DataType::Null => {
                if array.null_count() != array.len() {
                    return Err(invalid());
                }
                Arc::new(NullArray::new(array.len()))
            }
            sdk::DataType::Timestamp(sdk::TimeUnit::Nanosecond, Some(zone))
                if zone.as_ref() == "UTC" =>
            {
                let timestamp = array
                    .as_any()
                    .downcast_ref::<TimestampNanosecondArray>()
                    .ok_or_else(invalid)?;
                Arc::new(timestamp.clone().with_timezone("UTC"))
            }
            sdk::DataType::List(field) => {
                let list = array
                    .as_any()
                    .downcast_ref::<ListArray>()
                    .ok_or_else(invalid)?;
                Arc::new(
                    ListArray::try_new(
                        field.clone(),
                        list.offsets().clone(),
                        Self::cast(list.values(), field.data_type())?,
                        list.nulls().cloned(),
                    )
                    .map_err(sdk::Error::from)
                    .context(crate::AnalysisContractSnafu)?,
                )
            }
            sdk::DataType::FixedSizeList(field, size) => {
                let list = array
                    .as_any()
                    .downcast_ref::<FixedSizeListArray>()
                    .ok_or_else(invalid)?;
                Arc::new(
                    FixedSizeListArray::try_new(
                        field.clone(),
                        *size,
                        Self::cast(list.values(), field.data_type())?,
                        list.nulls().cloned(),
                    )
                    .map_err(sdk::Error::from)
                    .context(crate::AnalysisContractSnafu)?,
                )
            }
            sdk::DataType::Struct(fields) => {
                let structure = array
                    .as_any()
                    .downcast_ref::<StructArray>()
                    .ok_or_else(invalid)?;
                if fields.len() != structure.num_columns() {
                    return Err(invalid());
                }
                let columns = structure
                    .columns()
                    .iter()
                    .zip(fields)
                    .map(|(array, field)| Self::cast(array, field.data_type()))
                    .collect::<Result<Vec<_>>>()?;
                Arc::new(
                    StructArray::try_new(fields.clone(), columns, structure.nulls().cloned())
                        .map_err(sdk::Error::from)
                        .context(crate::AnalysisContractSnafu)?,
                )
            }
            _ => duckdb::arrow::compute::cast_with_options(
                array,
                kind,
                &duckdb::arrow::compute::CastOptions {
                    safe: false,
                    ..Default::default()
                },
            )
            .map_err(sdk::Error::from)
            .context(crate::AnalysisContractSnafu)?,
        })
    }
}
