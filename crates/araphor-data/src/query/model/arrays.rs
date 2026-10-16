use araphor_analysis_sdk as sdk;
use datafusion::arrow::array::{make_array, new_null_array, ArrayRef};
use datafusion::arrow::compute::{cast_with_options, CastOptions};
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
        if *kind == sdk::DataType::Null {
            if array.logical_null_count() != array.len() {
                return Err(invalid());
            }
            return Ok(new_null_array(kind, array.len()));
        }
        let fields = match kind {
            sdk::DataType::List(field) | sdk::DataType::FixedSizeList(field, _) => {
                std::slice::from_ref(field)
            }
            sdk::DataType::Struct(fields) => fields.as_ref(),
            _ => {
                return cast_with_options(
                    array.as_ref(),
                    kind,
                    &CastOptions {
                        safe: false,
                        ..Default::default()
                    },
                )
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu);
            }
        };
        let data = array.to_data();
        if data.child_data().len() != fields.len() {
            return Err(invalid());
        }
        let children = data
            .child_data()
            .iter()
            .zip(fields)
            .map(|(child, field)| {
                Self::cast(&make_array(child.clone()), field.data_type())
                    .map(|array| array.to_data())
            })
            .collect::<Result<Vec<_>>>()?;
        data.into_builder()
            .data_type(kind.clone())
            .child_data(children)
            .build()
            .map(make_array)
            .map_err(sdk::Error::from)
            .context(crate::AnalysisContractSnafu)
    }
}
