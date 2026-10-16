use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::Result;

pub fn decode_parameters(
    schema: &sdk::Schema,
    value: Option<&serde_json::Value>,
) -> Result<Option<sdk::RecordBatch>> {
    if schema.fields().is_empty() {
        if value.is_none_or(|value| value.as_object().is_some_and(|object| object.is_empty())) {
            return Ok(None);
        }
        return Err(super::PackageErrorCodeV1::Invalid.error("undeclared model parameters"));
    }
    let value = value
        .filter(|value| value.is_object())
        .ok_or_else(|| super::PackageErrorCodeV1::Invalid.error("model parameter object"))?;
    ParameterShape::object(schema.fields(), value)?;
    let mut decoder = arrow_json::reader::ReaderBuilder::new(Arc::new(schema.clone()))
        .with_batch_size(1)
        .with_strict_mode(true)
        .build_decoder()
        .map_err(sdk::Error::from)
        .context(crate::AnalysisContractSnafu)?;
    decoder
        .serialize(&[value])
        .map_err(sdk::Error::from)
        .context(crate::AnalysisContractSnafu)?;
    decoder
        .flush()
        .map_err(sdk::Error::from)
        .context(crate::AnalysisContractSnafu)
}

struct ParameterShape;

impl ParameterShape {
    fn object(fields: &[Arc<sdk::Field>], value: &serde_json::Value) -> Result<()> {
        let object = value
            .as_object()
            .ok_or_else(|| super::PackageErrorCodeV1::Invalid.error("model parameter object"))?;
        if object
            .keys()
            .any(|key| !fields.iter().any(|field| field.name() == key))
        {
            return Err(super::PackageErrorCodeV1::Invalid.error("unknown model parameter"));
        }
        for field in fields {
            Self::field(
                field,
                object.get(field.name()).unwrap_or(&serde_json::Value::Null),
            )?;
        }
        Ok(())
    }

    fn field(field: &sdk::Field, value: &serde_json::Value) -> Result<()> {
        use sdk::DataType::*;
        if value.is_null() {
            return if field.is_nullable() {
                Ok(())
            } else {
                Err(super::PackageErrorCodeV1::Invalid.error("required model parameter"))
            };
        }
        let valid = match field.data_type() {
            Int8 | Int16 | Int32 | Int64 => value.as_i64().is_some(),
            UInt8 | UInt16 | UInt32 | UInt64 => value.as_u64().is_some(),
            Boolean => value.is_boolean(),
            Float32 => value
                .as_f64()
                .is_some_and(|number| (number as f32).is_finite()),
            Float64 => value.as_f64().is_some(),
            Utf8 | Binary | FixedSizeBinary(_) => value.is_string(),
            Timestamp(_, _) => value.is_string() || value.as_i64().is_some(),
            Struct(fields) => return Self::object(fields, value),
            List(child) | FixedSizeList(child, _) => {
                let items = value.as_array().ok_or_else(|| {
                    super::PackageErrorCodeV1::Invalid.error("model parameter list")
                })?;
                for item in items {
                    Self::field(child, item)?;
                }
                !matches!(field.data_type(), FixedSizeList(_, size) if items.len() != *size as usize)
            }
            _ => false,
        };
        if !valid {
            return Err(super::PackageErrorCodeV1::Invalid.error("model parameter type"));
        }
        Ok(())
    }
}
