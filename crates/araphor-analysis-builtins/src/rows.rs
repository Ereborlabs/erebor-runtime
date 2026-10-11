use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use schemars::JsonSchema;
use sdk::arrow_array::{builder::BinaryBuilder, Array, BinaryArray};
use serde::{de::DeserializeOwned, Serialize};

pub struct Rows;

impl Rows {
    pub fn port<T: JsonSchema>(name: &str, type_id: &str) -> sdk::Port {
        let metadata = HashMap::from([
            ("araphor.type".into(), type_id.into()),
            ("araphor.encoding".into(), "serde-json-v1".into()),
            (
                "araphor.json_schema".into(),
                schemars::schema_for!(T).to_value().to_string(),
            ),
        ]);
        sdk::Port::new(
            name,
            sdk::Schema::new(vec![
                sdk::Field::new("value", sdk::DataType::Binary, false).with_metadata(metadata)
            ]),
        )
    }

    pub fn encode<T: Serialize>(
        port: &sdk::Port,
        values: &[T],
        bounds: sdk::Limits,
    ) -> sdk::Result<sdk::Dataset> {
        Self::check_port(port)?;
        if bounds.max_batches == 0 || values.len() as u64 > bounds.max_rows {
            return Err(sdk::Error::contract(sdk::ErrorCode::Limit, "row count"));
        }
        let mut builder = BinaryBuilder::new();
        let mut remaining = usize::try_from(bounds.max_bytes)
            .unwrap_or(usize::MAX)
            .min(i32::MAX as usize);
        for value in values {
            let mut buffer = RowBuffer {
                bytes: Vec::new(),
                remaining: &mut remaining,
                limited: false,
            };
            if let Err(source) = serde_json::to_writer(&mut buffer, value) {
                return Err(if buffer.limited {
                    sdk::Error::contract(sdk::ErrorCode::Limit, "row bytes")
                } else {
                    sdk::Error::Encoding {
                        source,
                        location: snafu::location!(),
                    }
                });
            }
            builder.append_value(&buffer.bytes);
        }
        let array = builder.finish();
        if array.get_array_memory_size() as u64 > bounds.max_bytes {
            return Err(sdk::Error::contract(sdk::ErrorCode::Limit, "row bytes"));
        }
        let batch =
            sdk::RecordBatch::try_new(Arc::new(port.schema.clone()), vec![Arc::new(array)])?;
        Ok(sdk::Dataset {
            name: port.name.clone(),
            batches: vec![batch],
        })
    }

    pub fn decode<T: DeserializeOwned>(
        port: &sdk::Port,
        dataset: &sdk::Dataset,
        bounds: sdk::Limits,
    ) -> sdk::Result<Vec<T>> {
        Self::check_port(port)?;
        if dataset.name != port.name {
            return Err(sdk::Error::contract(sdk::ErrorCode::Invalid, "row dataset"));
        }
        if dataset.batches.len() as u64 > u64::from(bounds.max_batches) {
            return Err(sdk::Error::contract(sdk::ErrorCode::Limit, "row batches"));
        }
        let mut bytes = 0u64;
        let mut rows = 0u64;
        let mut output = Vec::new();
        for batch in &dataset.batches {
            if batch.schema().as_ref() != &port.schema {
                return Err(sdk::Error::contract(sdk::ErrorCode::Invalid, "row schema"));
            }
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<BinaryArray>()
                .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "row type"))?;
            array.to_data().validate_full()?;
            if array.null_count() != 0 {
                return Err(sdk::Error::contract(sdk::ErrorCode::Invalid, "null row"));
            }
            bytes = bytes.saturating_add(array.get_array_memory_size() as u64);
            rows = rows.saturating_add(array.len() as u64);
            if bytes > bounds.max_bytes || rows > bounds.max_rows {
                return Err(sdk::Error::contract(sdk::ErrorCode::Limit, "row input"));
            }
            for value in array.iter().flatten() {
                output.push(serde_json::from_slice(value).map_err(|source| {
                    sdk::Error::Encoding {
                        source,
                        location: snafu::location!(),
                    }
                })?);
            }
        }
        Ok(output)
    }

    fn check_port(port: &sdk::Port) -> sdk::Result<()> {
        if port.schema.fields().len() != 1
            || port.schema.field(0).data_type() != &sdk::DataType::Binary
            || port.schema.field(0).is_nullable()
        {
            return Err(sdk::Error::contract(sdk::ErrorCode::Invalid, "row port"));
        }
        Ok(())
    }
}

struct RowBuffer<'a> {
    bytes: Vec<u8>,
    remaining: &'a mut usize,
    limited: bool,
}

impl Write for RowBuffer<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(remaining) = self.remaining.checked_sub(bytes.len()) else {
            self.limited = true;
            return Err(std::io::Error::other("row bytes exceed the limit"));
        };
        self.bytes.extend_from_slice(bytes);
        *self.remaining = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
