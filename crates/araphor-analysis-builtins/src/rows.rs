use std::collections::HashMap;
use std::io::{BufWriter, Write};
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

    pub fn encode<T: Serialize>(port: &sdk::Port, values: &[T]) -> sdk::Result<sdk::Dataset> {
        Self::check_port(port)?;
        let (bytes, _) = Self::capacity(values)?;
        Self::encode_capacity(port, values, bytes)
    }

    pub fn capacity<T: Serialize>(values: &[T]) -> sdk::Result<(usize, usize)> {
        let mut size = RowSize {
            bytes: 0,
            limit: i32::MAX as usize,
        };
        for value in values {
            serde_json::to_writer(&mut size, value).map_err(|source| {
                if source.io_error_kind() == Some(std::io::ErrorKind::FileTooLarge) {
                    sdk::Error::contract(sdk::ErrorCode::Limit, "row bytes")
                } else {
                    sdk::Error::Encoding {
                        source,
                        location: snafu::location!(),
                    }
                }
            })?;
        }
        let array = Self::array_bytes(values.len(), size.bytes)?;
        let allocation = array
            .checked_add(8192.min(size.bytes))
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Limit, "row allocation"))?;
        Ok((size.bytes, allocation))
    }

    fn array_bytes(rows: usize, bytes: usize) -> sdk::Result<usize> {
        rows.checked_add(1)
            .and_then(|rows| rows.checked_mul(std::mem::size_of::<i32>()))
            .and_then(|offsets| offsets.checked_add(bytes))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<BinaryArray>()))
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Limit, "row allocation"))
    }

    pub fn encode_capacity<T: Serialize>(
        port: &sdk::Port,
        values: &[T],
        bytes: usize,
    ) -> sdk::Result<sdk::Dataset> {
        Self::check_port(port)?;
        Self::array_bytes(values.len(), bytes)?;
        if bytes > i32::MAX as usize {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Limit,
                "row allocation",
            ));
        }
        let mut builder = BinaryBuilder::with_capacity(values.len(), bytes);
        let limit = bytes;
        for value in values {
            let remaining = limit - builder.values_slice().len();
            let result = {
                let buffer = sdk::wire::BoundedBuffer::from_writer(&mut builder, remaining as u64);
                let mut writer = BufWriter::with_capacity(8192.min(remaining), buffer);
                let serialized = serde_json::to_writer(&mut writer, value);
                writer
                    .flush()
                    .map_err(serde_json::Error::io)
                    .and(serialized)
            };
            if let Err(source) = result {
                return Err(
                    if source.io_error_kind() == Some(std::io::ErrorKind::FileTooLarge) {
                        sdk::Error::contract(sdk::ErrorCode::Limit, "row bytes")
                    } else {
                        sdk::Error::Encoding {
                            source,
                            location: snafu::location!(),
                        }
                    },
                );
            }
            builder.append_value(b"");
        }
        let array = builder.finish();
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
    ) -> sdk::Result<Vec<T>> {
        Self::check_port(port)?;
        if dataset.name != port.name {
            return Err(sdk::Error::contract(sdk::ErrorCode::Invalid, "row dataset"));
        }
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
            Self::values(array, &mut output)?;
        }
        Ok(output)
    }

    pub fn input<T: DeserializeOwned>(
        checked: &sdk::CheckedEvaluation<'_>,
        name: &str,
    ) -> sdk::Result<Vec<T>> {
        let port = checked
            .model()
            .inputs
            .iter()
            .find(|input| input.port.name == name)
            .map(|input| &input.port)
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "row port"))?;
        Self::check_port(port)?;
        let dataset = &checked.evaluation().input(name)?.data;
        let mut output = Vec::new();
        for batch in &dataset.batches {
            let array = batch
                .column(0)
                .as_any()
                .downcast_ref::<BinaryArray>()
                .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "row type"))?;
            Self::values(array, &mut output)?;
        }
        Ok(output)
    }

    fn values<T: DeserializeOwned>(array: &BinaryArray, output: &mut Vec<T>) -> sdk::Result<()> {
        for value in array.iter().flatten() {
            output.push(
                serde_json::from_slice(value).map_err(|source| sdk::Error::Encoding {
                    source,
                    location: snafu::location!(),
                })?,
            );
        }
        Ok(())
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

struct RowSize {
    bytes: usize,
    limit: usize,
}

impl Write for RowSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|bytes| *bytes <= self.limit)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::FileTooLarge))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
