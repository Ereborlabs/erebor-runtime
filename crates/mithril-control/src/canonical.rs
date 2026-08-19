use std::convert::Infallible;

use minicbor::Encoder;

pub(crate) fn encode_value(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: &serde_json::Value,
) -> std::result::Result<(), minicbor::encode::Error<Infallible>> {
    match value {
        serde_json::Value::Null => {
            encoder.null()?;
        }
        serde_json::Value::Bool(value) => {
            encoder.bool(*value)?;
        }
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                encoder.u64(value)?;
            } else if let Some(value) = value.as_i64() {
                encoder.i64(value)?;
            } else {
                return Err(minicbor::encode::Error::message(
                    "floating-point canonical values are forbidden",
                ));
            }
        }
        serde_json::Value::String(value) => {
            encoder.str(value)?;
        }
        serde_json::Value::Array(values) => {
            encoder.array(values.len() as u64)?;
            for value in values {
                encode_value(encoder, value)?;
            }
        }
        serde_json::Value::Object(values) => {
            let mut fields = values.iter().collect::<Vec<_>>();
            fields.sort_unstable_by(|(left, _), (right, _)| {
                left.len().cmp(&right.len()).then_with(|| left.cmp(right))
            });
            encoder.map(fields.len() as u64)?;
            for (key, value) in fields {
                encoder.str(key)?;
                encode_value(encoder, value)?;
            }
        }
    }
    Ok(())
}
