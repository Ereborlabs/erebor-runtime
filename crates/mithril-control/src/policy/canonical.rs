use std::convert::Infallible;

use minicbor::Encoder;
use serde::Serialize;

use crate::error::PolicyValidationSnafu;
use crate::Result;

pub(crate) fn canonical_cbor<T: Serialize>(policy_id: &str, value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|error| {
        PolicyValidationSnafu {
            policy_id,
            code: "CFG_CANONICAL_VALUE",
            reason: error.to_string(),
        }
        .build()
    })?;
    let mut bytes = Vec::new();
    encode_value(&mut Encoder::new(&mut bytes), &value).map_err(|error| {
        PolicyValidationSnafu {
            policy_id,
            code: "CFG_CANONICAL_CBOR",
            reason: error.to_string(),
        }
        .build()
    })?;
    Ok(bytes)
}

fn encode_value(
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
                    "floating-point policy values are forbidden",
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
            fields.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            encoder.map(fields.len() as u64)?;
            for (key, value) in fields {
                encoder.str(key)?;
                encode_value(encoder, value)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::canonical_cbor;

    #[derive(Serialize)]
    struct OrderedDifferently {
        z: u8,
        a: u8,
    }

    #[test]
    fn map_keys_are_canonical_not_struct_ordered() -> crate::Result<()> {
        let bytes = canonical_cbor("test", &OrderedDifferently { z: 1, a: 2 })?;
        assert_eq!(bytes, [0xa2, 0x61, b'a', 2, 0x61, b'z', 1]);
        Ok(())
    }
}
