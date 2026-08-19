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
    crate::canonical::encode_value(&mut Encoder::new(&mut bytes), &value).map_err(|error| {
        PolicyValidationSnafu {
            policy_id,
            code: "CFG_CANONICAL_CBOR",
            reason: error.to_string(),
        }
        .build()
    })?;
    Ok(bytes)
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

    #[derive(Serialize)]
    struct DifferentLengths {
        aa: u8,
        b: u8,
    }

    #[test]
    fn map_keys_are_canonical_not_struct_ordered() -> crate::Result<()> {
        let bytes = canonical_cbor("test", &OrderedDifferently { z: 1, a: 2 })?;
        assert_eq!(bytes, [0xa2, 0x61, b'a', 2, 0x61, b'z', 1]);
        Ok(())
    }

    #[test]
    fn map_keys_use_rfc_8949_length_then_byte_order() -> crate::Result<()> {
        let bytes = canonical_cbor("test", &DifferentLengths { aa: 1, b: 2 })?;
        assert_eq!(bytes, [0xa2, 0x61, b'b', 2, 0x62, b'a', b'a', 1]);
        Ok(())
    }
}
