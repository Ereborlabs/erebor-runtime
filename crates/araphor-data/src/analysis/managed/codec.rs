use serde::{de::DeserializeOwned, Serialize};

pub(super) struct ManagedCodec;

impl ManagedCodec {
    pub(super) fn encode<T: Serialize>(
        value: &T,
    ) -> std::result::Result<Vec<u8>, rmp_serde::encode::Error> {
        rmp_serde::to_vec_named(value)
    }

    pub(super) fn decode<T: DeserializeOwned>(
        bytes: &[u8],
    ) -> std::result::Result<T, rmp_serde::decode::Error> {
        let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
        let value = T::deserialize(&mut decoder)?;
        if decoder.position() != bytes.len() as u64 {
            return Err(rmp_serde::decode::Error::Syntax(
                "managed trailing bytes".into(),
            ));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ManagedFrontier;

    #[test]
    fn managed_codec_rejects_json_and_trailing_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let value = ManagedFrontier {
            cursor: vec![1, 2],
            next_change: Some(3),
            pending: false,
        };
        let mut bytes = ManagedCodec::encode(&value)?;
        assert_eq!(ManagedCodec::decode::<ManagedFrontier>(&bytes)?, value);
        bytes.push(0);
        assert!(matches!(
            ManagedCodec::decode::<ManagedFrontier>(&bytes),
            Err(rmp_serde::decode::Error::Syntax(message)) if message == "managed trailing bytes"
        ));
        assert!(ManagedCodec::decode::<ManagedFrontier>(&serde_json::to_vec(&value)?).is_err());
        Ok(())
    }
}
