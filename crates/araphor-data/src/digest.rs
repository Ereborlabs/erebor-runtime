use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{CanonicalEncodingSnafu, Result};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DiscoveryDigestV1(pub [u8; 32]);

impl DiscoveryDigestV1 {
    pub fn of(value: &impl Serialize) -> Result<Self> {
        let value = serde_json::to_value(value).map_err(|error| Self::error(&error))?;
        let mut bytes = Vec::new();
        crate::canonical::encode_value(&mut minicbor::Encoder::new(&mut bytes), &value)
            .map_err(|error| Self::error(&error))?;
        let mut hash = Sha256::new();
        hash.update(b"ARAPHOR-DISCOVERY-V1\0");
        hash.update(bytes);
        Ok(Self(hash.finalize().into()))
    }

    fn error(error: &impl std::fmt::Display) -> crate::Error {
        CanonicalEncodingSnafu {
            reason: error.to_string(),
        }
        .build()
    }
}

#[cfg(test)]
mod tests {
    use super::DiscoveryDigestV1;

    #[test]
    fn digest_preserves_canonical_domain() -> crate::Result<()> {
        let digest = DiscoveryDigestV1::of(&serde_json::json!({"zz": 2, "a": 1}))?;
        assert_eq!(
            digest.0,
            [
                0x4e, 0xb3, 0xb2, 0x13, 0x83, 0x6f, 0xc9, 0xf5, 0x9c, 0x45, 0x6c, 0x59, 0x88, 0xf4,
                0x59, 0xd0, 0xba, 0xb5, 0x5a, 0xcc, 0xd6, 0x6b, 0x02, 0x0d, 0xda, 0x3a, 0xce, 0xea,
                0x49, 0x62, 0x8f, 0x86,
            ]
        );
        assert!(DiscoveryDigestV1::of(&1.25_f64).is_err());
        Ok(())
    }
}
