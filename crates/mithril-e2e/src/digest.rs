use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DigestV1([u8; 32]);

impl DigestV1 {
    #[must_use]
    pub fn of(bytes: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(bytes.as_ref()).into())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for DigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::DigestV1;

    #[test]
    fn sha256_digest_uses_fixed_lowercase_hex() {
        assert_eq!(
            DigestV1::of(b"mithril").to_hex(),
            "3311063c3d681e3bb048ea56a5130a820bf6ddc606140ca2f2e3c692cdd61bbb"
        );
    }
}
