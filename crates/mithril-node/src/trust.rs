use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};

use crate::error::{ControlProtocolSnafu, IdentityStateSnafu, IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledTrustGenerationV1 {
    pub generation: u64,
    pub bundle_digest: String,
    pub control_connection_nonce: String,
    pub control_sequence: u64,
}

pub struct TrustCache {
    path: PathBuf,
    installed: InstalledTrustGenerationV1,
}

impl TrustCache {
    pub fn load(state_directory: &Path) -> Result<Self> {
        let path = state_directory.join("control-trust.json");
        let installed = match fs::read(&path) {
            Ok(bytes) => {
                let installed: InstalledTrustGenerationV1 =
                    serde_json::from_slice(&bytes).context(JsonSnafu { path: &path })?;
                ensure!(
                    installed.is_valid(),
                    IdentityStateSnafu {
                        reason: "persisted Control trust cache is invalid",
                    }
                );
                installed
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                InstalledTrustGenerationV1::default()
            }
            Err(source) => {
                return Err(crate::Error::Io {
                    path,
                    source,
                    location: snafu::Location::default(),
                })
            }
        };
        Ok(Self { path, installed })
    }

    #[must_use]
    pub const fn installed(&self) -> &InstalledTrustGenerationV1 {
        &self.installed
    }

    pub fn install(
        &mut self,
        generation: u64,
        bundle_digest: String,
        control_connection_nonce: &[u8],
        control_sequence: u64,
    ) -> Result<()> {
        ensure!(
            generation > 0
                && is_sha256_hex(&bundle_digest)
                && control_connection_nonce.len() == 16
                && control_sequence > 0,
            ControlProtocolSnafu {
                reason: "Control delivered an invalid trust generation",
            }
        );
        ensure!(
            generation >= self.installed.generation,
            ControlProtocolSnafu {
                reason: "Control attempted a trust-generation rollback",
            }
        );
        ensure!(
            generation != self.installed.generation
                || self.installed.bundle_digest.is_empty()
                || bundle_digest == self.installed.bundle_digest,
            ControlProtocolSnafu {
                reason: "Control changed an already installed trust generation",
            }
        );
        let control_connection_nonce = hex(control_connection_nonce);
        ensure!(
            control_connection_nonce != self.installed.control_connection_nonce
                || control_sequence > self.installed.control_sequence,
            ControlProtocolSnafu {
                reason: "Control replayed an authority-bearing stream sequence",
            }
        );
        let installed = InstalledTrustGenerationV1 {
            generation,
            bundle_digest,
            control_connection_nonce,
            control_sequence,
        };
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
        }
        let bytes =
            serde_json::to_vec_pretty(&installed).context(JsonSnafu { path: &self.path })?;
        let temporary = self.path.with_extension("json.next");
        let mut file = File::create(&temporary).context(IoSnafu { path: &temporary })?;
        file.write_all(&bytes)
            .context(IoSnafu { path: &temporary })?;
        file.sync_all().context(IoSnafu { path: &temporary })?;
        fs::rename(&temporary, &self.path).context(IoSnafu { path: &self.path })?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)
                .context(IoSnafu { path: parent })?
                .sync_all()
                .context(IoSnafu { path: parent })?;
        }
        self.installed = installed;
        Ok(())
    }
}

impl InstalledTrustGenerationV1 {
    fn is_valid(&self) -> bool {
        self.generation > 0
            && is_sha256_hex(&self.bundle_digest)
            && self.control_connection_nonce.len() == 32
            && self
                .control_connection_nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && self.control_sequence > 0
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _result = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs;

    use snafu::ResultExt as _;

    use super::TrustCache;
    use crate::error::IoSnafu;

    #[test]
    fn cache_rejects_rollback_and_same_generation_replacement() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary trust directory",
        })?;
        let mut cache = TrustCache::load(directory.path())?;
        cache.install(2, "a".repeat(64), &[1; 16], 2)?;
        assert!(cache.install(1, "a".repeat(64), &[2; 16], 2).is_err());
        assert!(cache.install(2, "b".repeat(64), &[2; 16], 2).is_err());
        assert!(cache.install(2, "a".repeat(64), &[1; 16], 2).is_err());
        assert_eq!(
            TrustCache::load(directory.path())?.installed().generation,
            2
        );
        assert_eq!(
            TrustCache::load(directory.path())?
                .installed()
                .control_sequence,
            2
        );
        Ok(())
    }

    #[test]
    fn cache_rejects_structurally_invalid_persisted_state() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary trust directory",
        })?;
        fs::write(
            directory.path().join("control-trust.json"),
            br#"{
                "generation": 0,
                "bundle_digest": "",
                "control_connection_nonce": "",
                "control_sequence": 0
            }"#,
        )
        .context(IoSnafu {
            path: "invalid trust cache",
        })?;
        assert!(TrustCache::load(directory.path()).is_err());
        Ok(())
    }
}
