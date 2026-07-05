use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;
use sha2::{Digest, Sha256};
use snafu::ResultExt;

use crate::{
    error::{EvidenceInvalidJsonSnafu, EvidenceReadFileSnafu},
    EvidenceTraceError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceTraceArtifact {
    label: String,
    path: PathBuf,
    sha256: String,
}

impl EvidenceTraceArtifact {
    #[must_use]
    pub fn new(
        label: impl Into<String>,
        path: impl Into<PathBuf>,
        sha256: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            path: path.into(),
            sha256: sha256.into(),
        }
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EvidenceTraceArtifactLoader;

impl EvidenceTraceArtifactLoader {
    pub(crate) fn read_json(path: &Path) -> Result<Value, EvidenceTraceError> {
        let source = fs::read_to_string(path).context(EvidenceReadFileSnafu {
            path: path.to_path_buf(),
        })?;
        serde_json::from_str(&source).context(EvidenceInvalidJsonSnafu {
            path: path.to_path_buf(),
        })
    }

    pub(crate) fn file_artifact(
        label: &str,
        path: &Path,
    ) -> Result<EvidenceTraceArtifact, EvidenceTraceError> {
        let bytes = fs::read(path).context(EvidenceReadFileSnafu {
            path: path.to_path_buf(),
        })?;
        Ok(EvidenceTraceArtifact::new(
            label,
            path.to_path_buf(),
            EvidenceHasher::sha256_hex(&bytes),
        ))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EvidenceHasher;

impl EvidenceHasher {
    pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::EvidenceHasher;

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            EvidenceHasher::sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
