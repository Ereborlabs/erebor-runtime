use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{AnalysisConflictSnafu, AnalysisDatabaseSnafu, JsonSnafu, Result};

const MAX_CONTEXT_BYTES: usize = 32 * 1024;
const MAX_CONTEXT_KEY_BYTES: usize = 256;
type ContextRow = (u64, Option<u64>, String, Vec<u8>, Vec<u8>, u64);

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AnalysisContextKeyV1 {
    pub tenant_id: [u8; 16],
    pub owner_id: String,
    pub entity_key: Vec<u8>,
    pub lifetime_key: Vec<u8>,
    pub owner_revision: u64,
}

impl AnalysisContextKeyV1 {
    pub(super) fn valid(&self) -> bool {
        self.tenant_id != [0; 16]
            && !self.owner_id.is_empty()
            && self.owner_id.len() <= 128
            && !self.entity_key.is_empty()
            && self.entity_key.len() <= MAX_CONTEXT_KEY_BYTES
            && !self.lifetime_key.is_empty()
            && self.lifetime_key.len() <= MAX_CONTEXT_KEY_BYTES
            && self.owner_revision > 0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ContextSensitivityV1 {
    Public,
    Tenant,
    HostRestricted,
}

impl From<ContextSensitivityV1> for &'static str {
    fn from(value: ContextSensitivityV1) -> Self {
        match value {
            ContextSensitivityV1::Public => "public",
            ContextSensitivityV1::Tenant => "tenant",
            ContextSensitivityV1::HostRestricted => "host_restricted",
        }
    }
}

impl TryFrom<&str> for ContextSensitivityV1 {
    type Error = ();

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "public" => Ok(Self::Public),
            "tenant" => Ok(Self::Tenant),
            "host_restricted" => Ok(Self::HostRestricted),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisContextVersionV1 {
    pub key: AnalysisContextKeyV1,
    pub valid_from_utc_ns: u64,
    pub valid_until_utc_ns: Option<u64>,
    pub sensitivity: ContextSensitivityV1,
    pub body: Vec<u8>,
}

impl AnalysisContextVersionV1 {
    fn valid(&self) -> bool {
        self.key.valid()
            && self.valid_from_utc_ns > 0
            && self
                .valid_until_utc_ns
                .is_none_or(|until| until > self.valid_from_utc_ns)
            && !self.body.is_empty()
            && self.body.len() <= MAX_CONTEXT_BYTES
    }

    pub fn content_digest(&self) -> std::result::Result<[u8; 32], serde_json::Error> {
        Ok(Sha256::digest(serde_json::to_vec(self)?).into())
    }
}

impl AnalysisStore {
    pub fn commit_context(&self, input: &AnalysisContextVersionV1) -> Result<u64> {
        if !input.valid() {
            return self.reject("the context version identity or bounds are invalid");
        }
        let path = self.root.join("analysis.duckdb");
        let digest = input.content_digest().context(JsonSnafu { path: &path })?;
        let key = &input.key;
        let mut writer = self.writer()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin context version",
        })?;
        let existing: Option<(Vec<u8>, u64)> = transaction
            .query_row(
                "SELECT content_sha256, commit_revision FROM context_versions
                 WHERE tenant_id = ? AND owner_id = ? AND entity_key = ?
                 AND lifetime_key = ? AND owner_revision = ?",
                params![
                    key.tenant_id.as_slice(),
                    key.owner_id,
                    key.entity_key.as_slice(),
                    key.lifetime_key.as_slice(),
                    key.owner_revision,
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read immutable context version",
            })?;
        if let Some((stored, revision)) = existing {
            if stored != digest {
                return AnalysisConflictSnafu.fail();
            }
            return Ok(revision);
        }
        let revision = Self::read_meta_from(&transaction, &path)?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        let sensitivity: &'static str = input.sensitivity.into();
        transaction
            .execute(
                "INSERT INTO context_versions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    key.tenant_id.as_slice(),
                    key.owner_id,
                    key.entity_key.as_slice(),
                    key.lifetime_key.as_slice(),
                    key.owner_revision,
                    input.valid_from_utc_ns,
                    input.valid_until_utc_ns,
                    sensitivity,
                    input.body.as_slice(),
                    digest.as_slice(),
                    revision,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert context version",
            })?;
        Self::record_revision(&transaction, revision, &["context_versions"])?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit context version",
        })?;
        self.revision.send_replace(revision);
        Ok(revision)
    }

    pub fn context_version(
        &self,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<AnalysisContextVersionV1>> {
        if !key.valid() {
            return self.reject("the context version key is invalid");
        }
        let writer = self.writer()?;
        Ok(Self::read_context_from(&writer, &self.root, key)?.map(|(version, _)| version))
    }

    pub(super) fn read_context_from(
        connection: &Connection,
        root: &Path,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<(AnalysisContextVersionV1, u64)>> {
        let stored: Option<ContextRow> = connection
            .query_row(
                "SELECT valid_from_utc_ns, valid_until_utc_ns, sensitivity, body,
                        content_sha256, commit_revision
                 FROM context_versions WHERE tenant_id = ? AND owner_id = ? AND entity_key = ?
                 AND lifetime_key = ? AND owner_revision = ?",
                params![
                    key.tenant_id.as_slice(),
                    key.owner_id,
                    key.entity_key.as_slice(),
                    key.lifetime_key.as_slice(),
                    key.owner_revision,
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read context version",
            })?;
        let Some((from, until, sensitivity, body, digest, revision)) = stored else {
            return Ok(None);
        };
        let sensitivity = match ContextSensitivityV1::try_from(sensitivity.as_str()) {
            Ok(value) => value,
            Err(()) => return Self::reject_path(root, "the context sensitivity is invalid"),
        };
        let result = AnalysisContextVersionV1 {
            key: key.clone(),
            valid_from_utc_ns: from,
            valid_until_utc_ns: until,
            sensitivity,
            body,
        };
        let path = root.join("analysis.duckdb");
        let expected = result.content_digest().context(JsonSnafu { path })?;
        if !result.valid() || expected.as_slice() != digest {
            return Self::reject_path(root, "the retained context version digest is invalid");
        }
        Ok(Some((result, revision)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_store_context_versions() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("analysis");
        let store = AnalysisStore::open(&path)?;
        let input = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "policy".into(),
                entity_key: b"workload-a".to_vec(),
                lifetime_key: b"pod-a".to_vec(),
                owner_revision: 4,
            },
            valid_from_utc_ns: 100,
            valid_until_utc_ns: Some(200),
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"policy-revision-4".to_vec(),
        };
        let revision = store.commit_context(&input)?;
        assert_eq!(store.commit_context(&input)?, revision);
        assert_eq!(store.context_version(&input.key)?, Some(input.clone()));
        let mut conflict = input.clone();
        conflict.body.push(0);
        assert!(matches!(
            store.commit_context(&conflict),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        let mut later = input.clone();
        later.key.owner_revision = 5;
        later.valid_from_utc_ns = 300;
        later.valid_until_utc_ns = None;
        store.commit_context(&later)?;
        assert_eq!(store.context_version(&input.key)?, Some(input.clone()));
        drop(store);
        let reopened = AnalysisStore::open(path)?;
        assert_eq!(reopened.context_version(&later.key)?, Some(later));
        let mut foreign = input.key.clone();
        foreign.tenant_id = [2; 16];
        assert_eq!(reopened.context_version(&foreign)?, None);
        reopened.writer()?.execute(
            "UPDATE context_versions SET body = ? WHERE tenant_id = ? AND owner_id = ?",
            duckdb::params![
                b"changed".as_slice(),
                input.key.tenant_id.as_slice(),
                input.key.owner_id,
            ],
        )?;
        assert!(reopened.context_version(&input.key).is_err());
        Ok(())
    }
}
