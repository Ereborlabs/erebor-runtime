use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{AnalysisConflictSnafu, AnalysisDatabaseSnafu, Result};

const MAX_CONTEXT_BYTES: usize = 32 * 1024;
const MAX_CONTEXT_KEY_BYTES: usize = 256;
type ContextRow = (Option<u64>, Option<u64>, String, Vec<u8>, u64);

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AnalysisContextKeyV1 {
    pub tenant_id: [u8; 16],
    pub owner_id: String,
    pub entity_key: Vec<u8>,
    pub lifetime_key: Vec<u8>,
    pub owner_revision: u64,
}

impl AnalysisContextKeyV1 {
    pub(crate) fn valid(&self) -> bool {
        self.tenant_id != [0; 16]
            && !self.owner_id.is_empty()
            && self.owner_id.len() <= 128
            && !self.entity_key.is_empty()
            && self.entity_key.len() <= MAX_CONTEXT_KEY_BYTES
            && !self.lifetime_key.is_empty()
            && self.lifetime_key.len() <= MAX_CONTEXT_KEY_BYTES
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
    pub valid_from_utc_ns: Option<u64>,
    pub valid_until_utc_ns: Option<u64>,
    pub sensitivity: ContextSensitivityV1,
    pub body: Vec<u8>,
}

impl AnalysisContextVersionV1 {
    fn valid(&self) -> bool {
        self.key.valid()
            && match (self.valid_from_utc_ns, self.valid_until_utc_ns) {
                (None, None) => true,
                (Some(from), until) => from > 0 && until.is_none_or(|end| end > from),
                (None, Some(_)) => false,
            }
            && !self.body.is_empty()
            && self.body.len() <= MAX_CONTEXT_BYTES
    }
}

impl AnalysisStore {
    pub fn commit_context(&self, input: &AnalysisContextVersionV1) -> Result<u64> {
        self.commit_context_value(input, false)
            .map(|reference| reference.commit_revision)
    }

    pub(crate) fn intern_context(
        &self,
        input: &AnalysisContextVersionV1,
    ) -> Result<super::AnalysisContextRefV1> {
        if !matches!(
            input.key.owner_id.as_str(),
            "discovery-facts-v1" | "discovery-source-v1"
        ) {
            return self.reject("the qualified context owner is invalid");
        }
        self.commit_context_value(input, true)
    }

    fn commit_context_value(
        &self,
        input: &AnalysisContextVersionV1,
        intern: bool,
    ) -> Result<super::AnalysisContextRefV1> {
        if !input.valid() {
            return self.reject("the context version identity or bounds are invalid");
        }
        let path = self.root.join("analysis.duckdb");
        let key = &input.key;
        let imported = (key.owner_id == "discovery-context-v1")
            .then(|| crate::DiscoveryContextRevisionV1::try_from(input))
            .transpose()?;
        let mut writer_guard = self.writer()?;
        let writer = writer_guard.get_mut()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin context version",
        })?;
        let sensitivity: &'static str = input.sensitivity.into();
        if intern {
            let stored: Option<(Vec<u8>, u64, u64)> = transaction
                .query_row(
                    "SELECT entity_key, owner_revision, commit_revision FROM context_versions
                 WHERE tenant_id = ? AND owner_id = ? AND lifetime_key = ? AND body = ?
                 AND sensitivity = ? AND valid_from_utc_ns IS NOT DISTINCT FROM ?
                 AND valid_until_utc_ns IS NOT DISTINCT FROM ? ORDER BY entity_key LIMIT 1",
                    params![
                        key.tenant_id.as_slice(),
                        key.owner_id,
                        key.lifetime_key.as_slice(),
                        input.body.as_slice(),
                        sensitivity,
                        input.valid_from_utc_ns,
                        input.valid_until_utc_ns
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "find exact qualified context",
                })?;
            if let Some((entity, owner, revision)) = stored {
                let mut key = key.clone();
                key.entity_key = entity;
                key.owner_revision = owner;
                return Ok(super::AnalysisContextRefV1 {
                    key,
                    commit_revision: revision,
                });
            }
        }
        if let Some((stored, revision)) = Self::read_context_from(&transaction, &self.root, key)? {
            if &stored != input {
                return AnalysisConflictSnafu.fail();
            }
            return Ok(super::AnalysisContextRefV1 {
                key: key.clone(),
                commit_revision: revision,
            });
        }
        if let Some(imported) = imported {
            let previous: Option<(Vec<u8>, u64)> = transaction
                .query_row(
                    "SELECT lifetime_key, owner_revision FROM context_versions
                 WHERE tenant_id = ? AND owner_id = ? AND entity_key = ?
                 ORDER BY owner_revision DESC LIMIT 1",
                    params![
                        key.tenant_id.as_slice(),
                        key.owner_id,
                        key.entity_key.as_slice()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read discovery document history",
                })?;
            let previous = previous
                .map(|(lifetime_key, owner_revision)| {
                    let previous = AnalysisContextKeyV1 {
                        lifetime_key,
                        owner_revision,
                        ..key.clone()
                    };
                    let (stored, _) = Self::read_context_from(&transaction, &self.root, &previous)?
                        .ok_or_else(|| {
                            self.state_error("the prior discovery document is absent")
                        })?;
                    crate::DiscoveryContextRevisionV1::try_from(&stored)
                })
                .transpose()?;
            let (documents, revisions): (u64, u64) = transaction
                .query_row(
                    "SELECT COUNT(DISTINCT entity_key), COUNT(*) FROM context_versions
                 WHERE tenant_id = ? AND owner_id = ?",
                    params![key.tenant_id.as_slice(), key.owner_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read discovery document bounds",
                })?;
            imported.validate_history(previous.as_ref(), documents, revisions)?;
        }
        let revision = Self::read_meta_from(&transaction, &path)?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        transaction
            .execute(
                "INSERT INTO context_versions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    revision,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert context version",
            })?;
        super::quota::UsageChange {
            bytes: (256
                + key.owner_id.len()
                + key.entity_key.len()
                + key.lifetime_key.len()
                + input.body.len()) as i64,
            contexts: 1,
            ..Default::default()
        }
        .apply(&transaction, &key.tenant_id)?;
        self.check_logical(&transaction, key.tenant_id, false)?;
        Self::record_revision(&transaction, revision, &["context_versions"])?;
        #[cfg(test)]
        self.crash_at("context.before");
        self.commit_metadata(transaction, "commit context version")?;
        #[cfg(test)]
        self.crash_at("context.after");
        self.revision.send_replace(revision);
        Ok(super::AnalysisContextRefV1 {
            key: key.clone(),
            commit_revision: revision,
        })
    }

    pub fn context_version(
        &self,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<AnalysisContextVersionV1>> {
        if !key.valid() {
            return self.reject("the context version key is invalid");
        }
        self.read_snapshot(|reader| {
            Ok(Self::read_context_from(reader, &self.root, key)?.map(|(version, _)| version))
        })
    }

    pub(super) fn read_context_from(
        connection: &Connection,
        root: &Path,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<(AnalysisContextVersionV1, u64)>> {
        let stored: Option<ContextRow> = connection
            .query_row(
                "SELECT valid_from_utc_ns, valid_until_utc_ns, sensitivity, body, commit_revision
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
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read context version",
            })?;
        let Some((from, until, sensitivity, body, revision)) = stored else {
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
        if !result.valid() || revision == 0 {
            return Self::reject_path(root, "the retained context version is invalid");
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
            valid_from_utc_ns: Some(100),
            valid_until_utc_ns: Some(200),
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"policy-revision-4".to_vec(),
        };
        let revision = store.commit_context(&input)?;
        assert_eq!(store.commit_context(&input)?, revision);
        assert_eq!(store.context_version(&input.key)?, Some(input.clone()));
        for change in 0..4 {
            let mut conflict = input.clone();
            match change {
                0 => conflict.body.push(0),
                1 => conflict.valid_from_utc_ns = Some(101),
                2 => conflict.valid_until_utc_ns = Some(201),
                _ => conflict.sensitivity = ContextSensitivityV1::HostRestricted,
            }
            assert!(matches!(
                store.commit_context(&conflict),
                Err(crate::Error::AnalysisConflict { .. })
            ));
            assert_eq!(store.meta()?.commit_revision, revision);
        }
        let mut later = input.clone();
        later.key.owner_revision = 5;
        later.valid_from_utc_ns = Some(300);
        later.valid_until_utc_ns = None;
        store.commit_context(&later)?;
        assert_eq!(store.context_version(&input.key)?, Some(input.clone()));
        let mut unknown = input.clone();
        unknown.key.owner_revision = 0;
        unknown.valid_from_utc_ns = None;
        unknown.valid_until_utc_ns = None;
        let zero_revision = store.commit_context(&unknown)?;
        assert_eq!(store.commit_context(&unknown)?, zero_revision);
        let before = store.meta()?;
        for (from, until) in [(None, Some(200)), (Some(0), None), (Some(200), Some(200))] {
            let mut invalid = unknown.clone();
            invalid.valid_from_utc_ns = from;
            invalid.valid_until_utc_ns = until;
            assert!(store.commit_context(&invalid).is_err());
            assert_eq!(store.meta()?, before);
        }
        drop(store);
        let reopened = AnalysisStore::open(path)?;
        assert_eq!(reopened.commit_context(&input)?, revision);
        assert_eq!(reopened.context_version(&later.key)?, Some(later));
        assert_eq!(reopened.context_version(&unknown.key)?, Some(unknown));
        let mut foreign = input.key.clone();
        foreign.tenant_id = [2; 16];
        assert_eq!(reopened.context_version(&foreign)?, None);
        reopened.writer()?.get()?.execute(
            "UPDATE context_versions SET body = ? WHERE tenant_id = ? AND owner_id = ?",
            duckdb::params![
                b"".as_slice(),
                input.key.tenant_id.as_slice(),
                input.key.owner_id,
            ],
        )?;
        assert!(reopened.context_version(&input.key).is_err());
        Ok(())
    }
}
