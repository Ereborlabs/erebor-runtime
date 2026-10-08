use crate::AnalysisContextRefV1;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::*;

impl AnalysisStore {
    pub fn commit_context(&self, input: &AnalysisContextVersionV1) -> Result<u64> {
        self.commit_context_value(input, false, None)
            .map(|reference| reference.commit_revision)
    }

    pub(crate) fn commit_context_checked(
        &self,
        input: &AnalysisContextVersionV1,
        expected: u64,
    ) -> Result<u64> {
        self.commit_context_value(input, false, Some(expected))
            .map(|reference| reference.commit_revision)
    }

    pub(crate) fn intern_context(
        &self,
        input: &AnalysisContextVersionV1,
    ) -> Result<AnalysisContextRefV1> {
        if !matches!(
            input.key.owner_id.as_str(),
            "discovery-facts-v1" | "discovery-source-v1"
        ) {
            return self.reject("the qualified context owner is invalid");
        }
        self.commit_context_value(input, true, None)
    }

    fn commit_context_value(
        &self,
        input: &AnalysisContextVersionV1,
        intern: bool,
        expected: Option<u64>,
    ) -> Result<AnalysisContextRefV1> {
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
        if let Some(reference) = self.context_retry(&transaction, input, intern)? {
            return Ok(reference);
        }
        self.context_expected(&transaction, key, expected)?;
        if let Some(imported) = imported {
            self.context_import(&transaction, key, &imported)?;
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
        crate::analysis::quota::UsageChange {
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
        Ok(AnalysisContextRefV1 {
            key: key.clone(),
            commit_revision: revision,
        })
    }

    fn context_retry(
        &self,
        reader: &Connection,
        input: &AnalysisContextVersionV1,
        intern: bool,
    ) -> Result<Option<AnalysisContextRefV1>> {
        let key = &input.key;
        let sensitivity: &'static str = input.sensitivity.into();
        if intern {
            let stored: Option<(Vec<u8>, u64, u64)> = reader
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
                return Ok(Some(AnalysisContextRefV1 {
                    key,
                    commit_revision: revision,
                }));
            }
        }
        if let Some((stored, revision)) = Self::read_context_from(reader, &self.root, key)? {
            if &stored != input {
                return AnalysisConflictSnafu.fail();
            }
            return Ok(Some(AnalysisContextRefV1 {
                key: key.clone(),
                commit_revision: revision,
            }));
        }
        Ok(None)
    }

    fn context_expected(
        &self,
        reader: &Connection,
        key: &AnalysisContextKeyV1,
        expected: Option<u64>,
    ) -> Result<()> {
        if let Some(expected) = expected {
            let latest: Option<u64> = reader
                .query_row(
                    "SELECT MAX(owner_revision) FROM context_versions
                 WHERE tenant_id = ? AND owner_id = ? AND entity_key = ? AND lifetime_key = ?",
                    params![
                        key.tenant_id.as_slice(),
                        key.owner_id,
                        key.entity_key.as_slice(),
                        key.lifetime_key.as_slice()
                    ],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read expected context head",
                })?;
            if latest.unwrap_or(0) != expected
                || expected.checked_add(1) != Some(key.owner_revision)
            {
                return AnalysisConflictSnafu.fail();
            }
        }
        Ok(())
    }

    fn context_import(
        &self,
        reader: &Connection,
        key: &AnalysisContextKeyV1,
        imported: &crate::DiscoveryContextRevisionV1,
    ) -> Result<()> {
        let previous: Option<(Vec<u8>, u64)> = reader
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
                let (stored, _) = Self::read_context_from(reader, &self.root, &previous)?
                    .ok_or_else(|| self.state_error("the prior discovery document is absent"))?;
                crate::DiscoveryContextRevisionV1::try_from(&stored)
            })
            .transpose()?;
        let (documents, revisions): (u64, u64) = reader
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
        Ok(())
    }
}
