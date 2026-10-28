use crate::AnalysisContextRefV1;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::*;

impl AnalysisStore {
    pub fn commit_contexts(
        &self,
        inputs: &[AnalysisContextVersionV1],
    ) -> Result<Vec<AnalysisContextRefV1>> {
        self.commit_context_values(inputs, false, None, &mut || Ok(()))
    }

    pub fn commit_context(&self, input: &AnalysisContextVersionV1) -> Result<u64> {
        self.commit_context_value(input, false, None)
            .map(|reference| reference.commit_revision)
    }

    pub fn commit_context_checked(
        &self,
        input: &AnalysisContextVersionV1,
        expected: u64,
    ) -> Result<u64> {
        self.commit_context_value(input, false, Some(expected))
            .map(|reference| reference.commit_revision)
    }

    pub fn intern_context(&self, input: &AnalysisContextVersionV1) -> Result<AnalysisContextRefV1> {
        self.intern_context_guarded(input, || Ok(()))
    }

    pub fn intern_context_guarded(
        &self,
        input: &AnalysisContextVersionV1,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<AnalysisContextRefV1> {
        if !matches!(
            input.key.owner_id.as_str(),
            "discovery-facts-v1" | "discovery-source-v1" | "native-package-v1"
        ) {
            return self.reject("the qualified context owner is invalid");
        }
        self.commit_context_values(std::slice::from_ref(input), true, None, &mut check)?
            .pop()
            .ok_or_else(|| self.state_error("the committed context reference is absent"))
    }

    fn commit_context_value(
        &self,
        input: &AnalysisContextVersionV1,
        intern: bool,
        expected: Option<u64>,
    ) -> Result<AnalysisContextRefV1> {
        self.commit_context_values(
            std::slice::from_ref(input),
            intern,
            expected,
            &mut || Ok(()),
        )?
        .pop()
        .ok_or_else(|| self.state_error("the committed context reference is absent"))
    }

    fn commit_context_values(
        &self,
        inputs: &[AnalysisContextVersionV1],
        intern: bool,
        expected: Option<u64>,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<AnalysisContextRefV1>> {
        if inputs.is_empty() {
            check()?;
            return Ok(Vec::new());
        }
        for input in inputs {
            if !input.valid() {
                return self.reject("the context version identity or bounds are invalid");
            }
        }
        let writer_guard = self.writer()?;
        let writer = writer_guard.get()?;
        // The writer guard stays held. Context writes do not change raw state.
        let transaction = writer
            .unchecked_transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin context version",
            })?;
        let mut revision = None;
        let references =
            self.context_rows(&transaction, inputs, intern, expected, &mut revision)?;
        let Some(revision) = revision else {
            check()?;
            return Ok(references);
        };
        if self.storage.logical_max_bytes.is_some()
            || self.storage.tenant_max_bytes.is_some()
            || self.storage.retained_revisions.is_some()
            || self.storage.tenant_revisions.is_some()
        {
            let tenants = references
                .iter()
                .filter(|reference| reference.commit_revision == revision)
                .map(|reference| reference.key.tenant_id)
                .collect::<std::collections::BTreeSet<_>>();
            for tenant in tenants {
                self.check_logical(&transaction, tenant, false)?;
            }
        }
        Self::record_revision(&transaction, revision, &["context_versions"])?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::super::AnalysisCommitStage::BeforeContextCommit)?;
        #[cfg(test)]
        self.crash_at("context.before");
        check()?;
        self.commit_metadata(transaction, "commit context version")?;
        #[cfg(test)]
        self.crash_at("context.after");
        self.revision.send_replace(revision);
        Ok(references)
    }

    pub(in crate::analysis) fn context_rows(
        &self,
        writer: &Connection,
        inputs: &[AnalysisContextVersionV1],
        intern: bool,
        expected: Option<u64>,
        revision: &mut Option<u64>,
    ) -> Result<Vec<AnalysisContextRefV1>> {
        let path = self.root.join("analysis.duckdb");
        let mut references = Vec::with_capacity(inputs.len());
        for input in inputs {
            let key = &input.key;
            let imported = (key.owner_id == "discovery-context-v1")
                .then(|| crate::DiscoveryContextRevisionV1::try_from(input))
                .transpose()?;
            Self::validate_context_packages(writer, input)?;
            if let Some(reference) = self.context_retry(writer, input, intern)? {
                references.push(reference);
                continue;
            }
            self.storage.check_context(input.body.len() as u64)?;
            self.context_expected(writer, key, expected)?;
            if let Some(imported) = imported {
                self.context_import(writer, key, &imported)?;
            }
            let current = match *revision {
                Some(revision) => revision,
                None => {
                    let current = Self::read_meta_from(writer, &path)?
                        .commit_revision
                        .checked_add(1)
                        .ok_or_else(|| {
                            self.state_error("the analysis commit revision is exhausted")
                        })?;
                    *revision = Some(current);
                    current
                }
            };
            let sensitivity: &'static str = input.sensitivity.into();
            writer
                .prepare_cached(
                    "INSERT INTO context_versions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .and_then(|mut statement| {
                    statement.execute(params![
                        key.tenant_id.as_slice(),
                        key.owner_id,
                        key.entity_key.as_slice(),
                        key.lifetime_key.as_slice(),
                        key.owner_revision,
                        input.valid_from_utc_ns,
                        input.valid_until_utc_ns,
                        sensitivity,
                        input.body.as_slice(),
                        current,
                    ])
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "insert context version",
                })?;
            references.push(AnalysisContextRefV1 {
                key: key.clone(),
                commit_revision: current,
            });
        }
        Ok(references)
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
        if let Some((stored, revision)) = Self::read_context_row_from(reader, &self.root, key)? {
            if &stored != input {
                Self::validate_stored_context_packages(reader, &stored)?;
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
                .prepare_cached(
                    "SELECT MAX(owner_revision) FROM context_versions
                 WHERE tenant_id = ? AND owner_id = ? AND entity_key = ? AND lifetime_key = ?",
                )
                .and_then(|mut statement| {
                    statement.query_row(
                        params![
                            key.tenant_id.as_slice(),
                            key.owner_id,
                            key.entity_key.as_slice(),
                            key.lifetime_key.as_slice()
                        ],
                        |row| row.get(0),
                    )
                })
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
        imported.validate_history(previous.as_ref())?;
        Ok(())
    }
}
