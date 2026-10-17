use duckdb::{params, OptionalExt as _, Transaction};
use snafu::ResultExt as _;

use super::{PackageCommitV1, PackageResultRefV1};
use crate::{AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisStore, JsonSnafu, Result};

impl AnalysisStore {
    pub fn commit_package(
        &self,
        input: &PackageCommitV1,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<PackageResultRefV1> {
        self.validate_package_commit(input)?;
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin package result",
            })?;
        if let Some(receipt) = self.package_retry(&transaction, input)? {
            check()?;
            return Ok(receipt);
        }
        let active = Self::activation_from(&transaction, &input.activation.key)?;
        if active.as_ref() != Some(&input.activation)
            || !input.activation.active
            || input.expected_checkpoint_revision != input.activation.checkpoint_revision
        {
            return AnalysisConflictSnafu.fail();
        }
        let before = Self::package_bytes(&transaction, input.activation.key.tenant_id)?;
        let revision = self.package_next(&transaction)?;
        self.package_commit_rows(&transaction, input, revision, before)?;
        check()?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::super::AnalysisCommitStage::BeforeResultCommit)?;
        #[cfg(test)]
        self.crash_at("package.before");
        self.commit_metadata(transaction, "commit package result")?;
        #[cfg(test)]
        self.crash_at("package.after");
        self.revision.send_replace(revision);
        Ok(PackageResultRefV1 {
            result_id: input.result_id.clone(),
            commit_revision: revision,
        })
    }

    pub(super) fn package_contract(input: &PackageCommitV1) -> Result<Vec<u8>> {
        serde_json::to_vec(input).context(JsonSnafu {
            path: "<package-result>",
        })
    }

    pub(super) fn package_retry(
        &self,
        transaction: &Transaction<'_>,
        input: &PackageCommitV1,
    ) -> Result<Option<PackageResultRefV1>> {
        let contract = transaction
            .query_row(
                "SELECT commit_meta FROM package_results WHERE result_id = ?",
                params![input.result_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read package retry",
            })?;
        let Some(contract) = contract else {
            return Ok(None);
        };
        let retained = Self::package_result_from(
            transaction,
            input.activation.key.tenant_id,
            &input.result_id,
            &self.root,
        )?;
        let Some(retained) = retained else {
            return AnalysisConflictSnafu.fail();
        };
        if contract != Self::package_contract(input)? || retained.commit != *input {
            return AnalysisConflictSnafu.fail();
        }
        Ok(Some(PackageResultRefV1 {
            result_id: input.result_id.clone(),
            commit_revision: retained.commit_revision,
        }))
    }

    pub(super) fn package_commit_rows(
        &self,
        transaction: &Transaction<'_>,
        input: &PackageCommitV1,
        revision: u64,
        before: i64,
    ) -> Result<()> {
        let key = &input.activation.key;
        for (relation, captured) in &input.source_revisions {
            let changed: u64 = transaction.query_row(
                "SELECT COALESCE(MAX(last_changed_revision), 0)::UBIGINT FROM relation_revisions WHERE relation_name = ?",
                params![relation], |row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation: "check package source revision" })?;
            if changed > *captured || *captured >= revision {
                return AnalysisConflictSnafu.fail();
            }
        }
        self.check_package_dependencies(transaction, input)?;
        for reference in &input.context_refs {
            let context = Self::read_context_from(transaction, &self.root, &reference.key)?;
            if context.is_none_or(|(_, revision)| revision != reference.commit_revision) {
                return self.reject("the package context reference is absent or changed");
            }
        }
        let segments = self.resolve_witnesses(&input.witnesses, revision - 1)?;
        let prior: Option<String> = transaction.query_row(
            "SELECT result_id FROM package_heads WHERE tenant_id = ? AND scope_id = ? AND package_id = ? AND export_name = ? AND window_id = ?",
            params![key.tenant_id.as_slice(), key.scope_id, key.package_id, key.export, input.window_id], |row| row.get(0),
        ).optional().context(AnalysisDatabaseSnafu { operation: "read replaced package result" })?;
        transaction.execute("INSERT INTO analysis_results (result_id, tenant_id, processor_id, body, request_meta, commit_revision)
            VALUES (?, ?, 'analysis-package', ?, ?, ?)",
            params![input.result_id, key.tenant_id.as_slice(), input.metadata, input.request, revision],
        ).context(AnalysisDatabaseSnafu { operation: "insert package receipt" })?;
        transaction
            .execute(
                "INSERT INTO package_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?)",
                params![
                    input.result_id,
                    key.tenant_id.as_slice(),
                    key.scope_id,
                    key.package_id,
                    key.export,
                    input.activation.revision,
                    input.window_id,
                    input.datasets,
                    input.checkpoint,
                    Self::package_contract(input)?
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert package output and checkpoint",
            })?;
        for dependency in &input.dependencies {
            transaction
                .execute(
                    "INSERT INTO package_dependencies VALUES (?, ?, ?, ?)",
                    params![
                        key.tenant_id.as_slice(),
                        input.result_id,
                        dependency.result_id,
                        dependency.commit_revision
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert exact package dependency",
                })?;
        }
        if let Some(prior) = prior {
            Self::stale_package_tree(transaction, key.tenant_id, &prior)?;
        }
        transaction.execute("INSERT INTO package_heads VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, scope_id, package_id, export_name, window_id) DO UPDATE SET result_id = excluded.result_id",
            params![key.tenant_id.as_slice(), key.scope_id, key.package_id, key.export, input.window_id, input.result_id],
        ).context(AnalysisDatabaseSnafu { operation: "replace package window" })?;
        transaction
            .execute(
                "UPDATE package_activations SET result_id = ?, checkpoint_revision = ?
            WHERE tenant_id = ? AND scope_id = ? AND package_id = ? AND export_name = ?",
                params![
                    input.result_id,
                    revision,
                    key.tenant_id.as_slice(),
                    key.scope_id,
                    key.package_id,
                    key.export
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "advance package checkpoint",
            })?;
        let references = Self::insert_references(
            transaction,
            &input.result_id,
            &input.witnesses,
            &segments,
            &input.context_refs,
        )?;
        let extra = references
            + (256
                + input.result_id.len()
                + "analysis-package".len()
                + input.metadata.len()
                + input.request.len()) as i64;
        self.package_charge(transaction, key.tenant_id, before, extra, 1)?;
        self.check_witnesses(transaction, key.tenant_id, input.created_utc_ns)?;
        Self::record_revision(
            transaction,
            revision,
            &[
                "analysis_results",
                "package_results",
                "package_activations",
                "package_heads",
                "package_dependencies",
                "evidence_refs",
                "context_refs",
            ],
        )
    }

    pub(super) fn stale_package_tree(
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<()> {
        transaction.execute("WITH RECURSIVE affected(result_id) AS (
            SELECT ? UNION SELECT d.result_id FROM package_dependencies d JOIN affected a ON d.dependency_id = a.result_id
            WHERE d.tenant_id = ?)
            UPDATE package_results SET stale = true WHERE tenant_id = ? AND result_id IN (SELECT result_id FROM affected)",
            params![id, tenant.as_slice(), tenant.as_slice()],
        ).context(AnalysisDatabaseSnafu { operation: "mark dependent package results stale" })?;
        Ok(())
    }

    fn check_package_dependencies(
        &self,
        transaction: &Transaction<'_>,
        input: &PackageCommitV1,
    ) -> Result<()> {
        for dependency in &input.dependencies {
            if self.package_source_revision(
                transaction,
                input.activation.key.tenant_id,
                &dependency.result_id,
            )? != dependency.commit_revision
            {
                return AnalysisConflictSnafu.fail();
            }
            if !Self::package_dependency_current(transaction, &input.activation.key, dependency)? {
                return AnalysisConflictSnafu.fail();
            }
        }
        Ok(())
    }

    pub(super) fn validate_package_commit(&self, input: &PackageCommitV1) -> Result<()> {
        let tenant = input.activation.key.tenant_id;
        let references: std::collections::BTreeSet<_> = input
            .dependencies
            .iter()
            .map(|reference| &reference.result_id)
            .collect();
        if !input.activation.key.valid()
            || input.result_id.is_empty()
            || input.result_id.len() > 256
            || input.window_id.is_empty()
            || input.window_id.len() > 256
            || input.request.is_empty()
            || input.request.len() > super::super::MAX_RESULT_BYTES
            || input.metadata.is_empty()
            || input.metadata.len() > super::super::MAX_RESULT_BYTES
            || input.datasets.len().saturating_add(input.checkpoint.len())
                > super::super::MAX_RESULT_BYTES
            || input.dependencies.len() > 64
            || input.source_revisions.len() > 64
            || input
                .source_revisions
                .windows(2)
                .any(|pair| pair[0].0 >= pair[1].0)
            || input
                .source_revisions
                .iter()
                .any(|(name, _)| name.is_empty() || name.len() > 128)
            || references.len() != input.dependencies.len()
            || input.dependencies.iter().any(|reference| {
                reference.result_id.is_empty()
                    || reference.result_id.len() > 256
                    || reference.commit_revision == 0
            })
            || input.witnesses.len() > super::super::MAX_RESULT_REFS
            || input.context_refs.len() > 256
            || input.created_utc_ns == 0
            || input
                .witnesses
                .windows(2)
                .any(|p| (&p[0].identity, p[0].cursor) >= (&p[1].identity, p[1].cursor))
            || input.context_refs.windows(2).any(|p| p[0].key >= p[1].key)
            || input
                .context_refs
                .iter()
                .any(|r| !r.key.valid() || r.key.tenant_id != tenant || r.commit_revision == 0)
            || input.witnesses.iter().any(|w| {
                !w.identity.valid()
                    || w.identity.tenant() != tenant
                    || w.cursor == 0
                    || w.expires_utc_ns < input.created_utc_ns
                    || w.expires_utc_ns - input.created_utc_ns > 7 * 24 * 60 * 60 * 1_000_000_000
            })
        {
            return self
                .reject("the package result exceeds its bounds or contains invalid references");
        }
        if Self::package_contract(input)?.len() > super::super::MAX_RESULT_BYTES {
            return self.reject("the package commit metadata exceeds its byte limit");
        }
        Ok(())
    }
}
