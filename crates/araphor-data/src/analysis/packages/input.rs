use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::{PackageActivationV1, PackageCommitV1, PackageKeyV1, PackageResultRefV1};
use crate::{
    AnalysisContextRefV1, AnalysisDatabaseSnafu, AnalysisExtractionV1, AnalysisReadControl,
    AnalysisSelectionV1, AnalysisStore, AnalysisWitnessV1, JsonSnafu, Result,
};

impl AnalysisStore {
    pub fn package_activation_until(
        &self,
        key: &PackageKeyV1,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageActivationV1>> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| Self::activation_from(reader, key))
    }

    pub fn package_input_current<'a>(
        &self,
        active: &PackageActivationV1,
        selection: &AnalysisSelectionV1,
        extraction: &AnalysisExtractionV1,
        witnesses: impl Iterator<Item = &'a AnalysisWitnessV1> + Clone,
        now: u64,
        control: &AnalysisReadControl,
    ) -> Result<Option<u64>> {
        let witness_count = witnesses.clone().count();
        if !active.active
            || !active.key.valid()
            || !selection.valid()
            || active.key.tenant_id != selection.tenant_id
        {
            return Ok(None);
        }
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            if Self::activation_from(reader, &active.key)?.as_ref() != Some(active) {
                return Ok(None);
            }
            let meta = Self::read_meta_from(reader, &self.root)?;
            let captured = &extraction.meta;
            if captured.store_uuid != meta.store_uuid
                || captured.schema_version != meta.schema_version
                || captured.recovery_epoch != meta.recovery_epoch
                || captured.commit_revision > meta.commit_revision
            {
                return Ok(None);
            }
            Self::check_trace_reads_from(
                reader,
                selection.tenant_id,
                extraction.trace_reads(),
                control,
            )?;
            if !Self::package_sources_current(
                reader,
                &selection.source_revisions(captured.commit_revision),
                control,
            )? {
                return Ok(None);
            }
            for reference in &extraction.references {
                control.check()?;
                if let Some(reference) = reference.result() {
                    if reference.commit_revision > captured.commit_revision
                        || !Self::package_dependency_current(reader, &active.key, reference)?
                    {
                        return Ok(None);
                    }
                }
                if let Some(reference) = reference.context() {
                    if reference.key.tenant_id != selection.tenant_id
                        || reference.commit_revision > captured.commit_revision
                        || !Self::package_context_current(reader, reference)?
                    {
                        return Ok(None);
                    }
                }
            }
            let mut expiry = u64::MAX;
            if witness_count == 0 {
                return Ok(Some(expiry));
            }
            let raw = self.raw.until(control)?;
            for witness in witnesses {
                control.check()?;
                if witness.identity.tenant() != selection.tenant_id
                    || witness.cursor == 0
                    || witness.expires_utc_ns <= now
                {
                    return Ok(None);
                }
                let key = witness.identity.key();
                let Some((entry, _)) =
                    raw.locate_retained(&key, witness.cursor, captured.commit_revision)
                else {
                    return Ok(None);
                };
                if entry.identity != witness.identity {
                    return Ok(None);
                }
                let retained: bool = reader
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM segments s WHERE s.segment_id = ?
                     AND s.stream_key = ? AND s.tenant_id = ? AND s.state = 'Live'
                     AND NOT EXISTS(SELECT 1 FROM expired_ranges x WHERE x.tenant_id = ?
                        AND x.stream_key = ? AND x.first_cursor <= ? AND x.last_cursor >= ?))",
                        params![
                            entry.reference.id,
                            key,
                            selection.tenant_id.as_slice(),
                            selection.tenant_id.as_slice(),
                            key,
                            witness.cursor,
                            witness.cursor
                        ],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "check retained input witness",
                    })?;
                if !retained {
                    return Ok(None);
                }
                expiry = expiry.min(witness.expires_utc_ns);
            }
            control.check()?;
            Ok(Some(expiry))
        })
    }

    pub fn package_completed(
        &self,
        before: &PackageActivationV1,
        receipt: &PackageResultRefV1,
        control: &AnalysisReadControl,
    ) -> Result<Option<(PackageActivationV1, Vec<u8>)>> {
        if !before.active
            || !before.key.valid()
            || receipt.result_id.is_empty()
            || receipt.result_id.len() > 256
            || receipt.commit_revision <= before.checkpoint_revision
        {
            return Ok(None);
        }
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let Some(after) = Self::activation_from(reader, &before.key)? else {
                return Ok(None);
            };
            let mut expected = before.clone();
            expected.checkpoint_revision = receipt.commit_revision;
            expected.result_id = Some(receipt.result_id.clone());
            if after != expected {
                return Ok(None);
            }
            let row: Option<u64> = reader
                .query_row(
                    "SELECT octet_length(r.commit_meta)::UBIGINT
                 FROM package_results r JOIN analysis_results x USING (result_id)
                 JOIN package_heads h USING (result_id)
                 WHERE r.tenant_id = ? AND r.scope_id = ? AND r.package_id = ?
                    AND r.export_name = ? AND r.revision = ? AND r.result_id = ?
                    AND x.commit_revision = ? AND NOT r.stale
                    AND h.tenant_id = r.tenant_id AND h.scope_id = r.scope_id
                    AND h.package_id = r.package_id AND h.export_name = r.export_name
                    AND h.window_id = r.window_id",
                    params![
                        before.key.tenant_id.as_slice(),
                        before.key.scope_id,
                        before.key.package_id,
                        before.key.export,
                        before.revision,
                        receipt.result_id,
                        receipt.commit_revision
                    ],
                    |row| row.get(0),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "bound completed package metadata",
                })?;
            let Some(contract_bytes) = row else {
                return Ok(None);
            };
            if contract_bytes > Self::RESULT_READ_BYTES {
                return self.reject("the completed package metadata exceeds its byte limit");
            }
            let (contract, body, window): (Vec<u8>, Vec<u8>, String) = reader
                .query_row(
                    "SELECT r.commit_meta, x.body, r.window_id
                 FROM package_results r JOIN analysis_results x USING (result_id)
                 WHERE r.tenant_id = ? AND r.result_id = ?",
                    params![before.key.tenant_id.as_slice(), receipt.result_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read completed package metadata",
                })?;
            let contract: PackageCommitV1 =
                serde_json::from_slice(&contract).context(JsonSnafu {
                    path: "<package-commit>",
                })?;
            if contract.activation != *before
                || contract.expected_checkpoint_revision != before.checkpoint_revision
                || contract.result_id != receipt.result_id
                || contract.window_id != window
            {
                return Ok(None);
            }
            Ok(Some((after, body)))
        })
    }

    pub(in crate::analysis) fn package_sources_current(
        reader: &Connection,
        sources: &[(String, u64)],
        control: &AnalysisReadControl,
    ) -> Result<bool> {
        for (relation, captured) in sources {
            control.check()?;
            let changed: u64 = reader
                .query_row(
                    "SELECT COALESCE(MAX(last_changed_revision), 0)::UBIGINT
                 FROM relation_revisions WHERE relation_name = ?",
                    params![relation],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read package source notice",
                })?;
            if changed > *captured {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn package_dependency_current(
        reader: &Connection,
        key: &PackageKeyV1,
        reference: &PackageResultRefV1,
    ) -> Result<bool> {
        reader
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM analysis_results x
             LEFT JOIN package_results r USING (result_id)
             WHERE x.tenant_id = ? AND x.result_id = ? AND x.commit_revision = ?
                AND (r.result_id IS NULL OR (r.scope_id = ? AND NOT r.stale
                    AND EXISTS(SELECT 1 FROM package_heads h WHERE h.result_id = r.result_id))))",
                params![
                    key.tenant_id.as_slice(),
                    reference.result_id,
                    reference.commit_revision,
                    key.scope_id
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read package dependency notice",
            })
    }

    pub(super) fn package_context_current(
        reader: &Connection,
        reference: &AnalysisContextRefV1,
    ) -> Result<bool> {
        let key = &reference.key;
        reader
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM context_versions WHERE tenant_id = ?
             AND owner_id = ? AND entity_key = ? AND lifetime_key = ?
             AND owner_revision = ? AND commit_revision = ?)",
                params![
                    key.tenant_id.as_slice(),
                    key.owner_id,
                    key.entity_key.as_slice(),
                    key.lifetime_key.as_slice(),
                    key.owner_revision,
                    reference.commit_revision
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read package context notice",
            })
    }
}
