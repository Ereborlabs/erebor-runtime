use super::*;
use crate::{DiscoveryProfileV1, DiscoverySnapshotRowV1, DiscoveryStateRowV1};

impl AnalysisStore {
    pub(super) fn extract_discovery_state(
        &self,
        snapshot: &Connection,
        receipt: &AnalysisSourceReceiptV1,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut tables::Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let Some(projected) = read.projected("discovery_state") else {
            return Ok(());
        };
        control.check()?;
        let schema = &Self::table_schemas()["discovery_state"];
        let decode = projected.iter().any(|index| {
            matches!(
                schema.field(*index).name().as_str(),
                "facts_revision"
                    | "coverage_revision"
                    | "created_utc_ns"
                    | "updated_utc_ns"
                    | "sealed"
                    | "input_bytes"
                    | "incomplete"
                    | "gaps"
                    | "context_refs"
                    | "snapshot"
            )
        });
        let identity = &receipt.identity;
        let key = identity.key();
        output.charge(key.capacity() + identity.node_id.len())?;
        let (mut state, body_bytes, retained): (DiscoveryStateRowV1, Option<usize>, Option<String>) = snapshot.query_row(
            "SELECT p.class, p.start_cursor, p.consumed_cursor, p.resume_floor, p.context_revision,
                p.retired, NULLIF(p.result_id, ''), r.result_id, r.commit_revision, r.interval_id,
                r.profile_revision, octet_length(r.body)
             FROM source_receipts s
             LEFT JOIN processor_progress p ON p.tenant_id = s.tenant_id AND p.stream_key = s.stream_key
                AND p.processor_id = 'discovery' AND p.method_version = ?
             LEFT JOIN analysis_results r ON r.tenant_id = p.tenant_id AND r.processor_id = p.processor_id
                AND r.stream_key = p.stream_key AND r.method_version = p.method_version AND r.result_id = p.result_id
             WHERE s.tenant_id = ? AND s.stream_key = ?",
            params![u64::from(crate::DISCOVERY_SCHEMA_VERSION), identity.tenant_id.as_slice(), key.as_slice()],
            |row| {
                let class: Option<String> = row.get(0)?;
                let current: Option<String> = row.get(6)?;
                let retained: Option<String> = row.get(7)?;
                Ok((DiscoveryStateRowV1 {
                    tenant_id: identity.tenant_id, node_id: identity.node_id.clone(),
                    node_boot_id: identity.node_boot_id, label_epoch: identity.label_epoch,
                    source_id: identity.source_id, source_epoch: identity.source_epoch,
                    cpu_id: receipt.cpu_id, contiguous_cursor: receipt.contiguous_cursor,
                    retained_floor: receipt.retained_floor, source_coverage_revision: receipt.coverage_revision,
                    method_version: u64::from(crate::DISCOVERY_SCHEMA_VERSION),
                    processor_present: class.is_some(), processor_class: class,
                    start_cursor: row.get(1)?, consumed_cursor: row.get(2)?, resume_floor: row.get(3)?,
                    context_revision: row.get(4)?, retired: row.get(5)?, current_result_id: current,
                    result_commit_revision: row.get(8)?, interval_id: row.get(9)?,
                    profile_revision: row.get(10)?, facts_revision: None, coverage_revision: None,
                    created_utc_ns: None, updated_utc_ns: None, sealed: None, input_bytes: None,
                    incomplete: None, gaps: None, context_refs: None, snapshot: None,
                }, row.get(11)?, retained))
            },
        ).context(AnalysisDatabaseSnafu { operation: "read captured discovery state" })?;
        if state.current_result_id != retained
            || state.current_result_id.is_some() != state.result_commit_revision.is_some()
            || state
                .result_commit_revision
                .is_some_and(|revision| revision == 0 || revision > output.meta.commit_revision)
        {
            return self.reject("the discovery current head has no exact retained result");
        }
        if let (Some(id), Some(revision)) = (&state.current_result_id, state.result_commit_revision)
        {
            output.reference_result(id, revision, AnalysisReferenceOriginV1::Profile)?;
            if decode {
                output.charge(
                    body_bytes
                        .ok_or_else(|| self.state_error("the discovery head body is absent"))?
                        .checked_mul(4)
                        .ok_or_else(|| {
                            AnalysisInputTooLargeSnafu {
                                resource: "native discovery state",
                            }
                            .build()
                        })?,
                )?;
                let body = self
                    .read_result_from(snapshot, identity.tenant_id, id)?
                    .ok_or_else(|| self.state_error("the discovery head result is absent"))?;
                let profile = DiscoveryProfileV1::try_from(body.as_slice())?;
                if profile.profile_id != *id
                    || profile.scope.identity != *identity
                    || profile.scope.method_version != state.method_version
                    || Some(&profile.interval_id) != state.interval_id.as_ref()
                    || Some(profile.revision) != state.profile_revision
                {
                    return self.reject("the discovery head differs from its retained profile");
                }
                state.facts_revision = Some(profile.facts_revision);
                state.coverage_revision = Some(profile.coverage_revision);
                state.created_utc_ns = Some(profile.created_utc_ns);
                state.updated_utc_ns = Some(profile.updated_utc_ns);
                state.sealed = Some(profile.sealed);
                state.input_bytes = Some(profile.input_bytes);
                state.incomplete = Some(profile.incomplete);
                state.gaps = Some(profile.gaps);
                state.context_refs = Some(profile.context_refs);
                state.snapshot = Some(DiscoverySnapshotRowV1::from_snapshot(profile.snapshot)?);
            }
        }
        if projected
            .iter()
            .any(|index| schema.field(*index).name() == "gaps")
        {
            let prior = state.gaps.take().unwrap_or_default();
            // Each span needs at most 65 JSON bytes for three u64 values, brackets, and commas.
            output.charge(
                prior
                    .len()
                    .checked_mul(65 + size_of::<[u64; 3]>())
                    .and_then(|bytes| bytes.checked_add(2))
                    .ok_or_else(|| {
                        AnalysisInputTooLargeSnafu {
                            resource: "discovery gap input",
                        }
                        .build()
                    })?,
            )?;
            let spans = prior
                .iter()
                .map(|gap| [gap.first_cursor, gap.last_cursor, gap.commit_revision])
                .collect::<Vec<_>>();
            let encoded =
                serde_json::to_string(&spans).context(crate::JsonSnafu { path: &self.root })?;
            let mut statement = snapshot.prepare(
                "WITH prior AS (SELECT UNNEST(CAST(? AS UBIGINT[][])) AS span)
                 SELECT span[1] AS first_cursor, span[2] AS last_cursor, span[3] AS commit_revision FROM prior
                 UNION
                 SELECT first_cursor, last_cursor, commit_revision FROM processor_gaps
                 WHERE processor_id = 'discovery' AND method_version = ? AND tenant_id = ?
                    AND stream_key = ? AND last_cursor > ?
                 ORDER BY first_cursor, last_cursor, commit_revision"
            ).context(AnalysisDatabaseSnafu { operation: "prepare captured discovery gaps" })?;
            let rows = statement
                .query_map(
                    params![
                        encoded,
                        state.method_version,
                        identity.tenant_id.as_slice(),
                        key.as_slice(),
                        state.consumed_cursor.unwrap_or(0)
                    ],
                    |row| {
                        Ok(AnalysisGapV1 {
                            first_cursor: row.get(0)?,
                            last_cursor: row.get(1)?,
                            commit_revision: row.get(2)?,
                        })
                    },
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read captured discovery gaps",
                })?;
            let mut gaps = Vec::new();
            for gap in rows {
                control.check()?;
                let gap = gap.context(AnalysisDatabaseSnafu {
                    operation: "decode captured discovery gap",
                })?;
                if gap.first_cursor == 0
                    || gap.last_cursor < gap.first_cursor
                    || gap.commit_revision == 0
                    || gap.commit_revision > output.meta.commit_revision
                    || gaps
                        .last()
                        .is_some_and(|last: &AnalysisGapV1| last.last_cursor >= gap.first_cursor)
                {
                    return self.reject("the captured discovery gaps are invalid or overlap");
                }
                let mut budget = output.sink(control);
                budget.grow(&mut gaps)?;
                gaps.push(gap);
            }
            state.gaps = Some(gaps);
        }
        capture.discovery_state(&state, &mut output.sink(control))?;
        Ok(())
    }
}
