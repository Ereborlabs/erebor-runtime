use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::super::graph_rows::GraphHeader;
use super::super::AnalysisStore;
use super::model::{Attempt, ManagedDestination, Step};
use crate::{
    AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, PackageErrorCodeV1 as Code, Result,
    GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION,
};

impl AnalysisStore {
    pub(super) fn check_graph_publication(
        reader: &Connection,
        tenant: [u8; 16],
        source: &EvidenceIntakeIdentityV1,
        reference: &super::super::PackageResultRefV1,
        selected_revision: u64,
    ) -> Result<()> {
        if !source.valid()
            || source.tenant_id != tenant
            || reference.result_id.is_empty()
            || reference.commit_revision == 0
            || reference.commit_revision > selected_revision
        {
            return Err(Code::Invalid.error("managed Graph publication"));
        }
        let retained: Option<(Vec<u8>, Vec<u8>, u64, u64)> = reader
            .query_row(
                "SELECT r.body, r.stream_key, r.method_version, r.first_cursor
                 FROM analysis_results r
                    JOIN graph_versions v USING (result_id)
                    WHERE r.result_id = ? AND r.tenant_id = ?
                        AND r.processor_id = ? AND r.method_version = ?
                        AND r.stream_key = ? AND r.commit_revision = ?
                        AND v.commit_revision = r.commit_revision",
                params![
                    reference.result_id,
                    tenant.as_slice(),
                    GRAPH_PROCESSOR,
                    GRAPH_SCHEMA_VERSION,
                    source.key().as_slice(),
                    reference.commit_revision,
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read managed Graph publication",
            })?;
        let (body, stream, method, first) =
            retained.ok_or_else(|| Code::Invalid.error("managed Graph publication"))?;
        GraphHeader::decode(&body)?.check_index(tenant, &stream, method, first)?;
        Ok(())
    }

    pub(super) fn validate_selected_header(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        step: &Step,
        revision: u64,
    ) -> Result<(Attempt, sdk::Schema)> {
        let attempt = Self::managed_attempt_from(reader, tenant, &step.instance, &step.attempt)?
            .ok_or_else(|| Code::Missing.error("managed selected attempt"))?;
        let spec =
            Self::managed_version_from(reader, tenant, &step.instance, attempt.capture.generation)?;
        let receipt = attempt
            .receipt
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("unpublished managed selected result"))?;
        attempt.capture.grant.validate()?;
        if attempt.capture.grant.selection
            != Self::managed_scope_from(reader, tenant, &step.instance, attempt.capture.generation)?
            || receipt.instance != step.instance
            || receipt.attempt != step.attempt
            || receipt.selected.result_id != id
            || receipt.selected.commit_revision != revision
            || receipt.commit_revision != revision
            || !receipt.matches_frontier(&attempt.request.frontier)
            || attempt.terminal.is_some()
            || attempt.registered == 0
            || revision <= attempt.registered
            || receipt.results.iter().any(|(call, reference)| {
                !spec.manifest.calls.contains_key(call)
                    || reference.result_id.is_empty()
                    || reference.commit_revision != revision
            })
        {
            return Err(Code::Invalid.error("retained managed selected contract"));
        }
        Self::check_source_evidence(reader, &attempt, step)?;
        match (&spec.destination, &receipt.graph) {
            (ManagedDestination::Graph { source, .. }, Some(reference)) => {
                Self::check_graph_publication(reader, tenant, source, reference, revision)?;
            }
            (ManagedDestination::Graph { .. }, None)
                if receipt.results.is_empty() && step.rows == 0 => {}
            (ManagedDestination::Graph { .. }, None) | (_, Some(_)) => {
                return Err(Code::Invalid.error("managed Graph publication"));
            }
            (_, None) => {}
        }
        let mut dependencies = attempt.capture.dependencies.clone();
        dependencies.extend(receipt.results.values().cloned());
        dependencies.extend(receipt.graph.iter().cloned());
        dependencies.sort_by(|left, right| left.result_id.cmp(&right.result_id));
        dependencies.dedup();
        if step.dependencies != dependencies {
            return Err(Code::Invalid.error("managed selected dependencies"));
        }
        for (call, reference) in &receipt.results {
            let (record, saved) = Self::managed_meta_from(reader, tenant, &reference.result_id)?;
            if saved != reference.commit_revision
                || saved != revision
                || record.call != *call
                || record.attempt != step.attempt
                || record.instance != step.instance
            {
                return Err(Code::Invalid.error("managed selected call binding"));
            }
        }
        Ok((attempt, spec.manifest.selected_schema))
    }

    pub(super) fn check_selected(data: &sdk::Dataset, schema: &sdk::Schema) -> Result<()> {
        let mut rows = 0_u64;
        for batch in &data.batches {
            rows = rows
                .checked_add(batch.num_rows() as u64)
                .ok_or_else(|| Code::Invalid.error("native selected row count"))?;
            if batch.schema().as_ref() != schema {
                return Err(Code::Invalid.error("native selected schema"));
            }
            for column in batch.columns() {
                column
                    .to_data()
                    .validate_full()
                    .context(crate::PackageArrowSnafu)?;
            }
        }
        Ok(())
    }
}
