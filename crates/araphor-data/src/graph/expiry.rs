use std::collections::BTreeSet;

use snafu::ResultExt as _;

use super::window::WindowHeads;
use super::*;
use crate::{
    AnalysisResultCommitV1, AnalysisSourceStatusV1, DiscoveryRecordIdV1, GraphEncodingSnafu,
    GraphInvalidSnafu,
};

impl GraphAndFindingOwner {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn expire_window_heads(
        &self,
        status: &AnalysisSourceStatusV1,
        heads: &WindowHeads,
        first: u64,
        last: u64,
        consumed: u64,
        advance: bool,
        now: u64,
        force: bool,
        notice: u64,
    ) -> Result<Option<bool>> {
        let expired = heads.values().filter(|(_, snapshot, _)| {
            (advance || snapshot.first_cursor == first)
                && (snapshot.witness_deadline_utc_ns <= now
                    || snapshot.first_cursor <= status.receipt.retained_floor)
        });
        let mut changed = None;
        for (id, snapshot, _) in expired {
            let committed = self.expire_window(
                id,
                snapshot,
                consumed,
                status.receipt.coverage_revision,
                notice,
                now,
            )?;
            changed = Some(changed.unwrap_or(false) | committed);
        }
        if changed.is_some() && advance {
            return self
                .commit_window(
                    &status.receipt.identity,
                    consumed.saturating_add(1),
                    last,
                    consumed,
                    true,
                    now,
                    force,
                )
                .map(Some);
        }
        Ok(changed)
    }

    pub(super) fn window_deadline(
        heads: &WindowHeads,
        selected: &BTreeSet<DiscoveryRecordIdV1>,
        now: u64,
    ) -> Result<u64> {
        Ok(heads
            .values()
            .filter(|(_, snapshot, _)| {
                snapshot
                    .input_manifest
                    .evidence
                    .iter()
                    .any(|id| selected.contains(id))
            })
            .map(|(_, snapshot, _)| snapshot.witness_deadline_utc_ns)
            .min()
            .unwrap_or(now.checked_add(GRAPH_WITNESS_TTL_NS).ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "witness deadline",
                }
                .build()
            })?))
    }

    pub(super) fn expire_window(
        &self,
        result_id: &str,
        previous: &GraphSnapshotV1,
        consumed: u64,
        coverage_revision: u64,
        notice: u64,
        now: u64,
    ) -> Result<bool> {
        if previous.findings.iter().all(|finding| {
            finding
                .limits
                .iter()
                .any(|limit| limit == "RETAINED_INPUT_EXPIRED")
        }) && previous
            .missing_ranges
            .contains(&(previous.first_cursor, previous.last_cursor))
        {
            return Ok(false);
        }
        let snapshot = Self::expiry_snapshot(previous, result_id, notice)?;
        let mut facts = Vec::new();
        for key in &snapshot.input_manifest.context {
            let fact = self.store.context_version(key)?.ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "expired graph context",
                }
                .build()
            })?;
            facts.push(fact);
        }
        let references = self.commit_contexts(&facts)?;
        self.store.commit_graph(
            &AnalysisResultCommitV1 {
                scope: snapshot.scope.clone(),
                expected_cursor: consumed,
                consumed_cursor: consumed,
                coverage_revision,
                context_revision: references
                    .iter()
                    .map(|reference| reference.commit_revision)
                    .max()
                    .unwrap_or(0),
                result_id: format!("graph:{}", uuid::Uuid::new_v4()),
                body: serde_json::to_vec(&snapshot).context(GraphEncodingSnafu)?,
                created_utc_ns: now,
                witnesses: vec![],
                context_refs: references,
            },
            false,
        )?;
        Ok(true)
    }

    fn expiry_snapshot(
        previous: &GraphSnapshotV1,
        result_id: &str,
        notice: u64,
    ) -> Result<GraphSnapshotV1> {
        let mut snapshot = previous.clone();
        snapshot.previous_result_id = Some(result_id.into());
        snapshot.context_notice_revision = notice;
        snapshot
            .missing_ranges
            .push((previous.first_cursor, previous.last_cursor));
        snapshot.missing_ranges.sort();
        snapshot.missing_ranges.dedup();
        snapshot.input_manifest.missing_ranges = snapshot.missing_ranges.clone();
        Self::expire_graph(&mut snapshot);
        Self::expire_findings(&mut snapshot);
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn expire_graph(snapshot: &mut GraphSnapshotV1) {
        snapshot.graph.revision = snapshot.input_manifest.clone();
        for edge in &mut snapshot.graph.edges {
            edge.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
            edge.key.cause = GraphCauseV1::Superseded;
        }
        snapshot
            .graph
            .edges
            .sort_by(|left, right| left.key.cmp(&right.key));
        snapshot
            .graph
            .edges
            .dedup_by(|left, right| left.key == right.key);
        for branch in &mut snapshot.graph.branches {
            branch.state = GraphBranchStateV1::CoverageUnknown;
            branch.missing_fields.push("RETAINED_INPUT_EXPIRED".into());
            branch.missing_fields.sort();
            branch.missing_fields.dedup();
        }
    }

    fn expire_findings(snapshot: &mut GraphSnapshotV1) {
        for finding in &mut snapshot.findings {
            finding.revision = snapshot.input_manifest.clone();
            finding.state = FindingStateV1::CoverageInsufficient;
            finding.limits.push("RETAINED_INPUT_EXPIRED".into());
            finding
                .limits
                .push("LATE_EVIDENCE_UNSUPPORTED_AFTER_RETENTION".into());
            finding.limits.sort();
            finding.limits.dedup();
            for effect in &mut finding.effects {
                effect.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
            }
        }
        for package in &mut snapshot.packages {
            package.state = GraphPackageStateV1::CoverageInsufficient;
        }
    }
}
