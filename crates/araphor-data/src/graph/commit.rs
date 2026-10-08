use std::collections::BTreeSet;

use snafu::ResultExt as _;

use super::window::WindowHead;
use super::*;
use crate::{
    AnalysisContextRefV1, AnalysisResultCommitV1, AnalysisSourceStatusV1, AnalysisStreamIdentityV1,
    AnalysisWitnessV1, GraphEncodingSnafu,
};

impl GraphAndFindingOwner {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit_bounded_window(
        &self,
        status: &AnalysisSourceStatusV1,
        first: u64,
        consumed: u64,
        advance: bool,
        now: u64,
        notice: u64,
        deadline: u64,
        positions: Vec<(crate::DiscoveryRecordIdV1, crate::StorePositionV1)>,
        input: GraphReplayInputV1,
        previous: Option<&WindowHead>,
    ) -> Result<Option<bool>> {
        let mut snapshot = Self::derive(&input)?;
        snapshot.first_cursor = first;
        snapshot.input_positions = positions;
        snapshot.context_notice_revision = notice;
        snapshot.witness_deadline_utc_ns = deadline;
        if previous.as_ref().is_some_and(|(_, previous, _)| {
            previous.input_manifest == snapshot.input_manifest
                && previous.graph == snapshot.graph
                && previous.findings == snapshot.findings
        }) {
            return Ok(Some(false));
        }
        snapshot.previous_result_id = previous.as_ref().map(|row| row.0.clone());
        snapshot.validate()?;
        let body = serde_json::to_vec(&snapshot).context(GraphEncodingSnafu)?;
        if body.len() > GRAPH_WINDOW_BYTES.min(crate::analysis::MAX_RESULT_BYTES) {
            return Ok(None);
        }
        self.commit_snapshot(snapshot, body, &input.facts, status, consumed, advance, now)?;
        Ok(Some(true))
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_snapshot(
        &self,
        snapshot: GraphSnapshotV1,
        body: Vec<u8>,
        facts: &[AnalysisContextVersionV1],
        status: &AnalysisSourceStatusV1,
        consumed: u64,
        advance: bool,
        now: u64,
    ) -> Result<()> {
        let references = self.commit_contexts(facts)?;
        let expires = snapshot.witness_deadline_utc_ns;
        let witness_ids: BTreeSet<_> = snapshot.input_manifest.evidence.iter().cloned().collect();
        let witnesses = witness_ids
            .into_iter()
            .map(|id| AnalysisWitnessV1 {
                identity: AnalysisStreamIdentityV1::Evidence(id.stream),
                cursor: id.durable_cursor,
                expires_utc_ns: expires,
            })
            .collect();
        let commit = AnalysisResultCommitV1 {
            scope: Self::scope(&status.receipt.identity),
            expected_cursor: consumed,
            consumed_cursor: if advance {
                snapshot.last_cursor
            } else {
                consumed
            },
            coverage_revision: status.receipt.coverage_revision,
            context_revision: references
                .iter()
                .map(|reference| reference.commit_revision)
                .max()
                .unwrap_or(0),
            result_id: format!("graph:{}", uuid::Uuid::new_v4()),
            body,
            created_utc_ns: now,
            witnesses,
            context_refs: references,
        };
        self.store.commit_graph(&commit, advance).map(|_| ())
    }

    pub(super) fn commit_contexts(
        &self,
        facts: &[AnalysisContextVersionV1],
    ) -> Result<Vec<AnalysisContextRefV1>> {
        let mut references = Vec::new();
        for fact in facts {
            references.push(AnalysisContextRefV1 {
                key: fact.key.clone(),
                commit_revision: self.store.commit_context(fact)?,
            });
        }
        references.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(references)
    }
}
