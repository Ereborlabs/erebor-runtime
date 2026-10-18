use std::collections::BTreeSet;

use super::window::{WindowHead, WindowRun};
use super::*;
use crate::{
    AnalysisContextRefV1, AnalysisResultCommitV1, AnalysisSourceStatusV1, AnalysisStreamIdentityV1,
    AnalysisWitnessV1,
};

impl GraphAndFindingOwner {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit_bounded_window(
        &self,
        status: &AnalysisSourceStatusV1,
        first: u64,
        consumed: u64,
        run: &mut WindowRun<'_>,
        now: u64,
        notice: u64,
        deadline: u64,
        positions: Vec<(crate::DiscoveryRecordIdV1, crate::StorePositionV1)>,
        input: GraphReplayInputV1,
        previous: Option<&WindowHead>,
    ) -> Result<Option<bool>> {
        if input.facts.len() > 255 {
            return Ok(None);
        }
        let execution = self.installed_snapshot(input.source.tenant_id, run.installed)?;
        let input = input.normalized()?;
        if !run.advance && !run.force {
            if let Some(previous) =
                previous.filter(|previous| previous.1.input_manifest == input.manifest())
            {
                input.validate()?;
                let coverage =
                    self.store
                        .graph_notice(&previous.1.scope, &previous.0, previous.2)?;
                let installed = Self::compatible_refs(&execution, input.source.tenant_id)?;
                if coverage
                    .is_some_and(|(_, revision)| revision == status.receipt.coverage_revision)
                    && self
                        .installed_refs(input.source.tenant_id, &previous.0)?
                        .as_ref()
                        == Some(&installed)
                {
                    self.acknowledge_window(
                        &execution,
                        previous,
                        &installed,
                        notice,
                        status.receipt.coverage_revision,
                    )?;
                    return Ok(Some(false));
                }
            }
        }
        let mut snapshot = match Self::derive_candidate(&input, &execution) {
            Ok(snapshot) => snapshot,
            Err(crate::Error::Data {
                source:
                    araphor_data::Error::GraphInvalid {
                        field: "graph output bytes",
                        ..
                    },
            }) => return Ok(None),
            Err(error) => return Err(error),
        };
        snapshot.first_cursor = first;
        snapshot.input_positions = positions;
        snapshot.context_notice_revision = notice;
        snapshot.witness_deadline_utc_ns = deadline;
        let installed = Self::analysis_refs(&execution, &snapshot)?;
        let unchanged = match previous {
            Some((id, previous, _))
                if previous.input_manifest == snapshot.input_manifest
                    && previous.graph == snapshot.graph
                    && previous.findings == snapshot.findings
                    && previous.packages == snapshot.packages =>
            {
                self.installed_refs(input.source.tenant_id, id)?.as_ref() == Some(&installed)
            }
            _ => false,
        };
        if let Some(previous) = previous.filter(|_| unchanged) {
            self.acknowledge_window(
                &execution,
                previous,
                &installed,
                notice,
                status.receipt.coverage_revision,
            )?;
            return Ok(Some(false));
        }
        snapshot.previous_result_id = previous.as_ref().map(|row| row.0.clone());
        let prepared = match araphor_data::analysis::CanonicalGraph::bounded(
            snapshot,
            GRAPH_WINDOW_BYTES.min(crate::analysis::MAX_RESULT_BYTES),
        ) {
            Ok(prepared) => prepared,
            Err(araphor_data::Error::GraphInvalid {
                field: "graph output bytes",
                ..
            }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        execution.authorize(
            input.source.tenant_id,
            &Self::package_revisions(&installed),
            || {
                self.commit_snapshot(
                    prepared,
                    &input.facts,
                    status,
                    consumed,
                    run.advance,
                    now,
                    &installed,
                )
            },
        )?;
        Ok(Some(true))
    }

    fn acknowledge_window(
        &self,
        execution: &crate::InstalledAnalysis,
        previous: &WindowHead,
        installed: &[crate::InstalledRefV1],
        notice: u64,
        coverage: u64,
    ) -> Result<()> {
        execution.authorize(
            previous.1.scope.identity.tenant_id,
            &Self::package_revisions(installed),
            || {
                self.store.mark_graph_notice(
                    &previous.1.scope,
                    &previous.0,
                    previous.2,
                    notice,
                    coverage,
                )
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_snapshot(
        &self,
        prepared: araphor_data::analysis::CanonicalGraph,
        facts: &[AnalysisContextVersionV1],
        status: &AnalysisSourceStatusV1,
        consumed: u64,
        advance: bool,
        now: u64,
        installed: &[crate::InstalledRefV1],
    ) -> araphor_data::Result<()> {
        let snapshot = prepared.snapshot();
        let result_id = format!("graph:{}", uuid::Uuid::new_v4());
        let mut references = self.commit_contexts(facts)?;
        references.push(self.package_context(snapshot, &result_id, installed)?);
        references.sort_by(|left, right| left.key.cmp(&right.key));
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
            result_id,
            body: Vec::new(),
            created_utc_ns: now,
            witnesses,
            context_refs: references,
        };
        self.store
            .commit_graph_snapshot(commit, prepared, advance)
            .map(|_| ())
    }

    pub(super) fn commit_contexts(
        &self,
        facts: &[AnalysisContextVersionV1],
    ) -> araphor_data::Result<Vec<AnalysisContextRefV1>> {
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
