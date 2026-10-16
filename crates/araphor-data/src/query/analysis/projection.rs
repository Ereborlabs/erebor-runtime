use araphor_analysis_sdk as sdk;

use super::*;
use crate::analysis::{AnalysisProjection, ProjectionSink};
use crate::{AnalysisInputV1, DiscoveryCoverageStateV1};

pub(super) struct GraphProjection<'a> {
    pub(super) rows: InputProjection<'a>,
    pub(super) coverage: &'a mut sdk::Coverage,
    pub(super) max_hops: u32,
}

impl GraphProjection<'_> {
    pub(super) fn selection(
        selection: &AnalysisSelectionV1,
        request: &GraphTraversalV1,
    ) -> Result<AnalysisSelectionV1> {
        request.validate()?;
        if !selection.valid()
            || request
                .seeds
                .iter()
                .any(|seed| seed.tenant_id != selection.tenant_id)
        {
            return crate::QueryDeniedSnafu.fail();
        }
        let mut selected = selection.clone();
        if !selected.results.is_empty() {
            if !selected.graphs.is_empty()
                && selected
                    .results
                    .iter()
                    .any(|id| !selected.graphs.contains(id))
            {
                return crate::QueryDeniedSnafu.fail();
            }
            selected.graphs = std::mem::take(&mut selected.results);
        }
        if !request.result_ids.is_empty() {
            if selected.graphs.is_empty()
                || request
                    .result_ids
                    .iter()
                    .any(|id| !selected.graphs.contains(id))
            {
                return crate::QueryDeniedSnafu.fail();
            }
            selected.graphs = request.result_ids.clone();
        }
        selected.graph = selected.graphs.is_empty();
        selected.graph_traversal = Some(request.clone());
        Ok(selected)
    }

    fn coverage(
        &mut self,
        graph: &crate::GraphSnapshotV1,
        sink: &mut ProjectionSink<'_, ()>,
    ) -> Result<()> {
        if graph.input_manifest.coverage.is_empty()
            && self.coverage.state != sdk::CoverageState::Gapped
        {
            self.coverage.state = sdk::CoverageState::Unknown;
        }
        for range in &graph.input_manifest.coverage {
            match range.state {
                DiscoveryCoverageStateV1::Gapped => {
                    self.coverage.state = sdk::CoverageState::Gapped
                }
                DiscoveryCoverageStateV1::Unknown
                    if self.coverage.state != sdk::CoverageState::Gapped =>
                {
                    self.coverage.state = sdk::CoverageState::Unknown;
                }
                _ => {}
            }
            for reason in &range.gap_reasons {
                self.limit(reason, sink)?;
            }
        }
        if !graph.missing_ranges.is_empty() {
            self.coverage.state = sdk::CoverageState::Gapped;
            self.limit("GRAPH_INPUT_GAPS", sink)?;
        }
        Ok(())
    }

    fn limit(&mut self, reason: &str, sink: &mut ProjectionSink<'_, ()>) -> Result<()> {
        if !self.coverage.limits.iter().any(|limit| limit == reason) {
            sink.charge(reason.len())?;
            sink.grow(&mut self.coverage.limits)?;
            self.coverage.limits.push(reason.into());
        }
        Ok(())
    }
}

impl AnalysisProjection for GraphProjection<'_> {
    type Row = ();

    fn graph_headers(&self) -> bool {
        true
    }

    fn project(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut ProjectionSink<'_, ()>,
    ) -> Result<bool> {
        let AnalysisInputV1::Graph {
            result_id,
            graph,
            commit_revision,
            sensitivity,
            ..
        } = &input
        else {
            return Ok(true);
        };
        sink.check()?;
        if !self.rows.selection.permits_graph(graph) {
            return crate::QueryDeniedSnafu.fail();
        }
        self.coverage(graph, sink)?;
        let mut cache = (None, None);
        let (source, manifest) =
            InputRelations::graph_prefix(&mut cache, graph, None, false, sink)?;
        self.rows.inputs.manifest(
            sink,
            None,
            (
                graph,
                result_id,
                *commit_revision,
                *sensitivity,
                source,
                manifest,
                self.max_hops,
                false,
            ),
        )?;
        self.rows.graph_rows(&input, &mut cache, sink)
    }
}
