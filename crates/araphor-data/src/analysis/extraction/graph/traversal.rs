use std::collections::BTreeMap;

use super::*;
use crate::analysis::graph::traversal::read::GraphWalk;
use crate::{GraphTraversalReceiptV1, GraphTraversalV1};

mod versions;

impl AnalysisStore {
    pub(in crate::analysis::extraction) fn traverse_graphs<T>(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        request: &GraphTraversalV1,
        output: &mut AnalysisExtractionV1<T>,
        control: &AnalysisReadControl,
        project: &mut impl AnalysisProjection<Row = T>,
    ) -> Result<()> {
        let (ids, versions) = self.traversal_versions(snapshot, selection, output, control)?;
        self.traversal_work(snapshot, &ids, output, control)?;
        let mut walk = GraphWalk::new(
            snapshot,
            control,
            request,
            &ids,
            output.limits.input_bytes.saturating_sub(output.input_bytes),
            !selection.binding_ids.is_empty(),
        )
        .run()?;
        output.charge(walk.bytes)?;
        walk.subjects.sort_by(|left, right| left.0.cmp(&right.0));
        let keys = walk
            .subjects
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let relationships = walk.edges.len();
        let mut edges: BTreeMap<String, Vec<u32>> = BTreeMap::new();
        for (id, ordinal) in walk.edges {
            edges.entry(id).or_default().push(ordinal);
        }
        let mut subjects = 0usize;
        for (id, version) in ids.iter().zip(&versions) {
            control.check()?;
            self.traversal_memory(output, version.buffer)?;
            let selected = GraphRows::selected_subjects(
                snapshot,
                id,
                &keys,
                control,
                !selection.binding_ids.is_empty(),
            )?;
            if selected.is_empty() && !edges.contains_key(id) && !project.graph_headers() {
                continue;
            }
            let header =
                self.traversal_header(snapshot, selection, id, version, output, control)?;
            let mut graph = header.snapshot;
            graph.graph.subjects = selected;
            subjects = subjects
                .checked_add(graph.graph.subjects.len())
                .ok_or_else(|| {
                    AnalysisInputTooLargeSnafu {
                        resource: "graph subject rows",
                    }
                    .build()
                })?;
            if subjects > request.max_subjects {
                return AnalysisInputTooLargeSnafu {
                    resource: "graph subject rows",
                }
                .fail();
            }
            if let Some(ordinals) = edges.remove(id) {
                graph.graph.edges = GraphRows::selected_edges(snapshot, id, &ordinals, control)?;
                if graph.graph.edges.len() != ordinals.len() {
                    return self.reject("the selected traversal relationships are absent");
                }
            }
            graph.validate()?;
            let remaining = output
                .limits
                .scan_bytes
                .saturating_sub(output.scanned_bytes);
            let mut budget = crate::discovery::InputByteLimit(remaining);
            serde_json::to_writer(&mut budget, &(&graph.graph.subjects, &graph.graph.edges))
                .map_err(|_| {
                    AnalysisInputTooLargeSnafu {
                        resource: "graph selected payload bytes",
                    }
                    .build()
                })?;
            output.scan(remaining - budget.0)?;
            output.project(
                project,
                AnalysisInputV1::Graph {
                    result_id: id,
                    graph: &graph,
                    commit_revision: version.revision,
                    sensitivity: version.sensitivity,
                    traversal_depths: Some(&walk.subjects),
                },
                control,
                None,
            )?;
        }
        if !edges.is_empty() {
            return self.reject("the traversal includes an unselected graph version");
        }
        output.graph_traversal = Some(GraphTraversalReceiptV1 {
            result_ids: ids,
            unique_subject_count: walk.subjects.len(),
            versioned_subject_count: subjects,
            relationship_count: relationships,
            max_hops: request.max_hops,
            hop_boundary: walk.hop_boundary,
        });
        Ok(())
    }
}
