use std::collections::BTreeMap;

use super::*;
use crate::analysis::graph::traversal::read::GraphWalk;
use crate::{GraphTraversalReceiptV1, GraphTraversalV1};

mod versions;

impl AnalysisStore {
    pub(in crate::analysis::extraction) fn traverse_graphs(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        request: &GraphTraversalV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
        capture: &mut super::super::tables::Capture<'_>,
    ) -> Result<()> {
        let (ids, versions) = self.traversal_versions(snapshot, selection, output, control)?;
        for (id, version) in ids.iter().zip(&versions) {
            output.reference_result(id, version.revision, AnalysisReferenceOriginV1::Graph)?;
        }
        let mut walk = GraphWalk::new(
            snapshot,
            control,
            request,
            &ids,
            !selection.binding_ids.is_empty(),
        )
        .run()?;
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
        for (id, version) in ids.iter().zip(versions) {
            control.check()?;
            let selected = GraphRows::selected_subjects(
                snapshot,
                id,
                &keys,
                control,
                !selection.binding_ids.is_empty(),
            )?;
            if selected.is_empty() && !edges.contains_key(id) && !capture.graph_headers() {
                continue;
            }
            let header = version.header;
            let mut graph = header.snapshot;
            let (selected, subject_ids): (Vec<_>, Vec<_>) = selected.into_iter().unzip();
            if subject_ids.windows(2).any(|pair| pair[0] >= pair[1])
                || subject_ids
                    .iter()
                    .any(|id| *id as usize >= header.subject_count)
            {
                return self.reject("the traversal subject ordinals are invalid");
            }
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
                for edge in &mut graph.graph.edges {
                    for endpoint in [&mut edge.key.from, &mut edge.key.to] {
                        *endpoint = subject_ids
                            .binary_search(endpoint)
                            .ok()
                            .and_then(|index| u32::try_from(index).ok())
                            .ok_or_else(|| {
                                self.state_error("the traversal edge subject is absent")
                            })?;
                    }
                }
            }
            graph.validate()?;
            capture.graph(
                id,
                &graph,
                graph.graph.subjects.len(),
                graph.graph.edges.len(),
                version.revision,
                version.sensitivity,
                Some(&walk.subjects),
                Some(&subject_ids),
                &[],
                header.notice,
                header.expired,
                &mut output.sink(control),
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
