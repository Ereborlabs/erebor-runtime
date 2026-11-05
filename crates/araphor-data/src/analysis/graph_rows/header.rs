pub(in crate::analysis) use crate::analysis::graph_rows::store::GraphHeader;

use super::*;

impl GraphRows {
    #[cfg(test)]
    pub(in crate::analysis) fn encode(graph: &GraphSnapshotV1) -> Result<Vec<u8>> {
        graph.validate()?;
        GraphHeader::encode(
            &GraphManifest::from_snapshot(graph),
            (
                graph.graph.subjects.len(),
                graph.graph.edges.len(),
                graph.findings.len(),
                graph.graph.branches.len(),
            ),
            (
                graph.input_manifest.evidence.len(),
                graph.input_positions.len(),
                graph.graph.facts.len(),
            ),
        )
        .map_err(Into::into)
    }
}
