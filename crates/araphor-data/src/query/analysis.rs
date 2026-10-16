use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{InputProjection, InputRelations, QueryLease, QueryOwner};
use crate::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisStoreMetaV1, GraphTraversalReceiptV1,
    GraphTraversalV1, Result,
};

mod projection;
mod schema;
#[cfg(test)]
mod tests;

use projection::GraphProjection;
use schema::GraphTable;
pub(super) use schema::MANIFEST;

#[derive(Debug)]
pub struct GraphAnalysisInputsV1 {
    inputs: Vec<sdk::Input>,
    pub meta: AnalysisStoreMetaV1,
    pub traversal: GraphTraversalReceiptV1,
    _lease: QueryLease,
}

impl GraphAnalysisInputsV1 {
    /// Each Arrow buffer retains its resource lease.
    pub fn inputs(&self) -> &[sdk::Input] {
        &self.inputs
    }
}

impl QueryOwner {
    /// Read SDK inputs for a trusted owner. The caller supplies the authorized scope.
    pub fn graph_inputs(
        &self,
        selection: &AnalysisSelectionV1,
        request: &GraphTraversalV1,
        control: &AnalysisReadControl,
    ) -> Result<GraphAnalysisInputsV1> {
        let control = control.within(self.limits.extract_timeout)?;
        let selection = GraphProjection::selection(selection, request)?;
        let lease = self.budget.evaluate(selection.tenant_id)?;
        let mut coverage = sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        };
        let bounds = crate::analysis::AnalysisExtractLimits {
            scan_bytes: self.limits.scan_bytes,
            input_bytes: self.limits.input_bytes,
            ..Default::default()
        };
        let (mut page, projection) = self.store.metadata_rows(
            &selection,
            bounds,
            &control,
            GraphProjection {
                rows: InputProjection::graph(&selection),
                coverage: &mut coverage,
                max_hops: request.max_hops,
            },
        )?;
        let mut input = projection.rows.finish(&mut page.extraction, &control)?;
        let mut extraction = page.extraction;
        let traversal = extraction.graph_traversal.take().ok_or_else(|| {
            crate::QueryInvalidSnafu {
                field: "graph input traversal receipt",
            }
            .build()
        })?;
        if traversal.result_ids.is_empty() {
            coverage.state = sdk::CoverageState::Unknown;
            coverage.limits.push("NO_SELECTED_GRAPH_VERSION".into());
        }
        if traversal.hop_boundary {
            if coverage.state != sdk::CoverageState::Gapped {
                coverage.state = sdk::CoverageState::Unknown;
            }
            coverage.limits.push("GRAPH_HOP_BOUNDARY".into());
        }
        coverage.limits.sort();
        coverage.limits.dedup();
        let revision = Self::graph_revision(&extraction.meta, &selection, request)?;
        input.set_boundary(traversal.hop_boundary, &mut extraction.sink(&control))?;
        let counts = GraphTable::ALL.map(|table| {
            input
                .tables
                .get(table.source())
                .map_or(1, |table| table.batches.len())
        });
        extraction
            .sink(&control)
            .charge(GraphTable::input_bytes(&revision, &coverage, counts))?;
        let mut inputs = GraphTable::inputs(&revision, &coverage, counts);
        for table in GraphTable::ALL {
            let mut batches = input
                .tables
                .remove(table.source())
                .ok_or_else(|| {
                    crate::QueryInvalidSnafu {
                        field: "graph input relation",
                    }
                    .build()
                })?
                .batches;
            for batch in &mut batches {
                control.check()?;
                *batch = lease.retain_batch(batch)?;
            }
            inputs[table.index()].data.batches = batches;
        }
        control.check()?;
        Ok(GraphAnalysisInputsV1 {
            inputs,
            meta: extraction.meta,
            traversal,
            _lease: lease,
        })
    }

    fn graph_revision(
        meta: &AnalysisStoreMetaV1,
        selection: &AnalysisSelectionV1,
        request: &GraphTraversalV1,
    ) -> Result<sdk::Revision> {
        let id = crate::digest::InputRevision::of(&(
            meta.store_uuid.as_bytes(),
            meta.recovery_epoch,
            meta.commit_revision,
            request,
            selection.tenant_id,
            selection.sources.is_all(),
            selection.sources.as_slice(),
            &selection.nodes,
            &selection.binding_ids,
            &selection.received_from,
            &selection.received_until,
            &selection.graphs,
        ))
        .context(crate::QueryEncodingSnafu)?;
        Ok(sdk::Revision {
            owner: "araphor-data.GraphAndFindingOwner".into(),
            id,
            window: None,
        })
    }
}
