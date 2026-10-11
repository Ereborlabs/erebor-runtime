use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{InputProjection, InputRow, QueryLease, QueryOwner};
use crate::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisStoreMetaV1, GraphTraversalReceiptV1,
    GraphTraversalV1, Result,
};

mod projection;
mod rows;
mod schema;
#[cfg(test)]
mod tests;

use projection::GraphProjection;
use rows::ArrowRows;
use schema::GraphTable;

#[derive(Debug)]
pub struct GraphAnalysisInputsV1 {
    inputs: Vec<sdk::Input>,
    pub meta: AnalysisStoreMetaV1,
    pub traversal: GraphTraversalReceiptV1,
    _lease: QueryLease,
}

impl GraphAnalysisInputsV1 {
    /// Keep this owner alive while an evaluation uses its Arrow buffers.
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
        let page = self.store.metadata_rows(
            &selection,
            bounds,
            &control,
            GraphProjection {
                rows: InputProjection::graph(&selection),
                coverage: &mut coverage,
                max_hops: request.max_hops,
            },
        )?;
        let extraction = page.extraction;
        let traversal = extraction.graph_traversal.ok_or_else(|| {
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
        let mut batches = [0_usize; 3];
        for page in &extraction.pages {
            batches[GraphTable::try_from(page.relation)?.index()] += 1;
        }
        let batches = batches.map(|count| count.max(1));
        let held = extraction
            .input_bytes
            .saturating_add(GraphTable::input_bytes(&revision, &coverage, batches));
        let mut encoder = ArrowRows::new(held, self.limits.input_bytes, &control)?;
        let mut inputs = GraphTable::inputs(&revision, &coverage, batches);
        for mut page in extraction.pages {
            control.check()?;
            let table = GraphTable::try_from(page.relation)?;
            if table == GraphTable::Manifest {
                for row in &mut page.rows {
                    let boundary = row.0.last_mut().ok_or_else(|| {
                        crate::QueryInvalidSnafu {
                            field: "graph manifest boundary",
                        }
                        .build()
                    })?;
                    *boundary = duckdb::types::Value::Boolean(traversal.hop_boundary);
                }
            }
            let batch = encoder.batch(table, &page.rows)?;
            inputs[table.index()].data.batches.push(batch);
        }
        for table in GraphTable::ALL {
            let batches = &mut inputs[table.index()].data.batches;
            if batches.is_empty() {
                batches.push(encoder.batch(table, &[])?);
            }
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
