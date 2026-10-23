use datafusion::arrow::array::{BinaryArray, UInt64Array};
use datafusion::execution::TaskContext;

use super::{AnalysisReadControl, AnalysisResultCommitV1, ExecutionReceipt, GraphConversion};
use crate::{graph::native::Projection, Graph};
use araphor_analysis_sdk as sdk;

impl GraphConversion {
    pub(crate) fn expiry(
        session: &araphor_query::execution::Session,
        context: &TaskContext,
        receipt: &ExecutionReceipt,
        batches: &[sdk::RecordBatch],
        control: &AnalysisReadControl,
    ) -> araphor_query::Result<Option<GraphConversion>> {
        let convert = || -> datafusion::common::Result<Option<GraphConversion>> {
            control.check().map_err(Projection::external)?;
            if !receipt.calls().is_empty() {
                return Err(Projection::invalid("graph expiry invoked a package"));
            }
            let source = context
                .session_config()
                .get_extension::<araphor_query::sources::SourceSnapshot>()
                .ok_or_else(|| Projection::invalid("graph expiry source"))?;
            let now = source.time_utc_ns();
            let memory = session.memory().reserve_input(0)?;
            let mut candidate = None;
            let mut complete = true;
            for batch in batches {
                for row in 0..batch.num_rows() {
                    control.check().map_err(Projection::external)?;
                    let bytes = Projection::column::<BinaryArray>(batch, "snapshot")?
                        .value(row)
                        .len()
                        .checked_mul(2)
                        .ok_or_else(|| Projection::invalid("graph expiry decoded bytes"))?;
                    let decoded = memory.new_empty();
                    decoded.try_grow(bytes)?;
                    let previous: araphor_data::GraphSnapshotV1 =
                        Projection::json(batch, "snapshot", row)?;
                    let (_, floor, _) =
                        Projection::progress(&[batch.slice(row, 1)], &previous.scope.identity)?;
                    if previous.witness_deadline_utc_ns > now && previous.first_cursor > floor {
                        continue;
                    }
                    if previous.retained_input_expired() {
                        continue;
                    }
                    if candidate.is_some() {
                        complete = false;
                        break;
                    }
                    candidate = Some((batch.clone(), row, previous, decoded));
                }
                if !complete {
                    break;
                }
            }
            let Some((batch, row, previous, memory)) = candidate else {
                return Ok(None);
            };
            let previous_id =
                Projection::column::<sdk::arrow_array::StringArray>(&batch, "graph_result_id")?
                    .value(row);
            let revision = Projection::column::<UInt64Array>(&batch, "commit_revision")?.value(row);
            if !receipt
                .snapshot()
                .results()
                .any(|result| result.result_id == previous_id && result.commit_revision == revision)
            {
                return Err(Projection::invalid("graph expiry captured head"));
            }
            let mut contexts: Vec<araphor_data::AnalysisContextRefV1> =
                Projection::json(&batch, "context_refs", row)?;
            contexts.sort_by(|left, right| left.key.cmp(&right.key));
            if contexts
                .windows(2)
                .any(|pair| pair[0].key == pair[1].key && pair[0] != pair[1])
            {
                return Err(Projection::invalid("graph expiry context identity"));
            }
            contexts.dedup();
            let (consumed, _, _) =
                Projection::progress(&[batch.slice(row, 1)], &previous.scope.identity)?;
            let coverage =
                Projection::column::<UInt64Array>(&batch, "coverage_revision")?.value(row);
            let bytes = Projection::column::<BinaryArray>(&batch, "snapshot")?
                .value(row)
                .len()
                .checked_mul(3)
                .ok_or_else(|| Projection::invalid("graph expiry output bytes"))?;
            memory.try_grow(bytes)?;
            let snapshot = Graph::expire(&previous, previous_id, previous.context_notice_revision)
                .map_err(Projection::external)?;
            let deadline = snapshot.witness_deadline_utc_ns;
            let commit = AnalysisResultCommitV1 {
                scope: snapshot.scope.clone(),
                expected_cursor: consumed,
                consumed_cursor: consumed,
                coverage_revision: coverage,
                context_revision: 0,
                result_id: format!("graph:{}", uuid::Uuid::new_v4()),
                body: Vec::new(),
                created_utc_ns: now,
                witnesses: Vec::new(),
                context_refs: Vec::new(),
            };
            let graph = araphor_data::analysis::CanonicalGraph::bounded(
                snapshot,
                session.engine().limits().output_bytes,
            )
            .map_err(Projection::external)?;
            let sources = receipt
                .snapshot()
                .selection
                .source_revisions(receipt.snapshot().page.extraction.meta.commit_revision);
            Ok(Some(GraphConversion {
                packet: araphor_data::analysis::GraphCommit {
                    request: commit,
                    graph,
                    contexts: Vec::new(),
                    proofs: contexts,
                    sources,
                    advance: false,
                },
                previous: Some((previous_id.to_owned(), revision)),
                completed: complete,
                deadline,
                _memory: Some(memory),
            }))
        };
        convert().map_err(|source| araphor_query::Error::Sql { source })
    }
}
