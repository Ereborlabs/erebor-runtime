use std::sync::{Arc, Weak};

use araphor_data::{
    analysis::GraphCommit, AnalysisReadControl, AnalysisResultCommitV1, PackageErrorCodeV1 as Code,
};
use araphor_query::definition::ExecutionReceipt;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;

use super::{GraphPublication, GraphRun, Projection};

pub(crate) struct GraphConversion {
    pub(crate) packet: GraphCommit,
    pub(crate) completed: bool,
    pub(crate) deadline: u64,
    pub(crate) expired: bool,
    _memory: Vec<MemoryReservation>,
}

impl GraphPublication {
    pub(crate) fn convert_graph(
        &self,
        context: &TaskContext,
        receipt: &ExecutionReceipt,
        result_id: String,
        control: &AnalysisReadControl,
    ) -> araphor_query::Result<GraphConversion> {
        control.check()?;
        let run = GraphRun::from_context(context, &self.projection)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let captured = run
            .captured
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or_else(|| Code::Incomplete.error("source input capture"))?;
        let source = context
            .session_config()
            .get_extension::<araphor_query::sources::SourceSnapshot>()
            .ok_or_else(|| Code::Invalid.error("captured source"))?;
        if !Weak::ptr_eq(&captured.source, &Arc::downgrade(&source)) {
            return Err(Code::Invalid.error("returned source capture").into());
        }
        for (id, returned) in receipt.calls() {
            if self
                .calls
                .get(id)
                .is_none_or(|call| !returned.belongs_to(call))
            {
                return Err(Code::Invalid.error("returned call identity").into());
            }
        }
        let selection = source
            .with_capture(|_, capture, reference| {
                if reference.is_some() {
                    return Err(Code::Denied.error("historical source publication"));
                }
                capture
                    .source()
                    .ok_or_else(|| Code::Missing.error("source input frame"))?
                    .input_selection()?
                    .ok_or_else(|| Code::Incomplete.error("source input selection"))
            })
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let (consumed, _, accepted, coverage) = captured
            .progress
            .ok_or_else(|| Code::Invalid.error("source publication progress"))?;
        let deadline = captured.metadata.witness_deadline_utc_ns;
        let last = captured.metadata.last_cursor;
        if !selection.expired() {
            Projection::check_deadline(deadline)?;
        }
        let packet = GraphCommit {
            input_proof: selection.prefix().cloned(),
            request: AnalysisResultCommitV1 {
                scope: captured.metadata.scope.clone(),
                expected_cursor: consumed,
                consumed_cursor: last.max(consumed),
                coverage_revision: coverage,
                context_revision: 0,
                result_id,
                body: Vec::new(),
                created_utc_ns: source.time_utc_ns(),
                witnesses: Vec::new(),
                context_refs: Vec::new(),
            },
            metadata: captured.metadata,
            contexts: Vec::new(),
            proofs: Vec::new(),
            record_proofs: Vec::new(),
            removed: Vec::new(),
            sources: Vec::new(),
            advance: last > consumed,
            expire: false,
        };
        Ok(GraphConversion {
            packet,
            completed: last >= accepted,
            deadline,
            expired: selection.expired(),
            _memory: captured._memory,
        })
    }
}

impl GraphConversion {
    pub(crate) fn check_deadline(deadline: u64) -> araphor_data::Result<()> {
        Projection::check_deadline(deadline)
    }
}
