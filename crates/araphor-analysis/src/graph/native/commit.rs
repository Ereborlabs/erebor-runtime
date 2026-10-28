use std::collections::BTreeSet;
use std::sync::{Arc, Weak};

use araphor_data::{
    AnalysisReadControl, AnalysisResultCommitV1, AnalysisWitnessV1, PackageErrorCodeV1 as Code,
    ProcessorScopeV1, GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION, GRAPH_WITNESS_TTL_NS,
};
use araphor_query::definition::ExecutionReceipt;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;

use super::{GraphPublication, GraphRun};
use crate::Graph;

mod expiry;

pub(crate) struct GraphConversion {
    pub(crate) packet: araphor_data::analysis::GraphCommit,
    pub(crate) completed: bool,
    pub(crate) deadline: u64,
    _memory: Option<MemoryReservation>,
}

impl GraphConversion {
    pub(crate) fn check_deadline(deadline: u64) -> araphor_data::Result<()> {
        super::Projection::check_deadline(deadline)
    }
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
        let owner = self;
        let run = GraphRun::from_context(context, &self.projection)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let captured = run
            .captured
            .get()
            .ok_or_else(|| Code::Incomplete.error("graph input capture"))?
            .clone()
            .map_err(|source| araphor_query::Error::Sql {
                source: datafusion::common::DataFusionError::Shared(source),
            })?;
        let source = context
            .session_config()
            .get_extension::<araphor_query::sources::SourceSnapshot>()
            .ok_or_else(|| Code::Invalid.error("graph captured source"))?;
        if !Weak::ptr_eq(&captured.source, &Arc::downgrade(&source)) {
            return Err(Code::Invalid.error("graph returned source capture").into());
        }
        for (id, returned) in receipt.calls() {
            if self
                .calls
                .get(id)
                .is_none_or(|call| !returned.belongs_to(call))
            {
                return Err(Code::Invalid.error("graph returned call identity").into());
            }
        }
        let calls = receipt.calls();
        let sources = receipt
            .snapshot()
            .selection
            .source_revisions(receipt.snapshot().page.extraction.meta.commit_revision);
        let mut graph = captured
            .graph
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or_else(|| Code::Invalid.error("graph publication was consumed"))?;
        let source = graph.input.source.clone();
        let mut contexts = graph.input.facts.clone();
        let mut actual = calls
            .iter()
            .filter_map(|(id, returned)| {
                let call = &owner.calls[id];
                call.descriptor()
                    .exports
                    .iter()
                    .find(|model| model.name == call.export())
                    .is_some_and(Graph::supports)
                    .then_some((call, returned))
            })
            .collect::<Vec<_>>();
        for id in araphor_data::FindingV1::PACKAGES {
            if actual
                .iter()
                .filter(|(call, _)| call.package().package_id == id)
                .count()
                != 1
            {
                return Err(Code::Invalid.error("required graph detector return").into());
            }
        }
        actual.sort_by_key(|(call, _)| {
            let package = &call.package().package_id;
            (
                araphor_data::FindingV1::PACKAGES
                    .iter()
                    .position(|id| *id == package.as_str())
                    .unwrap_or(3),
                package.clone(),
            )
        });
        for (call, returned) in actual {
            for input in &returned.evaluation().inputs {
                let expected = captured
                    .inputs
                    .iter()
                    .find(|expected| expected.data.name == input.data.name)
                    .ok_or_else(|| Code::Invalid.error("graph qualified input"))?;
                if input.revision != expected.revision || input.coverage != expected.coverage {
                    return Err(Code::Invalid.error("graph qualified input").into());
                }
            }
            graph = graph.apply(call, returned)?;
        }
        for id in calls.keys() {
            let call = &owner.calls[id];
            let bundle = owner
                .prepared
                .images()
                .find(|bundle| {
                    bundle.bundle().root == call.image().image
                        && bundle.digest() == call.image().digest.as_str()
                })
                .ok_or_else(|| Code::Denied.error("graph image attribution"))?;
            contexts.push(araphor_data::AnalysisContextVersionV1::from_package(
                bundle,
                owner.projection.tenant,
                call.package(),
                call.export(),
                call.output(),
            )?);
        }
        contexts.sort_by(|left, right| left.key.cmp(&right.key));
        if contexts
            .windows(2)
            .any(|pair| pair[0].key == pair[1].key && pair[0] != pair[1])
        {
            return Err(Code::Conflict.error("graph context identity").into());
        }
        contexts.dedup();
        let mut proofs = captured.proofs.clone();
        proofs.sort_by(|left, right| left.key.cmp(&right.key));
        proofs.dedup();
        let memory = graph._memory.take();
        let mut snapshot = graph.finish()?;
        let previous = captured
            .heads
            .iter()
            .find(|head| head.first == snapshot.first_cursor);
        snapshot.previous_result_id = previous.map(|head| head.id.clone());
        snapshot.input_positions = captured.positions.clone();
        snapshot.context_notice_revision = proofs
            .iter()
            .map(|reference| reference.commit_revision)
            .max()
            .unwrap_or(0);
        snapshot.witness_deadline_utc_ns = captured
            .heads
            .iter()
            .map(|head| head.deadline)
            .min()
            .map(Ok)
            .unwrap_or_else(|| {
                captured
                    .now
                    .checked_add(GRAPH_WITNESS_TTL_NS)
                    .ok_or_else(|| Code::Invalid.error("graph witness deadline"))
            })?;
        let deadline = snapshot.witness_deadline_utc_ns;
        let witnesses = snapshot
            .input_manifest
            .evidence
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|id| AnalysisWitnessV1 {
                identity: id.stream.into(),
                cursor: id.durable_cursor,
                expires_utc_ns: deadline,
            })
            .collect();
        let scope = ProcessorScopeV1 {
            processor_id: GRAPH_PROCESSOR.into(),
            method_version: u64::from(GRAPH_SCHEMA_VERSION),
            identity: source,
        };
        let advanced = snapshot.last_cursor > captured.consumed;
        let completed = !owner.feedback && snapshot.last_cursor >= captured.accepted;
        let commit = AnalysisResultCommitV1 {
            scope,
            expected_cursor: captured.consumed,
            consumed_cursor: if advanced {
                snapshot.last_cursor
            } else {
                captured.consumed
            },
            coverage_revision: captured.coverage_revision,
            context_revision: 0,
            result_id: result_id.clone(),
            body: Vec::new(),
            created_utc_ns: captured.now,
            witnesses,
            context_refs: Vec::new(),
        };
        let prepared = araphor_data::analysis::CanonicalGraph::new(snapshot)?;
        Ok(GraphConversion {
            packet: araphor_data::analysis::GraphCommit {
                request: commit,
                graph: prepared,
                contexts,
                proofs,
                sources,
                advance: advanced,
            },
            completed,
            deadline,
            _memory: memory,
        })
    }
}
