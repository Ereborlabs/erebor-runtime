use std::collections::BTreeSet;
use std::sync::{Arc, Weak};

use araphor_data::{
    analysis::{GraphCommit, GraphManifest},
    AnalysisReadControl, AnalysisResultCommitV1, AnalysisWitnessV1, PackageErrorCodeV1 as Code,
    ProcessorScopeV1, GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION, GRAPH_WITNESS_TTL_NS,
};
use araphor_query::definition::ExecutionReceipt;
use datafusion::arrow::array::{BinaryArray, StringArray, UInt64Array};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;

use super::{GraphPublication, GraphRun, Projection};
use crate::Graph;

pub(crate) struct GraphConversion {
    pub(crate) packet: GraphCommit,
    pub(crate) completed: bool,
    pub(crate) deadline: u64,
    _memory: Option<MemoryReservation>,
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
        let mut graph = captured
            .graph
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or_else(|| Code::Invalid.error("graph publication was consumed"))?;
        let mut actual = receipt
            .calls()
            .iter()
            .filter_map(|(id, result)| {
                let call = &self.calls[id];
                call.descriptor()
                    .exports
                    .iter()
                    .any(|model| model.name == call.export() && Graph::supports(model))
                    .then_some((call, result))
            })
            .collect::<Vec<_>>();
        for package in araphor_data::FindingV1::PACKAGES {
            if actual
                .iter()
                .filter(|(call, _)| call.package().package_id == package)
                .count()
                != 1
            {
                return Err(Code::Invalid.error("required graph detector return").into());
            }
        }
        actual.sort_by_key(|(call, _)| {
            (
                araphor_data::FindingV1::PACKAGES
                    .iter()
                    .position(|id| *id == call.package().package_id)
                    .unwrap_or(3),
                call.package().package_id.clone(),
            )
        });
        for (call, result) in actual {
            graph.check_call(call, result)?;
            for input in &result.evaluation().inputs {
                let expected = captured
                    .inputs
                    .iter()
                    .find(|value| value.data.name == input.data.name)
                    .ok_or_else(|| Code::Invalid.error("graph qualified input"))?;
                if input.revision != expected.revision || input.coverage != expected.coverage {
                    return Err(Code::Invalid.error("graph qualified input").into());
                }
            }
            let model = call
                .descriptor()
                .exports
                .iter()
                .find(|model| model.name == call.export())
                .ok_or_else(|| Code::Invalid.error("graph export contract"))?;
            graph.check_inputs(model, result.evaluation())?;
            if captured.recheck
                && !self.sparse.contains(&call.id())
                && !result.evaluation().previous_outputs.is_empty()
            {
                graph.apply_output(
                    call.descriptor(),
                    result.evaluation(),
                    result.output(),
                    result.retained().is_some(),
                    None,
                )?;
            } else {
                let checkpoint = graph.validate_output(
                    call.descriptor(),
                    result.evaluation(),
                    result.output(),
                    result.retained().is_some(),
                )?;
                graph.packages.push(checkpoint);
            }
        }
        let mut contexts = captured.contexts.clone();
        contexts.sort_by(|left, right| left.key.cmp(&right.key));
        if contexts
            .windows(2)
            .any(|pair| pair[0].key == pair[1].key && pair[0] != pair[1])
        {
            return Err(Code::Conflict.error("graph context identity").into());
        }
        contexts.dedup();
        let mut proofs = captured.proofs.clone();
        proofs.extend_from_slice(&captured.fact_refs);
        for id in receipt.calls().keys() {
            proofs.push(
                self.packages
                    .get(id)
                    .cloned()
                    .ok_or_else(|| Code::Denied.error("graph package attribution"))?,
            );
        }
        proofs.sort_by(|left, right| left.key.cmp(&right.key));
        if proofs
            .windows(2)
            .any(|pair| pair[0].key == pair[1].key && pair[0] != pair[1])
        {
            return Err(Code::Conflict.error("graph proof identity").into());
        }
        proofs.dedup();
        if graph.input.input_positions != captured.positions {
            return Err(Code::Invalid.error("graph captured positions").into());
        }
        let first = graph
            .input
            .records
            .iter()
            .map(|record| record.id.durable_cursor)
            .min()
            .ok_or_else(|| Code::Invalid.error("graph first record"))?;
        let last = graph
            .input
            .records
            .iter()
            .map(|record| record.id.durable_cursor)
            .max()
            .ok_or_else(|| Code::Invalid.error("graph last record"))?;
        let deadline = captured
            .heads
            .iter()
            .map(|head| head.deadline)
            .min()
            .or_else(|| captured.now.checked_add(GRAPH_WITNESS_TTL_NS))
            .ok_or_else(|| Code::Invalid.error("graph witness deadline"))?;
        let scope = ProcessorScopeV1 {
            processor_id: GRAPH_PROCESSOR.into(),
            method_version: u64::from(GRAPH_SCHEMA_VERSION),
            identity: graph.input.source.clone(),
        };
        let metadata = GraphManifest {
            schema_version: GRAPH_SCHEMA_VERSION,
            scope: scope.clone(),
            first_cursor: first,
            last_cursor: last,
            input_manifest: graph.revision,
            facts: graph.facts,
            packages: graph.packages,
            missing_ranges: graph.input.missing_ranges.clone(),
            input_positions: graph.input.input_positions.clone(),
            previous_result_id: captured
                .heads
                .iter()
                .find(|head| head.first == first)
                .map(|head| head.id.clone()),
            context_notice_revision: captured
                .proofs
                .iter()
                .map(|proof| proof.commit_revision)
                .max()
                .unwrap_or(0),
            witness_deadline_utc_ns: deadline,
        };
        let witnesses = metadata
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
        let advanced = last > captured.consumed;
        let request = AnalysisResultCommitV1 {
            scope,
            expected_cursor: captured.consumed,
            consumed_cursor: last.max(captured.consumed),
            coverage_revision: captured.coverage_revision,
            context_revision: 0,
            result_id,
            body: Vec::new(),
            created_utc_ns: captured.now,
            witnesses,
            context_refs: Vec::new(),
        };
        let sources = receipt
            .snapshot()
            .selection
            .source_revisions(receipt.snapshot().page.extraction.meta.commit_revision);
        Ok(GraphConversion {
            packet: GraphCommit {
                request,
                metadata,
                contexts,
                proofs,
                sources,
                advance: advanced,
                expire: false,
            },
            completed: !self.feedback && last >= captured.accepted,
            deadline,
            _memory: graph._memory.take(),
        })
    }
}

impl GraphConversion {
    pub(crate) fn check_deadline(deadline: u64) -> araphor_data::Result<()> {
        Projection::check_deadline(deadline)
    }

    pub(crate) fn expiry(
        context: &TaskContext,
        receipt: &ExecutionReceipt,
        batches: &[araphor_analysis_sdk::RecordBatch],
        control: &AnalysisReadControl,
    ) -> araphor_query::Result<Option<Self>> {
        let convert = || -> datafusion::common::Result<Option<Self>> {
            control.check().map_err(Projection::external)?;
            if !receipt.calls().is_empty() {
                return Err(Projection::invalid("graph expiry invoked a package"));
            }
            let source = context
                .session_config()
                .get_extension::<araphor_query::sources::SourceSnapshot>()
                .ok_or_else(|| Projection::invalid("graph expiry source"))?;
            let mut candidate = None;
            let mut completed = true;
            for batch in batches {
                for row in 0..batch.num_rows() {
                    control.check().map_err(Projection::external)?;
                    let metadata = GraphManifest::decode(
                        Projection::column::<BinaryArray>(batch, "metadata")?.value(row),
                    )
                    .map_err(Projection::external)?;
                    let (consumed, floor, _) =
                        Projection::progress(&[batch.slice(row, 1)], &metadata.scope.identity)?;
                    if metadata.witness_deadline_utc_ns > source.time_utc_ns()
                        && metadata.first_cursor > floor
                    {
                        continue;
                    }
                    if candidate.is_some() {
                        completed = false;
                        break;
                    }
                    candidate = Some((batch, row, metadata, consumed));
                }
                if !completed {
                    break;
                }
            }
            let Some((batch, row, mut metadata, consumed)) = candidate else {
                return Ok(None);
            };
            let previous = Projection::column::<StringArray>(batch, "graph_result_id")?.value(row);
            let revision = Projection::column::<UInt64Array>(batch, "commit_revision")?.value(row);
            if !receipt
                .snapshot()
                .results()
                .any(|result| result.result_id == previous && result.commit_revision == revision)
            {
                return Err(Projection::invalid("graph expiry captured head"));
            }
            let mut proofs: Vec<araphor_data::AnalysisContextRefV1> =
                Projection::value(batch, "context_refs", row)?;
            proofs.sort_by(|left, right| left.key.cmp(&right.key));
            if proofs
                .windows(2)
                .any(|pair| pair[0].key == pair[1].key && pair[0] != pair[1])
            {
                return Err(Projection::invalid("graph expiry context identity"));
            }
            proofs.dedup();
            metadata.previous_result_id = Some(previous.into());
            metadata
                .missing_ranges
                .push((metadata.first_cursor, metadata.last_cursor));
            metadata.missing_ranges.sort();
            metadata.missing_ranges.dedup();
            metadata.input_manifest.missing_ranges = metadata.missing_ranges.clone();
            for package in &mut metadata.packages {
                package.state = araphor_data::GraphPackageStateV1::CoverageInsufficient;
            }
            let deadline = metadata.witness_deadline_utc_ns;
            let request = AnalysisResultCommitV1 {
                scope: metadata.scope.clone(),
                expected_cursor: consumed,
                consumed_cursor: consumed,
                coverage_revision: Projection::column::<UInt64Array>(batch, "coverage_revision")?
                    .value(row),
                context_revision: 0,
                result_id: format!("graph:{}", uuid::Uuid::new_v4()),
                body: Vec::new(),
                created_utc_ns: source.time_utc_ns(),
                witnesses: Vec::new(),
                context_refs: Vec::new(),
            };
            let sources = receipt
                .snapshot()
                .selection
                .source_revisions(receipt.snapshot().page.extraction.meta.commit_revision);
            Ok(Some(Self {
                packet: GraphCommit {
                    request,
                    metadata,
                    contexts: Vec::new(),
                    proofs,
                    sources,
                    advance: false,
                    expire: true,
                },
                completed,
                deadline,
                _memory: None,
            }))
        };
        convert().map_err(|source| araphor_query::Error::Sql { source })
    }
}
