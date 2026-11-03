use std::collections::BTreeSet;
use std::sync::{Arc, Weak};

use araphor_data::{
    analysis::{GraphCommit, GraphManifest},
    AnalysisReadControl, AnalysisResultCommitV1, AnalysisWitnessV1, PackageErrorCodeV1 as Code,
    GRAPH_SCHEMA_VERSION,
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
        let started = std::time::Instant::now();
        control.check()?;
        let run = GraphRun::from_context(context, &self.projection)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let mut captured = run
            .captured
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or_else(|| Code::Incomplete.error("graph input capture"))?;
        let source = context
            .session_config()
            .get_extension::<araphor_query::sources::SourceSnapshot>()
            .ok_or_else(|| Code::Invalid.error("graph captured source"))?;
        if !Weak::ptr_eq(&captured.source, &Arc::downgrade(&source)) {
            return Err(Code::Invalid.error("graph returned source capture").into());
        }
        let (consumed, _, accepted, coverage_revision) = captured
            .progress
            .ok_or_else(|| Code::Invalid.error("graph publication progress"))?;
        let restricted = captured
            .restricted
            .ok_or_else(|| Code::Invalid.error("graph publication restriction"))?;
        for (id, returned) in receipt.calls() {
            if self
                .calls
                .get(id)
                .is_none_or(|call| !returned.belongs_to(call))
            {
                return Err(Code::Invalid.error("graph returned call identity").into());
            }
        }
        let memory = source
            .memory()
            .prepare_input(source.extraction_limits().input_bytes)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let (input, references) = captured.take_input();
        let mut graph = Graph::from_parts(input, restricted != 0)?;
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
            let model = call
                .descriptor()
                .exports
                .iter()
                .find(|model| model.name == call.export())
                .ok_or_else(|| Code::Invalid.error("graph export contract"))?;
            graph.check_inputs(model, result.evaluation())?;
            graph.check_targets(model, result)?;
            let checkpoint =
                graph.validate_output(call.descriptor(), result.evaluation(), result.output())?;
            graph.packages.push(checkpoint);
        }
        let mut proofs = receipt
            .calls()
            .keys()
            .map(|id| {
                self.packages
                    .get(id)
                    .cloned()
                    .ok_or_else(|| Code::Denied.error("graph package attribution"))
            })
            .collect::<araphor_data::Result<Vec<_>>>()?;
        proofs.sort_by(|left, right| left.key.cmp(&right.key));
        if proofs
            .windows(2)
            .any(|pair| pair[0].key == pair[1].key && pair[0] != pair[1])
        {
            return Err(Code::Conflict.error("graph proof identity").into());
        }
        proofs.dedup();
        let deadline = captured.metadata.witness_deadline_utc_ns;
        let first = captured.metadata.first_cursor;
        let last = captured.metadata.last_cursor;
        Projection::check_deadline(deadline)?;
        let mut coverage = captured
            .metadata
            .input_manifest
            .coverage
            .into_iter()
            .collect::<BTreeSet<_>>();
        coverage.extend(std::mem::take(&mut graph.revision.coverage));
        graph.revision.coverage = coverage.into_iter().collect();
        let bytes = graph
            .preparation_bytes()
            .ok_or_else(|| Code::Limit.error("Graph preparation memory"))?;
        let mut input = graph.input.into_owned();
        let contexts = std::mem::take(&mut input.facts)
            .into_iter()
            .filter(|value| !references.contains_key(&value.key))
            .collect();
        let mut context_refs = references.into_values().collect::<Vec<_>>();
        context_refs.sort_by(|left, right| left.key.cmp(&right.key));

        let metadata = GraphManifest {
            schema_version: GRAPH_SCHEMA_VERSION,
            scope: captured.metadata.scope,
            first_cursor: first,
            last_cursor: last,
            input_manifest: graph.revision,
            facts: graph.facts,
            packages: graph.packages,
            missing_ranges: input.missing_ranges,
            input_positions: input.input_positions,
            previous_result_id: captured.metadata.previous_result_id,
            context_notice_revision: receipt.snapshot().page.extraction.meta.commit_revision,
            witness_deadline_utc_ns: deadline,
        };
        let witnesses = metadata
            .input_manifest
            .evidence
            .iter()
            .cloned()
            .map(|id| AnalysisWitnessV1 {
                identity: id.stream.into(),
                cursor: id.durable_cursor,
                expires_utc_ns: deadline,
            })
            .collect();
        let request = AnalysisResultCommitV1 {
            scope: metadata.scope.clone(),
            expected_cursor: consumed,
            consumed_cursor: last.max(consumed),
            coverage_revision,
            context_revision: context_refs
                .iter()
                .map(|reference| reference.commit_revision)
                .max()
                .unwrap_or(0),
            result_id,
            body: Vec::new(),
            created_utc_ns: source.time_utc_ns(),
            witnesses,
            context_refs,
        };
        let sources = receipt
            .snapshot()
            .selection
            .source_revisions(receipt.snapshot().page.extraction.meta.commit_revision);
        let record_proofs = captured
            .proofs
            .into_iter()
            .map(|((record, _), proof)| (record, proof))
            .collect();
        let removed = captured.removed.into_iter().collect();
        let packet = GraphCommit {
            request,
            metadata,
            contexts,
            proofs,
            record_proofs,
            removed,
            sources,
            advance: last > consumed,
            expire: false,
        };
        let before = captured._memory.capacity();
        captured
            ._memory
            .try_reserve(1)
            .map_err(|source| araphor_query::Error::Sql {
                source: Projection::external(source),
            })?;
        let bytes =
            (|| -> Option<usize> {
                let bytes = bytes.checked_add(
                    captured
                        ._memory
                        .capacity()
                        .checked_sub(before)?
                        .checked_mul(std::mem::size_of::<MemoryReservation>())?,
                )?;
                packet
                    .proofs
                    .iter()
                    .try_fold(
                        bytes.checked_add(packet.proofs.capacity().checked_mul(
                            std::mem::size_of::<araphor_data::AnalysisContextRefV1>(),
                        )?)?,
                        |bytes, proof| bytes.checked_add(proof.key.allocated_bytes()),
                    )
                    .and_then(|bytes| {
                        packet.sources.iter().try_fold(
                            bytes.checked_add(
                                packet.sources.capacity().checked_mul(std::mem::size_of::<(
                                    String,
                                    u64,
                                )>(
                                ))?,
                            )?,
                            |bytes, (name, _)| bytes.checked_add(name.capacity()),
                        )
                    })
                    .and_then(|bytes| {
                        packet.request.witnesses.iter().try_fold(
                            bytes.checked_add(
                                packet
                                    .request
                                    .witnesses
                                    .capacity()
                                    .checked_mul(std::mem::size_of::<AnalysisWitnessV1>())?,
                            )?,
                            |bytes, witness| {
                                bytes.checked_add(match &witness.identity {
                                    araphor_data::AnalysisStreamIdentityV1::Evidence(identity) => {
                                        identity.node_id.capacity()
                                    }
                                    araphor_data::AnalysisStreamIdentityV1::Diagnostic(_) => 0,
                                })
                            },
                        )
                    })
                    .and_then(|bytes| {
                        bytes
                            .checked_add(packet.request.scope.processor_id.capacity())?
                            .checked_add(packet.request.scope.identity.node_id.capacity())?
                            .checked_add(packet.request.result_id.capacity())?
                            .checked_add(packet.request.body.capacity())
                    })
            })()
            .ok_or_else(|| Code::Limit.error("Graph publication memory"))?;
        if bytes > source.extraction_limits().input_bytes {
            return Err(Code::Limit.error("Graph publication memory").into());
        }
        drop(input.source);
        drop(captured.metadata.missing_ranges);
        memory
            .try_resize(bytes)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        captured._memory.push(memory);
        erebor_telemetry::debug!(
            stage = "graph_conversion", result_id = %packet.request.result_id,
            cut_revision = receipt.snapshot().page.extraction.meta.commit_revision,
            calls = receipt.calls().len(), elapsed_s = started.elapsed().as_secs_f64(),
            "Graph conversion completed"
        );
        Ok(GraphConversion {
            packet,
            completed: last >= accepted,
            deadline,
            _memory: captured._memory,
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
                    record_proofs: Vec::new(),
                    removed: Vec::new(),
                    sources,
                    advance: false,
                    expire: true,
                },
                completed,
                deadline,
                _memory: Vec::new(),
            }))
        };
        convert().map_err(|source| araphor_query::Error::Sql { source })
    }
}
