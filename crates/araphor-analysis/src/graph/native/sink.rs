use std::any::Any;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex, Weak};

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisResultCommitV1, AnalysisResultReceiptV1, AnalysisWitnessV1, PackageActionV1,
    PackageBundleRef, PackageErrorCodeV1 as Code, ProcessorScopeV1, GRAPH_PROCESSOR,
    GRAPH_SCHEMA_VERSION, GRAPH_WITNESS_TTL_NS,
};
use araphor_query::definition::ExecutionReceipt;
use async_trait::async_trait;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::Result;
use datafusion::datasource::sink::{DataSink, DataSinkExec};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{dml::InsertOp, Expr, TableType};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, SendableRecordBatchStream,
};
use futures_util::TryStreamExt as _;

use super::{GraphPublication, Projection};
use crate::Graph;

type Receipt = (String, AnalysisResultReceiptV1);

#[derive(Clone)]
pub(super) struct Publication {
    pub(super) owner: Arc<GraphPublication>,
    pub(super) schema: sdk::arrow_schema::SchemaRef,
    pub(super) result_id: String,
    pub(super) receipt: Arc<Mutex<Option<Receipt>>>,
}
impl fmt::Debug for Publication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GraphPublication")
    }
}
impl DisplayAs for Publication {
    fn fmt_as(&self, _: DisplayFormatType, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("GraphPublication")
    }
}
#[async_trait]
impl TableProvider for Publication {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn schema(&self) -> sdk::arrow_schema::SchemaRef {
        Arc::clone(&self.schema)
    }
    fn table_type(&self) -> TableType {
        TableType::Base
    }
    async fn scan(
        &self,
        _: &dyn Session,
        _: Option<&Vec<usize>>,
        _: &[Expr],
        _: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        Err(Projection::invalid("graph publication scan"))
    }
    async fn insert_into(
        &self,
        _: &dyn Session,
        input: Arc<dyn ExecutionPlan>,
        operation: InsertOp,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        if operation != InsertOp::Append || input.schema() != self.schema {
            return Err(Projection::invalid("graph publication input"));
        }
        Ok(Arc::new(DataSinkExec::new(
            input,
            Arc::new(self.clone()),
            None,
        )))
    }
}
#[async_trait]
impl DataSink for Publication {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn schema(&self) -> &sdk::arrow_schema::SchemaRef {
        &self.schema
    }
    async fn write_all(
        &self,
        mut data: SendableRecordBatchStream,
        context: &Arc<TaskContext>,
    ) -> Result<u64> {
        let mut rows = 0usize;
        let mut bytes = 0usize;
        while let Some(batch) = data.try_next().await? {
            rows = rows
                .checked_add(batch.num_rows())
                .ok_or_else(|| Projection::invalid("graph selected rows overflow"))?;
            bytes = bytes
                .checked_add(batch.get_array_memory_size())
                .ok_or_else(|| Projection::invalid("graph selected bytes overflow"))?;
            if rows > self.owner.session.engine().limits().output_rows
                || bytes > self.owner.session.engine().limits().output_bytes
            {
                return Err(Projection::external(
                    Code::Limit.error("graph selected relation"),
                ));
            }
        }
        let receipt = ExecutionReceipt::from_context(context)?;
        let captured = self
            .owner
            .projection
            .captured
            .get()
            .ok_or_else(|| Projection::invalid("graph detector input was not executed"))?
            .clone()
            .map_err(datafusion::common::DataFusionError::Shared)?;
        if !Weak::ptr_eq(
            &captured.source,
            &Arc::downgrade(
                &context
                    .session_config()
                    .get_extension::<araphor_query::sources::SourceSnapshot>()
                    .ok_or_else(|| Projection::invalid("graph captured source"))?,
            ),
        ) {
            return Err(Projection::invalid("graph returned source capture"));
        }
        for (id, returned) in receipt.calls() {
            if self
                .owner
                .calls
                .get(id)
                .is_none_or(|call| !returned.belongs_to(call))
            {
                return Err(Projection::invalid("graph returned call identity"));
            }
        }
        let owner = Arc::clone(&self.owner);
        let result_id = self.result_id.clone();
        let state = Arc::clone(&self.receipt);
        let calls = receipt.calls().clone();
        let sources = receipt
            .snapshot()
            .selection
            .source_revisions(receipt.snapshot().page.extraction.meta.commit_revision);
        receipt
            .blocking(context, captured, move |control| {
                let captured = owner
                    .projection
                    .captured
                    .get()
                    .ok_or_else(|| Code::Incomplete.error("graph input capture"))?
                    .clone()
                    .map_err(|source| araphor_query::Error::Sql {
                        source: datafusion::common::DataFusionError::Shared(source),
                    })?;
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
                        if input.revision != expected.revision
                            || input.coverage != expected.coverage
                        {
                            return Err(Code::Invalid.error("graph qualified input").into());
                        }
                    }
                    graph = graph.apply(call, returned)?;
                }
                for id in calls.keys() {
                    let call = &owner.calls[id];
                    let (bundle, digest) = owner
                        .prepared
                        .images()
                        .find(|(bundle, digest)| {
                            bundle.root == call.image().image
                                && *digest == call.image().digest.as_str()
                        })
                        .ok_or_else(|| Code::Denied.error("graph image attribution"))?;
                    contexts.push(PackageBundleRef::retained(bundle, digest).context(
                        owner.grant.selection.tenant_id,
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
                let _graph_memory = graph._memory.take();
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
                let commit = AnalysisResultCommitV1 {
                    scope,
                    expected_cursor: captured.consumed,
                    consumed_cursor: captured.consumed,
                    coverage_revision: captured.coverage_revision,
                    context_revision: 0,
                    result_id: result_id.clone(),
                    body: Vec::new(),
                    created_utc_ns: captured.now,
                    witnesses,
                    context_refs: Vec::new(),
                };
                let mut prepared = Some(araphor_data::analysis::CanonicalGraph::bounded(
                    snapshot,
                    owner.session.engine().limits().output_bytes,
                )?);
                let images = owner
                    .prepared
                    .images()
                    .map(|(bundle, digest)| PackageBundleRef::retained(bundle, digest))
                    .collect::<Vec<_>>();
                let grants = std::iter::once((&owner.grant, None))
                    .chain(images.iter().map(|image| (&owner.grant, Some(image))))
                    .collect::<Vec<_>>();
                let mut output = None;
                owner
                    .authority
                    .commit_many(&grants, PackageActionV1::Run, &mut || {
                        owner.grant.remaining()?;
                        owner.session.control().check()?;
                        control.check()?;
                        Projection::check_deadline(deadline)?;
                        let receipt = owner.session.engine().store().commit_graph_snapshot(
                            commit.clone(),
                            prepared
                                .take()
                                .ok_or_else(|| Code::Invalid.error("graph publication callback"))?,
                            &contexts,
                            &proofs,
                            &sources,
                            false,
                            || {
                                owner.grant.remaining()?;
                                owner.session.control().check()?;
                                control.check()?;
                                Projection::check_deadline(deadline)
                            },
                        )?;
                        let id = previous
                            .filter(|head| head.revision == receipt.commit_revision)
                            .map_or_else(|| result_id.clone(), |head| head.id.clone());
                        output = Some((id, receipt));
                        Ok(())
                    })?;
                *state.lock().unwrap_or_else(|error| error.into_inner()) =
                    Some(output.ok_or_else(|| Code::Denied.error("graph publication authority"))?);
                Ok(())
            })
            .await?;
        Ok(rows as u64)
    }
}
