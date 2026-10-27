use super::{AnalysisResultCommitV1, AnalysisResultReceiptV1, AnalysisStore, ResultHead};
use crate::{
    FindingStateV1, GraphBranchStateV1, GraphCauseV1, GraphPackageStateV1, GraphSnapshotV1,
    ManagedCommit, ManagedDestination, ManagedGraphOperation, ManagedReceipt,
    PackageErrorCodeV1 as Code, Result, TemporalCoverageV1,
};

impl AnalysisStore {
    pub fn commit_managed_graph(
        &self,
        managed: &ManagedCommit<'_>,
        packet: Option<super::super::graph::GraphCommit>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<(ManagedReceipt, Option<AnalysisResultReceiptV1>)> {
        let spec = &managed.attempt.instance().spec;
        let ManagedDestination::Graph {
            source,
            calls,
            operation,
            ..
        } = &spec.destination
        else {
            return Err(Code::Invalid.error("managed graph destination"));
        };
        let Some(packet) = packet else {
            if !managed.returns.is_empty()
                || managed
                    .selected
                    .batches
                    .iter()
                    .any(|batch| batch.num_rows() != 0)
            {
                return Err(Code::Invalid.error("managed graph empty result"));
            }
            return self
                .commit_managed_projection(managed, |_, _, _| Ok(Vec::new()), check)
                .map(|receipt| (receipt, None));
        };
        if calls
            .iter()
            .copied()
            .ne(managed.returns.iter().map(|returned| returned.call))
        {
            return Err(Code::Invalid.error("managed graph capture"));
        }
        if packet.request.scope.identity != *source
            || packet.request.created_utc_ns != managed.attempt.request().time_utc_ns
            || !packet.request.body.is_empty()
        {
            return Err(Code::Invalid.error("managed graph capture"));
        }
        let (graph, body) = packet.graph.into_parts();
        let mut input = packet.request;
        input.body = body;
        self.check_graph_commit(&input, &graph, packet.advance)?;
        if *operation == ManagedGraphOperation::Expire
            && (packet.advance
                || !input.witnesses.is_empty()
                || !graph
                    .missing_ranges
                    .contains(&(graph.first_cursor, graph.last_cursor))
                || graph.graph.edges.iter().any(|edge| {
                    edge.key.cause != GraphCauseV1::Superseded
                        || edge.proof_quality.temporal_coverage != TemporalCoverageV1::Unknown
                })
                || graph.graph.branches.iter().any(|branch| {
                    branch.state != GraphBranchStateV1::CoverageUnknown
                        || !branch
                            .missing_fields
                            .iter()
                            .any(|field| field == "RETAINED_INPUT_EXPIRED")
                })
                || graph.findings.iter().any(|finding| {
                    finding.state != FindingStateV1::CoverageInsufficient
                        || !finding
                            .limits
                            .iter()
                            .any(|limit| limit == "RETAINED_INPUT_EXPIRED")
                        || !finding
                            .limits
                            .iter()
                            .any(|limit| limit == "LATE_EVIDENCE_UNSUPPORTED_AFTER_RETENTION")
                        || finding.effects.iter().any(|effect| {
                            effect.proof_quality.temporal_coverage != TemporalCoverageV1::Unknown
                        })
                })
                || graph
                    .packages
                    .iter()
                    .any(|package| package.state != GraphPackageStateV1::CoverageInsufficient))
        {
            return Err(Code::Invalid.error("managed graph expiry"));
        }
        let mut graph_receipt = None;
        let receipt = self.commit_managed_projection(
            managed,
            |transaction, revision, _| {
                let notice = if managed.attempt.follows_graph() {
                    managed.attempt.captured_revision()
                } else {
                    revision
                };
                let write = self.progress_rows(
                    transaction,
                    &input,
                    ResultHead::Unchecked,
                    packet.advance,
                    None,
                    Some((&graph, notice)),
                    &packet.contexts,
                    &packet.proofs,
                    &packet.sources,
                    managed.attempt.follows_graph(),
                    true,
                )?;
                graph_receipt = Some(write.receipt);
                Ok(write.relations)
            },
            check,
        )?;
        Ok((
            receipt,
            Some(graph_receipt.ok_or_else(|| Code::Incomplete.error("managed graph receipt"))?),
        ))
    }

    pub(super) fn check_graph_commit(
        &self,
        input: &AnalysisResultCommitV1,
        graph: &GraphSnapshotV1,
        advance: bool,
    ) -> Result<()> {
        let expected: Vec<_> = graph
            .input_manifest
            .evidence
            .iter()
            .filter(|id| {
                !graph
                    .missing_ranges
                    .iter()
                    .any(|(first, last)| (*first..=*last).contains(&id.durable_cursor))
            })
            .map(|id| {
                (
                    super::super::AnalysisStreamIdentityV1::Evidence(id.stream.clone()),
                    id.durable_cursor,
                )
            })
            .collect();
        let actual: Vec<_> = input
            .witnesses
            .iter()
            .map(|witness| (witness.identity.clone(), witness.cursor))
            .collect();
        if graph.scope != input.scope
            || expected != actual
            || input
                .witnesses
                .iter()
                .any(|witness| witness.expires_utc_ns != graph.witness_deadline_utc_ns)
            || (advance && graph.last_cursor != input.consumed_cursor)
            || (!advance && input.expected_cursor != input.consumed_cursor)
        {
            return self.reject("the graph input manifest, witnesses, or progress differ");
        }
        Ok(())
    }
}
