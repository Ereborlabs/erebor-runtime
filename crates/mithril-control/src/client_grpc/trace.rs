use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use araphor_data::{
    QueryCheckpoint, QueryFrame, QueryGrant, QueryPayload, QueryPlan, QuerySql, QueryStream,
};
use duckdb::types::Value;
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use tonic::Status;

use super::query::QueryTransport;
use super::wire::WireFrame;
use super::{proto, ClientAccess, ClientGrpcOwner};
use crate::{TraceAcceptedV1, TraceOwner, TraceRecipeV1, TraceRequestV1, TraceSourceV1};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TraceBookmark {
    trace_id: [u8; 16],
    checkpoint: Vec<u8>,
}

impl TraceBookmark {
    fn decode(bytes: &[u8], trace: [u8; 16]) -> Result<Option<QueryCheckpoint>, Status> {
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.len() > 2048 {
            return Err(Status::invalid_argument(
                "The trace bookmark exceeds its bound.",
            ));
        }
        let value: Self = rmp_serde::from_slice(bytes)
            .map_err(|_| Status::invalid_argument("The trace bookmark is invalid."))?;
        if value.trace_id != trace {
            return Err(Status::invalid_argument(
                "The bookmark names another trace.",
            ));
        }
        QueryTransport::checkpoint(&value.checkpoint)
    }

    fn encode(trace: [u8; 16], checkpoint: &QueryCheckpoint) -> Result<Vec<u8>, Status> {
        let value = Self {
            trace_id: trace,
            checkpoint: checkpoint.encode().map_err(QueryTransport::failure)?,
        };
        rmp_serde::to_vec_named(&value)
            .map_err(|_| Status::internal("The trace bookmark cannot be encoded."))
    }
}

impl ClientGrpcOwner {
    async fn load_trace(
        &self,
        trace: [u8; 16],
        access: &Arc<ClientAccess>,
    ) -> Result<(araphor_data::TraceStateV1, TraceAcceptedV1), Status> {
        let grant = access.trace_access().map_err(Self::auth_failure)?;
        let store = self.data()?.store.clone();
        let now = Self::now()?;
        let result = tokio::task::spawn_blocking(move || {
            TraceOwner::new(store)
                .read(grant.tenant_id, trace, &grant, now)
                .map_err(Self::failure)
        })
        .await
        .map_err(|_| Status::internal("The trace read task failed."))?;
        access.check().map_err(Self::auth_failure)?;
        result
    }

    pub(super) async fn submit(
        &self,
        input: proto::SubmitTraceRequest,
        access: Arc<ClientAccess>,
    ) -> Result<proto::TraceReceipt, Status> {
        let trace = Self::identity(&input.idempotency_key)?;
        let selection = input
            .selection
            .ok_or_else(|| Status::invalid_argument("Trace submission requires a target."))?;
        Self::selection_shape(&selection)?;
        if selection.target.is_empty() || !selection.node_ids.is_empty() {
            return Err(Status::invalid_argument(
                "Trace requires one target locator.",
            ));
        }
        let source = match input.source {
            Some(proto::submit_trace_request::Source::Script(bytes)) => {
                TraceSourceV1::new(bytes).map_err(Self::failure)?
            }
            Some(proto::submit_trace_request::Source::Recipe(recipe)) => {
                let recipe = match recipe.as_str() {
                    "syscall-errors@1" => TraceRecipeV1::SyscallErrors,
                    "failed-opens@1" => TraceRecipeV1::FailedOpens,
                    _ => return Err(Status::unimplemented("The trace recipe is unavailable.")),
                };
                recipe.manifest().map_err(Self::failure)?.source
            }
            None => return Err(Status::invalid_argument("The trace source is absent.")),
        };
        let seconds = if input.collection_seconds == 0 {
            30
        } else {
            input.collection_seconds
        };
        if !(1..=300).contains(&seconds) {
            return Err(Status::invalid_argument(
                "Trace duration must be 1..300 seconds.",
            ));
        }
        let grant = access.trace_access().map_err(Self::auth_failure)?;
        let (targets, unresolved) = match self.load_trace(trace, &access).await {
            Ok((_, accepted)) => (accepted.request.targets, accepted.request.unresolved),
            Err(error) if error.code() == tonic::Code::NotFound => {
                let facts = self.facts(&selection, access.tenant_id())?;
                let participants = self.control.resolve_trace_targets(facts, &grant).await?;
                access.check().map_err(Self::auth_failure)?;
                let (resolved, unresolved): (Vec<_>, Vec<_>) = participants
                    .into_iter()
                    .partition(|participant| participant.target.is_some());
                let targets: Vec<_> = resolved
                    .into_iter()
                    .filter_map(|participant| participant.target)
                    .collect();
                if targets.is_empty() {
                    return Err(Status::failed_precondition(
                        "No target lifetime can be resolved.",
                    ));
                }
                (targets, unresolved)
            }
            Err(error) => return Err(error),
        };
        let request = TraceRequestV1 {
            tenant_id: access.tenant_id(),
            request_id: trace,
            source,
            targets,
            unresolved,
            collection_seconds: seconds as u16,
            selection: Some(crate::TraceSelectionV1 {
                target: selection.target,
                cluster: selection.cluster,
                container: selection.container,
            }),
            finding_reference: (!input.finding_reference.is_empty())
                .then_some(input.finding_reference),
        };
        let control = self.control.clone();
        let current = access.clone();
        tokio::task::spawn_blocking(move || {
            let grant = current.trace_access().map_err(Self::auth_failure)?;
            control.accept_trace(request, grant)
        })
        .await
        .map_err(|_| Status::internal("The trace acceptance task failed."))??;
        let (state, accepted) = self.load_trace(trace, &access).await?;
        Ok(Self::receipt(&state, &accepted))
    }

    pub(super) async fn detail(
        &self,
        trace: [u8; 16],
        access: &Arc<ClientAccess>,
    ) -> Result<proto::TraceDetail, Status> {
        let (state, accepted) = self.load_trace(trace, access).await?;
        Ok(Self::trace_detail(&state, &accepted))
    }

    fn receipt(
        state: &araphor_data::TraceStateV1,
        accepted: &TraceAcceptedV1,
    ) -> proto::TraceReceipt {
        proto::TraceReceipt {
            trace_id: accepted.request.request_id.to_vec(),
            source_sha256: accepted.request.source.sha256.to_vec(),
            accepted_unix_ns: accepted.accepted_unix_ns,
            deadline_unix_ns: accepted.deadline_unix_ns,
            cancel_requested: state.cancel_requested,
        }
    }

    fn trace_detail(
        state: &araphor_data::TraceStateV1,
        accepted: &TraceAcceptedV1,
    ) -> proto::TraceDetail {
        proto::TraceDetail {
            receipt: Some(Self::receipt(state, accepted)),
            source: accepted.request.source.bytes.clone(),
            recipe: match accepted.recipe {
                Some(TraceRecipeV1::SyscallErrors) => "syscall-errors@1",
                Some(TraceRecipeV1::FailedOpens) => "failed-opens@1",
                None => "",
            }
            .into(),
            collection_seconds: u32::from(accepted.request.collection_seconds),
            principal: accepted.access.principal.clone(),
            targets: accepted
                .request
                .targets
                .iter()
                .enumerate()
                .map(|(index, target)| proto::TraceTarget {
                    index: index as u32,
                    node_id: target.fact.node_id.clone(),
                    node_boot_id: target.node_boot_id.to_vec(),
                    cluster_uid: target.fact.cluster_uid.clone(),
                    namespace_uid: target.fact.namespace_uid.clone(),
                    pod_uid: target.fact.pod_uid.clone(),
                    container_id: target.runtime_container_id.clone(),
                    container_name: target.fact.container_name.clone(),
                    binding_id: target.binding_id.to_vec(),
                    cgroup_id: target.cgroup_id,
                    container_generation: target.container_generation,
                    label_epoch: target.label_epoch,
                    namespace_name: target
                        .fact
                        .kubernetes
                        .as_ref()
                        .map(|identity| identity.namespace_name.clone())
                        .unwrap_or_default(),
                    pod_name: target
                        .fact
                        .kubernetes
                        .as_ref()
                        .map(|identity| identity.pod_name.clone())
                        .unwrap_or_default(),
                })
                .collect(),
            unresolved: accepted
                .request
                .unresolved
                .iter()
                .map(|participant| proto::TraceParticipant {
                    fact_digest: participant.fact_digest.0.to_vec(),
                    state: format!("{:?}", participant.state),
                })
                .collect(),
            requested: accepted
                .request
                .selection
                .as_ref()
                .map(|selection| proto::InputSelection {
                    target: selection.target.clone(),
                    cluster: selection.cluster.clone(),
                    container: selection.container.clone(),
                    node_ids: Vec::new(),
                }),
            finding_reference: accepted
                .request
                .finding_reference
                .clone()
                .unwrap_or_default(),
            limits: Some(proto::TraceLimits {
                source_bytes: crate::MAX_TRACE_SOURCE_BYTES as u32,
                frame_bytes: crate::MAX_TRACE_FRAME_BYTES as u32,
                output_bytes: crate::MAX_TRACE_OUTPUT_BYTES as u32,
                frame_count: 4096,
                target_count: crate::MAX_TRACE_TARGETS as u32,
                collection_seconds: 300,
            }),
        }
    }

    pub(super) async fn watch(
        &self,
        input: proto::WatchTraceRequest,
        access: Arc<ClientAccess>,
    ) -> Result<TraceTransport, Status> {
        let trace = Self::identity(&input.trace_id)?;
        let (state, accepted) = self.load_trace(trace, &access).await?;
        let bookmark = TraceBookmark::decode(&input.bookmark, trace)?;
        let sql = QuerySql::admit(
            "SELECT execution_id,target_index,sequence,kind,bytes,commit_revision,ordinal FROM trace_output WHERE request_id = $1",
            vec![Value::Blob(trace.to_vec())],
            true,
        ).map_err(QueryTransport::failure)?;
        let mut selection = araphor_data::AnalysisSelectionV1::tenant(access.tenant_id());
        selection.all_traces = false;
        selection.traces = accepted
            .request
            .targets
            .iter()
            .enumerate()
            .map(|(index, _)| {
                accepted
                    .binding(index as u16)
                    .map(|binding| binding.identity)
                    .map_err(Self::failure)
            })
            .collect::<Result<_, _>>()?;
        let plan = QueryPlan::client(
            QueryGrant {
                principal: access.principal().to_owned(),
                revision: access.revision(),
                selection,
            },
            sql,
        )
        .map_err(QueryTransport::failure)?;
        let store = self.data()?.store.clone();
        let frozen = accepted.clone();
        let terminals = tokio::task::spawn_blocking(move || {
            frozen
                .request
                .targets
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    let binding = frozen.binding(index as u16).map_err(Self::failure)?;
                    store
                        .trace_receipt(&binding.identity)
                        .map_err(Self::failure)
                        .map(|receipt| receipt.and_then(|receipt| receipt.terminal))
                })
                .collect::<Result<Vec<_>, Status>>()
        })
        .await
        .map_err(|_| Status::internal("The trace receipt task failed."))??;
        access.check().map_err(Self::auth_failure)?;
        // The query snapshot must include every terminal receipt used below.
        let stream = self
            .data()?
            .query
            .stream_client(plan, bookmark, access.clone())
            .map_err(QueryTransport::failure)?;
        let remaining = accepted.deadline_unix_ns.saturating_sub(Self::now()?);
        Ok(TraceTransport {
            inner: stream,
            access,
            trace,
            detail: Some(Self::trace_detail(&state, &accepted)),
            held: None,
            guard: None,
            row: 0,
            checking: None,
            ending: false,
            terminals,
            unresolved: accepted.request.unresolved.len(),
            exhausted: false,
            header: proto::TraceFrame::default(),
            pending: None,
            deadline: Box::pin(tokio::time::sleep(
                Duration::from_nanos(remaining).saturating_add(Duration::from_secs(10)),
            )),
            done: false,
        })
    }
}

pub(super) struct TraceTransport {
    inner: QueryStream,
    access: Arc<ClientAccess>,
    trace: [u8; 16],
    detail: Option<proto::TraceDetail>,
    held: Option<Arc<QueryFrame>>,
    guard: Option<Arc<QueryFrame>>,
    row: usize,
    checking: Option<Pin<Box<dyn Future<Output = araphor_data::Result<()>> + Send>>>,
    ending: bool,
    terminals: Vec<Option<crate::TraceTerminalV1>>,
    unresolved: usize,
    exhausted: bool,
    header: proto::TraceFrame,
    pending: Option<Status>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    done: bool,
}

impl TraceTransport {
    #[cfg(test)]
    pub(super) fn expire(&mut self) {
        self.deadline.as_mut().reset(tokio::time::Instant::now());
    }

    fn frame(&self, payload: proto::trace_frame::Payload) -> proto::TraceFrame {
        proto::TraceFrame {
            schema_version: 1,
            trace_id: self.trace.to_vec(),
            store_uuid: self.header.store_uuid.clone(),
            recovery_epoch: self.header.recovery_epoch,
            read_revision: self.header.read_revision,
            coverage: self.header.coverage.clone(),
            payload: Some(payload),
            ..Default::default()
        }
    }

    fn result(&self) -> proto::TraceResult {
        let missing: Vec<_> = self
            .terminals
            .iter()
            .enumerate()
            .filter_map(|(index, terminal)| terminal.is_none().then_some(index as u32))
            .collect();
        let complete = self.exhausted && missing.is_empty() && self.unresolved == 0;
        proto::TraceResult {
            complete,
            output_incomplete: !complete
                || self.terminals.iter().flatten().any(|terminal| {
                    terminal.output_incomplete
                        || !matches!(
                            terminal.reason,
                            crate::TraceTerminalReasonV1::Completed
                                | crate::TraceTerminalReasonV1::Cancelled
                        )
                }),
            cleanup_complete: missing.is_empty()
                && self
                    .terminals
                    .iter()
                    .flatten()
                    .all(|terminal| terminal.cleanup == crate::TraceCleanupV1::Verified),
            missing_targets: missing,
        }
    }

    fn output(&mut self) -> Result<proto::TraceFrame, Status> {
        let frame = self
            .held
            .as_ref()
            .ok_or_else(|| Status::internal("Trace output is absent."))?;
        let QueryPayload::Append { result } = &frame.payload else {
            return Err(Status::internal("Trace output operation changed."));
        };
        let row = result
            .rows
            .get(self.row)
            .ok_or_else(|| Status::internal("Trace output row is absent."))?;
        let [Value::Blob(execution), index, sequence, Value::Text(kind), Value::Blob(bytes), ..] =
            row.as_slice()
        else {
            return Err(Status::data_loss("Trace output schema changed."));
        };
        let number = |value: &Value| match value {
            Value::UBigInt(value) => Some(*value),
            Value::UInt(value) => Some(u64::from(*value)),
            Value::USmallInt(value) => Some(u64::from(*value)),
            _ => None,
        };
        let index = number(index)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < self.terminals.len())
            .ok_or_else(|| Status::data_loss("Trace target index is invalid."))?;
        let sequence =
            number(sequence).ok_or_else(|| Status::data_loss("Trace sequence is invalid."))?;
        let position = result
            .positions
            .get(self.row)
            .ok_or_else(|| Status::data_loss("Trace output has no committed position."))?;
        let payload = if kind == "terminal" {
            let terminal: crate::TraceTerminalV1 = serde_json::from_slice(bytes)
                .map_err(|_| Status::data_loss("The retained trace terminal is invalid."))?;
            terminal.validate().map_err(ClientGrpcOwner::failure)?;
            if terminal.execution_id.as_slice() != execution {
                return Err(Status::data_loss("The terminal names another execution."));
            }
            let value = proto::TraceTerminal {
                reason: format!("{:?}", terminal.reason),
                output_incomplete: terminal.output_incomplete,
                kernel_lost_events: terminal.kernel_lost_events,
                ready_at_unix_ns: terminal.ready_at_unix_ns,
                exit_code: terminal.exit_code,
                forced_kill: terminal.forced_kill,
                cleanup: format!("{:?}", terminal.cleanup),
                last_sequence: terminal.last_sequence,
                output_bytes: terminal.output_bytes,
            };
            self.terminals[index] = Some(terminal);
            proto::trace_frame::Payload::Terminal(value)
        } else {
            proto::trace_frame::Payload::Output(proto::TraceOutput {
                kind: kind.clone(),
                bytes: bytes.clone(),
            })
        };
        Ok(proto::TraceFrame {
            schema_version: 1,
            trace_id: self.trace.to_vec(),
            commit_revision: position.commit_revision,
            ordinal: position.ordinal,
            execution_id: execution.clone(),
            sequence,
            target_index: index as u32,
            bookmark: Vec::new(),
            payload: Some(payload),
            store_uuid: self.header.store_uuid.clone(),
            recovery_epoch: self.header.recovery_epoch,
            read_revision: self.header.read_revision,
            coverage: self.header.coverage.clone(),
        })
    }
}

impl Stream for TraceTransport {
    type Item = Result<proto::TraceFrame, Status>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        if let Err(error) = self.access.check() {
            self.done = true;
            let _cancelled = self.inner.cancel();
            return Poll::Ready(Some(Err(ClientGrpcOwner::auth_failure(error))));
        }
        if let Some(status) = self.pending.take() {
            self.done = true;
            return Poll::Ready(Some(Err(status)));
        }
        loop {
            if self.ending
                || self.deadline.as_mut().poll(context).is_ready()
                || (self.held.is_none()
                    && self.exhausted
                    && self.terminals.iter().all(Option::is_some))
            {
                if !self.ending {
                    self.ending = true;
                    self.held = None;
                    self.checking = None;
                }
                let Some(frame) = self.guard.clone() else {
                    self.done = true;
                    let _cancelled = self.inner.cancel();
                    return Poll::Ready(Some(Err(Status::deadline_exceeded(
                        "Trace ended before its first read checkpoint.",
                    ))));
                };
                let checking = self
                    .checking
                    .get_or_insert_with(|| Box::pin(async move { frame.check_read().await }));
                match checking.as_mut().poll(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        self.done = true;
                        self.guard = None;
                        self.checking = None;
                        let _cancelled = self.inner.cancel();
                        return Poll::Ready(Some(Err(QueryTransport::failure(error))));
                    }
                    Poll::Ready(Ok(())) => self.checking = None,
                }
                if let Err(error) = self.access.check() {
                    self.done = true;
                    self.guard = None;
                    let _cancelled = self.inner.cancel();
                    return Poll::Ready(Some(Err(ClientGrpcOwner::auth_failure(error))));
                }
                self.done = true;
                self.guard = None;
                let _cancelled = self.inner.cancel();
                return Poll::Ready(Some(Ok(
                    self.frame(proto::trace_frame::Payload::Result(self.result()))
                )));
            }
            if let Some(frame) = self.held.clone() {
                let checking = self
                    .checking
                    .get_or_insert_with(|| Box::pin(async move { frame.check_read().await }));
                match checking.as_mut().poll(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        self.done = true;
                        return Poll::Ready(Some(Err(QueryTransport::failure(error))));
                    }
                    Poll::Ready(Ok(())) => {
                        self.checking = None;
                    }
                }
                if let Err(error) = self.access.check() {
                    self.done = true;
                    return Poll::Ready(Some(Err(ClientGrpcOwner::auth_failure(error))));
                }
                let output = self.output();
                self.row += 1;
                if let Some(frame) = &self.held {
                    if matches!(&frame.payload, QueryPayload::Append { result } if self.row >= result.rows.len())
                    {
                        self.held = None;
                    }
                }
                if output.is_err() {
                    self.done = true;
                }
                return Poll::Ready(Some(output));
            }
            match Pin::new(&mut self.inner).poll_next(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(Status::unavailable(
                        "Trace reads ended without a result.",
                    ))));
                }
                Poll::Ready(Some(Err(error))) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(QueryTransport::failure(error))));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    self.header.store_uuid = frame.store_uuid.to_vec();
                    self.header.recovery_epoch = frame.recovery_epoch;
                    self.header.read_revision = frame.read_revision;
                    self.header.coverage =
                        frame.coverage().iter().map(WireFrame::coverage).collect();
                    match &frame.payload {
                        QueryPayload::Metadata(_) => {
                            self.guard = Some(Arc::new(frame));
                            if let Some(detail) = self.detail.take() {
                                return Poll::Ready(Some(Ok(self.frame(
                                    proto::trace_frame::Payload::Metadata(detail.into()),
                                ))));
                            }
                        }
                        QueryPayload::Append { result } if !result.rows.is_empty() => {
                            self.row = 0;
                            self.exhausted = false;
                            self.held = Some(Arc::new(frame));
                        }
                        QueryPayload::Checkpoint {
                            checkpoint,
                            exhausted,
                            ..
                        } => {
                            self.exhausted = *exhausted;
                            let bookmark = match TraceBookmark::encode(self.trace, checkpoint) {
                                Ok(bookmark) => bookmark,
                                Err(error) => {
                                    self.done = true;
                                    return Poll::Ready(Some(Err(error)));
                                }
                            };
                            let mut output = self.frame(proto::trace_frame::Payload::Checkpoint(
                                proto::TraceCheckpoint {},
                            ));
                            output.bookmark = bookmark;
                            self.guard = Some(Arc::new(frame));
                            return Poll::Ready(Some(Ok(output)));
                        }
                        QueryPayload::Health {
                            dependency_revision,
                            storage_health,
                            ..
                        } => {
                            return Poll::Ready(Some(Ok(self.frame(
                                proto::trace_frame::Payload::Health(proto::QueryHealth {
                                    dependency_revision: *dependency_revision,
                                    write_ready: storage_health.write_ready,
                                    retention_healthy: storage_health.retention_healthy,
                                    intake_capacity: storage_health.intake_capacity,
                                    maintenance_capacity: storage_health.maintenance_capacity,
                                }),
                            ))));
                        }
                        QueryPayload::Error {
                            code,
                            reason,
                            position,
                            floor,
                            last_checkpoint,
                            ..
                        } => {
                            let code = *code;
                            let error = proto::QueryError {
                                code: format!("{code:?}"),
                                reason: (*reason).into(),
                                last_checkpoint: match last_checkpoint {
                                    Some(checkpoint) => {
                                        TraceBookmark::encode(self.trace, checkpoint)?
                                    }
                                    None => Vec::new(),
                                },
                                position: position.map(|value| proto::StorePosition {
                                    commit_revision: value.commit_revision,
                                    ordinal: value.ordinal,
                                }),
                                floor: floor.map(|value| proto::StorePosition {
                                    commit_revision: value.commit_revision,
                                    ordinal: value.ordinal,
                                }),
                            };
                            self.pending = Some(QueryTransport::code(code));
                            return Poll::Ready(Some(Ok(
                                self.frame(proto::trace_frame::Payload::Error(error))
                            )));
                        }
                        QueryPayload::Terminal { reason, .. } => {
                            self.done = true;
                            let code = match reason {
                                araphor_data::QueryTerminalReason::OutputTimeout => {
                                    araphor_data::QueryErrorCode::OutputTimeout
                                }
                                araphor_data::QueryTerminalReason::Cancelled => {
                                    araphor_data::QueryErrorCode::Cancelled
                                }
                                _ => araphor_data::QueryErrorCode::StorageUnavailable,
                            };
                            return Poll::Ready(Some(Err(QueryTransport::code(code))));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
