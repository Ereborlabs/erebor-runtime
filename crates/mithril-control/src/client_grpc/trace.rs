use std::sync::Arc;
use std::time::Duration;

use araphor_data::Selection;
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use araphor_query::follow::{Action, Consumer, Delivery, Update};
use araphor_query::Failure;
use datafusion_common::ScalarValue;
use tokio::time::Instant;
use tonic::Status;

use super::wire::Wire;
use super::{proto, ClientAccess, ClientGrpcOwner};
use crate::{TraceAcceptedV1, TraceOwner, TraceRecipeV1, TraceRequestV1, TraceSourceV1};

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
    ) -> Result<Delivery<TraceEncoder>, Status> {
        let trace = Self::identity(&input.trace_id)?;
        let (state, accepted) = self.load_trace(trace, &access).await?;
        let mut selection = araphor_data::AnalysisSelectionV1::tenant(access.tenant_id());
        selection.traces = Selection::Exact(
            accepted
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
                .collect::<Result<_, _>>()?,
        );
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
        let request = proto::QueryRequest {
            sql: "SELECT execution_id,target_index,sequence,kind,bytes,commit_revision,ordinal FROM trace_output WHERE request_id = $1".into(),
            parameters: vec![proto::QueryValue { kind: Some(proto::query_value::Kind::Binary(trace.to_vec())) }],
            follow: true,
            bookmark: input.bookmark,
            ..Default::default()
        };
        let stream = self.subscription(request, selection, &access).await?;
        let remaining = accepted.deadline_unix_ns.saturating_sub(Self::now()?);
        let metadata = self
            .data()?
            .query
            .memory()
            .reserve_output(self.data()?.query.limits().output_bytes)
            .map_err(|_| Self::query_code(Failure::Busy))?;
        let detail = Self::trace_detail(&state, &accepted);
        let detail_bytes = Wire::trace_detail_bytes(&detail);
        if detail_bytes > self.data()?.query.limits().output_bytes {
            return Err(Self::query_code(Failure::ResultTooLarge));
        }
        metadata.resize(detail_bytes);
        let encoder = TraceEncoder {
            expires: Instant::now()
                + Duration::from_nanos(access.expires_ns().saturating_sub(Self::now()?)),
            access,
            trace,
            detail: Some(detail),
            terminals,
            unresolved: accepted.request.unresolved.len(),
            byte_limit: self.data()?.query.limits().output_bytes,
        };
        Delivery::new(
            stream,
            encoder,
            Some(
                Instant::now()
                    + Duration::from_nanos(remaining).saturating_add(Duration::from_secs(10)),
            ),
            self.data()?.output_timeout,
            Some(metadata),
        )
        .map_err(Self::query_failure)
    }
}

pub(super) struct TraceEncoder {
    access: Arc<ClientAccess>,
    expires: Instant,
    trace: [u8; 16],
    detail: Option<proto::TraceDetail>,
    terminals: Vec<Option<crate::TraceTerminalV1>>,
    unresolved: usize,
    byte_limit: usize,
}

impl TraceEncoder {
    fn frame(&self, update: &Update, payload: proto::trace_frame::Payload) -> proto::TraceFrame {
        let extraction = &update.snapshot.page.extraction;
        proto::TraceFrame {
            schema_version: 1,
            trace_id: self.trace.to_vec(),
            store_uuid: extraction.meta.store_uuid.as_bytes().to_vec(),
            recovery_epoch: extraction.meta.recovery_epoch,
            read_revision: extraction.meta.commit_revision,
            coverage: extraction.sources.iter().map(Wire::coverage).collect(),
            payload: Some(payload),
            ..Default::default()
        }
    }

    fn result(&self, update: &Update) -> proto::TraceResult {
        let missing: Vec<_> = self
            .terminals
            .iter()
            .enumerate()
            .filter_map(|(index, terminal)| terminal.is_none().then_some(index as u32))
            .collect();
        let complete = update.exhausted && missing.is_empty() && self.unresolved == 0;
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

    fn reserve(
        &self,
        update: &Update,
        memory: &mut MemoryReservation,
        bytes: usize,
    ) -> Result<(), Status> {
        ClientGrpcOwner::frame_memory(
            memory,
            Wire::receipt_bytes(&update.snapshot).saturating_add(bytes),
            self.byte_limit,
        )
    }

    fn output(
        &mut self,
        update: &Update,
        row: usize,
        memory: &mut MemoryReservation,
    ) -> Result<proto::TraceFrame, Status> {
        let batches = update
            .batches
            .as_ref()
            .ok_or_else(|| Status::internal("Trace output batches are absent."))?;
        let mut offset = row;
        let mut selected = None;
        for batch in batches {
            if offset < batch.num_rows() {
                selected = Some(batch);
                break;
            }
            offset -= batch.num_rows();
        }
        let batch = selected.ok_or_else(|| Status::internal("Trace output row is absent."))?;
        if batch.num_columns() < 5 {
            return Err(Status::data_loss("Trace output schema changed."));
        }
        let position = *update
            .positions
            .get(row)
            .ok_or_else(|| Status::data_loss("Trace output has no committed position."))?;
        let bytes = Wire::conversion_bytes(&[batch.slice(offset, 1)])?
            .saturating_mul(2)
            .saturating_add(512);
        self.reserve(update, memory, bytes)?;
        let scalar = |column| {
            ScalarValue::try_from_array(batch.column(column), offset)
                .map_err(|_| Status::data_loss("Trace output schema changed."))
        };
        let [ScalarValue::Binary(Some(execution)), index, sequence, ScalarValue::Utf8(Some(kind)), ScalarValue::Binary(Some(bytes))] =
            [scalar(0)?, scalar(1)?, scalar(2)?, scalar(3)?, scalar(4)?]
        else {
            return Err(Status::data_loss("Trace output schema changed."));
        };
        let number = |value: &ScalarValue| match value {
            ScalarValue::UInt64(Some(value)) => Some(*value),
            ScalarValue::UInt32(Some(value)) => Some(u64::from(*value)),
            ScalarValue::UInt16(Some(value)) => Some(u64::from(*value)),
            _ => None,
        };
        let index = number(&index)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < self.terminals.len())
            .ok_or_else(|| Status::data_loss("Trace target index is invalid."))?;
        let sequence =
            number(&sequence).ok_or_else(|| Status::data_loss("Trace sequence is invalid."))?;
        let payload = if kind == "terminal" {
            let terminal: crate::TraceTerminalV1 = serde_json::from_slice(&bytes)
                .map_err(|_| Status::data_loss("The retained trace terminal is invalid."))?;
            terminal.validate().map_err(ClientGrpcOwner::failure)?;
            if terminal.execution_id.as_slice() != execution.as_slice() {
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
            proto::trace_frame::Payload::Output(proto::TraceOutput { kind, bytes })
        };
        Ok(proto::TraceFrame {
            commit_revision: position.commit_revision,
            ordinal: position.ordinal,
            execution_id: execution,
            sequence,
            target_index: index as u32,
            ..self.frame(update, payload)
        })
    }
}

impl Consumer for TraceEncoder {
    type Item = proto::TraceFrame;
    type Error = Status;

    fn authorize(&self) -> Result<(), Status> {
        self.access.check().map_err(ClientGrpcOwner::auth_failure)
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.access.changes()
    }

    fn expires(&self) -> Instant {
        self.expires
    }

    fn expired(&self) -> Status {
        Status::unauthenticated("Client authentication expired or failed.")
    }

    fn code(&self, code: Failure) -> Status {
        ClientGrpcOwner::query_code(code)
    }

    fn rows(&self, update: &Update) -> usize {
        update.batches.as_ref().map_or(0, |batches| {
            batches.iter().map(arrow_array::RecordBatch::num_rows).sum()
        })
    }

    fn encode(
        &mut self,
        action: Action<'_>,
        update: &Update,
        memory: &mut MemoryReservation,
    ) -> Result<Self::Item, Status> {
        if matches!(&action, Action::Error { .. } | Action::Complete { .. }) {
            self.detail = None;
        }
        if let Action::Row(index) = action {
            return self.output(update, index, memory);
        }
        let bytes = match &action {
            Action::Metadata => {
                2048usize.saturating_add(self.detail.as_ref().map_or(0, Wire::trace_detail_bytes))
            }
            Action::Complete { .. } => 512 + 4 * self.terminals.len(),
            _ => 2048,
        };
        self.reserve(update, memory, bytes)?;
        let bookmark = if matches!(&action, Action::Checkpoint) {
            Some(Wire::bookmark(Some(&update.cursor))?)
        } else {
            None
        };
        let payload = match action {
            Action::Metadata => {
                let detail = self
                    .detail
                    .take()
                    .ok_or_else(|| Status::internal("Trace metadata is absent."))?;
                proto::trace_frame::Payload::Metadata(detail.into())
            }
            Action::Checkpoint => {
                proto::trace_frame::Payload::Checkpoint(proto::TraceCheckpoint {})
            }
            Action::Health(health) => {
                proto::trace_frame::Payload::Health(ClientGrpcOwner::query_health(update, health))
            }
            Action::Error {
                failure,
                cause,
                last,
            } => proto::trace_frame::Payload::Error(ClientGrpcOwner::query_error(
                failure, cause, last,
            )?),
            Action::Complete { .. } => proto::trace_frame::Payload::Result(self.result(update)),
            Action::Row(_) => return Err(Status::internal("Trace row state is invalid.")),
        };
        let mut frame = self.frame(update, payload);
        if let Some(bookmark) = bookmark {
            frame.bookmark = bookmark;
        }
        Ok(frame)
    }

    fn complete_after_checkpoint(&self, update: &Update) -> bool {
        update.exhausted && self.terminals.iter().all(Option::is_some)
    }

    fn deadline_completes(&self) -> bool {
        true
    }
}
