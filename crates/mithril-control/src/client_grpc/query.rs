use std::mem::size_of;
use std::sync::Arc;
use std::time::Duration;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, GraphTraversalV1, StorageHealthV1};
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use araphor_query::follow::{
    Action, Consumer, Cursor, Delivery, Subscription, SystemClock, Update,
};
use araphor_query::Failure;
use arrow_schema::SchemaRef;
use sha2::{Digest as _, Sha256};
use tokio::time::Instant;
use tonic::Status;

use super::wire::{Parameters, Wire};
use super::{proto, ClientAccess, ClientGrpcOwner};

pub(super) struct QueryEncoder {
    access: Arc<ClientAccess>,
    expires: Instant,
    schema: SchemaRef,
    moving: Option<u64>,
    row_limit: usize,
    byte_limit: usize,
}

impl ClientGrpcOwner {
    pub(super) async fn subscription(
        &self,
        request: proto::QueryRequest,
        selection: AnalysisSelectionV1,
        access: &ClientAccess,
    ) -> Result<Subscription, Status> {
        access.check().map_err(Self::auth_failure)?;
        if selection.tenant_id != access.tenant_id() {
            return Err(Self::query_code(Failure::Denied));
        }
        let scope =
            rmp_serde::to_vec_named(&(access.principal(), access.revision(), access.tenant_id()))
                .map_err(|_| Status::internal("The query scope cannot be encoded."))?;
        let binding = Sha256::digest(scope);
        let parameters = Parameters::try_from(request.parameters)?.0;
        let resume = Self::query_cursor(&request.bookmark)?;
        let control = Arc::new(
            AnalysisReadControl::with_timeout(Duration::from_nanos(
                access.expires_ns().saturating_sub(Self::now()?).max(1),
            ))
            .map_err(Self::failure)?,
        );
        let inner = self
            .data()?
            .query
            .subscribe(
                &request.sql,
                parameters,
                selection,
                control,
                &binding,
                resume,
                Arc::new(SystemClock::default()),
                request.follow,
            )
            .await
            .map_err(Self::query_failure)?;
        access.check().map_err(Self::auth_failure)?;
        Ok(inner)
    }

    pub(super) async fn query_request(
        &self,
        mut request: proto::QueryRequest,
        access: Arc<ClientAccess>,
    ) -> Result<Delivery<QueryEncoder>, Status> {
        if request.duration_ns == Some(0) {
            return Err(Status::invalid_argument("The follow duration is empty."));
        }
        if !request.follow && request.duration_ns.is_some() {
            return Err(Status::invalid_argument("Duration requires follow."));
        }
        let mut selection = self.select(request.selection.take(), access.tenant_id())?;
        if let Some(traversal) = request.graph_traversal.take() {
            if request.follow || !request.bookmark.is_empty() {
                return Err(Status::unimplemented(
                    "Graph traversal does not support follow or bookmarks.",
                ));
            }
            let traversal = GraphTraversalV1::try_from(traversal.definition_json.as_slice())
                .map_err(Self::failure)?;
            if traversal
                .seeds
                .iter()
                .any(|seed| seed.tenant_id != access.tenant_id())
            {
                return Err(Self::query_code(Failure::Denied));
            }
            selection
                .select_graphs(araphor_data::Selection::All, Some(traversal))
                .map_err(Self::failure)?;
        }
        if !request.follow && !request.bookmark.is_empty() {
            return Err(Self::query_code(Failure::InvalidCheckpoint));
        }
        let duration = request.duration_ns;
        let inner = self.subscription(request, selection, &access).await?;
        let encoder = QueryEncoder {
            schema: inner.schema(),
            moving: inner.moving_resolution_ns(),
            row_limit: self.data()?.query.limits().output_rows,
            byte_limit: self.data()?.query.limits().output_bytes,
            expires: Instant::now()
                + Duration::from_nanos(access.expires_ns().saturating_sub(Self::now()?)),
            access,
        };
        Delivery::new(
            inner,
            encoder,
            duration.map(|duration| Instant::now() + Duration::from_nanos(duration)),
            self.data()?.output_timeout,
            None,
        )
        .map_err(Self::query_failure)
    }

    pub(super) fn query_cursor(bytes: &[u8]) -> Result<Option<Cursor>, Status> {
        if bytes.is_empty() {
            Ok(None)
        } else {
            Cursor::decode(bytes).map(Some).map_err(Self::query_failure)
        }
    }

    pub(super) fn query_failure(error: araphor_query::Error) -> Status {
        Self::query_code(Failure::from(&error))
    }

    pub(super) fn query_reason(code: Failure) -> &'static str {
        match code {
            Failure::InvalidQuery => "The query is invalid.",
            Failure::InvalidCheckpoint => "The checkpoint does not match this query or store.",
            Failure::Unsupported => "A required query relation is unavailable.",
            Failure::InputTooLarge => "The complete query input exceeds its bound.",
            Failure::ResultTooLarge => "The query output exceeds its bound.",
            Failure::CursorExpired => "The checkpoint cannot replay retained history.",
            Failure::Cancelled => "The query was cancelled.",
            Failure::DeadlineExceeded => "The query reached its deadline.",
            Failure::Busy => "Query admission is full.",
            Failure::Denied => "Query disclosure is not authorized.",
            Failure::StorageUnavailable => "Query storage is unavailable.",
            Failure::OutputTimeout => "The query output wait reached its deadline.",
            Failure::EvaluationFailed => "The query evaluation failed.",
        }
    }

    pub(super) fn query_code(code: Failure) -> Status {
        let status = match code {
            Failure::InvalidQuery | Failure::InvalidCheckpoint => tonic::Code::InvalidArgument,
            Failure::CursorExpired => tonic::Code::OutOfRange,
            Failure::Denied => tonic::Code::PermissionDenied,
            Failure::Unsupported => tonic::Code::Unimplemented,
            Failure::InputTooLarge | Failure::ResultTooLarge | Failure::Busy => {
                tonic::Code::ResourceExhausted
            }
            Failure::Cancelled => tonic::Code::Cancelled,
            Failure::DeadlineExceeded | Failure::OutputTimeout => tonic::Code::DeadlineExceeded,
            Failure::StorageUnavailable => tonic::Code::Unavailable,
            Failure::EvaluationFailed => tonic::Code::Internal,
        };
        Status::new(status, Self::query_reason(code))
    }

    pub(super) fn frame_memory(
        reservation: &mut MemoryReservation,
        bytes: usize,
        limit: usize,
    ) -> Result<(), Status> {
        if bytes > limit {
            return Err(Self::query_code(Failure::ResultTooLarge));
        }
        reservation
            .try_resize(bytes)
            .map_err(|_| Self::query_code(Failure::Busy))
    }

    pub(super) fn query_error(
        code: Failure,
        cause: Option<&araphor_query::Error>,
        cursor: Option<&Cursor>,
    ) -> Result<proto::QueryError, Status> {
        let mut current = cause.map(|error| error as &(dyn std::error::Error + 'static));
        let (mut position, mut floor) = (None, None);
        while let Some(error) = current {
            let data =
                error
                    .downcast_ref::<araphor_data::Error>()
                    .or_else(|| match error.downcast_ref::<araphor_query::Error>() {
                        Some(araphor_query::Error::Data { source }) => Some(source),
                        _ => None,
                    });
            if let Some(araphor_data::Error::AnalysisReplayExpired {
                position: replay,
                floor: retained,
                ..
            }) = data
            {
                position = Some(*replay);
                floor = Some(*retained);
                break;
            }
            current = error.source();
        }
        Ok(proto::QueryError {
            code: format!("{code:?}"),
            reason: Self::query_reason(code).into(),
            last_checkpoint: Wire::bookmark(cursor)?,
            position: position.map(Wire::position),
            floor: floor.map(Wire::position),
        })
    }

    pub(super) fn query_health(update: &Update, health: StorageHealthV1) -> proto::QueryHealth {
        proto::QueryHealth {
            dependency_revision: update.snapshot.page.extraction.meta.commit_revision,
            write_ready: health.write_ready,
            retention_healthy: health.retention_healthy,
            intake_capacity: health.intake_capacity,
            maintenance_capacity: health.maintenance_capacity,
        }
    }
}

impl Consumer for QueryEncoder {
    type Item = proto::QueryFrame;
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
        usize::from(update.batches.is_some())
    }

    fn encode(
        &mut self,
        action: Action<'_>,
        update: &Update,
        memory: &mut MemoryReservation,
    ) -> Result<Self::Item, Status> {
        let bytes = match &action {
            Action::Metadata => {
                size_of::<proto::QueryMetadata>()
                    + 128
                    + self
                        .schema
                        .fields()
                        .iter()
                        .map(|field| Wire::column_bytes(field))
                        .sum::<usize>()
            }
            Action::Row(_) => {
                let batches = update
                    .batches
                    .as_ref()
                    .ok_or_else(|| Status::internal("Query row batches are absent."))?;
                Wire::conversion_bytes(batches)?
                    .saturating_add(
                        update
                            .positions
                            .len()
                            .saturating_mul(size_of::<proto::StorePosition>()),
                    )
                    .saturating_add(Wire::row_receipts(&update.snapshot))
            }
            _ => 2048,
        };
        ClientGrpcOwner::frame_memory(
            memory,
            Wire::receipt_bytes(&update.snapshot).saturating_add(bytes),
            self.byte_limit,
        )?;
        let payload = match action {
            Action::Metadata => proto::query_frame::Payload::Metadata(proto::QueryMetadata {
                columns: self
                    .schema
                    .fields()
                    .iter()
                    .map(|field| Wire::column(field))
                    .collect(),
                evaluated_utc_ns: update.evaluated_utc_ns,
                dependency_revision: update.snapshot.page.extraction.meta.commit_revision,
                row_limit: self.row_limit as u64,
                byte_limit: self.byte_limit as u64,
                moving_resolution_ns: self.moving,
                resume_semantics: if update.operation == araphor_query::follow::Operation::Append {
                    "Resume after the committed position."
                } else {
                    "Resume with current state."
                }
                .into(),
            }),
            Action::Row(_) => proto::query_frame::Payload::Rows(Wire::rows(
                update
                    .batches
                    .as_ref()
                    .ok_or_else(|| Status::internal("Query row batches are absent."))?,
                &update.snapshot,
                &update.positions,
                update.evaluated_utc_ns,
                update.limited,
            )?),
            Action::Checkpoint => {
                proto::query_frame::Payload::Checkpoint(Wire::bookmark(Some(&update.cursor))?)
            }
            Action::Health(health) => {
                proto::query_frame::Payload::Health(ClientGrpcOwner::query_health(update, health))
            }
            Action::Error {
                failure,
                cause,
                last,
            } => proto::query_frame::Payload::Error(ClientGrpcOwner::query_error(
                failure, cause, last,
            )?),
            Action::Complete { last } => {
                proto::query_frame::Payload::Terminal(proto::QueryTerminal {
                    reason: "Completed".into(),
                    last_checkpoint: Wire::bookmark(last)?,
                })
            }
        };
        let mut frame = Wire::header(&update.snapshot, update.operation, update.clock_changed);
        frame.payload = Some(payload);
        Ok(frame)
    }

    fn initial_error(
        &mut self,
        failure: Failure,
        cause: &araphor_query::Error,
        snapshot: &araphor_query::sources::ArrowSnapshot,
        operation: araphor_query::follow::Operation,
        memory: &mut MemoryReservation,
    ) -> Result<Self::Item, Status> {
        ClientGrpcOwner::frame_memory(
            memory,
            Wire::receipt_bytes(snapshot).saturating_add(2048),
            self.byte_limit,
        )?;
        let mut frame = Wire::header(snapshot, operation, false);
        frame.payload = Some(proto::query_frame::Payload::Error(
            ClientGrpcOwner::query_error(failure, Some(cause), None)?,
        ));
        Ok(frame)
    }

    fn complete_after_checkpoint(&self, _update: &Update) -> bool {
        false
    }

    fn deadline_completes(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_pressure_keeps_category() -> Result<(), Box<dyn std::error::Error>> {
        let memory = araphor_query::memory::Memory::new(Some(8), Some(8));
        let _held = memory.reserve_input(8)?;
        let pressure = araphor_query::Error::Sql {
            source: memory
                .reserve_input(1)
                .err()
                .ok_or("the pool capacity is held")?,
        };
        assert_eq!(Failure::from(&pressure), Failure::Busy);
        assert_eq!(
            ClientGrpcOwner::query_code(Failure::from(&pressure)).code(),
            tonic::Code::ResourceExhausted
        );
        let oversize = araphor_query::Error::Sql {
            source: memory
                .reserve_input(9)
                .err()
                .ok_or("the allocation exceeds capacity")?,
        };
        assert_eq!(Failure::from(&oversize), Failure::InputTooLarge);
        assert_eq!(
            ClientGrpcOwner::query_reason(Failure::from(&oversize)),
            "The complete query input exceeds its bound."
        );
        Ok(())
    }
}
