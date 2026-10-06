use std::{future::Future, io, pin::Pin, time::Duration};

use erebor_runtime_client::AraphorClient;
use erebor_runtime_ipc::araphor as wire;
use tokio::time::Instant;

mod args;
pub(crate) mod error;
mod output;

use args::Prepared;
pub(crate) use args::{AraphorArgs, AraphorCli};
use error::{AraphorCommandError as Error, Result};
use output::Output;

type Interrupt = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

pub(crate) struct AraphorCommandOwner<'a> {
    args: &'a AraphorArgs,
}

impl<'a> AraphorCommandOwner<'a> {
    pub(crate) fn new(args: &'a AraphorArgs) -> Self {
        Self { args }
    }

    pub(crate) fn execute(&self) -> std::result::Result<(), crate::error::CliError> {
        let runtime = tokio::runtime::Runtime::new().map_err(|source| {
            Self::cli(Error::Runtime {
                source,
                location: snafu::Location::default(),
            })
        })?;
        let result = runtime.block_on(self.run());
        runtime.shutdown_timeout(Duration::from_secs(1));
        result.map_err(Self::cli)
    }

    async fn run(&self) -> Result<()> {
        let prepared = self.args.prepare()?;
        let profile = self.args.connection()?;
        let mut signal: Interrupt = Box::pin(tokio::signal::ctrl_c());
        let client = tokio::select! {
            biased;
            _ = signal.as_mut() => return Err(CommandRun::interrupted()),
            result = AraphorClient::connect(profile) => result.map_err(CommandRun::client_error)?,
        };
        let mut run = CommandRun {
            client,
            output: Output::new(self.args.output),
            signal,
        };
        match prepared {
            Prepared::Sql { request, duration } => run.sql(request, duration).await,
            Prepared::Trace { request, trace_id } => run.trace(request, trace_id).await,
        }
    }

    fn cli(source: Error) -> crate::error::CliError {
        crate::error::CliError::Araphor {
            source: Box::new(source),
            location: snafu::Location::default(),
        }
    }
}

struct CommandRun {
    client: AraphorClient,
    output: Output,
    signal: Interrupt,
}

impl CommandRun {
    async fn sql(
        &mut self,
        mut request: wire::QueryRequest,
        duration: Option<Duration>,
    ) -> Result<()> {
        let deadline = duration.and_then(|duration| Instant::now().checked_add(duration));
        let wait = async {
            if let Some(deadline) = deadline {
                tokio::time::sleep_until(deadline).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(wait);
        let mut replay = QueryReplay::default();
        let mut stream: Option<tonic::Streaming<wire::QueryFrame>> = None;
        let mut retries = 0;
        loop {
            if stream.is_none() {
                request.bookmark.clone_from(&replay.bookmark);
                let result = tokio::select! {
                    _ = self.signal.as_mut() => return Err(Self::interrupted()),
                    _ = &mut wait => return replay.duration(),
                    result = self.client.query(request.clone()) => result,
                };
                match result {
                    Ok(opened) => stream = Some(opened),
                    Err(error) if error.retryable() && retries < 3 => {
                        retries += 1;
                        self.pause(retries).await?;
                        continue;
                    }
                    Err(error) => return Err(Self::client_error(error)),
                }
            }
            let opened = stream
                .as_mut()
                .ok_or_else(|| Self::protocol("query stream"))?;
            let next = tokio::select! {
                _ = self.signal.as_mut() => return Err(Self::interrupted()),
                _ = &mut wait => return replay.duration(),
                result = opened.message() => result,
            };
            let mut frame = match next {
                Ok(Some(frame)) => frame,
                Ok(None) if retries < 3 => {
                    retries += 1;
                    stream = None;
                    self.pause(retries).await?;
                    continue;
                }
                Ok(None) => return Err(Self::uncertain()),
                Err(status) => {
                    let error = AraphorClient::rpc_error(status);
                    if error.retryable() && retries < 3 {
                        retries += 1;
                        stream = None;
                        self.pause(retries).await?;
                        continue;
                    }
                    return Err(Self::client_error(error));
                }
            };
            if replay.advance(&mut frame)? {
                let bytes = self.output.query(&frame)?;
                tokio::select! {
                    _ = self.signal.as_mut() => return Err(Self::interrupted()),
                    _ = &mut wait => return Err(Error::OutputDeadline { location: snafu::Location::default() }),
                    result = self.output.write(&bytes) => result?,
                }
            }
            match frame.payload.as_ref() {
                Some(wire::query_frame::Payload::Error(error)) => {
                    return Err(Self::query_error(&error.code));
                }
                Some(wire::query_frame::Payload::Terminal(terminal)) => {
                    return match terminal.reason.as_str() {
                        "Completed" => replay.complete(),
                        "Cancelled" => Err(Self::interrupted()),
                        "OutputTimeout" => Err(Error::OutputDeadline {
                            location: snafu::Location::default(),
                        }),
                        _ => Err(Self::uncertain()),
                    };
                }
                _ => {}
            }
        }
    }

    async fn trace(
        &mut self,
        request: Option<wire::SubmitTraceRequest>,
        trace_id: Vec<u8>,
    ) -> Result<()> {
        let initiator = request.is_some();
        let mut replay = TraceReplay::default();
        let result = self.trace_read(request, &trace_id, &mut replay).await;
        if result.is_err() && initiator && !replay.finished {
            let cancel = self
                .client
                .cancel_trace(wire::CancelTraceRequest {
                    trace_id: trace_id.clone(),
                })
                .await;
            if matches!(&cancel, Ok(receipt) if receipt.trace_id == trace_id && receipt.cancel_requested)
            {
                let print = !matches!(
                    &result,
                    Err(Error::Output { .. } | Error::OutputDeadline { .. })
                );
                let drained = tokio::time::timeout(
                    Duration::from_secs(10),
                    self.trace_drain(&trace_id, &mut replay, print),
                )
                .await;
                if !matches!(drained, Ok(Ok(()))) {
                    eprintln!("Final cleanup is not confirmed. Node lease expiry still applies.");
                }
            } else {
                eprintln!("Cancellation is not confirmed. Node lease expiry still applies.");
            }
        }
        result
    }

    async fn trace_read(
        &mut self,
        request: Option<wire::SubmitTraceRequest>,
        trace_id: &[u8],
        replay: &mut TraceReplay,
    ) -> Result<()> {
        let receipt = if let Some(request) = request {
            tokio::select! {
                _ = self.signal.as_mut() => return Err(Self::interrupted()),
                result = self.client.submit_trace(request) => result.map_err(Self::client_error)?,
            }
        } else {
            let detail = tokio::select! {
                _ = self.signal.as_mut() => return Err(Self::interrupted()),
                result = self.client.get_trace(wire::GetTraceRequest { trace_id: trace_id.to_vec() }) => result.map_err(Self::client_error)?,
            };
            detail
                .receipt
                .ok_or_else(|| Self::protocol("trace receipt"))?
        };
        if receipt.trace_id != trace_id
            || receipt.source_sha256.len() != 32
            || receipt.deadline_unix_ns < receipt.accepted_unix_ns
        {
            return Err(Self::protocol("trace receipt identity or bounds"));
        }
        let bytes = self.output.receipt(&receipt)?;
        tokio::select! {
            _ = self.signal.as_mut() => return Err(Self::interrupted()),
            result = self.output.write(&bytes) => result?,
        }
        let mut stream: Option<tonic::Streaming<wire::TraceFrame>> = None;
        let mut retries = 0;
        loop {
            if stream.is_none() {
                let result = tokio::select! {
                    _ = self.signal.as_mut() => return Err(Self::interrupted()),
                    result = self.client.watch_trace(wire::WatchTraceRequest { trace_id: trace_id.to_vec(), bookmark: replay.bookmark.clone() }) => result,
                };
                match result {
                    Ok(opened) => stream = Some(opened),
                    Err(error) if error.retryable() && retries < 3 => {
                        retries += 1;
                        self.pause(retries).await?;
                        continue;
                    }
                    Err(error) => return Err(Self::client_error(error)),
                }
            }
            let opened = stream
                .as_mut()
                .ok_or_else(|| Self::protocol("trace stream"))?;
            let next = tokio::select! {
                _ = self.signal.as_mut() => return Err(Self::interrupted()),
                result = opened.message() => result,
            };
            let frame = match next {
                Ok(Some(frame)) => frame,
                Ok(None) if retries < 3 => {
                    retries += 1;
                    stream = None;
                    self.pause(retries).await?;
                    continue;
                }
                Ok(None) => return Err(Self::uncertain()),
                Err(status) => {
                    let error = AraphorClient::rpc_error(status);
                    if error.retryable() && retries < 3 {
                        retries += 1;
                        stream = None;
                        self.pause(retries).await?;
                        continue;
                    }
                    return Err(Self::client_error(error));
                }
            };
            if replay.advance(&frame, trace_id)? {
                let bytes = self.output.trace(&frame)?;
                tokio::select! {
                    _ = self.signal.as_mut() => return Err(Self::interrupted()),
                    result = self.output.write(&bytes) => result?,
                }
            }
            if let Some(wire::trace_frame::Payload::Error(error)) = frame.payload.as_ref() {
                return Err(Self::query_error(&error.code));
            }
            if replay.finished {
                return Self::complete(replay.partial);
            }
        }
    }

    async fn trace_drain(
        &mut self,
        trace_id: &[u8],
        replay: &mut TraceReplay,
        print: bool,
    ) -> Result<()> {
        let mut stream = self
            .client
            .watch_trace(wire::WatchTraceRequest {
                trace_id: trace_id.to_vec(),
                bookmark: replay.bookmark.clone(),
            })
            .await
            .map_err(Self::client_error)?;
        while let Some(frame) = stream
            .message()
            .await
            .map_err(|status| Self::client_error(AraphorClient::rpc_error(status)))?
        {
            if replay.advance(&frame, trace_id)? && print {
                let bytes = self.output.trace(&frame)?;
                self.output.write(&bytes).await?;
            }
            if replay.finished {
                return Self::complete(replay.partial);
            }
        }
        Err(Self::uncertain())
    }

    async fn pause(&mut self, retries: u64) -> Result<()> {
        tokio::select! {
            _ = self.signal.as_mut() => Err(Self::interrupted()),
            _ = tokio::time::sleep(Duration::from_millis(250 * retries)) => Ok(()),
        }
    }

    fn complete(partial: bool) -> Result<()> {
        if partial {
            Err(Error::Partial {
                location: snafu::Location::default(),
            })
        } else {
            Ok(())
        }
    }
    fn interrupted() -> Error {
        Error::Interrupted {
            location: snafu::Location::default(),
        }
    }
    fn uncertain() -> Error {
        Error::Uncertain {
            location: snafu::Location::default(),
        }
    }
    fn protocol(field: &'static str) -> Error {
        Error::Protocol {
            field,
            location: snafu::Location::default(),
        }
    }
    fn client_error(source: erebor_runtime_client::AraphorError) -> Error {
        Error::Client {
            source,
            location: snafu::Location::default(),
        }
    }

    fn query_error(code: &str) -> Error {
        match code {
            "InvalidQuery" | "InvalidCheckpoint" => Error::Invalid {
                field: "query or bookmark",
                location: snafu::Location::default(),
            },
            "InputTooLarge" | "ResultTooLarge" => Error::Partial {
                location: snafu::Location::default(),
            },
            "DeadlineExceeded" | "OutputTimeout" => Error::OutputDeadline {
                location: snafu::Location::default(),
            },
            "Cancelled" => Self::interrupted(),
            "CursorExpired" => Self::client_error(AraphorClient::rpc_error(
                tonic::Status::out_of_range("retained history expired"),
            )),
            "Denied" => Self::client_error(AraphorClient::rpc_error(
                tonic::Status::permission_denied("investigate permission denied"),
            )),
            "Unsupported" => Self::client_error(AraphorClient::rpc_error(
                tonic::Status::unimplemented("query operation is unsupported"),
            )),
            "Busy" => Self::client_error(AraphorClient::rpc_error(
                tonic::Status::resource_exhausted("query capacity is unavailable"),
            )),
            "StorageUnavailable" => Self::client_error(AraphorClient::rpc_error(
                tonic::Status::unavailable("query storage is unavailable"),
            )),
            _ => Self::client_error(AraphorClient::rpc_error(tonic::Status::internal(
                "query failed",
            ))),
        }
    }
}

#[derive(Default)]
struct QueryReplay {
    identity: Option<(Vec<u8>, u64, i32)>,
    bookmark: Vec<u8>,
    position: Option<(u64, u32)>,
    metadata: bool,
    partial: bool,
    pending: bool,
}

impl QueryReplay {
    fn duration(&self) -> Result<()> {
        if self.bookmark.is_empty() {
            return Err(Error::OutputDeadline {
                location: snafu::Location::default(),
            });
        }
        self.complete()
    }

    fn complete(&self) -> Result<()> {
        CommandRun::complete(self.partial || self.pending)
    }

    fn advance(&mut self, frame: &mut wire::QueryFrame) -> Result<bool> {
        if frame.schema_version != 1
            || frame.store_uuid.len() != 16
            || !matches!(frame.operation, 1 | 2)
        {
            return Err(CommandRun::protocol("query envelope"));
        }
        let identity = (
            frame.store_uuid.clone(),
            frame.recovery_epoch,
            frame.operation,
        );
        if self
            .identity
            .as_ref()
            .is_some_and(|current| *current != identity)
        {
            return Err(CommandRun::protocol(
                "query store or operation changed during reconnect",
            ));
        }
        self.identity = Some(identity);
        match frame
            .payload
            .as_mut()
            .ok_or_else(|| CommandRun::protocol("query payload"))?
        {
            wire::query_frame::Payload::Metadata(_) => self.metadata = true,
            wire::query_frame::Payload::Rows(rows) => {
                if !self.metadata {
                    return Err(CommandRun::protocol("query rows before metadata"));
                }
                self.partial |= rows.limited || !rows.missing_contexts.is_empty();
                if frame.operation == wire::QueryOperation::Append as i32 {
                    if rows.rows.len() != rows.positions.len() {
                        return Err(CommandRun::protocol("append row positions"));
                    }
                    let mut previous = None;
                    for position in &rows.positions {
                        let position = (position.commit_revision, position.ordinal);
                        if position.0 > frame.read_revision
                            || previous.is_some_and(|previous| previous >= position)
                        {
                            return Err(CommandRun::protocol("append position order or revision"));
                        }
                        previous = Some(position);
                    }
                    let before = self.position;
                    let count = rows.rows.len();
                    let positions = &rows.positions;
                    let mut index = 0;
                    rows.rows.retain(|_| {
                        let position = &positions[index];
                        index += 1;
                        before.is_none_or(|before| {
                            (position.commit_revision, position.ordinal) > before
                        })
                    });
                    rows.positions.retain(|position| {
                        before.is_none_or(|before| {
                            (position.commit_revision, position.ordinal) > before
                        })
                    });
                    if let Some(position) = previous {
                        self.position = Some(
                            self.position
                                .map_or(position, |before| before.max(position)),
                        );
                    }
                    if count != 0 && rows.rows.is_empty() {
                        return Ok(false);
                    }
                }
                self.pending = true;
            }
            wire::query_frame::Payload::Checkpoint(bookmark) => {
                if bookmark.is_empty() || bookmark.len() > 1024 {
                    return Err(CommandRun::protocol("query bookmark bound"));
                }
                self.bookmark.clone_from(bookmark);
                self.pending = false;
            }
            _ => {}
        }
        Ok(true)
    }
}

#[derive(Default)]
struct TraceReplay {
    identity: Option<(Vec<u8>, u64)>,
    bookmark: Vec<u8>,
    position: Option<(u64, u32)>,
    metadata: bool,
    partial: bool,
    finished: bool,
}

impl TraceReplay {
    fn advance(&mut self, frame: &wire::TraceFrame, trace_id: &[u8]) -> Result<bool> {
        if frame.schema_version != 1
            || frame.trace_id != trace_id
            || frame.store_uuid.len() != 16
            || frame.bookmark.len() > 2048
        {
            return Err(CommandRun::protocol("trace identity or bookmark bound"));
        }
        let identity = (frame.store_uuid.clone(), frame.recovery_epoch);
        if self
            .identity
            .as_ref()
            .is_some_and(|current| *current != identity)
        {
            return Err(CommandRun::protocol("trace store changed during reconnect"));
        }
        self.identity = Some(identity);
        let payload = frame
            .payload
            .as_ref()
            .ok_or_else(|| CommandRun::protocol("trace payload"))?;
        if matches!(payload, wire::trace_frame::Payload::Metadata(_)) {
            self.metadata = true;
        }
        if !frame.bookmark.is_empty() {
            self.bookmark.clone_from(&frame.bookmark);
        }
        if matches!(
            payload,
            wire::trace_frame::Payload::Output(_) | wire::trace_frame::Payload::Terminal(_)
        ) {
            if !self.metadata
                || frame.execution_id.len() != 16
                || frame.commit_revision > frame.read_revision
            {
                return Err(CommandRun::protocol("trace execution identity or revision"));
            }
            let position = (frame.commit_revision, frame.ordinal);
            if self.position.is_some_and(|before| position <= before) {
                return Ok(false);
            }
            self.position = Some(position);
        }
        if let wire::trace_frame::Payload::Terminal(terminal) = payload {
            self.partial |= terminal.output_incomplete
                || terminal.kernel_lost_events.is_some_and(|lost| lost != 0);
        }
        if let wire::trace_frame::Payload::Result(result) = payload {
            self.finished = true;
            self.partial |= !result.complete
                || result.output_incomplete
                || !result.cleanup_complete
                || !result.missing_targets.is_empty();
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_cli_append_replay() -> Result<()> {
        let mut replay = QueryReplay::default();
        let mut frame = wire::QueryFrame {
            schema_version: 1,
            operation: 1,
            store_uuid: vec![1; 16],
            read_revision: 9,
            payload: Some(wire::query_frame::Payload::Metadata(
                wire::QueryMetadata::default(),
            )),
            ..Default::default()
        };
        replay.advance(&mut frame)?;
        frame.payload = Some(wire::query_frame::Payload::Rows(wire::QueryRows {
            rows: vec![wire::QueryRow::default(), wire::QueryRow::default()],
            positions: vec![
                wire::StorePosition {
                    commit_revision: 8,
                    ordinal: 0,
                },
                wire::StorePosition {
                    commit_revision: 9,
                    ordinal: 0,
                },
            ],
            ..Default::default()
        }));
        assert!(replay.advance(&mut frame)?);
        assert!(!replay.advance(&mut frame)?);
        frame.recovery_epoch += 1;
        assert!(replay.advance(&mut frame).is_err());
        Ok(())
    }

    #[test]
    fn observability_cli_global_terminal() -> Result<()> {
        let mut replay = TraceReplay::default();
        let mut frame = wire::TraceFrame {
            schema_version: 1,
            trace_id: vec![1; 16],
            execution_id: vec![2; 16],
            store_uuid: vec![3; 16],
            read_revision: 3,
            commit_revision: 3,
            payload: Some(wire::trace_frame::Payload::Metadata(
                wire::TraceDetail::default(),
            )),
            ..Default::default()
        };
        replay.advance(&frame, &[1; 16])?;
        frame.payload = Some(wire::trace_frame::Payload::Terminal(
            wire::TraceTerminal::default(),
        ));
        replay.advance(&frame, &[1; 16])?;
        assert!(!replay.finished);
        assert!(!replay.advance(&frame, &[1; 16])?);
        frame.payload = Some(wire::trace_frame::Payload::Checkpoint(
            wire::TraceCheckpoint {},
        ));
        frame.bookmark = vec![7, 8, 9];
        replay.advance(&frame, &[1; 16])?;
        assert_eq!(replay.bookmark, vec![7, 8, 9]);
        frame.payload = Some(wire::trace_frame::Payload::Result(wire::TraceResult {
            complete: true,
            cleanup_complete: true,
            ..Default::default()
        }));
        replay.advance(&frame, &[1; 16])?;
        assert!(replay.finished);
        assert!(!replay.partial);
        frame.recovery_epoch += 1;
        assert!(replay.advance(&frame, &[1; 16]).is_err());
        Ok(())
    }

    #[test]
    fn observability_cli_exit_codes() {
        use erebor_runtime_error::{ErrorExt, StatusCode};

        assert_eq!(CommandRun::interrupted().exit_code(), 130);
        assert_eq!(CommandRun::uncertain().exit_code(), 4);
        for (code, exit, status) in [
            ("Denied", 3, StatusCode::PermissionDenied),
            ("CursorExpired", 4, StatusCode::IllegalState),
            ("InvalidQuery", 2, StatusCode::InvalidArguments),
            ("InvalidCheckpoint", 2, StatusCode::InvalidArguments),
            ("InputTooLarge", 4, StatusCode::IllegalState),
            ("ResultTooLarge", 4, StatusCode::IllegalState),
            ("Cancelled", 130, StatusCode::Cancelled),
            ("DeadlineExceeded", 4, StatusCode::DeadlineExceeded),
            ("OutputTimeout", 4, StatusCode::DeadlineExceeded),
            ("Unsupported", 5, StatusCode::Unsupported),
            ("Busy", 5, StatusCode::Unavailable),
            ("StorageUnavailable", 5, StatusCode::Unavailable),
            ("EvaluationFailed", 5, StatusCode::Internal),
            ("Unknown", 5, StatusCode::Internal),
        ] {
            let error = CommandRun::query_error(code);
            assert_eq!(error.exit_code(), exit, "{code}");
            assert_eq!(error.status_code(), status, "{code}");
        }
        let mut replay = QueryReplay::default();
        assert_eq!(
            replay.duration().err().map(|error| error.exit_code()),
            Some(4)
        );
        replay.bookmark = vec![1];
        assert!(replay.duration().is_ok());
    }

    #[test]
    fn observability_cli_pending_result() -> Result<()> {
        let mut replay = QueryReplay::default();
        let mut frame = wire::QueryFrame {
            schema_version: 1,
            operation: wire::QueryOperation::Replace as i32,
            store_uuid: vec![1; 16],
            read_revision: 1,
            payload: Some(wire::query_frame::Payload::Metadata(
                wire::QueryMetadata::default(),
            )),
            ..Default::default()
        };
        replay.advance(&mut frame)?;
        frame.payload = Some(wire::query_frame::Payload::Checkpoint(vec![1]));
        replay.advance(&mut frame)?;
        assert!(replay.duration().is_ok());
        assert!(replay.complete().is_ok());

        frame.read_revision = 2;
        frame.payload = Some(wire::query_frame::Payload::Rows(wire::QueryRows {
            rows: vec![wire::QueryRow::default()],
            ..Default::default()
        }));
        assert!(replay.advance(&mut frame)?);
        assert_eq!(
            replay.duration().err().map(|error| error.exit_code()),
            Some(4)
        );
        frame.payload = Some(wire::query_frame::Payload::Terminal(wire::QueryTerminal {
            reason: "Completed".into(),
            last_checkpoint: vec![1],
        }));
        replay.advance(&mut frame)?;
        assert_eq!(
            replay.complete().err().map(|error| error.exit_code()),
            Some(4)
        );

        frame.payload = Some(wire::query_frame::Payload::Checkpoint(vec![2]));
        replay.advance(&mut frame)?;
        assert!(replay.duration().is_ok());
        assert!(replay.complete().is_ok());
        Ok(())
    }
}
