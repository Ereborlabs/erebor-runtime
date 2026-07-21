//! Typed local transport for the daemon-control service.

mod approvals;
mod error;
mod policy;
mod runner;
mod session;

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use erebor_runtime_ipc::{
    v1::{
        DaemonCommandResult, DaemonError, DaemonHello, DaemonHelloAck, DaemonLogRecord,
        DaemonLogsEnd, DaemonLogsRequest, DaemonReloadRequest, DaemonStatusRequest,
        DaemonStatusResponse, DaemonStopRequest, Envelope, Header, EREBOR_IDEMPOTENCY_KEY_HEADER,
        KIND_DAEMON_COMMAND_RESULT, KIND_DAEMON_ERROR, KIND_DAEMON_HELLO, KIND_DAEMON_HELLO_ACK,
        KIND_DAEMON_LOGS_END, KIND_DAEMON_LOGS_REQUEST, KIND_DAEMON_LOG_RECORD,
        KIND_DAEMON_RELOAD_REQUEST, KIND_DAEMON_STATUS_REQUEST, KIND_DAEMON_STATUS_RESPONSE,
        KIND_DAEMON_STOP_REQUEST, PROTOCOL_VERSION,
    },
    AsyncFrameCodec,
};
use snafu::ResultExt;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UnixStream,
};

pub use approvals::{ApprovalPage, ApprovalRecord};
pub use erebor_runtime_ipc::v1::{
    PolicyPackageListResponse, PolicyPackageRecord, PolicySetListResponse, PolicySetRecord,
    PolicyTestResponse,
};
use error::{ConnectSnafu, DaemonSnafu, IpcSnafu, ProtocolSnafu, TimedOutSnafu};
pub use error::{DaemonClientError, Result};
pub use runner::RunnerCapability;
pub use session::{SessionEventPage, SessionEvidencePage, SessionLogPage};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct DaemonClient {
    socket_path: PathBuf,
}

impl DaemonClient {
    #[must_use]
    pub fn local() -> Self {
        Self::at("/run/erebor/daemon.sock")
    }

    #[must_use]
    pub fn at(path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
        }
    }

    pub async fn status(&self) -> Result<DaemonStatusResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_DAEMON_STATUS_REQUEST,
                &DaemonStatusRequest {},
                KIND_DAEMON_STATUS_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn logs(
        &self,
        after_sequence: u64,
        maximum_records: u32,
    ) -> Result<Vec<DaemonLogRecord>> {
        let mut connection = self.connect().await?;
        let request_id = connection
            .send(
                KIND_DAEMON_LOGS_REQUEST,
                &DaemonLogsRequest {
                    after_sequence,
                    maximum_records,
                },
                Vec::new(),
            )
            .await?;
        let mut records = Vec::new();
        loop {
            let envelope = connection.receive(request_id).await?;
            match envelope.message_kind.as_str() {
                KIND_DAEMON_LOG_RECORD => records.push(
                    envelope
                        .decode_typed_payload(KIND_DAEMON_LOG_RECORD)
                        .context(IpcSnafu)?,
                ),
                KIND_DAEMON_LOGS_END => {
                    let _end: DaemonLogsEnd = envelope
                        .decode_typed_payload(KIND_DAEMON_LOGS_END)
                        .context(IpcSnafu)?;
                    return Ok(records);
                }
                KIND_DAEMON_ERROR => return Err(connection.daemon_error(envelope)?),
                actual => {
                    return ProtocolSnafu {
                        reason: format!("unexpected daemon logs response kind `{actual}`"),
                    }
                    .fail()
                }
            }
        }
    }

    pub async fn reload(&self, idempotency_key: &str) -> Result<String> {
        self.mutate(
            KIND_DAEMON_RELOAD_REQUEST,
            &DaemonReloadRequest {},
            idempotency_key,
        )
        .await
    }

    pub async fn stop(&self, idempotency_key: &str) -> Result<String> {
        self.mutate(
            KIND_DAEMON_STOP_REQUEST,
            &DaemonStopRequest {},
            idempotency_key,
        )
        .await
    }

    async fn mutate<T: prost::Message>(
        &self,
        kind: &str,
        request: &T,
        idempotency_key: &str,
    ) -> Result<String> {
        let mut connection = self.connect().await?;
        let result: DaemonCommandResult = connection
            .unary(
                kind,
                request,
                KIND_DAEMON_COMMAND_RESULT,
                vec![Header {
                    key: EREBOR_IDEMPOTENCY_KEY_HEADER.to_string(),
                    value: idempotency_key.to_string(),
                }],
            )
            .await?;
        Ok(result.message)
    }

    async fn connect(&self) -> Result<DaemonConnection> {
        let stream = tokio::time::timeout(REQUEST_TIMEOUT, UnixStream::connect(&self.socket_path))
            .await
            .map_err(|_elapsed| {
                TimedOutSnafu {
                    operation: "connecting to erebord",
                }
                .build()
            })?
            .context(ConnectSnafu {
                path: self.socket_path.clone(),
            })?;
        let mut connection = DaemonConnection {
            stream,
            next_message_id: 1,
        };
        let ack: DaemonHelloAck = connection
            .unary(
                KIND_DAEMON_HELLO,
                &DaemonHello {
                    protocol_version: PROTOCOL_VERSION,
                    client_name: String::from("erebor-runtime-client"),
                    capabilities: Vec::new(),
                },
                KIND_DAEMON_HELLO_ACK,
                Vec::new(),
            )
            .await?;
        if ack.protocol_version != PROTOCOL_VERSION {
            return ProtocolSnafu {
                reason: String::from("daemon negotiated an unsupported protocol version"),
            }
            .fail();
        }
        Ok(connection)
    }
}

struct DaemonConnection<S = UnixStream> {
    stream: S,
    next_message_id: u64,
}

impl<S> DaemonConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn unary<T: prost::Message, R: prost::Message + Default>(
        &mut self,
        kind: &str,
        request: &T,
        response_kind: &str,
        headers: Vec<Header>,
    ) -> Result<R> {
        let request_id = self.send(kind, request, headers).await?;
        let envelope = self.receive(request_id).await?;
        if envelope.message_kind == KIND_DAEMON_ERROR {
            return Err(self.daemon_error(envelope)?);
        }
        envelope
            .decode_typed_payload(response_kind)
            .context(IpcSnafu)
    }

    async fn send<T: prost::Message>(
        &mut self,
        kind: &str,
        request: &T,
        headers: Vec<Header>,
    ) -> Result<u64> {
        let message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.saturating_add(1);
        let mut envelope =
            Envelope::wrap_message(message_id, 0, kind, request).context(IpcSnafu)?;
        envelope.headers = headers;
        let frame = envelope.into_frame().context(IpcSnafu)?;
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            AsyncFrameCodec::write_frame(&mut self.stream, &frame),
        )
        .await
        .map_err(|_elapsed| {
            TimedOutSnafu {
                operation: "writing daemon request",
            }
            .build()
        })?
        .context(IpcSnafu)?;
        Ok(message_id)
    }

    async fn receive(&mut self, request_id: u64) -> Result<Envelope> {
        self.receive_with_timeout(request_id, REQUEST_TIMEOUT).await
    }

    async fn receive_with_timeout(
        &mut self,
        request_id: u64,
        timeout: Duration,
    ) -> Result<Envelope> {
        let frame = tokio::time::timeout(timeout, AsyncFrameCodec::read_frame(&mut self.stream))
            .await
            .map_err(|_elapsed| {
                TimedOutSnafu {
                    operation: "reading daemon response",
                }
                .build()
            })?
            .context(IpcSnafu)?;
        let envelope: Envelope = frame.decode_payload().context(IpcSnafu)?;
        envelope.require_supported_protocol().context(IpcSnafu)?;
        if envelope.correlation_id != request_id {
            return ProtocolSnafu {
                reason: format!(
                    "daemon response correlation {} does not match request {request_id}",
                    envelope.correlation_id
                ),
            }
            .fail();
        }
        Ok(envelope)
    }

    fn daemon_error(&self, envelope: Envelope) -> Result<DaemonClientError> {
        let error: DaemonError = envelope
            .decode_typed_payload(KIND_DAEMON_ERROR)
            .context(IpcSnafu)?;
        Ok(DaemonSnafu {
            status_code: error.status_code,
            message: error.message,
        }
        .build())
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_ipc::{
        v1::{DaemonStatusResponse, Envelope, KIND_DAEMON_STATUS_RESPONSE},
        AsyncFrameCodec,
    };

    use super::DaemonConnection;

    #[tokio::test]
    async fn client_rejects_response_with_wrong_correlation_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (first, mut second) = tokio::io::duplex(1024);
        let mut connection = DaemonConnection {
            stream: first,
            next_message_id: 1,
        };
        let response = Envelope::wrap_message(
            2,
            99,
            KIND_DAEMON_STATUS_RESPONSE,
            &DaemonStatusResponse {
                daemon_pid: 7,
                configuration_generation: 1,
                service_state: String::from("running"),
            },
        )?;
        AsyncFrameCodec::write_frame(&mut second, &response.into_frame()?).await?;
        assert!(connection.receive(1).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn client_rejects_response_with_unsupported_protocol(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (first, mut second) = tokio::io::duplex(1024);
        let mut connection = DaemonConnection {
            stream: first,
            next_message_id: 1,
        };
        let mut response = Envelope::wrap_message(
            2,
            1,
            KIND_DAEMON_STATUS_RESPONSE,
            &DaemonStatusResponse {
                daemon_pid: 1,
                configuration_generation: 1,
                service_state: String::from("running"),
            },
        )?;
        response.protocol_version = 2;
        AsyncFrameCodec::write_frame(&mut second, &response.into_frame()?).await?;

        assert!(connection.receive(1).await.is_err());
        Ok(())
    }
}
