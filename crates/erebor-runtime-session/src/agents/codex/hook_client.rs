use std::{path::PathBuf, time::Duration};

use erebor_runtime_ipc::{
    transport::{connect_unix, MAX_GRPC_MESSAGE_BYTES},
    v1::{
        hook_client_message, hook_server_message, hook_service_client::HookServiceClient,
        HookClientMessage, HookEvent, HookHello, HookResult,
    },
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;

use super::{
    broker::CodexHookService,
    error::{HookRejectedSnafu, InvalidHookEventSnafu},
    CodexSessionError,
};

/// The client embedded in the root-controlled managed Codex hook artifact.
///
/// The endpoint is fixed by the managed session filesystem projection, not by
/// a hook-supplied environment variable or argument.
pub struct CodexHookClient {
    endpoint: PathBuf,
}

impl Default for CodexHookClient {
    fn default() -> Self {
        Self {
            endpoint: PathBuf::from(CodexHookService::session_endpoint()),
        }
    }
}

impl CodexHookClient {
    pub const MAX_NATIVE_EVENT_BYTES: usize = 32 * 1024;

    pub fn submit(&self, event: HookEvent) -> Result<HookResult, CodexSessionError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                protocol_error(format!("could not start hook RPC runtime: {error}"))
            })?;
        runtime.block_on(self.submit_async(
            std::env::var("EREBOR_SESSION_ID").unwrap_or_default(),
            event,
        ))
    }

    async fn submit_async(
        &self,
        session_id: impl Into<String>,
        event: HookEvent,
    ) -> Result<HookResult, CodexSessionError> {
        if event.native_event_json.len() > Self::MAX_NATIVE_EVENT_BYTES {
            return InvalidHookEventSnafu {
                reason: format!(
                    "native event is larger than {} bytes",
                    Self::MAX_NATIVE_EVENT_BYTES
                ),
            }
            .fail();
        }
        let channel = connect_unix(&self.endpoint).await.map_err(|error| {
            protocol_error(format!("could not connect to hook service: {error}"))
        })?;
        let mut client = HookServiceClient::new(channel)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES);
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let mut request = Request::new(ReceiverStream::new(receiver));
        request.set_timeout(Duration::from_secs(10));
        sender
            .send(HookClientMessage {
                item: Some(hook_client_message::Item::Hello(HookHello {
                    session_id: session_id.into(),
                })),
            })
            .await
            .map_err(|_closed| protocol_error("hook request stream closed before hello"))?;
        let mut output = client
            .open(request)
            .await
            .map_err(|status| protocol_error(format!("hook open failed: {status}")))?
            .into_inner();
        let response = output
            .message()
            .await
            .map_err(|status| protocol_error(format!("hook hello failed: {status}")))?
            .ok_or_else(|| protocol_error("hook service closed before hello acknowledgement"))?;
        let Some(hook_server_message::Item::HelloAck(ack)) = response.item else {
            return Err(protocol_error(
                "hook service returned an invalid hello response",
            ));
        };
        if !ack.accepted {
            return HookRejectedSnafu {
                stage: String::from("hello"),
                reason: ack.reason,
            }
            .fail();
        }

        sender
            .send(HookClientMessage {
                item: Some(hook_client_message::Item::Event(event)),
            })
            .await
            .map_err(|_closed| protocol_error("hook request stream closed before event"))?;
        drop(sender);
        let response = output
            .message()
            .await
            .map_err(|status| protocol_error(format!("hook event failed: {status}")))?
            .ok_or_else(|| protocol_error("hook service closed before event result"))?;
        match response.item {
            Some(hook_server_message::Item::Result(result)) if result.accepted => Ok(result),
            Some(hook_server_message::Item::Result(_result)) => HookRejectedSnafu {
                stage: String::from("result"),
                reason: String::from("broker returned a non-accepted hook result"),
            }
            .fail(),
            Some(hook_server_message::Item::Rejection(rejection)) => HookRejectedSnafu {
                stage: String::from("event"),
                reason: rejection.reason,
            }
            .fail(),
            _ => Err(protocol_error(
                "hook service returned an invalid event result",
            )),
        }
    }
}

fn protocol_error(reason: impl Into<String>) -> CodexSessionError {
    CodexSessionError::HookBrokerProtocol {
        reason: reason.into(),
        location: snafu::Location::default(),
    }
}
