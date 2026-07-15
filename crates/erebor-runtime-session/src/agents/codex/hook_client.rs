use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
};

use erebor_runtime_ipc::{
    v1::{
        Envelope, HookEvent, HookHello, HookHelloAck, HookRejection, HookResult, KIND_HOOK_EVENT,
        KIND_HOOK_HELLO, KIND_HOOK_HELLO_ACK, KIND_HOOK_REJECTION, KIND_HOOK_RESULT,
        PROTOCOL_VERSION,
    },
    EreborIpcFrame,
};
use snafu::ResultExt;

use super::{
    broker::CodexHookBroker,
    error::{HookBrokerIoSnafu, HookBrokerProtocolSnafu, HookRejectedSnafu, InvalidHookEventSnafu},
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
            endpoint: PathBuf::from(CodexHookBroker::session_endpoint()),
        }
    }
}

impl CodexHookClient {
    pub const MAX_NATIVE_EVENT_BYTES: usize = 32 * 1024;

    pub fn submit(&self, event: HookEvent) -> Result<HookResult, CodexSessionError> {
        let mut stream = UnixStream::connect(&self.endpoint).context(HookBrokerIoSnafu)?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .context(HookBrokerIoSnafu)?;
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .context(HookBrokerIoSnafu)?;
        Self::submit_on_stream(&mut stream, event)
    }

    pub(crate) fn submit_on_stream(
        stream: &mut UnixStream,
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
        let hello = HookHello {
            protocol_version: PROTOCOL_VERSION,
            ticket_id: String::new(),
        };
        let hello_request = Envelope::wrap_message(1, 0, KIND_HOOK_HELLO, &hello)
            .context(HookBrokerProtocolSnafu)?;
        Self::write_envelope(stream, &hello_request)?;
        let hello_response = Self::read_envelope(stream)?;
        let ack: HookHelloAck = hello_response
            .decode_typed_payload(KIND_HOOK_HELLO_ACK)
            .context(HookBrokerProtocolSnafu)?;
        if !ack.accepted || ack.protocol_version != PROTOCOL_VERSION {
            return HookRejectedSnafu {
                stage: String::from("hello"),
                reason: ack.reason,
            }
            .fail();
        }

        let event_request = Envelope::wrap_message(2, 1, KIND_HOOK_EVENT, &event)
            .context(HookBrokerProtocolSnafu)?;
        Self::write_envelope(stream, &event_request)?;
        let response = Self::read_envelope(stream)?;
        if response.message_kind == KIND_HOOK_REJECTION {
            let rejection: HookRejection = response
                .decode_typed_payload(KIND_HOOK_REJECTION)
                .context(HookBrokerProtocolSnafu)?;
            return HookRejectedSnafu {
                stage: String::from("event"),
                reason: rejection.reason,
            }
            .fail();
        }
        let result: HookResult = response
            .decode_typed_payload(KIND_HOOK_RESULT)
            .context(HookBrokerProtocolSnafu)?;
        if !result.accepted {
            return HookRejectedSnafu {
                stage: String::from("result"),
                reason: String::from("broker returned a non-accepted hook result"),
            }
            .fail();
        }
        Ok(result)
    }

    fn read_envelope(stream: &mut UnixStream) -> Result<Envelope, CodexSessionError> {
        let frame = Self::read_frame(stream)?;
        frame.decode_payload().context(HookBrokerProtocolSnafu)
    }

    fn write_envelope(
        stream: &mut UnixStream,
        envelope: &Envelope,
    ) -> Result<(), CodexSessionError> {
        let frame = envelope.into_frame().context(HookBrokerProtocolSnafu)?;
        let encoded = frame.encode().context(HookBrokerProtocolSnafu)?;
        stream.write_all(&encoded).context(HookBrokerIoSnafu)
    }

    fn read_frame(stream: &mut UnixStream) -> Result<EreborIpcFrame, CodexSessionError> {
        let mut header = [0_u8; 12];
        stream.read_exact(&mut header).context(HookBrokerIoSnafu)?;
        let payload_len =
            u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
        let mut source = header.to_vec();
        source.resize(12 + payload_len, 0);
        stream
            .read_exact(&mut source[12..])
            .context(HookBrokerIoSnafu)?;
        EreborIpcFrame::decode(&source).context(HookBrokerProtocolSnafu)
    }
}
