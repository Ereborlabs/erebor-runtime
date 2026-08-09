use std::path::PathBuf;

use erebor_runtime_ipc::v1::{
    Envelope, EnvelopeServiceFamily, MithrilObservationHello, MithrilObservationHelloAck,
    MithrilObservationSnapshot, MithrilObservationSnapshotRequest, KIND_MITHRIL_OBSERVATION_HELLO,
    KIND_MITHRIL_OBSERVATION_HELLO_ACK, KIND_MITHRIL_OBSERVATION_SNAPSHOT,
    KIND_MITHRIL_OBSERVATION_SNAPSHOT_REQUEST, MITHRIL_OBSERVATION_PROTOCOL_VERSION,
};
use erebor_runtime_ipc::AsyncFrameCodec;
use snafu::ResultExt as _;
use tokio::net::UnixStream;

use crate::error::{ConnectSnafu, IpcSnafu, ProtocolSnafu};
use crate::Result;

#[derive(Clone, Debug)]
pub struct MithrilObservationClient {
    socket_path: PathBuf,
    cgroup_scope: String,
}

impl MithrilObservationClient {
    #[must_use]
    pub fn new(socket_path: PathBuf, cgroup_scope: String) -> Self {
        Self {
            socket_path,
            cgroup_scope,
        }
    }

    pub async fn snapshot(&self) -> Result<MithrilObservationSnapshot> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .context(ConnectSnafu {
                path: &self.socket_path,
            })?;
        let hello = Envelope::wrap_message(
            1,
            0,
            KIND_MITHRIL_OBSERVATION_HELLO,
            &MithrilObservationHello {
                protocol_version: MITHRIL_OBSERVATION_PROTOCOL_VERSION,
                cgroup_scope: self.cgroup_scope.clone(),
            },
        )
        .context(IpcSnafu)?;
        AsyncFrameCodec::write_frame(&mut stream, &hello.into_frame().context(IpcSnafu)?)
            .await
            .context(IpcSnafu)?;
        let ack = receive(&mut stream).await?;
        let ack: MithrilObservationHelloAck = ack
            .decode_typed_payload(KIND_MITHRIL_OBSERVATION_HELLO_ACK)
            .context(IpcSnafu)?;
        if !ack.accepted || ack.protocol_version != MITHRIL_OBSERVATION_PROTOCOL_VERSION {
            return ProtocolSnafu { reason: ack.reason }.fail();
        }
        let request = Envelope::wrap_message(
            2,
            1,
            KIND_MITHRIL_OBSERVATION_SNAPSHOT_REQUEST,
            &MithrilObservationSnapshotRequest {},
        )
        .context(IpcSnafu)?;
        AsyncFrameCodec::write_frame(&mut stream, &request.into_frame().context(IpcSnafu)?)
            .await
            .context(IpcSnafu)?;
        let response = receive(&mut stream).await?;
        response
            .validate_headers(EnvelopeServiceFamily::MithrilObservation)
            .context(IpcSnafu)?;
        let snapshot: MithrilObservationSnapshot = response
            .decode_typed_payload(KIND_MITHRIL_OBSERVATION_SNAPSHOT)
            .context(IpcSnafu)?;
        if snapshot.cgroup_scope != self.cgroup_scope {
            return ProtocolSnafu {
                reason: "Mithril returned a snapshot outside the requested cgroup scope".to_owned(),
            }
            .fail();
        }
        Ok(snapshot)
    }
}

async fn receive(stream: &mut UnixStream) -> Result<Envelope> {
    let frame = AsyncFrameCodec::read_frame(stream)
        .await
        .context(IpcSnafu)?;
    let envelope: Envelope = frame.decode_payload().context(IpcSnafu)?;
    envelope.require_supported_protocol().context(IpcSnafu)?;
    Ok(envelope)
}
