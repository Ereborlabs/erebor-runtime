use std::path::PathBuf;

use erebor_runtime_ipc::v1::{
    Envelope, EnvelopeServiceFamily, MithrilObservationSnapshot, MithrilObservationSnapshotRequest,
    MithrilObservationSnapshotResponse, KIND_MITHRIL_OBSERVATION_SNAPSHOT_REQUEST,
    KIND_MITHRIL_OBSERVATION_SNAPSHOT_RESPONSE,
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
        let request = Envelope::wrap_message(
            1,
            0,
            KIND_MITHRIL_OBSERVATION_SNAPSHOT_REQUEST,
            &MithrilObservationSnapshotRequest {
                cgroup_scope: self.cgroup_scope.clone(),
            },
        )
        .context(IpcSnafu)?;
        AsyncFrameCodec::write_frame(&mut stream, &request.into_frame().context(IpcSnafu)?)
            .await
            .context(IpcSnafu)?;
        let envelope = receive(&mut stream).await?;
        envelope
            .validate_headers(EnvelopeServiceFamily::MithrilObservation)
            .context(IpcSnafu)?;
        if envelope.correlation_id != request.message_id {
            return ProtocolSnafu {
                reason: "Mithril returned an unrelated observation response".to_owned(),
            }
            .fail();
        }
        let response: MithrilObservationSnapshotResponse = envelope
            .decode_typed_payload(KIND_MITHRIL_OBSERVATION_SNAPSHOT_RESPONSE)
            .context(IpcSnafu)?;
        if !response.accepted {
            return ProtocolSnafu {
                reason: response.reason,
            }
            .fail();
        }
        let Some(snapshot) = response.snapshot else {
            return ProtocolSnafu {
                reason: "Mithril accepted an observation request without a snapshot".to_owned(),
            }
            .fail();
        };
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
