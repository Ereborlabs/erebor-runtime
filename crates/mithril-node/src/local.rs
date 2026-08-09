use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use erebor_interceptor::KernelObjectManifestV1;
use erebor_runtime_ipc::v1::{
    Envelope, EnvelopeServiceFamily, MithrilObservationSnapshot, MithrilObservationSnapshotRequest,
    MithrilObservationSnapshotResponse, KIND_MITHRIL_OBSERVATION_SNAPSHOT_REQUEST,
    KIND_MITHRIL_OBSERVATION_SNAPSHOT_RESPONSE,
};
use erebor_runtime_ipc::AsyncFrameCodec;
use mithril_control::CapabilityRecord;
use rustix::{fs::chown, process::Uid};
use snafu::ResultExt as _;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use crate::error::{ControlProtocolSnafu, IoSnafu, LocalIpcSnafu};
use crate::{Result, RuntimeObservationConfig};

pub struct RuntimeObservationServer {
    config: RuntimeObservationConfig,
    listener: UnixListener,
    snapshot: MithrilObservationSnapshot,
}

impl RuntimeObservationServer {
    pub fn bind(
        config: RuntimeObservationConfig,
        manifest: &KernelObjectManifestV1,
        capabilities: &[CapabilityRecord],
    ) -> Result<Self> {
        if let Some(parent) = config.socket_path.parent() {
            fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
        }
        if config.socket_path.exists() {
            return ControlProtocolSnafu {
                reason: format!(
                    "Runtime observation socket `{}` already exists",
                    config.socket_path.display()
                ),
            }
            .fail();
        }
        let listener = UnixListener::bind(&config.socket_path).context(IoSnafu {
            path: &config.socket_path,
        })?;
        chown(
            &config.socket_path,
            Some(Uid::from_raw(config.allowed_uid)),
            None,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: &config.socket_path,
        })?;
        fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600)).context(
            IoSnafu {
                path: &config.socket_path,
            },
        )?;
        let snapshot = MithrilObservationSnapshot {
            cgroup_scope: config.cgroup_scope.clone(),
            node_boot_id: manifest.node_boot_id.clone(),
            label_epoch: manifest.label_epoch,
            program_digest: manifest.object_sha256.clone(),
            kernel_ready: manifest.ready,
            capability_ids: capabilities
                .iter()
                .map(|capability| capability.capability_id.clone())
                .collect(),
        };
        Ok(Self {
            config,
            listener,
            snapshot,
        })
    }

    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, _address) = accepted.context(IoSnafu {
                        path: &self.config.socket_path,
                    })?;
                    let allowed_uid = self.config.allowed_uid;
                    let scope = self.config.cgroup_scope.clone();
                    let snapshot = self.snapshot.clone();
                    tokio::spawn(async move {
                        let _result = handle(stream, allowed_uid, &scope, snapshot).await;
                    });
                }
                changed = shutdown.changed() => {
                    let _result = changed;
                    return Ok(());
                }
            }
        }
    }
}

impl Drop for RuntimeObservationServer {
    fn drop(&mut self) {
        let _result = fs::remove_file(&self.config.socket_path);
    }
}

async fn handle(
    mut stream: UnixStream,
    allowed_uid: u32,
    allowed_scope: &str,
    snapshot: MithrilObservationSnapshot,
) -> Result<()> {
    let peer = stream.peer_cred().context(IoSnafu {
        path: Path::new("Runtime observation peer"),
    })?;
    let envelope = receive(&mut stream).await?;
    let request: MithrilObservationSnapshotRequest = envelope
        .decode_typed_payload(KIND_MITHRIL_OBSERVATION_SNAPSHOT_REQUEST)
        .context(LocalIpcSnafu)?;
    let accepted = peer.uid() == allowed_uid && request.cgroup_scope == allowed_scope;
    let reason = if accepted {
        "accepted"
    } else {
        "peer identity or cgroup scope was rejected"
    };
    send(
        &mut stream,
        Envelope::wrap_message(
            2,
            envelope.message_id,
            KIND_MITHRIL_OBSERVATION_SNAPSHOT_RESPONSE,
            &MithrilObservationSnapshotResponse {
                accepted,
                reason: reason.to_owned(),
                snapshot: accepted.then_some(snapshot),
            },
        )
        .context(LocalIpcSnafu)?,
    )
    .await
}

async fn receive(stream: &mut UnixStream) -> Result<Envelope> {
    let frame = AsyncFrameCodec::read_frame(stream)
        .await
        .context(LocalIpcSnafu)?;
    let envelope: Envelope = frame.decode_payload().context(LocalIpcSnafu)?;
    envelope
        .require_supported_protocol()
        .context(LocalIpcSnafu)?;
    envelope
        .validate_headers(EnvelopeServiceFamily::MithrilObservation)
        .context(LocalIpcSnafu)?;
    Ok(envelope)
}

async fn send(stream: &mut UnixStream, envelope: Envelope) -> Result<()> {
    let frame = envelope.into_frame().context(LocalIpcSnafu)?;
    AsyncFrameCodec::write_frame(stream, &frame)
        .await
        .context(LocalIpcSnafu)
}
