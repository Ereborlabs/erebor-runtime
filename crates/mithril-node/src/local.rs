use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::{KernelObjectManifestV1, KernelStateReader};
use erebor_runtime_ipc::v1::{
    Envelope, EnvelopeServiceFamily, MithrilCapabilityRecord, MithrilObservationSnapshot,
    MithrilObservationSnapshotRequest, MithrilObservationSnapshotResponse,
    KIND_MITHRIL_OBSERVATION_SNAPSHOT_REQUEST, KIND_MITHRIL_OBSERVATION_SNAPSHOT_RESPONSE,
};
use erebor_runtime_ipc::AsyncFrameCodec;
use mithril_control::CapabilityRecord;
use rustix::{fs::chown, process::Uid};
use snafu::ResultExt as _;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use crate::error::{ControlProtocolSnafu, IoSnafu, LocalIpcSnafu};
use crate::{EffectObservationStore, Result, RuntimeObservationConfig};

pub struct RuntimeObservationServer {
    config: RuntimeObservationConfig,
    listener: UnixListener,
    snapshot: MithrilObservationSnapshot,
    observations: EffectObservationStore,
    kernel_reader: Option<KernelStateReader>,
}

impl RuntimeObservationServer {
    pub fn bind(
        config: RuntimeObservationConfig,
        manifest: &KernelObjectManifestV1,
        capabilities: &[CapabilityRecord],
    ) -> Result<Self> {
        Self::bind_inner(
            config,
            manifest,
            capabilities,
            EffectObservationStore::default(),
            None,
        )
    }

    pub fn bind_with_effects(
        config: RuntimeObservationConfig,
        manifest: &KernelObjectManifestV1,
        capabilities: &[CapabilityRecord],
        observations: EffectObservationStore,
        pin_root: PathBuf,
    ) -> Result<Self> {
        Self::bind_inner(
            config,
            manifest,
            capabilities,
            observations,
            Some(KernelStateReader::new(pin_root)),
        )
    }

    fn bind_inner(
        config: RuntimeObservationConfig,
        manifest: &KernelObjectManifestV1,
        capabilities: &[CapabilityRecord],
        observations: EffectObservationStore,
        kernel_reader: Option<KernelStateReader>,
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
        let configured = chown(
            &config.socket_path,
            Some(Uid::from_raw(config.allowed_uid)),
            None,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: &config.socket_path,
        })
        .and_then(|()| {
            fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600)).context(
                IoSnafu {
                    path: &config.socket_path,
                },
            )
        });
        if let Err(error) = configured {
            let _result = fs::remove_file(&config.socket_path);
            return Err(error);
        }
        let snapshot = MithrilObservationSnapshot {
            cgroup_scope: config.cgroup_scope.clone(),
            node_boot_id: manifest.node_boot_id.clone(),
            label_epoch: manifest.label_epoch,
            program_digest: manifest.object_sha256.clone(),
            kernel_ready: manifest.ready,
            capabilities: capabilities
                .iter()
                .map(|capability| MithrilCapabilityRecord {
                    capability_id: capability.capability_id.clone(),
                    state: capability.state.clone(),
                    reason_code: capability.reason_code.clone(),
                })
                .collect(),
            recent_effects: Vec::new(),
            attempted_effects: 0,
            emitted_effects: 0,
            lost_effects: 0,
            unresolved_effects: 0,
            decoder_errors: 0,
            effect_health_available: false,
        };
        Ok(Self {
            config,
            listener,
            snapshot,
            observations,
            kernel_reader,
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
                    let observations = self.observations.clone();
                    let kernel_reader = self.kernel_reader.clone();
                    tokio::spawn(async move {
                        let _result = handle(
                            stream,
                            allowed_uid,
                            &scope,
                            snapshot,
                            observations,
                            kernel_reader,
                        ).await;
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
    mut snapshot: MithrilObservationSnapshot,
    observations: EffectObservationStore,
    kernel_reader: Option<KernelStateReader>,
) -> Result<()> {
    let peer = stream.peer_cred().context(IoSnafu {
        path: Path::new("Runtime observation peer"),
    })?;
    let envelope = receive(&mut stream).await?;
    let request: MithrilObservationSnapshotRequest = envelope
        .decode_typed_payload(KIND_MITHRIL_OBSERVATION_SNAPSHOT_REQUEST)
        .context(LocalIpcSnafu)?;
    let accepted = peer.uid() == allowed_uid
        && request.cgroup_scope == allowed_scope
        && peer
            .pid()
            .is_some_and(|pid| peer_in_cgroup_scope(pid, allowed_scope));
    let reason = if accepted {
        "accepted"
    } else {
        "peer identity or cgroup scope was rejected"
    };
    if accepted {
        let health_bytes = kernel_reader.as_ref().and_then(|reader| {
            reader
                .lookup("effect_observation_health", &0_u32.to_ne_bytes())
                .ok()
                .flatten()
        });
        let health = observations.health(health_bytes.as_deref());
        snapshot.recent_effects = observations.recent();
        snapshot.attempted_effects = health.attempted;
        snapshot.emitted_effects = health.emitted;
        snapshot.lost_effects = health.lost;
        snapshot.unresolved_effects = health.unresolved;
        snapshot.decoder_errors = health.decoder_errors;
        snapshot.effect_health_available = health_bytes.is_some();
    }
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

fn peer_in_cgroup_scope(pid: i32, allowed_scope: &str) -> bool {
    if pid <= 0 {
        return false;
    }
    let Ok(cgroups) = fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
        return false;
    };
    cgroups.lines().any(|line| {
        let mut fields = line.splitn(3, ':');
        fields.next() == Some("0")
            && fields.next() == Some("")
            && fields.next().is_some_and(|actual| {
                actual == allowed_scope
                    || allowed_scope == "/"
                    || actual
                        .strip_prefix(allowed_scope)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
    })
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
