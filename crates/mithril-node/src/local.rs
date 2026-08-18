use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::{KernelObjectManifestV1, KernelStateReader};
use erebor_runtime_ipc::v1::{
    Envelope, EnvelopeServiceFamily, MithrilCapabilityRecord, MithrilObservationSnapshot,
    MithrilObservationSnapshotRequest, MithrilObservationSnapshotResponse,
    KIND_MITHRIL_OBSERVATION_SNAPSHOT_REQUEST, KIND_MITHRIL_OBSERVATION_SNAPSHOT_RESPONSE,
};
use erebor_runtime_ipc::{AsyncFrameCodec, IpcProtocolError};
use mithril_control::CapabilityRecord;
use rustix::{fs::chown, process::Uid};
use snafu::ResultExt as _;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use crate::error::{ControlProtocolSnafu, IoSnafu, LocalIpcSnafu};
use crate::{EffectObservationStore, NodeReadinessV1, Result, RuntimeObservationConfig};

pub struct RuntimeObservationServer {
    config: RuntimeObservationConfig,
    listener: UnixListener,
    snapshot: MithrilObservationSnapshot,
    observations: EffectObservationStore,
    kernel_reader: Option<KernelStateReader>,
    readiness: watch::Receiver<NodeReadinessV1>,
}

impl RuntimeObservationServer {
    pub fn bind(
        config: RuntimeObservationConfig,
        manifest: &KernelObjectManifestV1,
        capabilities: &[CapabilityRecord],
        readiness: watch::Receiver<NodeReadinessV1>,
    ) -> Result<Self> {
        Self::bind_inner(
            config,
            manifest,
            capabilities,
            EffectObservationStore::default(),
            None,
            readiness,
        )
    }

    pub fn bind_with_effects(
        config: RuntimeObservationConfig,
        manifest: &KernelObjectManifestV1,
        capabilities: &[CapabilityRecord],
        observations: EffectObservationStore,
        pin_root: PathBuf,
        readiness: watch::Receiver<NodeReadinessV1>,
    ) -> Result<Self> {
        Self::bind_inner(
            config,
            manifest,
            capabilities,
            observations,
            Some(KernelStateReader::new(pin_root)),
            readiness,
        )
    }

    fn bind_inner(
        config: RuntimeObservationConfig,
        manifest: &KernelObjectManifestV1,
        capabilities: &[CapabilityRecord],
        observations: EffectObservationStore,
        kernel_reader: Option<KernelStateReader>,
        readiness: watch::Receiver<NodeReadinessV1>,
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
            readiness,
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
                    let readiness = self.readiness.clone();
                    tokio::spawn(async move {
                        let _result = handle(
                            stream,
                            allowed_uid,
                            &scope,
                            snapshot,
                            observations,
                            kernel_reader,
                            readiness,
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
    readiness: watch::Receiver<NodeReadinessV1>,
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
        let readiness = *readiness.borrow();
        apply_readiness(&mut snapshot, readiness);
        snapshot.recent_effects = observations.recent();
        update_effect_health(&mut snapshot, &observations, || {
            kernel_reader.as_ref().and_then(|reader| {
                reader
                    .lookup("effect_observation_health", &0_u32.to_ne_bytes())
                    .ok()
                    .flatten()
            })
        });
    }
    let response = bounded_observation_response(
        envelope.message_id,
        MithrilObservationSnapshotResponse {
            accepted,
            reason: reason.to_owned(),
            snapshot: accepted.then_some(snapshot),
        },
    )
    .context(LocalIpcSnafu)?;
    send(&mut stream, response).await
}

fn bounded_observation_response(
    correlation_id: u64,
    mut response: MithrilObservationSnapshotResponse,
) -> erebor_runtime_ipc::Result<Envelope> {
    loop {
        let envelope = Envelope::wrap_message(
            2,
            correlation_id,
            KIND_MITHRIL_OBSERVATION_SNAPSHOT_RESPONSE,
            &response,
        )?;
        match envelope.into_frame() {
            Ok(_frame) => return Ok(envelope),
            Err(IpcProtocolError::PayloadTooLarge { .. }) => {
                let Some(recent) = response
                    .snapshot
                    .as_mut()
                    .map(|snapshot| &mut snapshot.recent_effects)
                else {
                    return envelope.into_frame().map(|_frame| envelope);
                };
                if recent.is_empty() {
                    return envelope.into_frame().map(|_frame| envelope);
                }
                let remove = recent.len().div_ceil(2);
                recent.drain(..remove);
            }
            Err(error) => return Err(error),
        }
    }
}

fn apply_readiness(snapshot: &mut MithrilObservationSnapshot, readiness: NodeReadinessV1) {
    snapshot.kernel_ready = readiness.kernel_ready;
    if !readiness.kernel_ready {
        for capability in &mut snapshot.capabilities {
            if matches!(
                capability.capability_id.as_str(),
                "EXACT_NATIVE_IDENTITY" | "LOCAL_EFFECT_PREVENTION" | "LOCAL_EFFECT_OBSERVATION"
            ) {
                capability.state = "UNHEALTHY".to_owned();
                capability.reason_code = "LIVE_KERNEL_MANIFEST_MISMATCH".to_owned();
            }
        }
        return;
    }
    if !readiness.identity_ready {
        for capability in &mut snapshot.capabilities {
            if matches!(
                capability.capability_id.as_str(),
                "EXACT_NATIVE_IDENTITY" | "LOCAL_EFFECT_OBSERVATION"
            ) {
                capability.state = "UNHEALTHY".to_owned();
                capability.reason_code = "LIVE_IDENTITY_RECONCILIATION_FAILED".to_owned();
            }
        }
    }
    if !readiness.effect_prevention_claims_enabled {
        if let Some(capability) = snapshot.capabilities.iter_mut().find(|capability| {
            capability.capability_id == "LOCAL_EFFECT_PREVENTION"
                && capability.state != "UNSUPPORTED"
        }) {
            capability.state = "UNSUPPORTED".to_owned();
            capability.reason_code = "LIVE_PREVENTION_CLAIM_CLOSED".to_owned();
        }
    }
}

fn update_effect_health(
    snapshot: &mut MithrilObservationSnapshot,
    observations: &EffectObservationStore,
    read_pinned_health: impl FnOnce() -> Option<Vec<u8>>,
) {
    let health_bytes = snapshot.kernel_ready.then(read_pinned_health).flatten();
    let health = observations.health(health_bytes.as_deref());
    snapshot.attempted_effects = health.attempted;
    snapshot.emitted_effects = health.emitted;
    snapshot.lost_effects = health.lost;
    snapshot.unresolved_effects = health.unresolved;
    snapshot.decoder_errors = health.decoder_errors;
    snapshot.effect_health_available = health_bytes.is_some();
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use erebor_runtime_ipc::v1::{
        MithrilCapabilityRecord, MithrilEffectObservation, MithrilObservationSnapshot,
        MithrilObservationSnapshotResponse, KIND_MITHRIL_OBSERVATION_SNAPSHOT_RESPONSE,
    };

    use super::{apply_readiness, bounded_observation_response, update_effect_health};
    use crate::{EffectObservationStore, NodeReadinessV1};

    #[test]
    fn observation_response_retains_the_newest_events_within_the_frame_bound(
    ) -> erebor_runtime_ipc::Result<()> {
        let string_field = "f".repeat(64);
        let template = MithrilEffectObservation {
            process_lineage_id: string_field.clone(),
            process_instance_id: string_field.clone(),
            entry_instance_id: string_field.clone(),
            authority_domain_id: string_field.clone(),
            binding_id: string_field.clone(),
            execution_set_id: string_field.clone(),
            reason: string_field.clone(),
            physical_result: string_field.clone(),
            stage: string_field.clone(),
            controller_process_state_id: string_field.clone(),
            target_process_state_id: string_field.clone(),
            io_uring_ring_id: string_field,
            ..MithrilEffectObservation::default()
        };
        let recent_effects = (0..1_024)
            .map(|task_cookie| MithrilEffectObservation {
                task_cookie,
                ..template.clone()
            })
            .collect::<Vec<_>>();
        let response = MithrilObservationSnapshotResponse {
            accepted: true,
            reason: "accepted".to_owned(),
            snapshot: Some(MithrilObservationSnapshot {
                recent_effects,
                ..MithrilObservationSnapshot::default()
            }),
        };

        let envelope = bounded_observation_response(7, response)?;
        envelope.into_frame()?;
        let response: MithrilObservationSnapshotResponse =
            envelope.decode_typed_payload(KIND_MITHRIL_OBSERVATION_SNAPSHOT_RESPONSE)?;
        let retained = response
            .snapshot
            .map(|snapshot| snapshot.recent_effects)
            .unwrap_or_default();

        assert!(!retained.is_empty());
        assert!(retained.len() < 1_024);
        assert_eq!(retained.last().map(|event| event.task_cookie), Some(1_023));
        assert!(retained.first().is_some_and(|event| event.task_cookie > 0));
        Ok(())
    }

    #[test]
    fn identity_failure_closes_only_identity_dependent_local_claims() {
        let mut snapshot = MithrilObservationSnapshot {
            kernel_ready: true,
            capabilities: [
                "EXACT_NATIVE_IDENTITY",
                "LOCAL_EFFECT_PREVENTION",
                "LOCAL_EFFECT_OBSERVATION",
                "RUNTIME_READ_ONLY_OBSERVATION",
            ]
            .into_iter()
            .map(|capability_id| MithrilCapabilityRecord {
                capability_id: capability_id.to_owned(),
                state: "SUPPORTED".to_owned(),
                reason_code: "INITIAL_STATE".to_owned(),
            })
            .collect(),
            ..MithrilObservationSnapshot::default()
        };

        apply_readiness(
            &mut snapshot,
            NodeReadinessV1 {
                kernel_ready: true,
                identity_ready: false,
                control_ready: true,
                admission_ready: false,
                effect_prevention_claims_enabled: false,
            },
        );

        assert!(snapshot.kernel_ready);
        assert_eq!(snapshot.capabilities[0].state, "UNHEALTHY");
        assert_eq!(
            snapshot.capabilities[0].reason_code,
            "LIVE_IDENTITY_RECONCILIATION_FAILED"
        );
        assert_eq!(snapshot.capabilities[1].state, "UNSUPPORTED");
        assert_eq!(snapshot.capabilities[2].state, "UNHEALTHY");
        assert_eq!(snapshot.capabilities[3].state, "SUPPORTED");
    }

    #[test]
    fn closed_kernel_readiness_suppresses_pinned_effect_health() {
        let read = Cell::new(false);
        let mut snapshot = MithrilObservationSnapshot {
            kernel_ready: false,
            attempted_effects: 1,
            emitted_effects: 2,
            lost_effects: 3,
            unresolved_effects: 4,
            effect_health_available: true,
            ..MithrilObservationSnapshot::default()
        };

        update_effect_health(&mut snapshot, &EffectObservationStore::default(), || {
            read.set(true);
            Some(vec![1])
        });

        assert!(!read.get());
        assert!(!snapshot.effect_health_available);
        assert_eq!(
            (
                snapshot.attempted_effects,
                snapshot.emitted_effects,
                snapshot.lost_effects,
                snapshot.unresolved_effects,
            ),
            (0, 0, 0, 0)
        );
    }
}
