use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use erebor_interceptor::{KernelObjectManifestV1, KernelStateReader};
use erebor_runtime_ipc::{
    transport::{UnixIncoming, UnixPeerIdentity, MAX_GRPC_MESSAGE_BYTES},
    v1::{
        runtime_observation_service_server::{
            RuntimeObservationService, RuntimeObservationServiceServer,
        },
        MithrilCapabilityRecord, MithrilCoverageInterval, MithrilObservationSnapshot,
        MithrilObservationSnapshotRequest, MithrilObservationSnapshotResponse,
    },
};
use mithril_control::CapabilityRecord;
use prost::Message as _;
use tokio::net::UnixListener;
use tokio::sync::watch;
use tonic::{Request, Response, Status};

use crate::{EffectObservationStore, NodeReadinessV1, Result, RuntimeObservationConfig};

pub struct RuntimeObservationServer {
    config: RuntimeObservationConfig,
    listener: Option<UnixListener>,
    _socket_owner: crate::unix_socket::UnixSocketPathOwner,
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
        let (listener, socket_owner) =
            crate::unix_socket::UnixSocketPathOwner::bind(&config.socket_path, config.allowed_uid)?;
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
            coverage_intervals: Vec::new(),
            negative_claim_eligible: false,
            evidence_errors: 0,
            wal_capacity_blocked: 0,
            reader_queue_dropped_events: 0,
        };
        Ok(Self {
            config,
            listener: Some(listener),
            _socket_owner: socket_owner,
            snapshot,
            observations,
            kernel_reader,
            readiness,
        })
    }

    pub async fn serve(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let listener = self.listener.take().ok_or_else(|| {
            crate::error::ControlProtocolSnafu {
                reason: String::from("Runtime observation listener is unavailable"),
            }
            .build()
        })?;
        let service = ObservationGrpc {
            allowed_uid: self.config.allowed_uid,
            allowed_scope: Arc::from(self.config.cgroup_scope.as_str()),
            snapshot: self.snapshot.clone(),
            observations: self.observations.clone(),
            kernel_reader: self.kernel_reader.clone(),
            readiness: self.readiness.clone(),
        };
        tonic::transport::Server::builder()
            .concurrency_limit_per_connection(32)
            .add_service(
                RuntimeObservationServiceServer::new(service)
                    .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
            )
            .serve_with_incoming_shutdown(UnixIncoming::new(listener), async move {
                while !*shutdown.borrow() {
                    if shutdown.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
            .map_err(|source| crate::Error::LocalTransport {
                source,
                location: snafu::Location::default(),
            })
    }
}

#[derive(Clone)]
struct ObservationGrpc {
    allowed_uid: u32,
    allowed_scope: Arc<str>,
    snapshot: MithrilObservationSnapshot,
    observations: EffectObservationStore,
    kernel_reader: Option<KernelStateReader>,
    readiness: watch::Receiver<NodeReadinessV1>,
}

#[tonic::async_trait]
impl RuntimeObservationService for ObservationGrpc {
    async fn get_snapshot(
        &self,
        request: Request<MithrilObservationSnapshotRequest>,
    ) -> std::result::Result<Response<MithrilObservationSnapshotResponse>, Status> {
        let peer = request
            .extensions()
            .get::<UnixPeerIdentity>()
            .copied()
            .ok_or_else(|| Status::unauthenticated("local peer credentials are unavailable"))?;
        let request = request.into_inner();
        let accepted = peer.uid == self.allowed_uid
            && request.cgroup_scope == self.allowed_scope.as_ref()
            && peer
                .pid
                .is_some_and(|pid| peer_in_cgroup_scope(pid, &self.allowed_scope));
        if !accepted {
            return Err(Status::permission_denied(
                "the local peer is outside the authorized Runtime scope",
            ));
        }
        let mut snapshot = self.snapshot.clone();
        apply_readiness(&mut snapshot, *self.readiness.borrow());
        snapshot.recent_effects = self.observations.recent();
        update_effect_health(&mut snapshot, &self.observations, || {
            self.kernel_reader.as_ref().and_then(|reader| {
                reader
                    .lookup("effect_observation_health", &0_u32.to_ne_bytes())
                    .ok()
                    .flatten()
            })
        });
        update_coverage(&mut snapshot, &self.observations);
        Ok(Response::new(bounded_observation_response(
            MithrilObservationSnapshotResponse {
                accepted: true,
                reason: String::from("accepted"),
                snapshot: Some(snapshot),
            },
        )))
    }
}

fn bounded_observation_response(
    mut response: MithrilObservationSnapshotResponse,
) -> MithrilObservationSnapshotResponse {
    loop {
        if response.encoded_len() <= MAX_GRPC_MESSAGE_BYTES {
            return response;
        }
        let Some(recent) = response
            .snapshot
            .as_mut()
            .map(|snapshot| &mut snapshot.recent_effects)
        else {
            return response;
        };
        if recent.is_empty() {
            return response;
        }
        let remove = recent.len().div_ceil(2);
        recent.drain(..remove);
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
    snapshot.evidence_errors = health.evidence_errors;
    snapshot.wal_capacity_blocked = health.wal_capacity_blocked;
    snapshot.reader_queue_dropped_events = health.reader_queue_dropped_events;
    snapshot.effect_health_available = health_bytes.is_some();
}

fn update_coverage(
    snapshot: &mut MithrilObservationSnapshot,
    observations: &EffectObservationStore,
) {
    let Some(coverage) = observations.coverage_snapshot() else {
        snapshot.coverage_intervals.clear();
        snapshot.negative_claim_eligible = false;
        return;
    };
    let evidence_failed = observations.evidence_errors() > 0;
    snapshot.negative_claim_eligible = !evidence_failed && coverage.supports_negative_claim();
    if !snapshot.negative_claim_eligible {
        if let Some(capability) = snapshot
            .capabilities
            .iter_mut()
            .find(|capability| capability.capability_id == "LOCAL_EFFECT_OBSERVATION")
        {
            capability.state = "UNHEALTHY".to_owned();
            capability.reason_code = if evidence_failed {
                "DURABLE_EVIDENCE_WRITE_FAILED"
            } else {
                "DURABLE_EVIDENCE_COVERAGE_GAPPED"
            }
            .to_owned();
        }
    }
    snapshot.coverage_intervals = coverage
        .all_intervals()
        .into_iter()
        .map(|interval| {
            let negative_claim_eligible = interval.supports_negative_claim();
            let counters = interval
                .closing_counters
                .unwrap_or(interval.opening_counters);
            MithrilCoverageInterval {
                interval_id: hex::encode(interval.interval_id.to_be_bytes()),
                source_id: hex::encode(interval.source_id.to_be_bytes()),
                source_epoch: interval.source_epoch,
                cpu_id: interval.cpu_id,
                revision: interval.revision,
                state: interval.state.as_str().to_owned(),
                first_sequence: interval.first_sequence,
                last_sequence: interval.last_sequence,
                gap_reasons: interval
                    .gap_reasons
                    .into_iter()
                    .map(|reason| reason.as_str().to_owned())
                    .collect(),
                attempted: counters.attempted,
                suppressed: counters.suppressed,
                requested: counters.requested,
                emitted: counters.emitted,
                lost: counters.lost,
                classifier_miss_count: counters.classifier_miss_count,
                unresolved: counters.unresolved,
                next_sequence: counters.next_sequence,
                negative_claim_eligible,
            }
        })
        .collect();
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

#[cfg(test)]
mod tests {
    use std::{cell::Cell, sync::Arc};

    use erebor_runtime_ipc::{
        transport::{UnixPeerIdentity, MAX_GRPC_MESSAGE_BYTES},
        v1::{
            runtime_observation_service_server::RuntimeObservationService, MithrilCapabilityRecord,
            MithrilEffectObservation, MithrilObservationSnapshot,
            MithrilObservationSnapshotRequest, MithrilObservationSnapshotResponse,
        },
    };
    use prost::Message as _;
    use tonic::{Code, Request};

    use super::{
        apply_readiness, bounded_observation_response, update_effect_health, ObservationGrpc,
    };
    use crate::{EffectObservationStore, NodeReadinessV1};

    #[test]
    fn observation_response_retains_the_newest_events_within_the_grpc_bound() {
        let string_field = "f".repeat(1_024);
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

        let response = bounded_observation_response(response);
        assert!(response.encoded_len() <= MAX_GRPC_MESSAGE_BYTES);
        let retained = response
            .snapshot
            .map(|snapshot| snapshot.recent_effects)
            .unwrap_or_default();

        assert!(!retained.is_empty());
        assert!(retained.len() < 1_024);
        assert_eq!(retained.last().map(|event| event.task_cookie), Some(1_023));
        assert!(retained.first().is_some_and(|event| event.task_cookie > 0));
    }

    #[tokio::test]
    async fn observation_rpc_requires_transport_uid_pid_and_cgroup_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let allowed_uid = rustix::process::geteuid().as_raw();
        let allowed_scope = std::fs::read_to_string("/proc/self/cgroup")?
            .lines()
            .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
            .ok_or("test process has no unified cgroup")?;
        let (_readiness, readiness) = tokio::sync::watch::channel(NodeReadinessV1::default());
        let service = ObservationGrpc {
            allowed_uid,
            allowed_scope: Arc::from(allowed_scope.as_str()),
            snapshot: MithrilObservationSnapshot::default(),
            observations: EffectObservationStore::default(),
            kernel_reader: None,
            readiness,
        };

        let missing = RuntimeObservationService::get_snapshot(
            &service,
            Request::new(MithrilObservationSnapshotRequest {
                cgroup_scope: allowed_scope.clone(),
            }),
        )
        .await
        .err()
        .ok_or("observation RPC accepted missing peer credentials")?;
        assert_eq!(missing.code(), Code::Unauthenticated);

        let mut wrong_uid = Request::new(MithrilObservationSnapshotRequest {
            cgroup_scope: allowed_scope.clone(),
        });
        wrong_uid.extensions_mut().insert(UnixPeerIdentity {
            pid: Some(i32::try_from(std::process::id())?),
            uid: allowed_uid.saturating_add(1),
            gid: 0,
        });
        let wrong_uid = RuntimeObservationService::get_snapshot(&service, wrong_uid)
            .await
            .err()
            .ok_or("observation RPC accepted the wrong UID")?;
        assert_eq!(wrong_uid.code(), Code::PermissionDenied);

        let mut missing_pid = Request::new(MithrilObservationSnapshotRequest {
            cgroup_scope: allowed_scope,
        });
        missing_pid.extensions_mut().insert(UnixPeerIdentity {
            pid: None,
            uid: allowed_uid,
            gid: 0,
        });
        let missing_pid = RuntimeObservationService::get_snapshot(&service, missing_pid)
            .await
            .err()
            .ok_or("observation RPC accepted a missing peer PID")?;
        assert_eq!(missing_pid.code(), Code::PermissionDenied);
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
