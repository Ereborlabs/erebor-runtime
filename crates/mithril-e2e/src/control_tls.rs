use std::convert::Infallible;
use std::error::Error as StdError;
use std::fs;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use kube::client::Body as KubeBody;
use kube::Client;
use mithril_control::{
    CapabilityRecord, ControlStore, NodeRegistration, PolicyActivationAcknowledgement,
    PolicyBundleV1, WorkloadProtectionPolicy,
};
use mithril_node::{NodeControlConnector, PolicyControlPacingOwner, TrustCache};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{oneshot, watch};
use tower::service_fn;

use crate::control_fixture::{
    control_store_lease_ready, Certificates, MtlsFixture, OutagePolicyFixture,
    OUTAGE_CLUSTER_UID, OUTAGE_NAMESPACE_UID, OUTAGE_TENANT_ID,
};

mod administrative;
mod admission;
mod backlog;
mod coverage;
mod decommission;
mod decommission_order;
mod gap;
mod intake_budget;
mod partition;
mod readiness;
mod registration;
mod rejection;
mod replay;
mod restart;
mod retained;
mod retention;
mod storage;
mod transfer;
mod transfer_tests;

const OUTAGE_NOW: i64 = 1_800_000_000_000_000_000;

#[tokio::test]
async fn kubernetes_outage_pending_policy_transfer_preempts_evidence_ack_backlog(
) -> Result<(), Box<dyn StdError>> {
    let mut pacing = PolicyControlPacingOwner::default();
    pacing.mark_pending();
    let mut poll = tokio::time::interval(Duration::from_secs(60));
    let (sender, mut messages) = tokio::sync::mpsc::unbounded_channel();
    if sender.send(()).is_err() {
        return Err("the message receiver closed before the test started".into());
    }

    let selected_policy = tokio::select! {
        biased;
        () = pacing.wait_until_ready(&mut poll) => true,
        Some(()) = messages.recv() => false,
    };

    assert!(selected_policy);
    Ok(())
}

#[test]
#[ignore = "the startup budget requires the shipped release optimization level"]
fn kubernetes_outage_retained_control_store_starts_from_latest_state(
) -> Result<(), Box<dyn StdError>> {
    const FIXTURE_BATCHES: u64 = 3_204;
    const RECORDS_PER_BATCH: usize = 74;
    const LEGACY_BYTES_PER_RECORD: u64 = 16_776;
    const STARTUP_BUDGET: Duration = Duration::from_secs(5);

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("control-store");
    let store = ControlStore::open(&store_path)?;
    let stored_bytes =
        store.write_retained_evidence_for_test(FIXTURE_BATCHES, RECORDS_PER_BATCH)?;
    let commit_index = store.commit_index();
    drop(store);

    let started = Instant::now();
    let reopened = ControlStore::open(&store_path)?;
    let elapsed = started.elapsed();
    let record_count = FIXTURE_BATCHES * RECORDS_PER_BATCH as u64;
    eprintln!(
        "opened {record_count} retained records in {elapsed:?}; compact store uses {stored_bytes} bytes"
    );
    assert_eq!(reopened.commit_index(), commit_index);
    assert_eq!(reopened.health()?.evidence_cursors, 1);
    assert!(elapsed <= STARTUP_BUDGET);
    assert!(stored_bytes * 100 <= LEGACY_BYTES_PER_RECORD * record_count);
    assert!(store_path.join("state.bin").is_file());
    assert!(!store_path.join("commits").exists());
    let segment_count = fs::read_dir(store_path.join("evidence/segments-v2"))?.count() as u64;
    assert!(segment_count > 0 && segment_count < FIXTURE_BATCHES);
    Ok(())
}

impl OutagePolicyFixture {
    fn active_acknowledgement(
        bundle: &PolicyBundleV1,
        profile_generation_ref_id: u64,
        observed_utc_ns: i64,
    ) -> PolicyActivationAcknowledgement {
        PolicyActivationAcknowledgement {
            tenant_id: bundle.candidate.tenant_id.clone(),
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
            target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
            state: "ACTIVE".to_owned(),
            node_bound_generation_digest: "1".repeat(64),
            profile_generation_ref_id,
            readback_digest: "2".repeat(64),
            probe_result_digest: "3".repeat(64),
            reason_code: String::new(),
            observed_utc_ns,
        }
    }

    fn kubernetes_client(
        &self,
        resource: &WorkloadProtectionPolicy,
    ) -> Result<Client, Box<dyn StdError>> {
        let policy = serde_json::to_value(resource)?;
        let service = service_fn(move |request: Request<KubeBody>| {
            let policy = policy.clone();
            async move {
                let value = match request.uri().path() {
                    "/api/v1/namespaces/tenant-a" => serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Namespace",
                        "metadata": {"name": "tenant-a", "uid": OUTAGE_NAMESPACE_UID}
                    }),
                    "/api/v1/namespaces/tenant-a/serviceaccounts/worker" => {
                        serde_json::json!({
                            "apiVersion": "v1",
                            "kind": "ServiceAccount",
                            "metadata": {
                                "name": "worker",
                                "namespace": "tenant-a",
                                "uid": "77777777-7777-4777-8777-777777777777"
                            }
                        })
                    }
                    "/apis/mithril.erebor.dev/v1alpha1/namespaces/tenant-a/workloadprotectionpolicies" => {
                        serde_json::json!({
                            "apiVersion": "mithril.erebor.dev/v1alpha1",
                            "kind": "WorkloadProtectionPolicyList",
                            "metadata": {"resourceVersion": "outage-list-1"},
                            "items": [policy]
                        })
                    }
                    "/apis/apps/v1/namespaces/mithril-system/daemonsets/mithril-node" => {
                        serde_json::json!({
                            "apiVersion": "apps/v1",
                            "kind": "DaemonSet",
                            "metadata": {"name": "mithril-node", "namespace": "mithril-system"},
                            "spec": {
                                "selector": {"matchLabels": {"app": "mithril-node"}},
                                "template": {
                                    "metadata": {"labels": {"app": "mithril-node"}},
                                    "spec": {
                                        "nodeSelector": {"kubernetes.io/os": "linux"},
                                        "containers": [{"name": "mithril-node", "image": "mithril-node:test"}]
                                    }
                                }
                            }
                        })
                    }
                    _ => {
                        let mut response = Response::new(Body::empty());
                        *response.status_mut() = StatusCode::NOT_FOUND;
                        return Ok::<_, Infallible>(response);
                    }
                };
                let mut response = Response::new(Body::from(value.to_string()));
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                Ok::<_, Infallible>(response)
            }
        });
        Ok(Client::new(service, "default"))
    }

    fn protected_pod_admission_review(&self) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "outage-admission-1",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "name": "outage-a",
                "namespace": "tenant-a",
                "operation": "CREATE",
                "userInfo": {},
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "outage-a",
                        "namespace": "tenant-a",
                        "labels": {"app.kubernetes.io/name": "mithril-outage-worker"}
                    },
                    "spec": {
                        "serviceAccountName": "worker",
                        "runtimeClassName": "mithril-outage-recovery",
                        "nodeSelector": {"qualification.mithril.erebor.dev/node": "a"},
                        "containers": [{
                            "name": "worker",
                            "image": concat!(
                                "docker.io/library/busybox:1.36.1@sha256:",
                                "73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
                            )
                        }]
                    }
                }
            }
        })
    }

    fn registration(node_boot_id: [u8; 16], active_policy: bool) -> NodeRegistration {
        let mut registration = registration_for(node_boot_id, 1);
        registration.effect_prevention_claims_enabled = true;
        registration.kubernetes_node_name = "worker-a".to_owned();
        registration.policy_authority_absent = !active_policy;
        registration.startup_absence_proof_digest = mithril_control::startup_absence_proof_digest(
            "node-a",
            &node_boot_id,
            1,
            !active_policy,
            true,
        );
        registration
    }
}

fn batch_source_id(batch: &mithril_node::EvidenceBatchV1) -> Result<[u8; 16], Box<dyn StdError>> {
    let wire: mithril_control::EvidenceBatch = batch.clone().into();
    wire.source_id
        .as_slice()
        .try_into()
        .map_err(|_error| "evidence batch source identity is not Id128".into())
}

fn registration() -> NodeRegistration {
    registration_for([7; 16], 1)
}

fn registration_for(node_boot_id: [u8; 16], label_epoch: u64) -> NodeRegistration {
    NodeRegistration {
        platform_digest: "a".repeat(64),
        program_digest: "b".repeat(64),
        label_epoch,
        kernel_ready: true,
        effect_prevention_claims_enabled: false,
        kubernetes_node_name: String::new(),
        startup_absence_proof_digest: mithril_control::startup_absence_proof_digest(
            "node-a",
            &node_boot_id,
            label_epoch,
            true,
            true,
        ),
        policy_authority_absent: true,
        exception_authority_absent: true,
        capabilities: capabilities(),
        workload_targets: Vec::new(),
    }
}

fn capabilities() -> Vec<CapabilityRecord> {
    vec![CapabilityRecord {
        capability_id: "KERNEL_LSM_CHASSIS".to_owned(),
        state: "SUPPORTED".to_owned(),
        reason_code: "EXACT_ATTACH_READBACK".to_owned(),
    }]
}

struct TcpBlackholeOwner {
    address: SocketAddr,
    blocked: watch::Sender<bool>,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl TcpBlackholeOwner {
    async fn start(upstream: SocketAddr) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (blocked, blocked_input) = watch::channel(false);
        let (shutdown, mut shutdown_input) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _result = &mut shutdown_input => break,
                    accepted = listener.accept() => {
                        let (downstream, _peer) = accepted?;
                        let upstream = tokio::net::TcpStream::connect(upstream).await?;
                        let blocked = blocked_input.clone();
                        connections.spawn(async move {
                            Self::relay(downstream, upstream, blocked).await
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            Ok(())
        });
        Ok(Self {
            address,
            blocked,
            shutdown,
            task,
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn block(&self) -> Result<(), watch::error::SendError<bool>> {
        self.blocked.send(true)
    }

    fn unblock(&self) -> Result<(), watch::error::SendError<bool>> {
        self.blocked.send(false)
    }

    async fn stop(self) -> Result<(), Box<dyn StdError>> {
        let _result = self.shutdown.send(());
        self.task.await??;
        Ok(())
    }

    async fn relay(
        downstream: tokio::net::TcpStream,
        upstream: tokio::net::TcpStream,
        blocked: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        let (mut downstream_read, mut downstream_write) = downstream.into_split();
        let (mut upstream_read, mut upstream_write) = upstream.into_split();
        let client_to_control = async move {
            let mut bytes = [0_u8; 16 * 1_024];
            loop {
                let count = downstream_read.read(&mut bytes).await?;
                if count == 0 {
                    return Ok::<(), std::io::Error>(());
                }
                // This matches the K8s test rule: packets from Node to Control disappear.
                if !*blocked.borrow() {
                    upstream_write.write_all(&bytes[..count]).await?;
                }
            }
        };
        let control_to_client = tokio::io::copy(&mut upstream_read, &mut downstream_write);
        tokio::select! {
            result = client_to_control => result,
            result = control_to_client => result.map(|_bytes| ()),
        }
    }
}
