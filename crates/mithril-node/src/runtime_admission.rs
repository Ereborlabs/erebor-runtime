use std::collections::HashMap;
use std::ffi::OsString;
use std::future::Future;
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use erebor_runtime_ipc::{
    transport::{connect_unix, UnixIncoming, UnixPeerIdentity},
    v1::{
        runtime_admission_service_client::RuntimeAdmissionServiceClient,
        runtime_admission_service_server::{
            RuntimeAdmissionService, RuntimeAdmissionServiceServer,
        },
        RuntimeAdmissionComplete, RuntimeAdmissionDecision, RuntimeAdmissionEntriesRequest,
        RuntimeAdmissionHealthRequest, RuntimeAdmissionPrepareRequest, RuntimeAdmissionReceipt,
        RuntimeAdmissionStageRequest,
    },
};
use sha2::{Digest as _, Sha256};
use snafu::ensure;
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tonic::{transport::Channel, Request, Response, Status};

use crate::admission_limits as limit;
use crate::error::IdentityStateSnafu;
use crate::{Result, RuntimeAdmissionConfig, WorkloadBindingConfig};

pub const POD_UID_ANNOTATION: &str = "io.kubernetes.cri.sandbox-uid";
pub const POD_NAMESPACE_ANNOTATION: &str = "io.kubernetes.cri.sandbox-namespace";
pub const CONTAINER_NAME_ANNOTATION: &str = "io.kubernetes.cri.container-name";
pub const IMAGE_NAME_ANNOTATION: &str = "io.kubernetes.cri.image-name";
pub const SANDBOX_ID_ANNOTATION: &str = "io.kubernetes.cri.sandbox-id";
pub const PROFILE_ID_ANNOTATION: &str = "mithril.erebor.dev/profile-id";
pub const POLICY_SOURCE_REVISION_ANNOTATION: &str = "mithril.erebor.dev/policy-source-revision";
pub(crate) const POLICY_CONVERGENCE_PENDING: &str = "POLICY_CONVERGENCE_PENDING";
pub(crate) const SECCOMP_LISTENER_METADATA: &str = "mithril-runtime-exec-v1";
const MAX_PENDING_ADMISSIONS: usize = 128;
const MAX_RPCS_PER_CONNECTION: usize = 32;
const POLICY_RETRY_DELAY: Duration = Duration::from_millis(25);

pub(crate) fn seccomp_listener_path(socket_path: &Path) -> PathBuf {
    socket_path.with_extension("seccomp.sock")
}

pub(crate) enum RuntimeAdmissionCall {
    Stage(RuntimeAdmissionStageRequest, AdmissionReply),
    Prepare(RuntimeAdmissionPrepareRequest, AdmissionReply),
    Entries(RuntimeAdmissionEntriesRequest, AdmissionReply),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeAdmissionResponseV1 {
    pub allowed: bool,
    pub reason_code: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KubernetesRuntimeIdentityV1 {
    pub namespace: String,
    pub pod_uid: String,
    pub container_name: String,
    pub image_digest: String,
    pub sandbox_id: String,
    pub profile_id: String,
}

/// This owner converts signed scheduling authority into one container lifetime.
pub struct ScheduledRuntimeBindingV1 {
    pub binding_index: usize,
    pub previous_binding_id: Option<String>,
    pub resolved: WorkloadBindingConfig,
}

pub(crate) struct AdmissionReply {
    peer_pid: u32,
    deadline: Instant,
    response: oneshot::Sender<RuntimeAdmissionResponseV1>,
    delivered: oneshot::Receiver<()>,
}

struct RuntimeAdmissionDispatch {
    response: RuntimeAdmissionResponseV1,
    delivered: oneshot::Sender<()>,
}

/// This owner controls the socket path, listener, and concurrent request dispatch.
pub(crate) struct RuntimeAdmissionServer {
    listener: UnixListener,
    _socket_owner: crate::unix_socket::UnixSocketPathOwner,
    maximum_request_bytes: usize,
    timeout: Duration,
    requests: mpsc::Sender<RuntimeAdmissionCall>,
}

#[derive(Clone)]
struct RuntimeAdmissionGrpc {
    timeout: Duration,
    requests: mpsc::Sender<RuntimeAdmissionCall>,
    pending: Arc<Mutex<HashMap<uuid::Uuid, AdmissionPending>>>,
}

struct AdmissionPending {
    peer_pid: u32,
    deadline: Instant,
    delivered: oneshot::Sender<()>,
}

/// This receiver gives the node event loop one bounded runtime request stream.
pub(crate) struct RuntimeAdmissionReceiver {
    requests: mpsc::Receiver<RuntimeAdmissionCall>,
}

/// This client controls one hook exchange and its fail-closed deadline.
pub struct RuntimeAdmissionClient {
    socket_path: PathBuf,
    timeout: Duration,
}

impl KubernetesRuntimeIdentityV1 {
    pub(crate) fn stage(request: &RuntimeAdmissionStageRequest) -> Result<Self> {
        let path = PathBuf::from(OsString::from_vec(request.cgroup_path.clone()));
        ensure!(
            clean_cgroup_path(&path),
            IdentityStateSnafu {
                reason: "runtime admission request is not canonical",
            }
        );
        Self::parse(&request.container_id, &request.annotations)
    }

    pub(crate) fn prepare(request: &RuntimeAdmissionPrepareRequest) -> Result<Self> {
        ensure!(
            request.initial_pid > 0,
            IdentityStateSnafu {
                reason: "runtime admission request is not canonical",
            }
        );
        Self::parse(&request.container_id, &request.annotations)
    }

    pub(crate) fn entries(request: &RuntimeAdmissionEntriesRequest) -> Result<Self> {
        let bundle = PathBuf::from(OsString::from_vec(request.oci_bundle.clone()));
        ensure!(
            clean_oci_bundle(&bundle) && request.oci_root_fd > 2,
            IdentityStateSnafu {
                reason: "runtime admission request is not canonical",
            }
        );
        Self::parse(&request.container_id, &request.annotations)
    }

    fn parse(container_id: &str, annotations: &HashMap<String, String>) -> Result<Self> {
        ensure!(
            !container_id.is_empty()
                && container_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte)),
            IdentityStateSnafu {
                reason: "runtime admission request is not canonical",
            }
        );
        let required = |key: &str| {
            annotations
                .get(key)
                .filter(|value| !value.is_empty())
                .cloned()
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!("runtime admission request has no `{key}` annotation"),
                    }
                    .build()
                })
        };
        let image = required(IMAGE_NAME_ANNOTATION)?;
        let image_digest = image
            .rsplit_once('@')
            .map_or(image.as_str(), |(_, digest)| digest);
        ensure!(
            image_digest.strip_prefix("sha256:").is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            }),
            IdentityStateSnafu {
                reason: "runtime admission image is not digest-pinned",
            }
        );
        let profile_id = required(PROFILE_ID_ANNOTATION)?;
        let policy_source_revision_id = required(POLICY_SOURCE_REVISION_ANNOTATION)?;
        // Treat the source annotation as untrusted provenance. The signed local
        // target selects the active source revision.
        ensure!(
            canonical_uuid(&profile_id) && valid_sha256(&policy_source_revision_id),
            IdentityStateSnafu {
                reason: "runtime admission policy annotations are not canonical",
            }
        );
        Ok(Self {
            namespace: required(POD_NAMESPACE_ANNOTATION)?,
            pod_uid: required(POD_UID_ANNOTATION)?,
            container_name: required(CONTAINER_NAME_ANNOTATION)?,
            image_digest: image_digest.to_owned(),
            sandbox_id: required(SANDBOX_ID_ANNOTATION)?,
            profile_id,
        })
    }
}

fn clean_oci_bundle(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

impl RuntimeAdmissionCall {
    fn reply(&self) -> &AdmissionReply {
        match self {
            Self::Stage(_, reply) | Self::Prepare(_, reply) | Self::Entries(_, reply) => reply,
        }
    }

    fn into_reply(self) -> AdmissionReply {
        match self {
            Self::Stage(_, reply) | Self::Prepare(_, reply) | Self::Entries(_, reply) => reply,
        }
    }

    #[must_use]
    pub(crate) fn peer_pid(&self) -> u32 {
        self.reply().peer_pid
    }

    pub(crate) fn ensure_active(&self) -> Result<()> {
        let reply = self.reply();
        ensure!(
            Instant::now() < reply.deadline && !reply.response.is_closed(),
            IdentityStateSnafu {
                reason: "runtime admission caller is no longer waiting".to_owned(),
            }
        );
        Ok(())
    }

    pub(crate) async fn deliver(self, response: RuntimeAdmissionResponseV1) -> Result<()> {
        self.ensure_active()?;
        let reply = self.into_reply();
        reply.response.send(response).map_err(|_response| {
            IdentityStateSnafu {
                reason: "runtime admission caller closed before its response".to_owned(),
            }
            .build()
        })?;
        tokio::time::timeout_at(reply.deadline, reply.delivered)
            .await
            .map_err(|_elapsed| {
                IdentityStateSnafu {
                    reason: "runtime admission response exceeded its delivery deadline".to_owned(),
                }
                .build()
            })?
            .map_err(|_closed| {
                IdentityStateSnafu {
                    reason: "runtime admission response did not reach its caller".to_owned(),
                }
                .build()
            })
    }
}

impl RuntimeAdmissionServer {
    pub(crate) fn bind(
        config: &RuntimeAdmissionConfig,
    ) -> Result<(Self, RuntimeAdmissionReceiver)> {
        let (listener, socket_owner) =
            crate::unix_socket::UnixSocketPathOwner::bind(&config.socket_path, 0)?;
        let (requests, receiver) = mpsc::channel(MAX_PENDING_ADMISSIONS);
        Ok((
            Self {
                listener,
                _socket_owner: socket_owner,
                maximum_request_bytes: config.maximum_request_bytes,
                timeout: Duration::from_millis(config.timeout_ms),
                requests,
            },
            RuntimeAdmissionReceiver { requests: receiver },
        ))
    }

    pub(crate) async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let service = RuntimeAdmissionGrpc {
            timeout: self.timeout,
            requests: self.requests.clone(),
            pending: Arc::new(Mutex::new(HashMap::new())),
        };
        let server = tonic::transport::Server::builder()
            .concurrency_limit_per_connection(MAX_RPCS_PER_CONNECTION)
            .add_service(
                RuntimeAdmissionServiceServer::new(service)
                    .max_decoding_message_size(self.maximum_request_bytes)
                    .max_encoding_message_size(limit::RESPONSE_BYTES),
            )
            .serve_with_incoming(UnixIncoming::new(self.listener));
        tokio::select! {
            result = server => result,
            () = async move {
                while !*shutdown.borrow() {
                    if shutdown.changed().await.is_err() {
                        break;
                    }
                }
            } => Ok(()),
        }
        .map_err(|source| crate::Error::LocalTransport {
            source,
            location: snafu::Location::default(),
        })
    }
}

impl RuntimeAdmissionReceiver {
    pub(crate) async fn receive(&mut self) -> Option<RuntimeAdmissionCall> {
        self.requests.recv().await
    }

    #[cfg(test)]
    pub(crate) fn test_request(
        request: RuntimeAdmissionPrepareRequest,
        timeout: Duration,
    ) -> (
        Self,
        tokio::task::JoinHandle<Result<RuntimeAdmissionResponseV1>>,
    ) {
        let (requests, receiver) = mpsc::channel(1);
        let deadline = Instant::now() + timeout;
        let response = tokio::spawn(async move {
            let (response, received) = oneshot::channel();
            let (delivered, delivery) = oneshot::channel();
            requests
                .send(RuntimeAdmissionCall::Prepare(
                    request,
                    AdmissionReply {
                        peer_pid: std::process::id(),
                        deadline,
                        response,
                        delivered: delivery,
                    },
                ))
                .await
                .map_err(|_closed| {
                    IdentityStateSnafu {
                        reason: "runtime admission test receiver closed".to_owned(),
                    }
                    .build()
                })?;
            let response = received.await.map_err(|_closed| {
                IdentityStateSnafu {
                    reason: "runtime admission test received no answer".to_owned(),
                }
                .build()
            })?;
            delivered.send(()).map_err(|()| {
                IdentityStateSnafu {
                    reason: "runtime admission test answer was not delivered".to_owned(),
                }
                .build()
            })?;
            Ok(response)
        });
        (Self { requests: receiver }, response)
    }
}

impl RuntimeAdmissionClient {
    pub fn new(socket_path: PathBuf, timeout: Duration) -> Result<Self> {
        ensure!(
            socket_path.is_absolute() && limit::TIMEOUT_MS.contains(&timeout.as_millis()),
            IdentityStateSnafu {
                reason:
                    "runtime admission client requires an absolute socket and a bounded timeout",
            }
        );
        Ok(Self {
            socket_path,
            timeout,
        })
    }

    pub async fn available(&self) -> bool {
        tokio::time::timeout(self.timeout, async {
            let channel = connect_unix(&self.socket_path).await.ok()?;
            let mut client = RuntimeAdmissionServiceClient::new(channel)
                .max_decoding_message_size(limit::RESPONSE_BYTES)
                .max_encoding_message_size(*limit::REQUEST_BYTES.end());
            let mut request = Request::new(RuntimeAdmissionHealthRequest {});
            request.set_timeout(self.timeout);
            client.health(request).await.ok().map(Response::into_inner)
        })
        .await
        .ok()
        .flatten()
        .is_some_and(|response| response.allowed && response.reason_code == "ADMISSION_READY")
    }

    pub async fn stage_runtime_facts(
        &self,
        input: RuntimeAdmissionStageRequest,
    ) -> Result<RuntimeAdmissionDecision> {
        self.bounded(async {
            let mut client = self.connect().await?;
            let mut request = Request::new(input);
            request.set_timeout(self.timeout);
            let decision = client
                .stage_runtime_facts(request)
                .await
                .map_err(Self::grpc_error)?
                .into_inner();
            self.confirm(&mut client, decision).await
        })
        .await
    }

    pub async fn prepare_container(
        &self,
        input: RuntimeAdmissionPrepareRequest,
    ) -> Result<RuntimeAdmissionDecision> {
        self.bounded(async {
            let mut client = self.connect().await?;
            let mut request = Request::new(input);
            request.set_timeout(self.timeout);
            let decision = client
                .prepare_container(request)
                .await
                .map_err(Self::grpc_error)?
                .into_inner();
            self.confirm(&mut client, decision).await
        })
        .await
    }

    pub async fn prepare_declared_entries(
        &self,
        input: RuntimeAdmissionEntriesRequest,
    ) -> Result<RuntimeAdmissionDecision> {
        self.bounded(async {
            let mut client = self.connect().await?;
            let mut request = Request::new(input);
            request.set_timeout(self.timeout);
            let decision = client
                .prepare_declared_entries(request)
                .await
                .map_err(Self::grpc_error)?
                .into_inner();
            self.confirm(&mut client, decision).await
        })
        .await
    }

    async fn bounded<T>(&self, work: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::time::timeout(self.timeout, work)
            .await
            .map_err(|_elapsed| {
                IdentityStateSnafu {
                    reason: "runtime admission endpoint exceeded its fail-closed timeout"
                        .to_owned(),
                }
                .build()
            })?
    }

    async fn connect(&self) -> Result<RuntimeAdmissionServiceClient<Channel>> {
        let channel = connect_unix(&self.socket_path)
            .await
            .map_err(|source| crate::Error::Io {
                path: self.socket_path.clone(),
                source: std::io::Error::other(source),
                location: snafu::Location::default(),
            })?;
        Ok(RuntimeAdmissionServiceClient::new(channel)
            .max_decoding_message_size(limit::RESPONSE_BYTES)
            .max_encoding_message_size(*limit::REQUEST_BYTES.end()))
    }

    async fn confirm(
        &self,
        client: &mut RuntimeAdmissionServiceClient<Channel>,
        decision: RuntimeAdmissionDecision,
    ) -> Result<RuntimeAdmissionDecision> {
        ensure!(
            uuid::Uuid::from_slice(&decision.receipt_token).is_ok(),
            IdentityStateSnafu {
                reason: "runtime admission decision has no receipt token",
            }
        );
        let mut receipt = Request::new(RuntimeAdmissionReceipt {
            token: decision.receipt_token,
        });
        receipt.set_timeout(self.timeout);
        client.confirm(receipt).await.map_err(Self::grpc_error)?;
        Ok(RuntimeAdmissionDecision {
            receipt_token: Vec::new(),
            ..decision
        })
    }

    fn grpc_error(status: Status) -> crate::Error {
        IdentityStateSnafu {
            reason: format!("runtime admission gRPC failed: {status}"),
        }
        .build()
    }
}

impl ScheduledRuntimeBindingV1 {
    pub fn runtime_binding_id(authority_binding_id: &str, container_id: &str) -> String {
        Self::derived_uuid(&[
            b"MITHRIL-KUBERNETES-RUNTIME-BINDING-V1\0",
            authority_binding_id.as_bytes(),
            container_id.as_bytes(),
        ])
    }

    pub fn authority_binding_id(pod_uid: &str, container_name: &str) -> String {
        Self::derived_uuid(&[
            b"MITHRIL-KUBERNETES-BINDING-V1\0",
            pod_uid.as_bytes(),
            container_name.as_bytes(),
        ])
    }

    pub(crate) fn resolve(
        configured: &[WorkloadBindingConfig],
        request: &RuntimeAdmissionPrepareRequest,
    ) -> Result<Self> {
        Self::resolve_request(
            configured,
            &request.container_id,
            KubernetesRuntimeIdentityV1::prepare(request)?,
        )
    }

    pub(crate) fn resolve_stage(
        configured: &[WorkloadBindingConfig],
        request: &RuntimeAdmissionStageRequest,
    ) -> Result<Self> {
        Self::resolve_request(
            configured,
            &request.container_id,
            KubernetesRuntimeIdentityV1::stage(request)?,
        )
    }

    fn resolve_request(
        configured: &[WorkloadBindingConfig],
        container_id: &str,
        identity: KubernetesRuntimeIdentityV1,
    ) -> Result<Self> {
        ensure!(
            !identity.sandbox_id.is_empty()
                && identity
                    .sandbox_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte)),
            IdentityStateSnafu {
                reason: "runtime admission sandbox identity is invalid",
            }
        );
        // Runtime facts must resolve to one signed scheduled authority before identity changes.
        let matches = configured
            .iter()
            .enumerate()
            .filter(|(_index, binding)| {
                binding.scheduled_binding_authority_id.is_some()
                    && binding.profile_id == identity.profile_id
                    && binding.namespace == identity.namespace
                    && binding.pod_uid == identity.pod_uid
                    && binding.container_name == identity.container_name
                    && binding.image_digest == identity.image_digest
            })
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            IdentityStateSnafu {
                reason: "runtime admission does not resolve to one signed scheduled target",
            }
        );
        let binding_index = matches[0].0;
        let current = matches[0].1;
        let authority_binding_id = current
            .scheduled_binding_authority_id
            .as_deref()
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "scheduled binding lost its signed authority".to_owned(),
                }
                .build()
            })?;
        ensure!(
            authority_binding_id
                == Self::authority_binding_id(&identity.pod_uid, &identity.container_name),
            IdentityStateSnafu {
                reason: "scheduled binding authority does not match its Pod and container",
            }
        );
        // A placeholder authorizes the first lifetime; a concrete binding authorizes no replay.
        let current_is_placeholder = current.container_id.starts_with("scheduled:");
        ensure!(
            (current_is_placeholder && current.binding_id == authority_binding_id)
                || (!current_is_placeholder
                    && current.binding_id
                        == Self::runtime_binding_id(authority_binding_id, &current.container_id)),
            IdentityStateSnafu {
                reason: "runtime binding is not derived from its signed scheduled authority",
            }
        );
        let mut resolved = current.clone();
        // Derive a distinct binding from signed authority and the runtime container identity.
        resolved.binding_id = Self::runtime_binding_id(authority_binding_id, container_id);
        ensure!(
            current_is_placeholder || resolved.binding_id != current.binding_id,
            IdentityStateSnafu {
                reason: "runtime admission attempted to reuse one container lifetime",
            }
        );
        resolved.container_id = container_id.to_owned();
        resolved.sandbox_id = identity.sandbox_id;
        resolved.root_cgroup_path = None;
        resolved.container_generation = if current_is_placeholder {
            1
        } else {
            current.container_generation.checked_add(1).ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "runtime container generation overflowed".to_owned(),
                }
                .build()
            })?
        };
        resolved.lifecycle_generation = if current_is_placeholder {
            current.lifecycle_generation
        } else {
            current.lifecycle_generation.checked_add(1).ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "runtime binding lifecycle generation overflowed".to_owned(),
                }
                .build()
            })?
        };
        Ok(Self {
            binding_index,
            previous_binding_id: (!current_is_placeholder).then(|| current.binding_id.clone()),
            resolved,
        })
    }

    fn derived_uuid(parts: &[&[u8]]) -> String {
        let digest = Sha256::digest(parts.concat());
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        uuid::Uuid::from_bytes(bytes).hyphenated().to_string()
    }
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn clean_cgroup_path(path: &Path) -> bool {
    path.is_absolute()
        && path.starts_with("/sys/fs/cgroup")
        && path != Path::new("/sys/fs/cgroup")
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

impl RuntimeAdmissionServer {
    async fn dispatch<F>(
        make: F,
        peer_pid: u32,
        requests: mpsc::Sender<RuntimeAdmissionCall>,
        deadline: Instant,
    ) -> Result<RuntimeAdmissionDispatch>
    where
        F: Fn(AdmissionReply) -> RuntimeAdmissionCall,
    {
        loop {
            let (response, receiver) = oneshot::channel();
            let (delivered, delivery) = oneshot::channel();
            requests
                .send(make(AdmissionReply {
                    peer_pid,
                    deadline,
                    response,
                    delivered: delivery,
                }))
                .await
                .map_err(|_closed| {
                    IdentityStateSnafu {
                        reason: "runtime admission owner is unavailable".to_owned(),
                    }
                    .build()
                })?;
            let response = receiver.await.map_err(|_closed| {
                IdentityStateSnafu {
                    reason: "runtime admission owner closed the request".to_owned(),
                }
                .build()
            })?;
            if response.reason_code != POLICY_CONVERGENCE_PENDING {
                return Ok(RuntimeAdmissionDispatch {
                    response,
                    delivered,
                });
            }
            // A pending response stays inside the node protocol and can start the next attempt.
            let _result = delivered.send(());
            tokio::time::sleep(POLICY_RETRY_DELAY).await;
        }
    }
}

impl RuntimeAdmissionGrpc {
    #[expect(clippy::result_large_err, reason = "tonic uses Status by value")]
    fn peer<T>(request: &Request<T>) -> std::result::Result<u32, Status> {
        let peer = request
            .extensions()
            .get::<UnixPeerIdentity>()
            .copied()
            .ok_or_else(|| Status::unauthenticated("runtime admission peer is unavailable"))?;
        if peer.uid != 0 {
            return Err(Status::permission_denied(
                "runtime admission peer is not root",
            ));
        }
        peer.pid
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or_else(|| Status::unauthenticated("runtime admission peer has no process ID"))
    }

    async fn decide<F>(
        &self,
        make: F,
        peer_pid: u32,
    ) -> std::result::Result<Response<RuntimeAdmissionDecision>, Status>
    where
        F: Fn(AdmissionReply) -> RuntimeAdmissionCall,
    {
        let deadline = Instant::now() + self.timeout;
        let dispatched = tokio::time::timeout_at(
            deadline,
            RuntimeAdmissionServer::dispatch(make, peer_pid, self.requests.clone(), deadline),
        )
        .await
        .map_err(|_elapsed| Status::deadline_exceeded("ADMISSION_TIMEOUT"))?
        .map_err(|_error| Status::unavailable("runtime admission owner is unavailable"))?;
        let token = uuid::Uuid::new_v4();
        {
            let mut pending = self.pending.lock().map_err(|_poison| {
                Status::internal("runtime admission receipts are unavailable")
            })?;
            if pending.len() >= MAX_PENDING_ADMISSIONS {
                return Err(Status::resource_exhausted(
                    "runtime admission receipts are full",
                ));
            }
            pending.insert(
                token,
                AdmissionPending {
                    peer_pid,
                    deadline,
                    delivered: dispatched.delivered,
                },
            );
        }
        let pending = self.pending.clone();
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            if let Ok(mut pending) = pending.lock() {
                pending.remove(&token);
            }
        });
        Ok(Response::new(RuntimeAdmissionDecision {
            allowed: dispatched.response.allowed,
            reason_code: dispatched.response.reason_code,
            receipt_token: token.as_bytes().to_vec(),
        }))
    }
}

#[tonic::async_trait]
impl RuntimeAdmissionService for RuntimeAdmissionGrpc {
    async fn health(
        &self,
        request: Request<RuntimeAdmissionHealthRequest>,
    ) -> std::result::Result<Response<RuntimeAdmissionDecision>, Status> {
        Self::peer(&request)?;
        Ok(Response::new(RuntimeAdmissionDecision {
            allowed: true,
            reason_code: "ADMISSION_READY".to_owned(),
            receipt_token: Vec::new(),
        }))
    }

    async fn stage_runtime_facts(
        &self,
        request: Request<RuntimeAdmissionStageRequest>,
    ) -> std::result::Result<Response<RuntimeAdmissionDecision>, Status> {
        let peer_pid = Self::peer(&request)?;
        let call = request.into_inner();
        self.decide(
            |reply| RuntimeAdmissionCall::Stage(call.clone(), reply),
            peer_pid,
        )
        .await
    }

    async fn prepare_container(
        &self,
        request: Request<RuntimeAdmissionPrepareRequest>,
    ) -> std::result::Result<Response<RuntimeAdmissionDecision>, Status> {
        let peer_pid = Self::peer(&request)?;
        let call = request.into_inner();
        self.decide(
            |reply| RuntimeAdmissionCall::Prepare(call.clone(), reply),
            peer_pid,
        )
        .await
    }

    async fn prepare_declared_entries(
        &self,
        request: Request<RuntimeAdmissionEntriesRequest>,
    ) -> std::result::Result<Response<RuntimeAdmissionDecision>, Status> {
        let peer_pid = Self::peer(&request)?;
        let call = request.into_inner();
        self.decide(
            |reply| RuntimeAdmissionCall::Entries(call.clone(), reply),
            peer_pid,
        )
        .await
    }

    async fn confirm(
        &self,
        request: Request<RuntimeAdmissionReceipt>,
    ) -> std::result::Result<Response<RuntimeAdmissionComplete>, Status> {
        let peer_pid = Self::peer(&request)?;
        let token = uuid::Uuid::from_slice(&request.into_inner().token)
            .map_err(|_error| Status::invalid_argument("runtime admission receipt is invalid"))?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_poison| Status::internal("runtime admission receipts are unavailable"))?;
        let receipt = pending
            .get(&token)
            .ok_or_else(|| Status::failed_precondition("runtime admission receipt is unknown"))?;
        if receipt.peer_pid != peer_pid {
            return Err(Status::permission_denied(
                "runtime admission receipt peer changed",
            ));
        }
        if Instant::now() >= receipt.deadline {
            pending.remove(&token);
            return Err(Status::deadline_exceeded("ADMISSION_TIMEOUT"));
        }
        let receipt = pending
            .remove(&token)
            .ok_or_else(|| Status::failed_precondition("runtime admission receipt is unknown"))?;
        receipt
            .delivered
            .send(())
            .map_err(|()| Status::cancelled("runtime admission owner closed"))?;
        Ok(Response::new(RuntimeAdmissionComplete {}))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::path::PathBuf;
    use std::time::Duration;

    use erebor_runtime_ipc::transport::UnixPeerIdentity;
    use erebor_runtime_ipc::v1::{
        runtime_admission_service_server::RuntimeAdmissionService, RuntimeAdmissionEntriesRequest,
        RuntimeAdmissionPrepareRequest, RuntimeAdmissionReceipt, RuntimeAdmissionStageRequest,
    };
    use tonic::{Code, Request};

    use super::{
        AdmissionPending, KubernetesRuntimeIdentityV1, RuntimeAdmissionCall,
        RuntimeAdmissionClient, RuntimeAdmissionGrpc, RuntimeAdmissionResponseV1,
        RuntimeAdmissionServer, ScheduledRuntimeBindingV1, CONTAINER_NAME_ANNOTATION,
        IMAGE_NAME_ANNOTATION, POD_NAMESPACE_ANNOTATION, POD_UID_ANNOTATION,
        POLICY_CONVERGENCE_PENDING, POLICY_SOURCE_REVISION_ANNOTATION, PROFILE_ID_ANNOTATION,
        SANDBOX_ID_ANNOTATION,
    };
    use crate::{ContainerKindV1, WorkloadBindingConfig};

    fn request() -> RuntimeAdmissionPrepareRequest {
        RuntimeAdmissionPrepareRequest {
            container_id: "a".repeat(64),
            initial_pid: 42,
            annotations: HashMap::from([
                (POD_NAMESPACE_ANNOTATION.to_owned(), "tenant-a".to_owned()),
                (POD_UID_ANNOTATION.to_owned(), "pod-a".to_owned()),
                (CONTAINER_NAME_ANNOTATION.to_owned(), "worker".to_owned()),
                (
                    IMAGE_NAME_ANNOTATION.to_owned(),
                    format!("repo/worker@sha256:{}", "b".repeat(64)),
                ),
                (SANDBOX_ID_ANNOTATION.to_owned(), "c".repeat(64)),
                (
                    PROFILE_ID_ANNOTATION.to_owned(),
                    "33333333-3333-4333-8333-333333333333".to_owned(),
                ),
                (POLICY_SOURCE_REVISION_ANNOTATION.to_owned(), "f".repeat(64)),
            ]),
        }
    }

    fn stage() -> RuntimeAdmissionStageRequest {
        let input = request();
        RuntimeAdmissionStageRequest {
            container_id: input.container_id,
            annotations: input.annotations,
            cgroup_path: b"/sys/fs/cgroup/kubepods/pod-a/container-a".to_vec(),
        }
    }

    fn entries() -> RuntimeAdmissionEntriesRequest {
        let input = request();
        RuntimeAdmissionEntriesRequest {
            container_id: input.container_id,
            annotations: input.annotations,
            oci_bundle: b"/run/oci/container-a".to_vec(),
            oci_root_fd: 3,
        }
    }

    fn scheduled_binding() -> WorkloadBindingConfig {
        WorkloadBindingConfig {
            binding_id: ScheduledRuntimeBindingV1::authority_binding_id("pod-a", "worker"),
            scheduled_binding_authority_id: Some(ScheduledRuntimeBindingV1::authority_binding_id(
                "pod-a", "worker",
            )),
            scheduled_target_digest: Some("e".repeat(64)),
            execution_set_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            protected_scope_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            workload_selector_id: "worker".to_owned(),
            profile_id: "33333333-3333-4333-8333-333333333333".to_owned(),
            container_id: format!("scheduled:{}", "d".repeat(64)),
            namespace: "tenant-a".to_owned(),
            cluster_uid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            namespace_uid: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
            controller_uid: "controller-a".to_owned(),
            service_account_uid: "service-account-a".to_owned(),
            pod_labels: BTreeMap::new(),
            pod_uid: "pod-a".to_owned(),
            sandbox_id: format!("scheduled:{}", "e".repeat(64)),
            container_name: "worker".to_owned(),
            image_digest: format!("sha256:{}", "b".repeat(64)),
            container_kind: ContainerKindV1::Application,
            container_generation: 1,
            root_cgroup_path: None,
            lifecycle_generation: 1,
            active_profile_generation_ref_id: 7,
            initial_role_id: 10,
            external_role_id: 11,
            arm_initial_root: true,
        }
    }

    #[test]
    fn exact_kubernetes_identity_is_canonical() -> crate::Result<()> {
        let identity = KubernetesRuntimeIdentityV1::prepare(&request())?;
        assert_eq!(identity.pod_uid, "pod-a");
        assert_eq!(identity.image_digest, format!("sha256:{}", "b".repeat(64)));
        Ok(())
    }

    #[test]
    fn oci_id_and_extra_annotations_need_no_digest_shape() -> crate::Result<()> {
        let mut input = request();
        input.container_id = "oci-container1".to_owned();
        input
            .annotations
            .insert(SANDBOX_ID_ANNOTATION.to_owned(), "sandbox-a".to_owned());
        input
            .annotations
            .insert("example.org/optional".to_owned(), String::new());
        let identity = KubernetesRuntimeIdentityV1::prepare(&input)?;
        assert_eq!(identity.sandbox_id, "sandbox-a");
        let resolved = ScheduledRuntimeBindingV1::resolve(&[scheduled_binding()], &input)?;
        assert_eq!(resolved.resolved.container_id, input.container_id);
        Ok(())
    }

    #[test]
    fn grpc_admission_requires_a_root_process() {
        let mut request = Request::new(());
        assert_eq!(
            RuntimeAdmissionGrpc::peer(&request)
                .err()
                .map(|error| error.code()),
            Some(Code::Unauthenticated)
        );
        request.extensions_mut().insert(UnixPeerIdentity {
            pid: Some(42),
            uid: 1,
            gid: 1,
        });
        assert_eq!(
            RuntimeAdmissionGrpc::peer(&request)
                .err()
                .map(|error| error.code()),
            Some(Code::PermissionDenied)
        );
        request.extensions_mut().insert(UnixPeerIdentity {
            pid: None,
            uid: 0,
            gid: 0,
        });
        assert_eq!(
            RuntimeAdmissionGrpc::peer(&request)
                .err()
                .map(|error| error.code()),
            Some(Code::Unauthenticated)
        );
    }

    #[tokio::test]
    async fn admission_receipt_is_peer_bound_and_one_use() {
        let token = uuid::Uuid::new_v4();
        let (delivered, confirmed) = tokio::sync::oneshot::channel();
        let (requests, _receiver) = tokio::sync::mpsc::channel(1);
        let server = RuntimeAdmissionGrpc {
            timeout: Duration::from_secs(1),
            requests,
            pending: std::sync::Arc::new(std::sync::Mutex::new(HashMap::from([(
                token,
                AdmissionPending {
                    peer_pid: 42,
                    deadline: tokio::time::Instant::now() + Duration::from_secs(1),
                    delivered,
                },
            )]))),
        };
        let receipt = |pid| {
            let mut request = Request::new(RuntimeAdmissionReceipt {
                token: token.as_bytes().to_vec(),
            });
            request.extensions_mut().insert(UnixPeerIdentity {
                pid: Some(pid),
                uid: 0,
                gid: 0,
            });
            request
        };
        assert_eq!(
            server
                .confirm(receipt(43))
                .await
                .err()
                .map(|error| error.code()),
            Some(Code::PermissionDenied)
        );
        assert!(server.confirm(receipt(42)).await.is_ok());
        assert!(confirmed.await.is_ok());
        assert_eq!(
            server
                .confirm(receipt(42))
                .await
                .err()
                .map(|error| error.code()),
            Some(Code::FailedPrecondition)
        );
    }

    #[test]
    fn first_hook_can_stage_facts_but_cannot_request_runtime_authority() -> crate::Result<()> {
        let stage = stage();
        let scheduled = scheduled_binding();
        let resolved = ScheduledRuntimeBindingV1::resolve_stage(&[scheduled], &stage)?;
        assert_eq!(resolved.resolved.root_cgroup_path, None);
        assert_eq!(
            stage.cgroup_path,
            b"/sys/fs/cgroup/kubepods/pod-a/container-a"
        );
        Ok(())
    }

    #[test]
    fn post_root_entry_preparation_has_no_initial_process_claim() -> crate::Result<()> {
        let mut input = entries();
        KubernetesRuntimeIdentityV1::entries(&input)?;
        input.oci_root_fd = 0;
        assert!(KubernetesRuntimeIdentityV1::entries(&input).is_err());
        Ok(())
    }

    #[test]
    fn malformed_or_unpinned_requests_fail_closed() {
        let mut invalid_path = stage();
        invalid_path.cgroup_path = b"/tmp/not-a-cgroup".to_vec();
        assert!(KubernetesRuntimeIdentityV1::stage(&invalid_path).is_err());

        let mut invalid_pid = request();
        invalid_pid.initial_pid = 0;
        assert!(KubernetesRuntimeIdentityV1::prepare(&invalid_pid).is_err());

        let mut unpinned = request();
        unpinned.annotations.insert(
            IMAGE_NAME_ANNOTATION.to_owned(),
            "repo/worker:latest".to_owned(),
        );
        assert!(KubernetesRuntimeIdentityV1::prepare(&unpinned).is_err());

        let mut forged_profile = request();
        forged_profile
            .annotations
            .insert(PROFILE_ID_ANNOTATION.to_owned(), "profile-a".to_owned());
        assert!(KubernetesRuntimeIdentityV1::prepare(&forged_profile).is_err());
    }

    #[test]
    fn each_runtime_container_gets_a_distinct_binding() {
        let first = ScheduledRuntimeBindingV1::runtime_binding_id(
            "11111111-1111-4111-8111-111111111111",
            &"a".repeat(64),
        );
        let second = ScheduledRuntimeBindingV1::runtime_binding_id(
            "11111111-1111-4111-8111-111111111111",
            &"b".repeat(64),
        );
        assert_ne!(first, second);
        assert_eq!(first.len(), 36);
    }

    #[test]
    fn signed_scheduled_target_resolves_one_runtime_lifetime() -> crate::Result<()> {
        let scheduled = scheduled_binding();
        let request = request();
        let resolved = ScheduledRuntimeBindingV1::resolve(&[scheduled], &request)?;
        assert_eq!(resolved.binding_index, 0);
        assert_eq!(resolved.resolved.container_id, request.container_id);
        assert_eq!(resolved.resolved.root_cgroup_path.as_deref(), None);
        assert!(resolved.previous_binding_id.is_none());
        Ok(())
    }

    #[test]
    fn annotation_mismatch_and_lifetime_reuse_fail_closed() -> crate::Result<()> {
        let scheduled = scheduled_binding();
        let mut wrong_pod = request();
        wrong_pod
            .annotations
            .insert(POD_UID_ANNOTATION.to_owned(), "pod-b".to_owned());
        assert!(
            ScheduledRuntimeBindingV1::resolve(std::slice::from_ref(&scheduled), &wrong_pod)
                .is_err()
        );

        let mut wrong_profile = request();
        wrong_profile.annotations.insert(
            PROFILE_ID_ANNOTATION.to_owned(),
            "44444444-4444-4444-8444-444444444444".to_owned(),
        );
        assert!(ScheduledRuntimeBindingV1::resolve(
            std::slice::from_ref(&scheduled),
            &wrong_profile
        )
        .is_err());

        let request = request();
        let active = ScheduledRuntimeBindingV1::resolve(&[scheduled], &request)?.resolved;
        assert!(ScheduledRuntimeBindingV1::resolve(&[active], &request).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn unavailable_or_silent_endpoint_fails_closed() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: PathBuf::from("temporary runtime admission directory"),
            source,
            location: snafu::Location::default(),
        })?;
        let missing = directory.path().join("missing.sock");
        let client = RuntimeAdmissionClient::new(missing, Duration::from_millis(100))?;
        let input = request();
        assert!(client
            .prepare_container(RuntimeAdmissionPrepareRequest {
                container_id: input.container_id,
                annotations: input.annotations.into_iter().collect(),
                initial_pid: input.initial_pid,
            })
            .await
            .is_err());

        assert!(
            tokio::time::timeout(Duration::from_millis(20), std::future::pending::<()>(),)
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn one_hook_call_waits_for_policy_convergence() -> crate::Result<()> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let task = tokio::spawn(RuntimeAdmissionServer::dispatch(
            |reply| RuntimeAdmissionCall::Prepare(request(), reply),
            std::process::id(),
            sender,
            deadline,
        ));
        let first = receiver
            .recv()
            .await
            .ok_or_else(|| crate::Error::IdentityState {
                reason: "runtime admission test lost its first request".to_owned(),
                location: snafu::Location::default(),
            })?;
        first
            .into_reply()
            .response
            .send(RuntimeAdmissionResponseV1 {
                allowed: false,
                reason_code: POLICY_CONVERGENCE_PENDING.to_owned(),
            })
            .map_err(|_| crate::Error::IdentityState {
                reason: "runtime admission test lost its pending response".to_owned(),
                location: snafu::Location::default(),
            })?;
        let second = receiver
            .recv()
            .await
            .ok_or_else(|| crate::Error::IdentityState {
                reason: "runtime admission test did not retry after pending policy".to_owned(),
                location: snafu::Location::default(),
            })?;
        second
            .into_reply()
            .response
            .send(RuntimeAdmissionResponseV1 {
                allowed: true,
                reason_code: "ACTIVE_POLICY_AND_BINDING_VERIFIED".to_owned(),
            })
            .map_err(|_| crate::Error::IdentityState {
                reason: "runtime admission test lost its allowed response".to_owned(),
                location: snafu::Location::default(),
            })?;
        assert!(
            task.await
                .map_err(|error| crate::Error::IdentityState {
                    reason: format!("runtime admission test task failed: {error}"),
                    location: snafu::Location::default(),
                })??
                .response
                .allowed
        );
        Ok(())
    }

    #[tokio::test]
    async fn expired_call_rejects_late_allow() -> crate::Result<()> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
        let task = tokio::spawn(RuntimeAdmissionServer::dispatch(
            |reply| RuntimeAdmissionCall::Prepare(request(), reply),
            std::process::id(),
            sender,
            deadline,
        ));
        let admission = receiver
            .recv()
            .await
            .ok_or_else(|| crate::Error::IdentityState {
                reason: "runtime admission test lost its delayed request".to_owned(),
                location: snafu::Location::default(),
            })?;

        // The owner can finish CRI work after the hook deadline, but it cannot publish an allow.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(admission.ensure_active().is_err());
        assert!(admission
            .deliver(RuntimeAdmissionResponseV1 {
                allowed: true,
                reason_code: "ACTIVE_POLICY_AND_BINDING_VERIFIED".to_owned(),
            })
            .await
            .is_err());
        assert!(task.await.is_ok_and(|result| result.is_err()));
        Ok(())
    }
}
