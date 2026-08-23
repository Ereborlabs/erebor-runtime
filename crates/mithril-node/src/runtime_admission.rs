use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream as StandardUnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch};

use crate::error::{IdentityStateSnafu, IoSnafu, JsonSnafu};
use crate::{Result, RuntimeAdmissionConfig, WorkloadBindingConfig};

pub const POD_UID_ANNOTATION: &str = "io.kubernetes.cri.sandbox-uid";
pub const POD_NAMESPACE_ANNOTATION: &str = "io.kubernetes.cri.sandbox-namespace";
pub const CONTAINER_NAME_ANNOTATION: &str = "io.kubernetes.cri.container-name";
pub const IMAGE_NAME_ANNOTATION: &str = "io.kubernetes.cri.image-name";
pub const SANDBOX_ID_ANNOTATION: &str = "io.kubernetes.cri.sandbox-id";
pub const PROFILE_ID_ANNOTATION: &str = "mithril.erebor.dev/profile-id";
pub const POLICY_SOURCE_REVISION_ANNOTATION: &str = "mithril.erebor.dev/policy-source-revision";
pub(crate) const POLICY_CONVERGENCE_PENDING: &str = "POLICY_CONVERGENCE_PENDING";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAdmissionRequestV1 {
    pub container_id: String,
    pub initial_pid: u32,
    pub cgroup_path: PathBuf,
    pub annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAdmissionResponseV1 {
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
pub(crate) struct ScheduledRuntimeBindingV1 {
    pub binding_index: usize,
    pub previous_binding_id: Option<String>,
    pub resolved: WorkloadBindingConfig,
}

pub(crate) struct RuntimeAdmissionEnvelope {
    pub request: RuntimeAdmissionRequestV1,
    pub response: oneshot::Sender<RuntimeAdmissionResponseV1>,
}

/// This owner controls the socket path, listener, and concurrent request dispatch.
pub(crate) struct RuntimeAdmissionServer {
    listener: UnixListener,
    socket_path: PathBuf,
    maximum_request_bytes: usize,
    timeout: Duration,
    requests: mpsc::Sender<RuntimeAdmissionEnvelope>,
}

/// This receiver gives the node event loop one bounded runtime request stream.
pub(crate) struct RuntimeAdmissionReceiver {
    requests: mpsc::Receiver<RuntimeAdmissionEnvelope>,
}

/// This client controls one hook exchange and its fail-closed deadline.
pub struct RuntimeAdmissionClient {
    socket_path: PathBuf,
    timeout: Duration,
}

impl RuntimeAdmissionRequestV1 {
    pub(crate) fn kubernetes_identity(&self) -> Result<KubernetesRuntimeIdentityV1> {
        ensure!(
            (32..=128).contains(&self.container_id.len())
                && self
                    .container_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
                && self.initial_pid > 0
                && clean_cgroup_path(&self.cgroup_path)
                && self.annotations.len() <= 64
                && self.annotations.iter().all(|(key, value)| {
                    !key.is_empty() && key.len() <= 253 && !value.is_empty() && value.len() <= 4_096
                }),
            IdentityStateSnafu {
                reason: "runtime admission request is not canonical and bounded",
            }
        );
        let required = |key: &str| {
            self.annotations.get(key).cloned().ok_or_else(|| {
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
        Ok(KubernetesRuntimeIdentityV1 {
            namespace: required(POD_NAMESPACE_ANNOTATION)?,
            pod_uid: required(POD_UID_ANNOTATION)?,
            container_name: required(CONTAINER_NAME_ANNOTATION)?,
            image_digest: image_digest.to_owned(),
            sandbox_id: required(SANDBOX_ID_ANNOTATION)?,
            profile_id,
        })
    }
}

impl RuntimeAdmissionServer {
    pub(crate) fn bind(
        config: &RuntimeAdmissionConfig,
    ) -> Result<(Self, RuntimeAdmissionReceiver)> {
        let parent = config.socket_path.parent().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "runtime admission socket has no parent directory".to_owned(),
            }
            .build()
        })?;
        // The root-owned parent and socket mode make this local endpoint a privileged boundary.
        let parent_metadata = fs::metadata(parent).context(IoSnafu { path: parent })?;
        ensure!(
            parent_metadata.is_dir()
                && parent_metadata.uid() == 0
                && parent_metadata.mode() & 0o022 == 0,
            IdentityStateSnafu {
                reason: "runtime admission socket parent must be root-owned and not group-writable or world-writable",
            }
        );
        if let Ok(metadata) = fs::symlink_metadata(&config.socket_path) {
            ensure!(
                metadata.file_type().is_socket() && metadata.uid() == 0,
                IdentityStateSnafu {
                    reason: "runtime admission socket path is occupied by an unsafe object",
                }
            );
            remove_stale_socket(&config.socket_path)?;
        }
        let listener = UnixListener::bind(&config.socket_path).context(IoSnafu {
            path: &config.socket_path,
        })?;
        fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600)).context(
            IoSnafu {
                path: &config.socket_path,
            },
        )?;
        let metadata = fs::metadata(&config.socket_path).context(IoSnafu {
            path: &config.socket_path,
        })?;
        ensure!(
            metadata.file_type().is_socket()
                && metadata.uid() == 0
                && metadata.mode() & 0o777 == 0o600,
            IdentityStateSnafu {
                reason: "runtime admission socket is not a root-owned mode 0600 socket",
            }
        );
        let (requests, receiver) = mpsc::channel(128);
        Ok((
            Self {
                listener,
                socket_path: config.socket_path.clone(),
                maximum_request_bytes: config.maximum_request_bytes,
                timeout: Duration::from_millis(config.timeout_ms),
                requests,
            },
            RuntimeAdmissionReceiver { requests: receiver },
        ))
    }

    pub(crate) async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, _address) = accepted.context(IoSnafu {
                        path: &self.socket_path,
                    })?;
                    let requests = self.requests.clone();
                    let path = self.socket_path.clone();
                    let maximum_request_bytes = self.maximum_request_bytes;
                    let timeout = self.timeout;
                    tokio::spawn(async move {
                        let _result = Self::handle_connection(
                            stream,
                            &path,
                            maximum_request_bytes,
                            timeout,
                            requests,
                        )
                        .await;
                    });
                }
                changed = shutdown.changed() => {
                    let _result = changed;
                    break;
                }
            }
        }
        fs::remove_file(&self.socket_path).context(IoSnafu {
            path: &self.socket_path,
        })
    }
}

impl RuntimeAdmissionReceiver {
    pub(crate) async fn receive(&mut self) -> Option<RuntimeAdmissionEnvelope> {
        self.requests.recv().await
    }
}

impl RuntimeAdmissionClient {
    pub fn new(socket_path: PathBuf, timeout: Duration) -> Result<Self> {
        ensure!(
            socket_path.is_absolute() && (100..=30_000).contains(&timeout.as_millis()),
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

    pub async fn submit(
        &self,
        request: &RuntimeAdmissionRequestV1,
    ) -> Result<RuntimeAdmissionResponseV1> {
        // Timeout is denial because the OCI prestart process stays held during this exchange.
        tokio::time::timeout(self.timeout, async {
            let stream = UnixStream::connect(&self.socket_path)
                .await
                .context(IoSnafu {
                    path: &self.socket_path,
                })?;
            self.exchange(stream, request).await
        })
        .await
        .map_err(|_elapsed| {
            IdentityStateSnafu {
                reason: "runtime admission endpoint exceeded its fail-closed timeout".to_owned(),
            }
            .build()
        })?
    }

    async fn exchange(
        &self,
        mut stream: UnixStream,
        request: &RuntimeAdmissionRequestV1,
    ) -> Result<RuntimeAdmissionResponseV1> {
        let mut bytes = serde_json::to_vec(request).context(JsonSnafu {
            path: "runtime-admission-request",
        })?;
        bytes.push(b'\n');
        stream.write_all(&bytes).await.context(IoSnafu {
            path: &self.socket_path,
        })?;
        let mut response = Vec::new();
        (&mut stream)
            .take(4_097)
            .read_to_end(&mut response)
            .await
            .context(IoSnafu {
                path: &self.socket_path,
            })?;
        ensure!(
            !response.is_empty() && response.len() <= 4_096,
            IdentityStateSnafu {
                reason: "runtime admission response exceeds its byte limit",
            }
        );
        serde_json::from_slice(&response).context(JsonSnafu {
            path: "runtime-admission-response",
        })
    }
}

impl ScheduledRuntimeBindingV1 {
    pub(crate) fn runtime_binding_id(authority_binding_id: &str, container_id: &str) -> String {
        Self::derived_uuid(&[
            b"MITHRIL-KUBERNETES-RUNTIME-BINDING-V1\0",
            authority_binding_id.as_bytes(),
            container_id.as_bytes(),
        ])
    }

    pub(crate) fn authority_binding_id(pod_uid: &str, container_name: &str) -> String {
        Self::derived_uuid(&[
            b"MITHRIL-KUBERNETES-BINDING-V1\0",
            pod_uid.as_bytes(),
            container_name.as_bytes(),
        ])
    }

    pub(crate) fn resolve(
        configured: &[WorkloadBindingConfig],
        request: &RuntimeAdmissionRequestV1,
    ) -> Result<Self> {
        let identity = request.kubernetes_identity()?;
        ensure!(
            (32..=128).contains(&identity.sandbox_id.len())
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
        resolved.binding_id = Self::runtime_binding_id(authority_binding_id, &request.container_id);
        ensure!(
            current_is_placeholder || resolved.binding_id != current.binding_id,
            IdentityStateSnafu {
                reason: "runtime admission attempted to reuse one container lifetime",
            }
        );
        resolved.container_id = request.container_id.clone();
        resolved.sandbox_id = identity.sandbox_id;
        resolved.root_cgroup_path = Some(request.cgroup_path.clone());
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

fn remove_stale_socket(socket_path: &Path) -> Result<()> {
    // Unlink only when connect proves that no live admission owner holds the path.
    match StandardUnixStream::connect(socket_path) {
        Ok(_stream) => IdentityStateSnafu {
            reason: "another runtime admission owner is active".to_owned(),
        }
        .fail(),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            fs::remove_file(socket_path).context(IoSnafu { path: socket_path })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => IdentityStateSnafu {
            reason: format!("runtime admission socket ownership is not provable: {error}"),
        }
        .fail(),
    }
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
    async fn handle_connection(
        mut stream: UnixStream,
        socket_path: &Path,
        maximum_request_bytes: usize,
        timeout: Duration,
        requests: mpsc::Sender<RuntimeAdmissionEnvelope>,
    ) -> Result<()> {
        let response = tokio::time::timeout(timeout, async {
            // SO_PEERCRED prevents an unprivileged local process from invoking the gate.
            ensure!(
                stream
                    .peer_cred()
                    .context(IoSnafu { path: socket_path })?
                    .uid()
                    == 0,
                IdentityStateSnafu {
                    reason: "runtime admission peer is not root",
                }
            );
            let maximum = u64::try_from(maximum_request_bytes).map_err(|_| {
                IdentityStateSnafu {
                    reason: "runtime admission request limit is invalid".to_owned(),
                }
                .build()
            })?;
            let mut bytes = Vec::new();
            BufReader::new(&mut stream)
                .take(maximum.saturating_add(1))
                .read_until(b'\n', &mut bytes)
                .await
                .context(IoSnafu { path: socket_path })?;
            ensure!(
                bytes.last() == Some(&b'\n') && bytes.len() <= maximum_request_bytes,
                IdentityStateSnafu {
                    reason: "runtime admission request exceeds its byte limit",
                }
            );
            bytes.pop();
            let request = serde_json::from_slice(&bytes).context(JsonSnafu {
                path: "runtime-admission-request",
            })?;
            Self::dispatch(request, requests).await
        })
        .await
        // Convert every timeout and internal error into an explicit denial response.
        .unwrap_or_else(|_elapsed| {
            Ok(RuntimeAdmissionResponseV1 {
                allowed: false,
                reason_code: "ADMISSION_TIMEOUT".to_owned(),
            })
        })
        .unwrap_or_else(|_error| RuntimeAdmissionResponseV1 {
            allowed: false,
            reason_code: "ADMISSION_REJECTED".to_owned(),
        });
        let bytes = serde_json::to_vec(&response).context(JsonSnafu {
            path: "runtime-admission-response",
        })?;
        stream
            .write_all(&bytes)
            .await
            .context(IoSnafu { path: socket_path })
    }

    async fn dispatch(
        request: RuntimeAdmissionRequestV1,
        requests: mpsc::Sender<RuntimeAdmissionEnvelope>,
    ) -> Result<RuntimeAdmissionResponseV1> {
        loop {
            let (response, receiver) = oneshot::channel();
            requests
                .send(RuntimeAdmissionEnvelope {
                    request: request.clone(),
                    response,
                })
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
                return Ok(response);
            }
            // Re-submit so that the node event loop can advance policy between attempts.
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{
        remove_stale_socket, RuntimeAdmissionClient, RuntimeAdmissionRequestV1,
        RuntimeAdmissionResponseV1, RuntimeAdmissionServer, ScheduledRuntimeBindingV1,
        CONTAINER_NAME_ANNOTATION, IMAGE_NAME_ANNOTATION, POD_NAMESPACE_ANNOTATION,
        POD_UID_ANNOTATION, POLICY_CONVERGENCE_PENDING, POLICY_SOURCE_REVISION_ANNOTATION,
        PROFILE_ID_ANNOTATION, SANDBOX_ID_ANNOTATION,
    };
    use crate::{ContainerKindV1, WorkloadBindingConfig};

    fn request() -> RuntimeAdmissionRequestV1 {
        RuntimeAdmissionRequestV1 {
            container_id: "a".repeat(64),
            initial_pid: 42,
            cgroup_path: PathBuf::from("/sys/fs/cgroup/kubepods/pod-a/container-a"),
            annotations: BTreeMap::from([
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
        let identity = request().kubernetes_identity()?;
        assert_eq!(identity.pod_uid, "pod-a");
        assert_eq!(identity.image_digest, format!("sha256:{}", "b".repeat(64)));
        Ok(())
    }

    #[test]
    fn malformed_or_unpinned_requests_fail_closed() {
        let mut invalid_path = request();
        invalid_path.cgroup_path = PathBuf::from("/tmp/not-a-cgroup");
        assert!(invalid_path.kubernetes_identity().is_err());

        let mut unpinned = request();
        unpinned.annotations.insert(
            IMAGE_NAME_ANNOTATION.to_owned(),
            "repo/worker:latest".to_owned(),
        );
        assert!(unpinned.kubernetes_identity().is_err());

        let mut forged_profile = request();
        forged_profile
            .annotations
            .insert(PROFILE_ID_ANNOTATION.to_owned(), "profile-a".to_owned());
        assert!(forged_profile.kubernetes_identity().is_err());
    }

    #[test]
    fn an_active_runtime_admission_owner_cannot_be_replaced(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("runtime-admission.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket)?;
        assert!(remove_stale_socket(&socket).is_err());
        assert!(socket.exists());
        Ok(())
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
        assert_eq!(
            resolved.resolved.root_cgroup_path.as_deref(),
            Some(request.cgroup_path.as_path())
        );
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
        assert!(client.submit(&request()).await.is_err());

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
        let task = tokio::spawn(RuntimeAdmissionServer::dispatch(request(), sender));
        let first = receiver
            .recv()
            .await
            .ok_or_else(|| crate::Error::IdentityState {
                reason: "runtime admission test lost its first request".to_owned(),
                location: snafu::Location::default(),
            })?;
        first
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
                .allowed
        );
        Ok(())
    }
}
