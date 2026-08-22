use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
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
}

pub(crate) struct ScheduledRuntimeBindingV1 {
    pub binding_index: usize,
    pub previous_binding_id: Option<String>,
    pub resolved: WorkloadBindingConfig,
}

pub(crate) struct RuntimeAdmissionEnvelope {
    pub request: RuntimeAdmissionRequestV1,
    pub response: oneshot::Sender<RuntimeAdmissionResponseV1>,
}

pub(crate) struct RuntimeAdmissionServer {
    listener: UnixListener,
    socket_path: PathBuf,
    maximum_request_bytes: usize,
    timeout: Duration,
    requests: mpsc::Sender<RuntimeAdmissionEnvelope>,
}

pub(crate) struct RuntimeAdmissionReceiver {
    requests: mpsc::Receiver<RuntimeAdmissionEnvelope>,
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
        Ok(KubernetesRuntimeIdentityV1 {
            namespace: required(POD_NAMESPACE_ANNOTATION)?,
            pod_uid: required(POD_UID_ANNOTATION)?,
            container_name: required(CONTAINER_NAME_ANNOTATION)?,
            image_digest: image_digest.to_owned(),
            sandbox_id: required(SANDBOX_ID_ANNOTATION)?,
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
            fs::remove_file(&config.socket_path).context(IoSnafu {
                path: &config.socket_path,
            })?;
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
                        let _result = handle_connection(
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

pub async fn submit_runtime_admission(
    socket_path: &Path,
    request: &RuntimeAdmissionRequestV1,
    timeout: Duration,
) -> Result<RuntimeAdmissionResponseV1> {
    tokio::time::timeout(timeout, async {
        let stream = UnixStream::connect(socket_path)
            .await
            .context(IoSnafu { path: socket_path })?;
        exchange_runtime_admission(stream, socket_path, request).await
    })
    .await
    .map_err(|_elapsed| {
        IdentityStateSnafu {
            reason: "runtime admission endpoint exceeded its fail-closed timeout".to_owned(),
        }
        .build()
    })?
}

async fn exchange_runtime_admission(
    mut stream: UnixStream,
    socket_path: &Path,
    request: &RuntimeAdmissionRequestV1,
) -> Result<RuntimeAdmissionResponseV1> {
    let mut bytes = serde_json::to_vec(request).context(JsonSnafu {
        path: "runtime-admission-request",
    })?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .await
        .context(IoSnafu { path: socket_path })?;
    let mut response = Vec::new();
    (&mut stream)
        .take(4_097)
        .read_to_end(&mut response)
        .await
        .context(IoSnafu { path: socket_path })?;
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

pub(crate) fn runtime_binding_id(authority_binding_id: &str, container_id: &str) -> String {
    let digest = Sha256::digest(
        [
            b"MITHRIL-KUBERNETES-RUNTIME-BINDING-V1\0".as_slice(),
            authority_binding_id.as_bytes(),
            container_id.as_bytes(),
        ]
        .concat(),
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).hyphenated().to_string()
}

pub(crate) fn scheduled_authority_binding_id(pod_uid: &str, container_name: &str) -> String {
    derived_uuid(&[
        b"MITHRIL-KUBERNETES-BINDING-V1\0",
        pod_uid.as_bytes(),
        container_name.as_bytes(),
    ])
}

pub(crate) fn resolve_scheduled_runtime_binding(
    configured: &[WorkloadBindingConfig],
    request: &RuntimeAdmissionRequestV1,
) -> Result<ScheduledRuntimeBindingV1> {
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
    let matches = configured
        .iter()
        .enumerate()
        .filter(|(_index, binding)| {
            binding.scheduled_binding_authority_id.is_some()
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
            == scheduled_authority_binding_id(&identity.pod_uid, &identity.container_name),
        IdentityStateSnafu {
            reason: "scheduled binding authority does not match its Pod and container",
        }
    );
    let current_is_placeholder = current.container_id.starts_with("scheduled:");
    ensure!(
        (current_is_placeholder && current.binding_id == authority_binding_id)
            || (!current_is_placeholder
                && current.binding_id
                    == runtime_binding_id(authority_binding_id, &current.container_id)),
        IdentityStateSnafu {
            reason: "runtime binding is not derived from its signed scheduled authority",
        }
    );
    let mut resolved = current.clone();
    resolved.binding_id = runtime_binding_id(authority_binding_id, &request.container_id);
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
    Ok(ScheduledRuntimeBindingV1 {
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

async fn handle_connection(
    mut stream: UnixStream,
    socket_path: &Path,
    maximum_request_bytes: usize,
    timeout: Duration,
    requests: mpsc::Sender<RuntimeAdmissionEnvelope>,
) -> Result<()> {
    let response = tokio::time::timeout(timeout, async {
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
        let (response, receiver) = oneshot::channel();
        requests
            .send(RuntimeAdmissionEnvelope { request, response })
            .await
            .map_err(|_closed| {
                IdentityStateSnafu {
                    reason: "runtime admission owner is unavailable".to_owned(),
                }
                .build()
            })?;
        receiver.await.map_err(|_closed| {
            IdentityStateSnafu {
                reason: "runtime admission owner closed the request".to_owned(),
            }
            .build()
        })
    })
    .await
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{
        resolve_scheduled_runtime_binding, runtime_binding_id, scheduled_authority_binding_id,
        submit_runtime_admission, RuntimeAdmissionRequestV1, CONTAINER_NAME_ANNOTATION,
        IMAGE_NAME_ANNOTATION, POD_NAMESPACE_ANNOTATION, POD_UID_ANNOTATION, SANDBOX_ID_ANNOTATION,
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
            ]),
        }
    }

    fn scheduled_binding() -> WorkloadBindingConfig {
        WorkloadBindingConfig {
            binding_id: scheduled_authority_binding_id("pod-a", "worker"),
            scheduled_binding_authority_id: Some(scheduled_authority_binding_id("pod-a", "worker")),
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
    }

    #[test]
    fn each_runtime_container_gets_a_distinct_binding() {
        let first = runtime_binding_id("11111111-1111-4111-8111-111111111111", &"a".repeat(64));
        let second = runtime_binding_id("11111111-1111-4111-8111-111111111111", &"b".repeat(64));
        assert_ne!(first, second);
        assert_eq!(first.len(), 36);
    }

    #[test]
    fn signed_scheduled_target_resolves_one_runtime_lifetime() -> crate::Result<()> {
        let scheduled = scheduled_binding();
        let request = request();
        let resolved = resolve_scheduled_runtime_binding(&[scheduled], &request)?;
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
            resolve_scheduled_runtime_binding(std::slice::from_ref(&scheduled), &wrong_pod)
                .is_err()
        );

        let request = request();
        let active = resolve_scheduled_runtime_binding(&[scheduled], &request)?.resolved;
        assert!(resolve_scheduled_runtime_binding(&[active], &request).is_err());
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
        assert!(
            submit_runtime_admission(&missing, &request(), Duration::from_millis(20))
                .await
                .is_err()
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(20), std::future::pending::<()>(),)
                .await
                .is_err()
        );
        Ok(())
    }
}
