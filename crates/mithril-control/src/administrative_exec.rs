use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer as _, SigningKey};
use erebor_interceptor_abi::Id128V1;
use minicbor::{Decoder, Encoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};
use uuid::Uuid;

use crate::error::{AdministrativeApprovalSnafu, IoSnafu, JsonSnafu};
use crate::{
    AdministrativeExecArmResult, AdministrativeExecResolution, ArmAdministrativeExec, ControlPlane,
    ResolveAdministrativeExec, Result,
};

const SIGNATURE_DOMAIN: &[u8] = b"MITHRIL-INTENT-V1\0";
const ADMINISTRATIVE_EXEC_KIND: u8 = 8;
const MAX_LIVE_APPROVALS: usize = 4096;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeApprovalConfigV1 {
    pub state_directory: PathBuf,
    pub tenant_id: String,
    pub cluster_uid: String,
    pub trust_domain_id: String,
    pub issuer_id: String,
    pub key_id: String,
    pub private_key_path: PathBuf,
    pub sequence_epoch: u64,
    pub authorization_lifetime_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrativeExecRequestV1 {
    pub node_id: String,
    pub namespace: Vec<u8>,
    pub pod_uid: Vec<u8>,
    pub container_name: Vec<u8>,
    pub full_container_id: Vec<u8>,
    pub container_generation: u64,
    pub argv: Vec<Vec<u8>>,
    pub stream_flags: u8,
    pub approved_role_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PendingAdministrativeApprovalV1 {
    pub request_id: Id128V1,
    pub requester_principal_id: Id128V1,
    pub expires_at_utc_ns: i64,
    pub resolution: AdministrativeExecResolution,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrativeExecCredentialV1 {
    pub approval_id: Id128V1,
    pub credential: String,
    pub expires_at_utc_ns: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedAdministrativeCredentialV1 {
    pub approval_id: Id128V1,
    pub principal_id: Id128V1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrativeAdmissionTargetV1 {
    pub admission_uid: Vec<u8>,
    pub namespace: Vec<u8>,
    pub pod_uid: Vec<u8>,
    pub container_name: Vec<u8>,
    pub full_container_id: Vec<u8>,
    pub container_generation: u64,
    pub argv: Vec<Vec<u8>>,
    pub stream_flags: u8,
    pub approved_role_id: String,
}

pub struct AdministrativeApprovalOwner {
    control: ControlPlane,
    config: PreparedApprovalConfig,
    signing_key: SigningKey,
    state: Mutex<ApprovalState>,
}

struct PreparedApprovalConfig {
    tenant_id: Id128V1,
    cluster_uid: Id128V1,
    trust_domain_id: Id128V1,
    issuer_id: Id128V1,
    key_id: Vec<u8>,
    sequence_epoch: u64,
    authorization_lifetime_ns: i64,
}

struct ApprovalState {
    sequence: SequenceOwner,
    pending: BTreeMap<Id128V1, PendingRequest>,
    approvals: BTreeMap<Id128V1, ApprovalRecord>,
    credentials: BTreeMap<[u8; 32], Id128V1>,
}

struct PendingRequest {
    requester_principal_id: Id128V1,
    node_id: String,
    expires_at_utc_ns: i64,
    resolution: AdministrativeExecResolution,
}

struct ApprovalRecord {
    requester_principal_id: Id128V1,
    node_id: String,
    expires_at_utc_ns: i64,
    proof_id: Id128V1,
    claim_slot_id: Id128V1,
    body_sha256: [u8; 32],
    signed_intent: Vec<u8>,
    resolution: AdministrativeExecResolution,
    state: ApprovalRecordState,
}

#[derive(Clone)]
enum ApprovalRecordState {
    Approved,
    Authenticated,
    Arming {
        admission_uid: Vec<u8>,
    },
    Committed {
        admission_uid: Vec<u8>,
        result: AdministrativeExecArmResult,
    },
    Closed,
    ReconciliationRequired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSequenceV1 {
    schema_version: u32,
    trust_domain_id: String,
    issuer_id: String,
    key_id: String,
    sequence_epoch: u64,
    last_sequence: u64,
}

struct SequenceOwner {
    path: PathBuf,
    state: StoredSequenceV1,
}

impl AdministrativeApprovalOwner {
    pub fn load(config: &AdministrativeApprovalConfigV1, control: ControlPlane) -> Result<Self> {
        let tenant_id = parse_id("tenant_id", &config.tenant_id)?;
        let cluster_uid = parse_id("cluster_uid", &config.cluster_uid)?;
        let trust_domain_id = parse_id("trust_domain_id", &config.trust_domain_id)?;
        let issuer_id = parse_id("issuer_id", &config.issuer_id)?;
        ensure!(
            (1..=128).contains(&config.key_id.len())
                && !config.key_id.chars().any(char::is_whitespace)
                && config.sequence_epoch > 0
                && (1..=300).contains(&config.authorization_lifetime_seconds),
            AdministrativeApprovalSnafu {
                reason: "administrative key, sequence epoch, or lifetime is invalid",
            }
        );
        let signing_key = read_signing_key(&config.private_key_path)?;
        let sequence = SequenceOwner::load(
            &config.state_directory,
            &config.trust_domain_id,
            &config.issuer_id,
            &config.key_id,
            config.sequence_epoch,
        )?;
        Ok(Self {
            control,
            config: PreparedApprovalConfig {
                tenant_id,
                cluster_uid,
                trust_domain_id,
                issuer_id,
                key_id: config.key_id.as_bytes().to_vec(),
                sequence_epoch: config.sequence_epoch,
                authorization_lifetime_ns: i64::try_from(
                    config.authorization_lifetime_seconds * 1_000_000_000,
                )
                .map_err(|error| approval_error(format!("lifetime overflow: {error}")))?,
            },
            signing_key,
            state: Mutex::new(ApprovalState {
                sequence,
                pending: BTreeMap::new(),
                approvals: BTreeMap::new(),
                credentials: BTreeMap::new(),
            }),
        })
    }

    pub async fn request(
        &self,
        requester_principal_id: Id128V1,
        request: AdministrativeExecRequestV1,
    ) -> Result<PendingAdministrativeApprovalV1> {
        let resolution = self.resolve(&request).await?;
        self.request_resolved(requester_principal_id, request, resolution)
    }

    pub async fn resolve(
        &self,
        request: &AdministrativeExecRequestV1,
    ) -> Result<AdministrativeExecResolution> {
        ensure!(
            valid_request(request),
            AdministrativeApprovalSnafu {
                reason: "administrative request is not exact or bounded",
            }
        );
        let request_id = random_id();
        let resolution = self
            .control
            .resolve_administrative_exec(
                &request.node_id,
                ResolveAdministrativeExec {
                    request_id: portable_id_bytes(request_id),
                    namespace: request.namespace.clone(),
                    pod_uid: request.pod_uid.clone(),
                    container_name: request.container_name.clone(),
                    full_container_id: request.full_container_id.clone(),
                    container_generation: request.container_generation,
                    argv: request.argv.clone(),
                    stream_flags: u32::from(request.stream_flags),
                    approved_role_id: request.approved_role_id.clone(),
                },
            )
            .await
            .map_err(|error| approval_error(format!("target node resolution failed: {error}")))?;
        validate_resolution(request, &resolution)?;
        Ok(resolution)
    }

    pub fn request_resolved(
        &self,
        requester_principal_id: Id128V1,
        request: AdministrativeExecRequestV1,
        resolution: AdministrativeExecResolution,
    ) -> Result<PendingAdministrativeApprovalV1> {
        ensure!(
            !requester_principal_id.is_zero() && valid_request(&request),
            AdministrativeApprovalSnafu {
                reason: "administrative request is not exact or bounded",
            }
        );
        validate_resolution(&request, &resolution)?;
        let request_id = proto_id(&resolution.request_id, "administrative request ID")?;
        let expires_at_utc_ns = current_utc_ns()?
            .checked_add(self.config.authorization_lifetime_ns)
            .ok_or_else(|| approval_error("administrative request expiry overflow"))?;
        let pending = PendingAdministrativeApprovalV1 {
            request_id,
            requester_principal_id,
            expires_at_utc_ns,
            resolution: resolution.clone(),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative approval state is poisoned"))?;
        state.retain_live(current_utc_ns()?);
        ensure!(
            state.pending.len() + state.approvals.len() < MAX_LIVE_APPROVALS
                && !state.pending.contains_key(&request_id),
            AdministrativeApprovalSnafu {
                reason: "administrative approval capacity or identity is unavailable",
            }
        );
        state.pending.insert(
            request_id,
            PendingRequest {
                requester_principal_id,
                node_id: request.node_id,
                expires_at_utc_ns,
                resolution,
            },
        );
        Ok(pending)
    }

    pub fn approve(
        &self,
        request_id: Id128V1,
        approver_principal_id: Id128V1,
    ) -> Result<AdministrativeExecCredentialV1> {
        let now = current_utc_ns()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative approval state is poisoned"))?;
        state.retain_live(now);
        let pending = state.pending.remove(&request_id).ok_or_else(|| {
            approval_error("administrative approval request is missing or already decided")
        })?;
        ensure!(
            !approver_principal_id.is_zero()
                && approver_principal_id == pending.requester_principal_id
                && now <= pending.expires_at_utc_ns,
            AdministrativeApprovalSnafu {
                reason:
                    "administrative approval requires the authenticated requester before expiry",
            }
        );
        let sequence = state.sequence.issue()?;
        let proof_id = random_id();
        let claim_slot_id = random_id();
        let body = encode_administrative_body(
            pending.requester_principal_id,
            approver_principal_id,
            self.config.cluster_uid,
            &pending.resolution,
        )?;
        let body_sha256: [u8; 32] = Sha256::digest(&body).into();
        let signed_intent = encode_signed_intent(
            &self.signing_key,
            &self.config,
            sequence,
            proof_id,
            claim_slot_id,
            now,
            pending.expires_at_utc_ns,
            &body,
        )?;
        let credential = format!(
            "mithril-exec-{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let credential_sha256: [u8; 32] = Sha256::digest(credential.as_bytes()).into();
        ensure!(
            !state.credentials.contains_key(&credential_sha256)
                && !state.approvals.contains_key(&proof_id),
            AdministrativeApprovalSnafu {
                reason: "administrative approval identity collided",
            }
        );
        state.credentials.insert(credential_sha256, proof_id);
        state.approvals.insert(
            proof_id,
            ApprovalRecord {
                requester_principal_id: pending.requester_principal_id,
                node_id: pending.node_id,
                expires_at_utc_ns: pending.expires_at_utc_ns,
                proof_id,
                claim_slot_id,
                body_sha256,
                signed_intent,
                resolution: pending.resolution,
                state: ApprovalRecordState::Approved,
            },
        );
        Ok(AdministrativeExecCredentialV1 {
            approval_id: proof_id,
            credential,
            expires_at_utc_ns: pending.expires_at_utc_ns,
        })
    }

    pub fn authenticate_credential(
        &self,
        credential: &str,
    ) -> Result<AuthenticatedAdministrativeCredentialV1> {
        let credential_sha256: [u8; 32] = Sha256::digest(credential.as_bytes()).into();
        let now = current_utc_ns()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative approval state is poisoned"))?;
        state.retain_live(now);
        let approval_id = *state
            .credentials
            .get(&credential_sha256)
            .ok_or_else(|| approval_error("administrative exec credential is invalid or used"))?;
        let approval = state.approvals.get_mut(&approval_id).ok_or_else(|| {
            approval_error("administrative exec credential lost its approval record")
        })?;
        ensure!(
            now <= approval.expires_at_utc_ns && credential_authentication_is_open(&approval.state),
            AdministrativeApprovalSnafu {
                reason: "administrative exec credential expired or changed state",
            }
        );
        if matches!(approval.state, ApprovalRecordState::Approved) {
            approval.state = ApprovalRecordState::Authenticated;
        }
        Ok(AuthenticatedAdministrativeCredentialV1 {
            approval_id,
            principal_id: approval.requester_principal_id,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admission_target(
        &self,
        approval_id: Id128V1,
        authenticated_principal_id: Id128V1,
        admission_uid: Vec<u8>,
        namespace: Vec<u8>,
        pod_uid: Vec<u8>,
        container_name: Vec<u8>,
        full_container_id: Vec<u8>,
        argv: Vec<Vec<u8>>,
        stream_flags: u8,
    ) -> Result<AdministrativeAdmissionTargetV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative approval state is poisoned"))?;
        state.retain_live(current_utc_ns()?);
        let approval = state
            .approvals
            .get(&approval_id)
            .ok_or_else(|| approval_error("administrative approval is missing"))?;
        ensure!(
            authenticated_principal_id == approval.requester_principal_id,
            AdministrativeApprovalSnafu {
                reason: "admission principal differs from the authenticated requester",
            }
        );
        Ok(AdministrativeAdmissionTargetV1 {
            admission_uid,
            namespace,
            pod_uid,
            container_name,
            full_container_id,
            container_generation: approval.resolution.container_generation,
            argv,
            stream_flags,
            approved_role_id: approval.resolution.approved_role_id.clone(),
        })
    }

    pub async fn admit(
        &self,
        approval_id: Id128V1,
        target: AdministrativeAdmissionTargetV1,
    ) -> Result<AdministrativeExecArmResult> {
        let (node_id, signed_intent, body_sha256, proof_id, claim_slot_id) = {
            let now = current_utc_ns()?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| approval_error("administrative approval state is poisoned"))?;
            state.retain_live(now);
            let approval = state.approvals.get_mut(&approval_id).ok_or_else(|| {
                approval_error("administrative approval is missing or already removed")
            })?;
            if let ApprovalRecordState::Committed {
                admission_uid,
                result,
            } = &approval.state
            {
                ensure!(
                    admission_uid == &target.admission_uid,
                    AdministrativeApprovalSnafu {
                        reason:
                            "administrative approval was committed to another admission request",
                    }
                );
                return Ok(result.clone());
            }
            ensure!(
                now <= approval.expires_at_utc_ns
                    && matches!(approval.state, ApprovalRecordState::Authenticated)
                    && admission_matches(&approval.resolution, &target),
                AdministrativeApprovalSnafu {
                    reason: "admission request differs from the authenticated exact approval",
                }
            );
            approval.state = ApprovalRecordState::Arming {
                admission_uid: target.admission_uid.clone(),
            };
            (
                approval.node_id.clone(),
                approval.signed_intent.clone(),
                approval.body_sha256,
                approval.proof_id,
                approval.claim_slot_id,
            )
        };
        let request_id = random_id();
        let outcome = self
            .control
            .arm_administrative_exec(
                &node_id,
                ArmAdministrativeExec {
                    request_id: portable_id_bytes(request_id),
                    signed_intent,
                    body_sha256: body_sha256.to_vec(),
                },
            )
            .await;
        let mut state = self
            .state
            .lock()
            .map_err(|_| approval_error("administrative approval state is poisoned"))?;
        let approval = state.approvals.get_mut(&approval_id).ok_or_else(|| {
            approval_error("administrative approval disappeared during node preparation")
        })?;
        ensure!(
            matches!(
                &approval.state,
                ApprovalRecordState::Arming { admission_uid }
                    if admission_uid == &target.admission_uid
            ),
            AdministrativeApprovalSnafu {
                reason: "administrative approval changed during node preparation",
            }
        );
        match outcome {
            Ok(result)
                if result.armed
                    && result.proof_id == portable_id_bytes(proof_id)
                    && result.claim_slot_id == portable_id_bytes(claim_slot_id) =>
            {
                approval.state = ApprovalRecordState::Committed {
                    admission_uid: target.admission_uid,
                    result: result.clone(),
                };
                Ok(result)
            }
            Ok(_) => {
                approval.state = ApprovalRecordState::Closed;
                AdministrativeApprovalSnafu {
                    reason: "target node rejected or misidentified the administrative slot",
                }
                .fail()
            }
            Err(error) => {
                approval.state = ApprovalRecordState::ReconciliationRequired;
                AdministrativeApprovalSnafu {
                    reason: format!(
                        "target node result is ambiguous and requires reconciliation: {error}"
                    ),
                }
                .fail()
            }
        }
    }
}

impl ApprovalState {
    fn retain_live(&mut self, now: i64) {
        self.pending
            .retain(|_, request| request.expires_at_utc_ns >= now);
        self.approvals
            .retain(|_, approval| approval.expires_at_utc_ns >= now);
        self.credentials
            .retain(|_, proof_id| self.approvals.contains_key(proof_id));
    }
}

fn credential_authentication_is_open(state: &ApprovalRecordState) -> bool {
    matches!(
        state,
        ApprovalRecordState::Approved
            | ApprovalRecordState::Authenticated
            | ApprovalRecordState::Arming { .. }
            | ApprovalRecordState::Committed { .. }
    )
}

impl SequenceOwner {
    fn load(
        directory: &Path,
        trust_domain_id: &str,
        issuer_id: &str,
        key_id: &str,
        sequence_epoch: u64,
    ) -> Result<Self> {
        fs::create_dir_all(directory).context(IoSnafu { path: directory })?;
        let path = directory.join("administrative-approval-sequence-v1.json");
        let expected = StoredSequenceV1 {
            schema_version: 1,
            trust_domain_id: trust_domain_id.to_owned(),
            issuer_id: issuer_id.to_owned(),
            key_id: key_id.to_owned(),
            sequence_epoch,
            last_sequence: 0,
        };
        let state = if path.exists() {
            let loaded: StoredSequenceV1 =
                serde_json::from_slice(&fs::read(&path).context(IoSnafu { path: &path })?)
                    .context(JsonSnafu { path: &path })?;
            ensure!(
                loaded.schema_version == expected.schema_version
                    && loaded.trust_domain_id == expected.trust_domain_id
                    && loaded.issuer_id == expected.issuer_id
                    && loaded.key_id == expected.key_id
                    && loaded.sequence_epoch == expected.sequence_epoch,
                AdministrativeApprovalSnafu {
                    reason: "administrative approval sequence state has another owner or epoch",
                }
            );
            loaded
        } else {
            expected
        };
        Ok(Self { path, state })
    }

    fn issue(&mut self) -> Result<u64> {
        self.state.last_sequence = self
            .state
            .last_sequence
            .checked_add(1)
            .ok_or_else(|| approval_error("administrative approval sequence exhausted"))?;
        persist_sequence(&self.path, &self.state)?;
        Ok(self.state.last_sequence)
    }
}

fn persist_sequence(path: &Path, state: &StoredSequenceV1) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| approval_error("administrative sequence path has no parent"))?;
    let temporary = parent.join(format!(
        ".administrative-approval-sequence-{}.tmp",
        Uuid::new_v4().simple()
    ));
    let bytes = serde_json::to_vec(state).context(JsonSnafu { path })?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .context(IoSnafu { path: &temporary })?;
    file.write_all(&bytes)
        .context(IoSnafu { path: &temporary })?;
    file.sync_all().context(IoSnafu { path: &temporary })?;
    fs::rename(&temporary, path).context(IoSnafu { path })?;
    File::open(parent)
        .context(IoSnafu { path: parent })?
        .sync_all()
        .context(IoSnafu { path: parent })
}

fn validate_resolution(
    request: &AdministrativeExecRequestV1,
    resolution: &AdministrativeExecResolution,
) -> Result<()> {
    let requested_node_id = parse_id("node_id", &request.node_id)?;
    let executable = resolution.resolved_executable.as_ref();
    let object = executable.and_then(|executable| executable.executable_object.as_ref());
    ensure!(
        resolution.resolved
            && resolution.request_id.len() == 16
            && resolution.target_node_id == portable_id_bytes(requested_node_id)
            && resolution.namespace == request.namespace
            && resolution.pod_uid == request.pod_uid
            && resolution.container_name == request.container_name
            && resolution.full_container_id == request.full_container_id
            && (request.container_generation == 0
                || resolution.container_generation == request.container_generation)
            && resolution.container_generation > 0
            && resolution.argv == request.argv
            && resolution.stream_flags == u32::from(request.stream_flags)
            && resolution.approved_role_id == request.approved_role_id
            && resolution.profile_id.len() == 16
            && resolution.profile_owner_generation > 0
            && resolution.profile_artifact_sha256.len() == 32
            && executable.is_some_and(|value| {
                value.requested_name == request.argv[0]
                    && value.resolution_mode > 0
                    && value.target_mount_namespace_id.len() == 16
                    && value.target_mount_topology_generation > 0
            })
            && object.is_some_and(|value| {
                value.mount_namespace_id.len() == 16
                    && value.mount_topology_generation > 0
                    && value.mount_id > 0
                    && value.filesystem_instance_id.len() == 16
                    && value.inode > 0
                    && value.inode_generation > 0
                    && value.exact_live_object_id.len() == 16
                    && value.object_kind == 1
                    && value.backing_identity.len() == 16
                    && value.live_interval_id.len() == 16
            }),
        AdministrativeApprovalSnafu {
            reason: "target node returned an incomplete or changed administrative resolution",
        }
    );
    Ok(())
}

fn admission_matches(
    resolution: &AdministrativeExecResolution,
    target: &AdministrativeAdmissionTargetV1,
) -> bool {
    (1..=128).contains(&target.admission_uid.len())
        && resolution.namespace == target.namespace
        && resolution.pod_uid == target.pod_uid
        && resolution.container_name == target.container_name
        && resolution.full_container_id == target.full_container_id
        && resolution.container_generation == target.container_generation
        && resolution.argv == target.argv
        && resolution.stream_flags == u32::from(target.stream_flags)
        && resolution.approved_role_id == target.approved_role_id
}

fn valid_request(request: &AdministrativeExecRequestV1) -> bool {
    Uuid::parse_str(&request.node_id)
        .is_ok_and(|uuid| uuid.hyphenated().to_string() == request.node_id)
        && (1..=253).contains(&request.namespace.len())
        && std::str::from_utf8(&request.namespace).is_ok()
        && (1..=64).contains(&request.pod_uid.len())
        && (1..=253).contains(&request.container_name.len())
        && std::str::from_utf8(&request.container_name).is_ok()
        && (32..=128).contains(&request.full_container_id.len())
        && !request.argv.is_empty()
        && request.argv.len() <= 256
        && !request.argv[0].is_empty()
        && request
            .argv
            .iter()
            .all(|argument| argument.len() <= 4096 && !argument.contains(&0))
        && (1..=4096).contains(&request.argv.iter().map(Vec::len).sum::<usize>())
        && request.stream_flags & !0x0f == 0
        && valid_policy_local_id(&request.approved_role_id)
}

fn encode_administrative_body(
    requester: Id128V1,
    approver: Id128V1,
    cluster_uid: Id128V1,
    resolution: &AdministrativeExecResolution,
) -> Result<Vec<u8>> {
    let executable = resolution
        .resolved_executable
        .as_ref()
        .ok_or_else(|| approval_error("administrative resolution has no executable"))?;
    let object = executable
        .executable_object
        .as_ref()
        .ok_or_else(|| approval_error("administrative resolution has no executable object"))?;
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder.map(2).map_err(cbor_error)?;
    encoder
        .u8(0)
        .map_err(cbor_error)?
        .u8(8)
        .map_err(cbor_error)?;
    encoder
        .u8(1)
        .map_err(cbor_error)?
        .map(16)
        .map_err(cbor_error)?;
    for (key, value) in [(0, requester), (1, approver), (2, cluster_uid)] {
        encoder.u8(key).map_err(cbor_error)?;
        encode_id(&mut encoder, value)?;
    }
    for (key, value) in [
        (3, resolution.namespace.as_slice()),
        (4, resolution.pod_uid.as_slice()),
        (5, resolution.container_name.as_slice()),
        (6, resolution.full_container_id.as_slice()),
    ] {
        encoder
            .u8(key)
            .map_err(cbor_error)?
            .bytes(value)
            .map_err(cbor_error)?;
    }
    encoder
        .u8(7)
        .map_err(cbor_error)?
        .u64(resolution.container_generation)
        .map_err(cbor_error)?;
    encoder
        .u8(8)
        .map_err(cbor_error)?
        .array(resolution.argv.len() as u64)
        .map_err(cbor_error)?;
    for argument in &resolution.argv {
        encoder.bytes(argument).map_err(cbor_error)?;
    }
    encoder
        .u8(9)
        .map_err(cbor_error)?
        .u32(resolution.stream_flags)
        .map_err(cbor_error)?
        .u8(10)
        .map_err(cbor_error)?
        .str(&resolution.approved_role_id)
        .map_err(cbor_error)?;
    encoder
        .u8(11)
        .map_err(cbor_error)?
        .map(3)
        .map_err(cbor_error)?;
    encoder.u8(0).map_err(cbor_error)?;
    encode_id(
        &mut encoder,
        proto_id(&resolution.profile_id, "profile ID")?,
    )?;
    encoder
        .u8(1)
        .map_err(cbor_error)?
        .u64(resolution.profile_owner_generation)
        .map_err(cbor_error)?;
    encoder.u8(2).map_err(cbor_error)?;
    encode_digest(&mut encoder, &resolution.profile_artifact_sha256)?;
    encoder.u8(12).map_err(cbor_error)?;
    encode_id(
        &mut encoder,
        proto_id(&resolution.target_node_id, "target node ID")?,
    )?;
    encoder
        .u8(13)
        .map_err(cbor_error)?
        .u8(1)
        .map_err(cbor_error)?
        .u8(14)
        .map_err(cbor_error)?
        .bool(true)
        .map_err(cbor_error)?;
    encoder
        .u8(15)
        .map_err(cbor_error)?
        .map(8)
        .map_err(cbor_error)?;
    for (key, value) in [
        (0, executable.requested_name.as_slice()),
        (2, executable.resolved_display_path.as_slice()),
        (3, executable.container_working_directory.as_slice()),
    ] {
        encoder
            .u8(key)
            .map_err(cbor_error)?
            .bytes(value)
            .map_err(cbor_error)?;
        if key == 0 {
            encoder
                .u8(1)
                .map_err(cbor_error)?
                .u32(executable.resolution_mode)
                .map_err(cbor_error)?;
        }
    }
    encoder
        .u8(4)
        .map_err(cbor_error)?
        .array(executable.effective_path_entries.len() as u64)
        .map_err(cbor_error)?;
    for entry in &executable.effective_path_entries {
        encoder.bytes(entry).map_err(cbor_error)?;
    }
    encoder.u8(5).map_err(cbor_error)?;
    encode_id(
        &mut encoder,
        proto_id(
            &executable.target_mount_namespace_id,
            "target mount namespace ID",
        )?,
    )?;
    encoder
        .u8(6)
        .map_err(cbor_error)?
        .u64(executable.target_mount_topology_generation)
        .map_err(cbor_error)?;
    encoder
        .u8(7)
        .map_err(cbor_error)?
        .map(10)
        .map_err(cbor_error)?;
    encode_file_object(&mut encoder, object)?;
    Ok(bytes)
}

fn encode_file_object(
    encoder: &mut Encoder<&mut Vec<u8>>,
    object: &crate::AdministrativeFileObject,
) -> Result<()> {
    encoder.u8(0).map_err(cbor_error)?;
    encode_id(
        encoder,
        proto_id(&object.mount_namespace_id, "object mount namespace ID")?,
    )?;
    encoder
        .u8(1)
        .map_err(cbor_error)?
        .u64(object.mount_topology_generation)
        .map_err(cbor_error)?
        .u8(2)
        .map_err(cbor_error)?
        .u32(object.mount_id)
        .map_err(cbor_error)?;
    encoder.u8(3).map_err(cbor_error)?;
    encode_id(
        encoder,
        proto_id(&object.filesystem_instance_id, "filesystem instance ID")?,
    )?;
    encoder
        .u8(4)
        .map_err(cbor_error)?
        .u64(object.inode)
        .map_err(cbor_error)?
        .u8(5)
        .map_err(cbor_error)?
        .u64(object.inode_generation)
        .map_err(cbor_error)?;
    encoder.u8(6).map_err(cbor_error)?;
    encode_id(
        encoder,
        proto_id(&object.exact_live_object_id, "exact live object ID")?,
    )?;
    encoder
        .u8(7)
        .map_err(cbor_error)?
        .u32(object.object_kind)
        .map_err(cbor_error)?;
    encoder.u8(8).map_err(cbor_error)?;
    encode_id(
        encoder,
        proto_id(&object.backing_identity, "backing identity")?,
    )?;
    encoder.u8(9).map_err(cbor_error)?;
    encode_id(
        encoder,
        proto_id(&object.live_interval_id, "live interval ID")?,
    )
}

#[cfg(feature = "test-fixtures")]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn encode_administrative_authorization_fixture(
    signing_key: &SigningKey,
    key_id: &[u8],
    tenant_id: Id128V1,
    cluster_uid: Id128V1,
    trust_domain_id: Id128V1,
    issuer_id: Id128V1,
    sequence_epoch: u64,
    sequence: u64,
    proof_id: Id128V1,
    claim_slot_id: Id128V1,
    issued_at_utc_ns: i64,
    expires_at_utc_ns: i64,
    requester: Id128V1,
    approver: Id128V1,
    resolution: &AdministrativeExecResolution,
) -> Result<(Vec<u8>, [u8; 32])> {
    let body = encode_administrative_body(requester, approver, cluster_uid, resolution)?;
    let body_sha256 = Sha256::digest(&body).into();
    let config = PreparedApprovalConfig {
        tenant_id,
        cluster_uid,
        trust_domain_id,
        issuer_id,
        key_id: key_id.to_vec(),
        sequence_epoch,
        authorization_lifetime_ns: expires_at_utc_ns.saturating_sub(issued_at_utc_ns),
    };
    let envelope = encode_signed_intent(
        signing_key,
        &config,
        sequence,
        proof_id,
        claim_slot_id,
        issued_at_utc_ns,
        expires_at_utc_ns,
        &body,
    )?;
    Ok((envelope, body_sha256))
}

#[allow(clippy::too_many_arguments)]
fn encode_signed_intent(
    signing_key: &SigningKey,
    config: &PreparedApprovalConfig,
    sequence: u64,
    proof_id: Id128V1,
    claim_slot_id: Id128V1,
    issued_at_utc_ns: i64,
    expires_at_utc_ns: i64,
    body: &[u8],
) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    let mut encoder = Encoder::new(&mut payload);
    encoder.map(13).map_err(cbor_error)?;
    encoder
        .u8(0)
        .map_err(cbor_error)?
        .u8(1)
        .map_err(cbor_error)?
        .u8(1)
        .map_err(cbor_error)?
        .u8(ADMINISTRATIVE_EXEC_KIND)
        .map_err(cbor_error)?;
    for (key, value) in [
        (2, proof_id),
        (3, config.tenant_id),
        (4, config.trust_domain_id),
        (5, config.issuer_id),
    ] {
        encoder.u8(key).map_err(cbor_error)?;
        encode_id(&mut encoder, value)?;
    }
    encoder
        .u8(6)
        .map_err(cbor_error)?
        .u64(config.sequence_epoch)
        .map_err(cbor_error)?
        .u8(7)
        .map_err(cbor_error)?
        .u64(sequence)
        .map_err(cbor_error)?
        .u8(8)
        .map_err(cbor_error)?
        .i64(issued_at_utc_ns)
        .map_err(cbor_error)?
        .u8(9)
        .map_err(cbor_error)?
        .i64(issued_at_utc_ns)
        .map_err(cbor_error)?
        .u8(10)
        .map_err(cbor_error)?
        .i64(expires_at_utc_ns)
        .map_err(cbor_error)?
        .u8(11)
        .map_err(cbor_error)?
        .array(1)
        .map_err(cbor_error)?;
    encode_id(&mut encoder, claim_slot_id)?;
    encoder.u8(12).map_err(cbor_error)?;
    let tokens = Decoder::new(body)
        .tokens()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(cbor_error)?;
    encoder.tokens(&tokens).map_err(cbor_error)?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&Sha256::digest(&payload));
    let signature = signing_key.sign(&message).to_bytes();
    let mut envelope = Vec::new();
    Encoder::new(&mut envelope)
        .map(5)
        .map_err(cbor_error)?
        .u8(0)
        .map_err(cbor_error)?
        .u8(1)
        .map_err(cbor_error)?
        .u8(1)
        .map_err(cbor_error)?
        .bytes(&config.key_id)
        .map_err(cbor_error)?
        .u8(2)
        .map_err(cbor_error)?
        .u8(1)
        .map_err(cbor_error)?
        .u8(3)
        .map_err(cbor_error)?
        .bytes(&payload)
        .map_err(cbor_error)?
        .u8(4)
        .map_err(cbor_error)?
        .bytes(&signature)
        .map_err(cbor_error)?;
    Ok(envelope)
}

fn encode_digest(encoder: &mut Encoder<&mut Vec<u8>>, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() == 32,
        AdministrativeApprovalSnafu {
            reason: "administrative digest is not 32 bytes",
        }
    );
    encoder
        .map(2)
        .map_err(cbor_error)?
        .u8(0)
        .map_err(cbor_error)?
        .u8(1)
        .map_err(cbor_error)?
        .u8(1)
        .map_err(cbor_error)?
        .bytes(bytes)
        .map_err(cbor_error)?;
    Ok(())
}

fn encode_id(encoder: &mut Encoder<&mut Vec<u8>>, value: Id128V1) -> Result<()> {
    ensure!(
        !value.is_zero(),
        AdministrativeApprovalSnafu {
            reason: "administrative identity is zero",
        }
    );
    encoder
        .bytes(&portable_id_bytes(value))
        .map_err(cbor_error)?;
    Ok(())
}

fn proto_id(bytes: &[u8], name: &str) -> Result<Id128V1> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| approval_error(format!("{name} is not one portable Id128 value")))?;
    let value = u128::from_be_bytes(bytes);
    let id = Id128V1::new((value >> 64) as u64, value as u64);
    ensure!(
        !id.is_zero(),
        AdministrativeApprovalSnafu {
            reason: format!("{name} is zero"),
        }
    );
    Ok(id)
}

fn parse_id(name: &str, value: &str) -> Result<Id128V1> {
    let uuid = Uuid::parse_str(value)
        .map_err(|error| approval_error(format!("{name} is not a canonical UUID: {error}")))?;
    ensure!(
        uuid.hyphenated().to_string() == value,
        AdministrativeApprovalSnafu {
            reason: format!("{name} is not a canonical UUID"),
        }
    );
    proto_id(uuid.as_bytes(), name)
}

fn random_id() -> Id128V1 {
    let value = u128::from_be_bytes(*Uuid::new_v4().as_bytes());
    Id128V1::new((value >> 64) as u64, value as u64)
}

fn portable_id_bytes(value: Id128V1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&value.high.to_be_bytes());
    bytes.extend_from_slice(&value.low.to_be_bytes());
    bytes
}

fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let bytes = fs::read(path).context(IoSnafu { path })?;
    let value = std::str::from_utf8(&bytes)
        .map(str::trim)
        .map_err(|error| approval_error(format!("signing key is not UTF-8: {error}")))?;
    let decoded = hex::decode(value)
        .map_err(|error| approval_error(format!("signing key is not hex: {error}")))?;
    ensure!(
        hex::encode(&decoded) == value,
        AdministrativeApprovalSnafu {
            reason: "signing key is not lowercase canonical hex",
        }
    );
    let key: [u8; 32] = decoded.try_into().map_err(|value: Vec<u8>| {
        approval_error(format!(
            "signing key has {} bytes instead of 32",
            value.len()
        ))
    })?;
    Ok(SigningKey::from_bytes(&key))
}

fn current_utc_ns() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| approval_error(format!("system clock precedes Unix epoch: {error}")))?;
    i64::try_from(duration.as_nanos())
        .map_err(|error| approval_error(format!("system clock exceeds i64 nanoseconds: {error}")))
}

fn valid_policy_local_id(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (index > 0 && (byte.is_ascii_digit() || byte == b'.' || byte == b'-'))
        })
}

fn cbor_error(error: impl std::fmt::Display) -> crate::Error {
    approval_error(format!("canonical CBOR encoding failed: {error}"))
}

fn approval_error(reason: impl Into<String>) -> crate::Error {
    AdministrativeApprovalSnafu {
        reason: reason.into(),
    }
    .build()
}

#[cfg(test)]
mod tests {
    use super::{credential_authentication_is_open, valid_request, ApprovalRecordState};
    use crate::AdministrativeExecRequestV1;

    #[test]
    fn administrative_credential_stays_open_for_the_committed_admission() {
        assert!(credential_authentication_is_open(
            &ApprovalRecordState::Approved
        ));
        assert!(credential_authentication_is_open(
            &ApprovalRecordState::Authenticated
        ));
        assert!(credential_authentication_is_open(
            &ApprovalRecordState::Committed {
                admission_uid: vec![1],
                result: Default::default(),
            }
        ));
        assert!(!credential_authentication_is_open(
            &ApprovalRecordState::Closed
        ));
    }

    #[test]
    fn administrative_request_requires_a_canonical_node_id() {
        let mut request = AdministrativeExecRequestV1 {
            node_id: "aaaaaaaa-0000-0000-0000-000000000001".to_owned(),
            namespace: b"default".to_vec(),
            pod_uid: b"00000000-0000-0000-0000-000000000002".to_vec(),
            container_name: b"app".to_vec(),
            full_container_id: vec![b'a'; 64],
            container_generation: 0,
            argv: vec![b"/bin/sh".to_vec()],
            stream_flags: 0b0110,
            approved_role_id: "administrative-diagnostic".to_owned(),
        };
        assert!(valid_request(&request));
        request.node_id.make_ascii_uppercase();
        assert!(!valid_request(&request));
    }
}
