mod replay;

use std::collections::BTreeSet;
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use erebor_interceptor::{KernelHost, MapInsertResult};
use erebor_interceptor_abi::{
    ExceptionBindingStateV1, ExceptionHandleBindingKeyV1, ExceptionHandleBindingV1,
    ExecutionApprovalSlotKeyV1, ExecutionApprovalSlotStateV1, ExecutionApprovalSlotV1,
    ExecutionArgvChunkKeyV1, ExecutionArgvChunkV1, ExecutionArgvSnapshotV1, ExternalRootClassV1,
    Id128V1, PendingExecutionApprovalStateV1, PendingExecutionApprovalV1,
    EXECUTION_ARGV_CHUNK_BYTES_V1, EXECUTION_ARGV_CHUNK_TERMINAL_V1,
};
use minicbor::data::Token;
use minicbor::{Decoder, Encoder};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};

use self::replay::{AcceptedProof, ReplayKey, ReplayLedger};
use zerocopy::{IntoBytes as _, KnownLayout, TryFromBytes};

use crate::error::{AuthorizationSnafu, InterceptorSnafu};
use crate::Result;

const ADMINISTRATIVE_EXEC_KIND: u8 = 8;
const MAX_PAYLOAD_BYTES: usize = 32 * 1024;
const MAX_AGGREGATE_BYTES: usize = 24 * 1024;
const MAX_ARRAY_MEMBERS: usize = 512;
const MAX_NESTING_DEPTH: usize = 8;
const MAX_CLOCK_SKEW_NS: i64 = 5 * 60 * 1_000_000_000;
const MAX_PROOF_LIFETIME_NS: i64 = 24 * 60 * 60 * 1_000_000_000;
const SIGNATURE_DOMAIN: &[u8] = b"MITHRIL-INTENT-V1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
struct IntentPayloadV1 {
    pub kind: u8,
    pub proof_id: Id128V1,
    pub tenant_id: Id128V1,
    pub trust_domain_id: Id128V1,
    pub issuer_id: Id128V1,
    pub sequence_epoch: u64,
    pub sequence: u64,
    pub issued_at_utc_ns: i64,
    pub not_before_utc_ns: i64,
    pub expires_at_utc_ns: i64,
    pub claim_slot_ids: Vec<Id128V1>,
    pub body_cbor: Vec<u8>,
    pub parent_proof_id: Option<Id128V1>,
    pub trigger_proof_ids: Vec<Id128V1>,
    pub administrative_exec: AdministrativeExecIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrativeExecIdentityV1 {
    pub authenticated_requester_principal_id: Id128V1,
    pub authenticated_approver_principal_id: Id128V1,
    pub cluster_uid: Id128V1,
    pub namespace: Vec<u8>,
    pub pod_uid: Vec<u8>,
    pub container_name: Vec<u8>,
    pub full_container_id: Vec<u8>,
    pub container_generation: u64,
    pub approved_argv: Vec<Vec<u8>>,
    pub stream_flags: u8,
    pub approved_role_id: String,
    pub profile: PortableProfileGenerationIdentityV1,
    pub target_node_id: Id128V1,
    pub resolved_executable: ResolvedAdministrativeExecutableIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableProfileGenerationIdentityV1 {
    pub profile_id: Id128V1,
    pub owner_generation: u64,
    pub artifact_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedAdministrativeExecutableIdentityV1 {
    pub requested_name: Vec<u8>,
    pub resolution_mode: u8,
    pub resolved_display_path: Vec<u8>,
    pub container_working_directory: Vec<u8>,
    pub effective_path_entries: Vec<Vec<u8>>,
    pub target_mount_namespace_id: Id128V1,
    pub target_mount_topology_generation: u64,
    pub executable_object: AdministrativeFileObjectIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrativeFileObjectIdentityV1 {
    pub mount_namespace_id: Id128V1,
    pub mount_topology_generation: u64,
    pub mount_id: u32,
    pub filesystem_instance_id: Id128V1,
    pub inode: u64,
    pub inode_generation: u64,
    pub exact_live_object_id: Id128V1,
    pub object_kind: u8,
    pub backing_identity: Id128V1,
    pub live_interval_id: Id128V1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerTrustV1 {
    pub issuer_id: Id128V1,
    pub key_id: Vec<u8>,
    pub public_key: [u8; 32],
    pub sequence_epoch: u64,
    pub valid_from_utc_ns: i64,
    pub valid_until_utc_ns: i64,
    pub revoked_at_utc_ns: Option<i64>,
    pub allowed_intent_kinds: Vec<u8>,
    pub allowed_tenant_ids: Vec<Id128V1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustBundleV1 {
    pub trust_domain_id: Id128V1,
    pub bundle_generation: u64,
    pub maximum_clock_skew_ns: i64,
    pub replay_window_size: u32,
    pub issuers: Vec<IssuerTrustV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationTargetV1 {
    pub tenant_id: Id128V1,
    pub trust_domain_id: Id128V1,
    pub issuer_id: Id128V1,
    pub intent_kind: u8,
    pub body_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAuthorizationProofV1 {
    pub proof_id: Id128V1,
    pub claim_slot_id: Id128V1,
    pub sequence_epoch: u64,
    pub sequence: u64,
    pub body_sha256: [u8; 32],
    pub deadline_boottime_ns: u64,
    administrative_exec: AdministrativeExecIdentityV1,
}

impl PreparedAuthorizationProofV1 {
    #[must_use]
    pub const fn administrative_exec(&self) -> &AdministrativeExecIdentityV1 {
        &self.administrative_exec
    }
}

pub struct AuthorizationProofOwner {
    node_id: Id128V1,
    node_boot_id: Id128V1,
    trust: TrustBundleV1,
    replay: ReplayLedger,
}

struct DecodedEnvelope<'a> {
    key_id: &'a [u8],
    payload_bytes: &'a [u8],
    signature: &'a [u8],
}

impl AuthorizationProofOwner {
    #[must_use]
    pub const fn node_boot_id(&self) -> Id128V1 {
        self.node_boot_id
    }

    pub fn load(
        state_directory: &Path,
        node_id: Id128V1,
        node_boot_id: Id128V1,
        trust: TrustBundleV1,
    ) -> Result<Self> {
        ensure!(
            !node_id.is_zero() && !node_boot_id.is_zero(),
            AuthorizationSnafu {
                reason: "authorization owner requires stable node and boot identities",
            }
        );
        trust.validate()?;
        Ok(Self {
            node_id,
            node_boot_id,
            trust,
            replay: ReplayLedger::load(state_directory, node_id, node_boot_id)?,
        })
    }

    pub fn verify_and_accept(
        &mut self,
        envelope_bytes: &[u8],
        expected: AuthorizationTargetV1,
        now_utc_ns: i64,
        now_boottime_ns: u64,
    ) -> Result<PreparedAuthorizationProofV1> {
        let envelope = DecodedEnvelope::decode(envelope_bytes)?;
        let payload = IntentPayloadV1::decode(envelope.payload_bytes)?;
        let issuer = self.trust.issuer(&payload, envelope.key_id)?;
        issuer.verify_signature(envelope.payload_bytes, envelope.signature)?;
        self.trust
            .validate_scope_and_time(&payload, expected, now_utc_ns, issuer)?;
        ensure!(
            payload.administrative_exec.target_node_id == self.node_id,
            AuthorizationSnafu {
                reason: "administrative authorization targets another stable node",
            }
        );
        let latest_expiry_utc_ns = payload
            .expires_at_utc_ns
            .checked_add(self.trust.maximum_clock_skew_ns)
            .ok_or_else(|| authorization_error("authorization expiry plus skew overflow"))?;
        let remaining_ns = latest_expiry_utc_ns
            .checked_sub(now_utc_ns)
            .ok_or_else(|| authorization_error("authorization expiry underflow"))?;
        let remaining_ns = u64::try_from(remaining_ns)
            .map_err(|error| authorization_error(format!("invalid remaining lifetime: {error}")))?;
        let deadline_boottime_ns = now_boottime_ns
            .checked_add(remaining_ns)
            .ok_or_else(|| authorization_error("boot-time deadline overflow"))?;
        let body_sha256 = Sha256::digest(&payload.body_cbor).into();
        self.replay.accept(AcceptedProof {
            key: ReplayKey {
                trust_domain_id: payload.trust_domain_id,
                issuer_id: payload.issuer_id,
                key_id: envelope.key_id.to_vec(),
                sequence_epoch: payload.sequence_epoch,
            },
            sequence: payload.sequence,
            proof_id: payload.proof_id,
            claim_slot_ids: &payload.claim_slot_ids,
            expires_at_utc_ns: payload.expires_at_utc_ns,
            body_sha256,
        })?;
        Ok(PreparedAuthorizationProofV1 {
            proof_id: payload.proof_id,
            claim_slot_id: payload.claim_slot_ids[0],
            sequence_epoch: payload.sequence_epoch,
            sequence: payload.sequence,
            body_sha256,
            deadline_boottime_ns,
            administrative_exec: payload.administrative_exec,
        })
    }

    pub fn consume(&mut self, proof_id: Id128V1, claim_slot_id: Id128V1) -> Result<()> {
        self.replay.consume(proof_id, claim_slot_id)
    }

    pub fn arm_execution_approval_slot(
        &mut self,
        host: &KernelHost,
        key: ExecutionApprovalSlotKeyV1,
        mut slot: ExecutionApprovalSlotV1,
        proof: PreparedAuthorizationProofV1,
    ) -> Result<()> {
        let argv_snapshot = execution_argv_snapshot(
            &proof.administrative_exec.approved_argv,
            proof.claim_slot_id,
        )?;
        slot.proof_id = proof.proof_id;
        slot.claim_slot_id = proof.claim_slot_id;
        slot.authorization_body_sha256 = proof.body_sha256;
        slot.deadline_boottime_ns = proof.deadline_boottime_ns;
        slot.expected_argv = argv_snapshot.descriptor;
        slot.state = ExecutionApprovalSlotStateV1::Armed;
        slot.transition_version = 1;
        ensure!(
            key.node_boot_id == self.node_boot_id
                && !key.cgroup_binding_id.is_zero()
                && !slot.cgroup_binding_nonce.is_zero()
                && slot.container_generation > 0
                && slot.container_generation == proof.administrative_exec.container_generation
                && slot.expected_argv.is_valid()
                && slot.resolved_executable.mount_namespace_inode > 0
                && slot.resolved_executable.mount_id > 0
                && slot.resolved_executable.mount_id
                    == proof
                        .administrative_exec
                        .resolved_executable
                        .executable_object
                        .mount_id
                && slot.resolved_executable.filesystem_device > 0
                && slot.resolved_executable.inode > 0
                && slot.resolved_executable.inode
                    == proof
                        .administrative_exec
                        .resolved_executable
                        .executable_object
                        .inode
                && slot.resolved_executable.inode_generation > 0
                && slot.resolved_executable.inode_generation
                    == proof
                        .administrative_exec
                        .resolved_executable
                        .executable_object
                        .inode_generation
                && slot.target_role_numeric_id > 0
                && slot.profile_generation_ref_id > 0
                && slot.admitted_entry_rule_id > 0
                && slot.expected_root_class == ExternalRootClassV1::ExternalRuntimeRoot,
            AuthorizationSnafu {
                reason: "execution approval slot is not an exact bounded external-root match",
            }
        );
        if slot.exception_numeric_handle > 0 {
            let exception_binding_key = ExceptionHandleBindingKeyV1 {
                profile_generation_ref_id: slot.profile_generation_ref_id,
                exception_numeric_handle: slot.exception_numeric_handle,
                reserved: 0,
            };
            let exception_binding = host
                .lookup_map(
                    "exception_handle_bindings",
                    exception_binding_key.as_bytes(),
                )
                .context(InterceptorSnafu)?
                .ok_or_else(|| {
                    AuthorizationSnafu {
                        reason: "execution approval slot has no active bounded-exception binding"
                            .to_owned(),
                    }
                    .build()
                })?;
            let exception_binding = read_abi_value::<ExceptionHandleBindingV1>(
                &exception_binding,
                "administrative exception binding",
            )?;
            ensure!(
                exception_binding.state == ExceptionBindingStateV1::Active
                    && exception_binding.runtime_state_key.node_id == self.node_id,
                AuthorizationSnafu {
                    reason: "execution approval slot exception is not active on this stable node",
                }
            );
        }
        let intent_sha256 = execution_approval_slot_intent_sha256(&key, &slot, &argv_snapshot);
        let existing = host
            .lookup_map("execution_approval_slots", key.as_bytes())
            .context(InterceptorSnafu)?;
        ensure!(
            existing
                .as_deref()
                .is_none_or(|value| value == slot.as_bytes()),
            AuthorizationSnafu {
                reason: "live cgroup binding already has a different execution approval slot",
            }
        );
        let inserted_chunks = publish_execution_argv_snapshot(host, &argv_snapshot)?;
        if let Err(error) = self.replay.arm(
            proof.proof_id,
            proof.claim_slot_id,
            proof.body_sha256,
            intent_sha256,
        ) {
            delete_execution_argv_chunks(host, inserted_chunks)?;
            return Err(error);
        }
        let publish_slot = (|| -> Result<()> {
            match host
                .insert_map("execution_approval_slots", key.as_bytes(), slot.as_bytes())
                .context(InterceptorSnafu)?
            {
                MapInsertResult::Inserted | MapInsertResult::AlreadyExists => {}
            }
            ensure!(
                host.lookup_map("execution_approval_slots", key.as_bytes())
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some(slot.as_bytes()),
                AuthorizationSnafu {
                    reason: "execution approval slot failed kernel readback",
                }
            );
            Ok(())
        })();
        if let Err(error) = publish_slot {
            if existing.is_none() {
                if host
                    .lookup_map("execution_approval_slots", key.as_bytes())
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some(slot.as_bytes())
                {
                    host.delete_map_entry("execution_approval_slots", key.as_bytes())
                        .context(InterceptorSnafu)?;
                }
                self.replay
                    .close(proof.proof_id, proof.claim_slot_id, intent_sha256)?;
            }
            delete_execution_argv_chunks(host, inserted_chunks)?;
            return Err(error);
        }
        Ok(())
    }

    pub fn reconcile_execution_approval_slots(&mut self, host: &KernelHost) -> Result<()> {
        let mut live_slots = BTreeSet::new();
        let mut live_argv_snapshots = BTreeSet::new();
        let mut reserved_matches = BTreeSet::new();
        for key in host
            .map_keys("pending_execution_approvals")
            .context(InterceptorSnafu)?
        {
            let Some(value) = host
                .lookup_map("pending_execution_approvals", &key)
                .context(InterceptorSnafu)?
            else {
                continue;
            };
            let pending =
                read_abi_value::<PendingExecutionApprovalV1>(&value, "pending execution approval")?;
            if pending_execution_approval_retains_reservation(pending.state) {
                reserved_matches.insert((pending.proof_id, pending.claim_slot_id));
            }
        }
        for key in host
            .map_keys("execution_approval_slots")
            .context(InterceptorSnafu)?
        {
            let slot_key =
                read_abi_value::<ExecutionApprovalSlotKeyV1>(&key, "execution approval slot key")?;
            let Some(value) = host
                .lookup_map("execution_approval_slots", &key)
                .context(InterceptorSnafu)?
            else {
                continue;
            };
            let mut slot =
                read_abi_value::<ExecutionApprovalSlotV1>(&value, "execution approval slot")?;
            let state = slot.state;
            let proof_id = slot.proof_id;
            let claim_slot_id = slot.claim_slot_id;
            slot.state = ExecutionApprovalSlotStateV1::Armed;
            slot.transition_version = 1;
            let argv_snapshot = read_execution_argv_snapshot(host, slot.expected_argv)?;
            let intent_sha256 =
                execution_approval_slot_intent_sha256(&slot_key, &slot, &argv_snapshot);
            match state {
                ExecutionApprovalSlotStateV1::Armed => {
                    ensure!(
                        self.replay.armed_intent(claim_slot_id) == Some(intent_sha256),
                        AuthorizationSnafu {
                            reason: "armed kernel slot differs from its durable intent",
                        }
                    );
                    live_slots.insert(claim_slot_id);
                    live_argv_snapshots.insert(slot.expected_argv.snapshot_id);
                }
                ExecutionApprovalSlotStateV1::Reserved => {
                    ensure!(
                        self.replay.armed_intent(claim_slot_id) == Some(intent_sha256),
                        AuthorizationSnafu {
                            reason: "reserved kernel slot differs from its durable intent",
                        }
                    );
                    if reserved_matches.contains(&(proof_id, claim_slot_id)) {
                        live_slots.insert(claim_slot_id);
                        live_argv_snapshots.insert(slot.expected_argv.snapshot_id);
                    } else {
                        self.replay.close(proof_id, claim_slot_id, intent_sha256)?;
                        host.delete_map_entry("execution_approval_slots", &key)
                            .context(InterceptorSnafu)?;
                        delete_execution_argv_chunks(
                            host,
                            argv_snapshot.keyed_chunks().map(|(key, _)| key),
                        )?;
                    }
                }
                ExecutionApprovalSlotStateV1::Consumed | ExecutionApprovalSlotStateV1::Tampered => {
                    self.replay
                        .reconcile_consumed(proof_id, claim_slot_id, intent_sha256)?;
                    host.delete_map_entry("execution_approval_slots", &key)
                        .context(InterceptorSnafu)?;
                    delete_execution_argv_chunks(
                        host,
                        argv_snapshot.keyed_chunks().map(|(key, _)| key),
                    )?;
                }
                ExecutionApprovalSlotStateV1::Expired
                | ExecutionApprovalSlotStateV1::Cancelled
                | ExecutionApprovalSlotStateV1::Corrupt => {
                    self.replay.close(proof_id, claim_slot_id, intent_sha256)?;
                    host.delete_map_entry("execution_approval_slots", &key)
                        .context(InterceptorSnafu)?;
                    delete_execution_argv_chunks(
                        host,
                        argv_snapshot.keyed_chunks().map(|(key, _)| key),
                    )?;
                }
                ExecutionApprovalSlotStateV1::Unknown => {
                    return AuthorizationSnafu {
                        reason: "execution approval slot is neither armed nor durably consumable"
                            .to_owned(),
                    }
                    .fail()
                }
            }
        }
        ensure!(
            self.replay
                .armed_slots()
                .into_iter()
                .all(|slot_id| live_slots.contains(&slot_id)),
            AuthorizationSnafu {
                reason: "durably armed execution approval slot is missing from the kernel",
            }
        );
        for raw_key in host
            .map_keys("execution_argv_expected_chunks")
            .context(InterceptorSnafu)?
        {
            let key =
                read_abi_value::<ExecutionArgvChunkKeyV1>(&raw_key, "expected argv chunk key")?;
            if !live_argv_snapshots.contains(&key.snapshot_id) {
                host.delete_map_entry("execution_argv_expected_chunks", &raw_key)
                    .context(InterceptorSnafu)?;
            }
        }
        Ok(())
    }
}

fn pending_execution_approval_retains_reservation(state: PendingExecutionApprovalStateV1) -> bool {
    matches!(
        state,
        PendingExecutionApprovalStateV1::SlotReserved
            | PendingExecutionApprovalStateV1::KernelArgvVerified
    )
}

#[derive(Debug, Eq, PartialEq)]
struct ExecutionArgvSnapshotRowsV1 {
    descriptor: ExecutionArgvSnapshotV1,
    chunks: Vec<ExecutionArgvChunkV1>,
}

impl ExecutionArgvSnapshotRowsV1 {
    fn from_arguments<T: AsRef<[u8]>>(arguments: &[T], snapshot_id: Id128V1) -> Result<Self> {
        ensure!(
            !snapshot_id.is_zero(),
            AuthorizationSnafu {
                reason: "argv snapshot ID is zero",
            }
        );
        ensure!(
            !arguments.is_empty() && !arguments[0].as_ref().is_empty(),
            AuthorizationSnafu {
                reason: "administrative argv is empty",
            }
        );
        let argument_count = u64::try_from(arguments.len())
            .map_err(|error| authorization_error(format!("argv count overflow: {error}")))?;
        let mut total_argument_span = 0_u64;
        let mut chunks = Vec::new();
        let mut chunk = ExecutionArgvChunkV1::default();
        for argument in arguments {
            let argument = argument.as_ref();
            ensure!(
                !argument.contains(&0),
                AuthorizationSnafu {
                    reason: "administrative argv contains NUL",
                }
            );
            total_argument_span = total_argument_span
                .checked_add(
                    u64::try_from(argument.len())
                        .map_err(|error| {
                            authorization_error(format!("argument size overflow: {error}"))
                        })?
                        .saturating_add(1),
                )
                .ok_or_else(|| authorization_error("argv span overflow"))?;
            for byte in argument.iter().copied().chain(std::iter::once(0)) {
                if chunk.length as usize == EXECUTION_ARGV_CHUNK_BYTES_V1 {
                    chunks.push(chunk);
                    chunk = ExecutionArgvChunkV1::default();
                }
                chunk.bytes[chunk.length as usize] = byte;
                chunk.length += 1;
            }
        }
        let chunk_count = u32::try_from(chunks.len() + 1)
            .map_err(|error| authorization_error(format!("argv chunk count overflow: {error}")))?;
        chunk.flags = EXECUTION_ARGV_CHUNK_TERMINAL_V1;
        chunks.push(chunk);
        let descriptor = ExecutionArgvSnapshotV1 {
            snapshot_id,
            argument_count,
            total_argument_span,
            chunk_count,
            reserved: 0,
        };
        ensure!(
            descriptor.is_valid()
                && chunks.iter().enumerate().all(|(index, chunk)| {
                    u32::try_from(index).is_ok_and(|index| chunk.is_valid_for(&descriptor, index))
                }),
            AuthorizationSnafu {
                reason: "administrative argv cannot form a complete immutable snapshot",
            }
        );
        Ok(Self { descriptor, chunks })
    }

    fn keyed_chunks(
        &self,
    ) -> impl Iterator<Item = (ExecutionArgvChunkKeyV1, &ExecutionArgvChunkV1)> {
        (0_u32..)
            .zip(self.chunks.iter())
            .map(|(chunk_index, chunk)| {
                (
                    ExecutionArgvChunkKeyV1 {
                        snapshot_id: self.descriptor.snapshot_id,
                        chunk_index,
                        reserved: 0,
                    },
                    chunk,
                )
            })
    }
}

pub(crate) fn validate_execution_argv<T: AsRef<[u8]>>(arguments: &[T]) -> Result<()> {
    ExecutionArgvSnapshotRowsV1::from_arguments(arguments, Id128V1::new(1, 1)).map(drop)
}

fn execution_argv_snapshot<T: AsRef<[u8]>>(
    arguments: &[T],
    snapshot_id: Id128V1,
) -> Result<ExecutionArgvSnapshotRowsV1> {
    ExecutionArgvSnapshotRowsV1::from_arguments(arguments, snapshot_id)
}

fn execution_approval_slot_intent_sha256(
    key: &ExecutionApprovalSlotKeyV1,
    slot: &ExecutionApprovalSlotV1,
    chunks: &ExecutionArgvSnapshotRowsV1,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"MITHRIL-ADMINISTRATIVE-SLOT-V1\0");
    digest.update(key.as_bytes());
    digest.update(slot.as_bytes());
    for (chunk_key, chunk) in chunks.keyed_chunks() {
        digest.update(chunk_key.as_bytes());
        digest.update(chunk.as_bytes());
    }
    digest.finalize().into()
}

fn read_execution_argv_snapshot(
    host: &KernelHost,
    descriptor: ExecutionArgvSnapshotV1,
) -> Result<ExecutionArgvSnapshotRowsV1> {
    ensure!(
        descriptor.is_valid(),
        AuthorizationSnafu {
            reason: "execution approval slot has an invalid argv snapshot descriptor",
        }
    );
    let mut chunks = Vec::with_capacity(descriptor.chunk_count as usize);
    for chunk_index in 0..descriptor.chunk_count {
        let key = ExecutionArgvChunkKeyV1 {
            snapshot_id: descriptor.snapshot_id,
            chunk_index,
            reserved: 0,
        };
        let value = host
            .lookup_map("execution_argv_expected_chunks", key.as_bytes())
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                AuthorizationSnafu {
                    reason: format!("expected argv chunk {chunk_index} is missing"),
                }
                .build()
            })?;
        let chunk = read_abi_value::<ExecutionArgvChunkV1>(&value, "expected argv chunk")?;
        ensure!(
            chunk.is_valid_for(&descriptor, chunk_index),
            AuthorizationSnafu {
                reason: format!("expected argv chunk {chunk_index} is invalid"),
            }
        );
        chunks.push(chunk);
    }
    Ok(ExecutionArgvSnapshotRowsV1 { descriptor, chunks })
}

fn publish_execution_argv_snapshot(
    host: &KernelHost,
    snapshot: &ExecutionArgvSnapshotRowsV1,
) -> Result<Vec<ExecutionArgvChunkKeyV1>> {
    let mut inserted = Vec::new();
    let publication = (|| -> Result<()> {
        for (key, chunk) in snapshot.keyed_chunks() {
            match host
                .insert_map(
                    "execution_argv_expected_chunks",
                    key.as_bytes(),
                    chunk.as_bytes(),
                )
                .context(InterceptorSnafu)?
            {
                MapInsertResult::Inserted => inserted.push(key),
                MapInsertResult::AlreadyExists => {}
            }
            ensure!(
                host.lookup_map("execution_argv_expected_chunks", key.as_bytes())
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some(chunk.as_bytes()),
                AuthorizationSnafu {
                    reason: format!(
                        "expected argv chunk {} failed exact readback",
                        key.chunk_index
                    ),
                }
            );
        }
        Ok(())
    })();
    if let Err(error) = publication {
        delete_execution_argv_chunks(host, inserted)?;
        return Err(error);
    }
    Ok(inserted)
}

fn delete_execution_argv_chunks(
    host: &KernelHost,
    chunks: impl IntoIterator<Item = ExecutionArgvChunkKeyV1>,
) -> Result<()> {
    for key in chunks {
        if host
            .lookup_map("execution_argv_expected_chunks", key.as_bytes())
            .context(InterceptorSnafu)?
            .is_some()
        {
            host.delete_map_entry("execution_argv_expected_chunks", key.as_bytes())
                .context(InterceptorSnafu)?;
        }
    }
    Ok(())
}

fn read_abi_value<T: KnownLayout + TryFromBytes>(bytes: &[u8], name: &str) -> Result<T> {
    T::try_read_from_bytes(bytes)
        .map_err(|error| authorization_error(format!("{name} has an invalid ABI value: {error}")))
}

impl TrustBundleV1 {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.trust_domain_id.is_zero()
                && self.bundle_generation > 0
                && (0..=MAX_CLOCK_SKEW_NS).contains(&self.maximum_clock_skew_ns)
                && self.replay_window_size == 4096
                && !self.issuers.is_empty(),
            AuthorizationSnafu {
                reason:
                    "trust bundle identity, generation, skew, replay window, or issuers are invalid",
            }
        );
        for (index, issuer) in self.issuers.iter().enumerate() {
            ensure!(
                !issuer.issuer_id.is_zero()
                    && (1..=128).contains(&issuer.key_id.len())
                    && issuer.sequence_epoch > 0
                    && issuer.valid_from_utc_ns <= issuer.valid_until_utc_ns
                    && issuer.revoked_at_utc_ns.is_none_or(|revoked| {
                        (issuer.valid_from_utc_ns..=issuer.valid_until_utc_ns).contains(&revoked)
                    })
                    && issuer.allowed_intent_kinds == [ADMINISTRATIVE_EXEC_KIND]
                    && !issuer.allowed_tenant_ids.is_empty()
                    && issuer
                        .allowed_tenant_ids
                        .iter()
                        .all(|tenant| !tenant.is_zero())
                    && issuer
                        .allowed_tenant_ids
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                    && VerifyingKey::from_bytes(&issuer.public_key).is_ok(),
                AuthorizationSnafu {
                    reason: format!("trust issuer at index {index} has invalid identity or scope"),
                }
            );
            ensure!(
                !self.issuers[..index].iter().any(|other| {
                    other.issuer_id == issuer.issuer_id
                        && other.sequence_epoch == issuer.sequence_epoch
                }),
                AuthorizationSnafu {
                    reason: "trust bundle repeats an issuer sequence epoch".to_owned(),
                }
            );
        }
        Ok(())
    }

    fn issuer<'a>(&'a self, payload: &IntentPayloadV1, key_id: &[u8]) -> Result<&'a IssuerTrustV1> {
        self.issuers
            .iter()
            .find(|issuer| {
                issuer.issuer_id == payload.issuer_id
                    && issuer.key_id == key_id
                    && issuer.sequence_epoch == payload.sequence_epoch
            })
            .ok_or_else(|| {
                authorization_error("issuer, signing key, or sequence epoch is untrusted")
            })
    }

    fn validate_scope_and_time(
        &self,
        payload: &IntentPayloadV1,
        expected: AuthorizationTargetV1,
        now_utc_ns: i64,
        issuer: &IssuerTrustV1,
    ) -> Result<()> {
        let body_sha256: [u8; 32] = Sha256::digest(&payload.body_cbor).into();
        ensure!(
            payload.tenant_id == expected.tenant_id
                && payload.trust_domain_id == self.trust_domain_id
                && payload.trust_domain_id == expected.trust_domain_id
                && payload.issuer_id == expected.issuer_id
                && payload.kind == expected.intent_kind
                && body_sha256 == expected.body_sha256
                && issuer.allowed_tenant_ids.contains(&payload.tenant_id)
                && issuer.allowed_intent_kinds.contains(&payload.kind),
            AuthorizationSnafu {
                reason: "authorization issuer, tenant, trust domain, kind, or exact target does not match",
            }
        );
        let skew = self.maximum_clock_skew_ns;
        let latest_now = now_utc_ns
            .checked_add(skew)
            .ok_or_else(|| authorization_error("clock-skew upper bound overflow"))?;
        let earliest_now = now_utc_ns
            .checked_sub(skew)
            .ok_or_else(|| authorization_error("clock-skew lower bound overflow"))?;
        let lifetime = payload
            .expires_at_utc_ns
            .checked_sub(payload.issued_at_utc_ns)
            .ok_or_else(|| authorization_error("authorization lifetime underflow"))?;
        ensure!(
            payload.issued_at_utc_ns <= payload.not_before_utc_ns
                && payload.not_before_utc_ns <= payload.expires_at_utc_ns
                && lifetime <= MAX_PROOF_LIFETIME_NS
                && payload.issued_at_utc_ns <= latest_now
                && payload.not_before_utc_ns <= latest_now
                && payload.expires_at_utc_ns >= earliest_now
                && issuer.valid_from_utc_ns <= payload.issued_at_utc_ns
                && issuer.valid_until_utc_ns >= payload.expires_at_utc_ns
                && issuer.revoked_at_utc_ns.is_none_or(|revoked| {
                    payload.issued_at_utc_ns < revoked && latest_now < revoked
                }),
            AuthorizationSnafu {
                reason: "authorization or issuer is outside its trusted time interval",
            }
        );
        Ok(())
    }
}

impl IssuerTrustV1 {
    fn verify_signature(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        let key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|error| authorization_error(format!("invalid Ed25519 key: {error}")))?;
        let signature = Signature::from_slice(signature)
            .map_err(|error| authorization_error(format!("invalid Ed25519 signature: {error}")))?;
        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32);
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&Sha256::digest(payload));
        key.verify_strict(&message, &signature)
            .map_err(|error| authorization_error(format!("Ed25519 verification failed: {error}")))
    }
}

impl<'a> DecodedEnvelope<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self> {
        validate_canonical_cbor(bytes)?;
        let mut decoder = Decoder::new(bytes);
        expect_map(&mut decoder, 5, "signed intent")?;
        expect_key(&mut decoder, 0)?;
        ensure!(
            decode_u64(&mut decoder)? == 1,
            AuthorizationSnafu {
                reason: "signed-intent wire version is not 1",
            }
        );
        expect_key(&mut decoder, 1)?;
        let key_id = decode_bytes(&mut decoder, 1, 128, false, "signing key ID")?;
        expect_key(&mut decoder, 2)?;
        ensure!(
            decode_u64(&mut decoder)? == 1,
            AuthorizationSnafu {
                reason: "signed-intent algorithm is not Ed25519",
            }
        );
        expect_key(&mut decoder, 3)?;
        let payload_bytes =
            decode_bytes(&mut decoder, 1, MAX_PAYLOAD_BYTES, false, "intent payload")?;
        expect_key(&mut decoder, 4)?;
        let signature = decode_bytes(&mut decoder, 64, 64, false, "Ed25519 signature")?;
        ensure!(
            decoder.position() == bytes.len(),
            AuthorizationSnafu {
                reason: "signed intent has trailing bytes",
            }
        );
        Ok(Self {
            key_id,
            payload_bytes,
            signature,
        })
    }
}

impl IntentPayloadV1 {
    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            (1..=MAX_PAYLOAD_BYTES).contains(&bytes.len()),
            AuthorizationSnafu {
                reason: "intent payload exceeds its byte bound",
            }
        );
        validate_canonical_cbor(bytes)?;
        let mut decoder = Decoder::new(bytes);
        let fields = decoder
            .map()
            .map_err(cbor_error)?
            .ok_or_else(|| authorization_error("intent payload map must have a definite length"))?;
        ensure!(
            (13..=15).contains(&fields),
            AuthorizationSnafu {
                reason: "intent payload has the wrong field count",
            }
        );
        expect_key(&mut decoder, 0)?;
        ensure!(
            decode_u64(&mut decoder)? == 1,
            AuthorizationSnafu {
                reason: "intent payload version is not 1",
            }
        );
        expect_key(&mut decoder, 1)?;
        let kind = u8::try_from(decode_u64(&mut decoder)?)
            .map_err(|error| authorization_error(format!("intent kind is invalid: {error}")))?;
        expect_key(&mut decoder, 2)?;
        let proof_id = decode_id(&mut decoder, "proof ID")?;
        expect_key(&mut decoder, 3)?;
        let tenant_id = decode_id(&mut decoder, "tenant ID")?;
        expect_key(&mut decoder, 4)?;
        let trust_domain_id = decode_id(&mut decoder, "trust-domain ID")?;
        expect_key(&mut decoder, 5)?;
        let issuer_id = decode_id(&mut decoder, "issuer ID")?;
        expect_key(&mut decoder, 6)?;
        let sequence_epoch = decode_u64(&mut decoder)?;
        expect_key(&mut decoder, 7)?;
        let sequence = decode_u64(&mut decoder)?;
        expect_key(&mut decoder, 8)?;
        let issued_at_utc_ns = decoder.i64().map_err(cbor_error)?;
        expect_key(&mut decoder, 9)?;
        let not_before_utc_ns = decoder.i64().map_err(cbor_error)?;
        expect_key(&mut decoder, 10)?;
        let expires_at_utc_ns = decoder.i64().map_err(cbor_error)?;
        expect_key(&mut decoder, 11)?;
        let claim_slot_ids = decode_sorted_ids(&mut decoder, 1, 64, "claim-slot IDs")?;
        expect_key(&mut decoder, 12)?;
        let body_start = decoder.position();
        decoder.skip().map_err(cbor_error)?;
        let body_cbor = bytes[body_start..decoder.position()].to_vec();
        let administrative_exec = validate_administrative_body(kind, &body_cbor, &claim_slot_ids)?;
        let mut parent_proof_id = None;
        let mut trigger_proof_ids = Vec::new();
        if fields >= 14 {
            expect_key(&mut decoder, 13)?;
            parent_proof_id = Some(decode_id(&mut decoder, "parent proof ID")?);
        }
        if fields == 15 {
            expect_key(&mut decoder, 14)?;
            trigger_proof_ids = decode_sorted_ids(&mut decoder, 1, 16, "trigger proof IDs")?;
        }
        ensure!(
            decoder.position() == bytes.len() && sequence_epoch > 0 && sequence > 0,
            AuthorizationSnafu {
                reason: "intent payload has trailing bytes or a zero sequence",
            }
        );
        Ok(Self {
            kind,
            proof_id,
            tenant_id,
            trust_domain_id,
            issuer_id,
            sequence_epoch,
            sequence,
            issued_at_utc_ns,
            not_before_utc_ns,
            expires_at_utc_ns,
            claim_slot_ids,
            body_cbor,
            parent_proof_id,
            trigger_proof_ids,
            administrative_exec,
        })
    }
}

fn validate_administrative_body(
    kind: u8,
    body: &[u8],
    claim_slot_ids: &[Id128V1],
) -> Result<AdministrativeExecIdentityV1> {
    ensure!(
        kind == ADMINISTRATIVE_EXEC_KIND && claim_slot_ids.len() == 1,
        AuthorizationSnafu {
            reason: "the administrative-exec owner supports exactly one bounded slot",
        }
    );
    let mut decoder = Decoder::new(body);
    expect_map(&mut decoder, 2, "intent body")?;
    expect_key(&mut decoder, 0)?;
    ensure!(
        decode_u64(&mut decoder)? == u64::from(kind),
        AuthorizationSnafu {
            reason: "intent body tag does not match payload kind",
        }
    );
    expect_key(&mut decoder, 1)?;
    expect_map(&mut decoder, 16, "administrative exec body")?;
    expect_key(&mut decoder, 0)?;
    let authenticated_requester_principal_id =
        decode_id(&mut decoder, "authenticated requester principal ID")?;
    expect_key(&mut decoder, 1)?;
    let authenticated_approver_principal_id =
        decode_id(&mut decoder, "authenticated approver principal ID")?;
    expect_key(&mut decoder, 2)?;
    let cluster_uid = decode_id(&mut decoder, "cluster UID")?;
    expect_key(&mut decoder, 3)?;
    let namespace = decode_bytes(&mut decoder, 1, 253, true, "namespace")?.to_vec();
    ensure!(
        std::str::from_utf8(&namespace).is_ok(),
        AuthorizationSnafu {
            reason: "namespace is not UTF-8",
        }
    );
    expect_key(&mut decoder, 4)?;
    let pod_uid = decode_bytes(&mut decoder, 1, 64, true, "Pod UID")?.to_vec();
    expect_key(&mut decoder, 5)?;
    let container_name = decode_bytes(&mut decoder, 1, 253, true, "container name")?.to_vec();
    ensure!(
        std::str::from_utf8(&container_name).is_ok(),
        AuthorizationSnafu {
            reason: "container name is not UTF-8",
        }
    );
    expect_key(&mut decoder, 6)?;
    let full_container_id = decode_bytes(&mut decoder, 32, 128, true, "container ID")?.to_vec();
    expect_key(&mut decoder, 7)?;
    let container_generation = decode_u64(&mut decoder)?;
    ensure!(
        container_generation > 0,
        AuthorizationSnafu {
            reason: "container generation must be nonzero",
        }
    );
    expect_key(&mut decoder, 8)?;
    let argument_count = expect_array(&mut decoder, 1, 256, "approved argv")?;
    let mut total_argument_bytes = 0_usize;
    let mut arguments = Vec::with_capacity(argument_count as usize);
    for index in 0..argument_count {
        let argument = decode_bytes(&mut decoder, 0, 4096, true, "approved argument")?;
        total_argument_bytes = total_argument_bytes
            .checked_add(argument.len())
            .ok_or_else(|| authorization_error("approved argv byte count overflow"))?;
        if index == 0 {
            ensure!(
                !argument.is_empty(),
                AuthorizationSnafu {
                    reason: "approved command name is empty",
                }
            );
        }
        arguments.push(argument);
    }
    ensure!(
        (1..=4096).contains(&total_argument_bytes),
        AuthorizationSnafu {
            reason: "approved argv exceeds its aggregate byte bound",
        }
    );
    expect_key(&mut decoder, 9)?;
    let stream_flags = decode_u64(&mut decoder)?;
    ensure!(
        stream_flags <= 0x0f,
        AuthorizationSnafu {
            reason: "administrative stream flags contain unallocated bits",
        }
    );
    expect_key(&mut decoder, 10)?;
    let role = decoder.str().map_err(cbor_error)?;
    ensure!(
        valid_policy_local_id(role),
        AuthorizationSnafu {
            reason: "approved role is not a PolicyLocalIdV1",
        }
    );
    let approved_role_id = role.to_owned();
    expect_key(&mut decoder, 11)?;
    let profile = validate_portable_profile_generation(&mut decoder)?;
    expect_key(&mut decoder, 12)?;
    let target_node_id = decode_id(&mut decoder, "target node ID")?;
    expect_key(&mut decoder, 13)?;
    ensure!(
        decode_u64(&mut decoder)? == 1,
        AuthorizationSnafu {
            reason: "execution approval mode is not NEXT_MATCHING_RUNTIME_EXTERNAL_ROOT",
        }
    );
    expect_key(&mut decoder, 14)?;
    ensure!(
        decoder.bool().map_err(cbor_error)?,
        AuthorizationSnafu {
            reason: "requester did not accept the documented next-match race",
        }
    );
    expect_key(&mut decoder, 15)?;
    let resolved_executable =
        validate_resolved_executable(&mut decoder, arguments.first().copied().unwrap_or_default())?;
    ensure!(
        decoder.position() == body.len(),
        AuthorizationSnafu {
            reason: "administrative body has trailing bytes",
        }
    );
    Ok(AdministrativeExecIdentityV1 {
        authenticated_requester_principal_id,
        authenticated_approver_principal_id,
        cluster_uid,
        namespace,
        pod_uid,
        container_name,
        full_container_id,
        container_generation,
        approved_argv: arguments.into_iter().map(ToOwned::to_owned).collect(),
        stream_flags: u8::try_from(stream_flags).map_err(|error| {
            authorization_error(format!("administrative stream flags exceed u8: {error}"))
        })?,
        approved_role_id,
        profile,
        target_node_id,
        resolved_executable,
    })
}

fn validate_portable_profile_generation(
    decoder: &mut Decoder<'_>,
) -> Result<PortableProfileGenerationIdentityV1> {
    expect_map(decoder, 3, "portable profile generation")?;
    expect_key(decoder, 0)?;
    let profile_id = decode_id(decoder, "portable profile ID")?;
    expect_key(decoder, 1)?;
    let owner_generation = decode_u64(decoder)?;
    ensure!(
        owner_generation > 0,
        AuthorizationSnafu {
            reason: "portable profile owner generation is zero",
        }
    );
    expect_key(decoder, 2)?;
    let artifact_sha256 = decode_digest(decoder, "compiled profile artifact digest")?;
    Ok(PortableProfileGenerationIdentityV1 {
        profile_id,
        owner_generation,
        artifact_sha256,
    })
}

fn validate_resolved_executable(
    decoder: &mut Decoder<'_>,
    command: &[u8],
) -> Result<ResolvedAdministrativeExecutableIdentityV1> {
    expect_map(decoder, 8, "resolved administrative executable")?;
    expect_key(decoder, 0)?;
    let requested_name =
        decode_bytes(decoder, 1, 4096, true, "requested executable name")?.to_vec();
    ensure!(
        requested_name == command,
        AuthorizationSnafu {
            reason: "resolved executable name differs from argv[0]",
        }
    );
    expect_key(decoder, 1)?;
    let resolution_mode = decode_u64(decoder)?;
    ensure!(
        (1..=3).contains(&resolution_mode),
        AuthorizationSnafu {
            reason: "executable resolution mode is unallocated",
        }
    );
    expect_key(decoder, 2)?;
    let resolved_display_path =
        decode_bytes(decoder, 1, 4096, true, "resolved executable path")?.to_vec();
    ensure!(
        resolved_display_path.first() == Some(&b'/'),
        AuthorizationSnafu {
            reason: "resolved executable path is not absolute",
        }
    );
    expect_key(decoder, 3)?;
    let container_working_directory =
        decode_bytes(decoder, 1, 4096, true, "container working directory")?.to_vec();
    ensure!(
        container_working_directory.first() == Some(&b'/'),
        AuthorizationSnafu {
            reason: "container working directory is not absolute",
        }
    );
    expect_key(decoder, 4)?;
    let path_count = expect_array(decoder, 0, 64, "effective PATH entries")?;
    let mut effective_path_entries = Vec::with_capacity(path_count as usize);
    for _ in 0..path_count {
        let path = decode_bytes(decoder, 1, 4096, true, "effective PATH entry")?;
        ensure!(
            path.first() == Some(&b'/'),
            AuthorizationSnafu {
                reason: "effective PATH entry is not absolute",
            }
        );
        effective_path_entries.push(path.to_vec());
    }
    expect_key(decoder, 5)?;
    let mount_namespace = decode_id(decoder, "target mount namespace ID")?;
    expect_key(decoder, 6)?;
    let mount_topology_generation = decode_u64(decoder)?;
    ensure!(
        mount_topology_generation > 0,
        AuthorizationSnafu {
            reason: "target mount-topology generation is zero",
        }
    );
    expect_key(decoder, 7)?;
    let executable_object =
        validate_file_object(decoder, mount_namespace, mount_topology_generation)?;
    Ok(ResolvedAdministrativeExecutableIdentityV1 {
        requested_name,
        resolution_mode: u8::try_from(resolution_mode).map_err(|error| {
            authorization_error(format!("executable resolution mode exceeds u8: {error}"))
        })?,
        resolved_display_path,
        container_working_directory,
        effective_path_entries,
        target_mount_namespace_id: mount_namespace,
        target_mount_topology_generation: mount_topology_generation,
        executable_object,
    })
}

fn validate_file_object(
    decoder: &mut Decoder<'_>,
    expected_mount_namespace: Id128V1,
    expected_mount_topology_generation: u64,
) -> Result<AdministrativeFileObjectIdentityV1> {
    expect_map(decoder, 10, "file-object identity")?;
    expect_key(decoder, 0)?;
    let mount_namespace = decode_id(decoder, "file-object mount namespace ID")?;
    expect_key(decoder, 1)?;
    let mount_topology_generation = decode_u64(decoder)?;
    ensure!(
        mount_namespace == expected_mount_namespace
            && mount_topology_generation == expected_mount_topology_generation,
        AuthorizationSnafu {
            reason: "executable object differs from its resolved target mount view",
        }
    );
    expect_key(decoder, 2)?;
    let mount_id = decode_u64(decoder)?.try_into().map_err(|error| {
        authorization_error(format!(
            "executable mount ID exceeds its Linux u32 ABI: {error}"
        ))
    })?;
    expect_key(decoder, 3)?;
    let filesystem_instance_id = decode_id(decoder, "filesystem instance ID")?;
    expect_key(decoder, 4)?;
    let inode = decode_u64(decoder)?;
    expect_key(decoder, 5)?;
    let inode_generation = decode_u64(decoder)?;
    ensure!(
        mount_id > 0 && inode > 0 && inode_generation > 0,
        AuthorizationSnafu {
            reason: "executable object has a zero mount, inode, or generation identity",
        }
    );
    expect_key(decoder, 6)?;
    let exact_live_object_id = decode_id(decoder, "exact live object ID")?;
    expect_key(decoder, 7)?;
    let object_kind = decode_u64(decoder)?;
    ensure!(
        (1..=12).contains(&object_kind),
        AuthorizationSnafu {
            reason: "executable object kind is unknown or unallocated",
        }
    );
    expect_key(decoder, 8)?;
    let backing_identity = decode_id(decoder, "backing object or volume identity")?;
    expect_key(decoder, 9)?;
    let live_interval_id = decode_id(decoder, "file-object live interval ID")?;
    Ok(AdministrativeFileObjectIdentityV1 {
        mount_namespace_id: mount_namespace,
        mount_topology_generation,
        mount_id,
        filesystem_instance_id,
        inode,
        inode_generation,
        exact_live_object_id,
        object_kind: u8::try_from(object_kind).map_err(|error| {
            authorization_error(format!("executable object kind exceeds u8: {error}"))
        })?,
        backing_identity,
        live_interval_id,
    })
}

fn decode_digest(decoder: &mut Decoder<'_>, name: &str) -> Result<[u8; 32]> {
    expect_map(decoder, 2, name)?;
    expect_key(decoder, 0)?;
    ensure!(
        decode_u64(decoder)? == 1,
        AuthorizationSnafu {
            reason: format!("{name} does not use SHA-256"),
        }
    );
    expect_key(decoder, 1)?;
    let sha256 = decode_bytes(decoder, 32, 32, false, name)?;
    sha256.try_into().map_err(|error| {
        authorization_error(format!("{name} has the wrong SHA-256 width: {error:?}"))
    })
}

fn validate_canonical_cbor(bytes: &[u8]) -> Result<()> {
    let mut decoder = Decoder::new(bytes);
    let tokens = decoder
        .tokens()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(cbor_error)?;
    ensure!(
        decoder.position() == bytes.len()
            && !tokens.iter().any(|token| {
                matches!(
                    token,
                    Token::BeginBytes
                        | Token::BeginString
                        | Token::BeginArray
                        | Token::BeginMap
                        | Token::Break
                        | Token::F16(_)
                        | Token::F32(_)
                        | Token::F64(_)
                        | Token::Tag(_)
                        | Token::Simple(_)
                        | Token::Null
                        | Token::Undefined
                )
            }),
        AuthorizationSnafu {
            reason: "CBOR contains trailing, indefinite, floating, tagged, simple, or null data",
        }
    );
    let mut position = 0;
    let mut counters = CborCounters::default();
    validate_token_item(&tokens, &mut position, 1, &mut counters)?;
    ensure!(
        position == tokens.len()
            && counters.aggregate_bytes <= MAX_AGGREGATE_BYTES
            && counters.array_members <= MAX_ARRAY_MEMBERS,
        AuthorizationSnafu {
            reason: "CBOR exceeds aggregate byte/member bounds or has extra items",
        }
    );
    let mut canonical = Vec::with_capacity(bytes.len());
    Encoder::new(&mut canonical)
        .tokens(&tokens)
        .map_err(cbor_error)?;
    ensure!(
        canonical == bytes,
        AuthorizationSnafu {
            reason: "CBOR is not in deterministic shortest form",
        }
    );
    Ok(())
}

#[derive(Default)]
struct CborCounters {
    aggregate_bytes: usize,
    array_members: usize,
}

fn validate_token_item(
    tokens: &[Token<'_>],
    position: &mut usize,
    depth: usize,
    counters: &mut CborCounters,
) -> Result<()> {
    ensure!(
        depth <= MAX_NESTING_DEPTH,
        AuthorizationSnafu {
            reason: "CBOR nesting exceeds 8 levels",
        }
    );
    let token = tokens
        .get(*position)
        .ok_or_else(|| authorization_error("CBOR container is truncated"))?;
    *position += 1;
    match token {
        Token::Map(length) => {
            let mut previous_key = None;
            for _ in 0..*length {
                let key = unsigned_token(
                    tokens
                        .get(*position)
                        .ok_or_else(|| authorization_error("CBOR map key is missing"))?,
                )?;
                ensure!(
                    previous_key.is_none_or(|previous| key > previous),
                    AuthorizationSnafu {
                        reason: "CBOR map keys are not unique ascending integers",
                    }
                );
                previous_key = Some(key);
                *position += 1;
                validate_token_item(tokens, position, depth + 1, counters)?;
            }
        }
        Token::Array(length) => {
            let length = usize::try_from(*length).map_err(|error| {
                authorization_error(format!("CBOR array is too large: {error}"))
            })?;
            counters.array_members = counters
                .array_members
                .checked_add(length)
                .ok_or_else(|| authorization_error("CBOR array-member count overflow"))?;
            for _ in 0..length {
                validate_token_item(tokens, position, depth + 1, counters)?;
            }
        }
        Token::Bytes(value) => add_bytes(counters, value.len())?,
        Token::String(value) => add_bytes(counters, value.len())?,
        Token::Bool(_)
        | Token::U8(_)
        | Token::U16(_)
        | Token::U32(_)
        | Token::U64(_)
        | Token::I8(_)
        | Token::I16(_)
        | Token::I32(_)
        | Token::I64(_)
        | Token::Int(_) => {}
        _ => {
            return AuthorizationSnafu {
                reason: "CBOR contains an unsupported token".to_owned(),
            }
            .fail()
        }
    }
    Ok(())
}

fn add_bytes(counters: &mut CborCounters, amount: usize) -> Result<()> {
    counters.aggregate_bytes = counters
        .aggregate_bytes
        .checked_add(amount)
        .ok_or_else(|| authorization_error("CBOR aggregate byte count overflow"))?;
    Ok(())
}

fn unsigned_token(token: &Token<'_>) -> Result<u64> {
    match token {
        Token::U8(value) => Ok(u64::from(*value)),
        Token::U16(value) => Ok(u64::from(*value)),
        Token::U32(value) => Ok(u64::from(*value)),
        Token::U64(value) => Ok(*value),
        _ => AuthorizationSnafu {
            reason: "CBOR map key is not an unsigned integer".to_owned(),
        }
        .fail(),
    }
}

fn expect_map(decoder: &mut Decoder<'_>, expected: u64, name: &str) -> Result<()> {
    let actual = decoder
        .map()
        .map_err(cbor_error)?
        .ok_or_else(|| authorization_error(format!("{name} map is indefinite")))?;
    ensure!(
        actual == expected,
        AuthorizationSnafu {
            reason: format!("{name} has {actual} fields, expected {expected}"),
        }
    );
    Ok(())
}

fn expect_array(decoder: &mut Decoder<'_>, minimum: u64, maximum: u64, name: &str) -> Result<u64> {
    let length = decoder
        .array()
        .map_err(cbor_error)?
        .ok_or_else(|| authorization_error(format!("{name} array is indefinite")))?;
    ensure!(
        (minimum..=maximum).contains(&length),
        AuthorizationSnafu {
            reason: format!("{name} length {length} is outside {minimum}..={maximum}"),
        }
    );
    Ok(length)
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u64) -> Result<()> {
    let actual = decode_u64(decoder)?;
    ensure!(
        actual == expected,
        AuthorizationSnafu {
            reason: format!("CBOR map key is {actual}, expected {expected}"),
        }
    );
    Ok(())
}

fn decode_u64(decoder: &mut Decoder<'_>) -> Result<u64> {
    decoder.u64().map_err(cbor_error)
}

fn decode_bytes<'a>(
    decoder: &mut Decoder<'a>,
    minimum: usize,
    maximum: usize,
    reject_nul: bool,
    name: &str,
) -> Result<&'a [u8]> {
    let bytes = decoder.bytes().map_err(cbor_error)?;
    ensure!(
        (minimum..=maximum).contains(&bytes.len()) && (!reject_nul || !bytes.contains(&0)),
        AuthorizationSnafu {
            reason: format!("{name} violates its byte or NUL bound"),
        }
    );
    Ok(bytes)
}

fn decode_id(decoder: &mut Decoder<'_>, name: &str) -> Result<Id128V1> {
    let bytes = decode_bytes(decoder, 16, 16, false, name)?;
    let high = u64::from_be_bytes(
        bytes[0..8]
            .try_into()
            .map_err(|error| authorization_error(format!("invalid {name}: {error}")))?,
    );
    let low = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|error| authorization_error(format!("invalid {name}: {error}")))?,
    );
    let id = Id128V1::new(high, low);
    ensure!(
        !id.is_zero(),
        AuthorizationSnafu {
            reason: format!("{name} is zero"),
        }
    );
    Ok(id)
}

fn decode_sorted_ids(
    decoder: &mut Decoder<'_>,
    minimum: u64,
    maximum: u64,
    name: &str,
) -> Result<Vec<Id128V1>> {
    let length = expect_array(decoder, minimum, maximum, name)?;
    let mut values = Vec::with_capacity(length as usize);
    for _ in 0..length {
        let value = decode_id(decoder, name)?;
        ensure!(
            values.last().is_none_or(|previous| *previous < value),
            AuthorizationSnafu {
                reason: format!("{name} are not sorted and unique"),
            }
        );
        values.push(value);
    }
    Ok(values)
}

fn valid_policy_local_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (index > 0 && (byte.is_ascii_digit() || byte == b'.' || byte == b'-'))
        })
}

fn cbor_error(error: impl std::fmt::Display) -> crate::Error {
    authorization_error(format!("invalid CBOR: {error}"))
}

fn authorization_error(reason: impl Into<String>) -> crate::Error {
    AuthorizationSnafu {
        reason: reason.into(),
    }
    .build()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use minicbor::{Decoder, Encoder};
    use sha2::{Digest as _, Sha256};

    use super::{
        authorization_error, cbor_error, execution_argv_snapshot,
        pending_execution_approval_retains_reservation, validate_administrative_body,
        AuthorizationProofOwner, AuthorizationTargetV1, IntentPayloadV1, IssuerTrustV1,
        TrustBundleV1, ADMINISTRATIVE_EXEC_KIND, SIGNATURE_DOMAIN,
    };
    use erebor_interceptor_abi::{
        Id128V1, PendingExecutionApprovalStateV1, EXECUTION_ARGV_CHUNK_TERMINAL_V1,
    };

    fn id(value: u64) -> Id128V1 {
        Id128V1::new(1, value)
    }

    #[test]
    fn only_in_flight_kernel_argv_states_retain_a_reserved_slot() {
        assert!(pending_execution_approval_retains_reservation(
            PendingExecutionApprovalStateV1::SlotReserved
        ));
        assert!(pending_execution_approval_retains_reservation(
            PendingExecutionApprovalStateV1::KernelArgvVerified
        ));
        for state in [
            PendingExecutionApprovalStateV1::Unknown,
            PendingExecutionApprovalStateV1::ArgumentsMatched,
            PendingExecutionApprovalStateV1::SlotConsumed,
            PendingExecutionApprovalStateV1::Tampered,
        ] {
            assert!(!pending_execution_approval_retains_reservation(state));
        }
    }

    fn encode_id(encoder: &mut Encoder<&mut Vec<u8>>, value: Id128V1) -> crate::Result<()> {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&value.high.to_be_bytes());
        bytes[8..].copy_from_slice(&value.low.to_be_bytes());
        encoder.bytes(&bytes).map_err(cbor_error)?;
        Ok(())
    }

    fn administrative_body(command: &[u8]) -> crate::Result<Vec<u8>> {
        administrative_body_with_object_generation(command, 1)
    }

    fn administrative_body_with_object_generation(
        command: &[u8],
        object_mount_generation: u8,
    ) -> crate::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        encoder
            .map(2)
            .map_err(cbor_error)?
            .u8(0)
            .map_err(cbor_error)?
            .u8(8)
            .map_err(cbor_error)?;
        encoder
            .u8(1)
            .map_err(cbor_error)?
            .map(16)
            .map_err(cbor_error)?;
        for key in 0..=2 {
            encoder.u8(key).map_err(cbor_error)?;
            encode_id(&mut encoder, id(u64::from(key) + 20))?;
        }
        encoder
            .u8(3)
            .map_err(cbor_error)?
            .bytes(b"default")
            .map_err(cbor_error)?;
        encoder
            .u8(4)
            .map_err(cbor_error)?
            .bytes(b"pod-uid")
            .map_err(cbor_error)?;
        encoder
            .u8(5)
            .map_err(cbor_error)?
            .bytes(b"worker")
            .map_err(cbor_error)?;
        encoder
            .u8(6)
            .map_err(cbor_error)?
            .bytes(&[b'c'; 32])
            .map_err(cbor_error)?;
        encoder
            .u8(7)
            .map_err(cbor_error)?
            .u8(1)
            .map_err(cbor_error)?;
        encoder
            .u8(8)
            .map_err(cbor_error)?
            .array(1)
            .map_err(cbor_error)?
            .bytes(command)
            .map_err(cbor_error)?;
        encoder
            .u8(9)
            .map_err(cbor_error)?
            .u8(2)
            .map_err(cbor_error)?;
        encoder
            .u8(10)
            .map_err(cbor_error)?
            .str("admin.exec")
            .map_err(cbor_error)?;
        encoder
            .u8(11)
            .map_err(cbor_error)?
            .map(3)
            .map_err(cbor_error)?;
        encoder.u8(0).map_err(cbor_error)?;
        encode_id(&mut encoder, id(31))?;
        encoder
            .u8(1)
            .map_err(cbor_error)?
            .u8(1)
            .map_err(cbor_error)?;
        encoder
            .u8(2)
            .map_err(cbor_error)?
            .map(2)
            .map_err(cbor_error)?;
        encoder
            .u8(0)
            .map_err(cbor_error)?
            .u8(1)
            .map_err(cbor_error)?;
        encoder
            .u8(1)
            .map_err(cbor_error)?
            .bytes(&[9; 32])
            .map_err(cbor_error)?;
        encoder.u8(12).map_err(cbor_error)?;
        encode_id(&mut encoder, id(32))?;
        encoder
            .u8(13)
            .map_err(cbor_error)?
            .u8(1)
            .map_err(cbor_error)?;
        encoder
            .u8(14)
            .map_err(cbor_error)?
            .bool(true)
            .map_err(cbor_error)?;
        encoder
            .u8(15)
            .map_err(cbor_error)?
            .map(8)
            .map_err(cbor_error)?;
        encoder
            .u8(0)
            .map_err(cbor_error)?
            .bytes(command)
            .map_err(cbor_error)?;
        encoder
            .u8(1)
            .map_err(cbor_error)?
            .u8(3)
            .map_err(cbor_error)?;
        encoder
            .u8(2)
            .map_err(cbor_error)?
            .bytes(b"/usr/bin/bash")
            .map_err(cbor_error)?;
        encoder
            .u8(3)
            .map_err(cbor_error)?
            .bytes(b"/workspace")
            .map_err(cbor_error)?;
        encoder
            .u8(4)
            .map_err(cbor_error)?
            .array(2)
            .map_err(cbor_error)?;
        encoder
            .bytes(b"/usr/local/bin")
            .map_err(cbor_error)?
            .bytes(b"/usr/bin")
            .map_err(cbor_error)?;
        encoder.u8(5).map_err(cbor_error)?;
        encode_id(&mut encoder, id(30))?;
        encoder
            .u8(6)
            .map_err(cbor_error)?
            .u8(1)
            .map_err(cbor_error)?;
        encoder
            .u8(7)
            .map_err(cbor_error)?
            .map(10)
            .map_err(cbor_error)?;
        encoder.u8(0).map_err(cbor_error)?;
        encode_id(&mut encoder, id(30))?;
        encoder
            .u8(1)
            .map_err(cbor_error)?
            .u8(object_mount_generation)
            .map_err(cbor_error)?;
        encoder
            .u8(2)
            .map_err(cbor_error)?
            .u8(42)
            .map_err(cbor_error)?;
        encoder.u8(3).map_err(cbor_error)?;
        encode_id(&mut encoder, id(33))?;
        encoder
            .u8(4)
            .map_err(cbor_error)?
            .u64(100)
            .map_err(cbor_error)?;
        encoder
            .u8(5)
            .map_err(cbor_error)?
            .u64((1_u64 << 63) | 2)
            .map_err(cbor_error)?;
        encoder.u8(6).map_err(cbor_error)?;
        encode_id(&mut encoder, id(34))?;
        encoder
            .u8(7)
            .map_err(cbor_error)?
            .u8(1)
            .map_err(cbor_error)?;
        encoder.u8(8).map_err(cbor_error)?;
        encode_id(&mut encoder, id(35))?;
        encoder.u8(9).map_err(cbor_error)?;
        encode_id(&mut encoder, id(36))?;
        Ok(bytes)
    }

    fn encode_payload(payload: &IntentPayloadV1) -> crate::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        encoder.map(13).map_err(cbor_error)?;
        encoder
            .u8(0)
            .map_err(cbor_error)?
            .u8(1)
            .map_err(cbor_error)?;
        encoder
            .u8(1)
            .map_err(cbor_error)?
            .u8(payload.kind)
            .map_err(cbor_error)?;
        for (key, value) in [
            (2, payload.proof_id),
            (3, payload.tenant_id),
            (4, payload.trust_domain_id),
            (5, payload.issuer_id),
        ] {
            encoder.u8(key).map_err(cbor_error)?;
            encode_id(&mut encoder, value)?;
        }
        encoder
            .u8(6)
            .map_err(cbor_error)?
            .u64(payload.sequence_epoch)
            .map_err(cbor_error)?;
        encoder
            .u8(7)
            .map_err(cbor_error)?
            .u64(payload.sequence)
            .map_err(cbor_error)?;
        encoder
            .u8(8)
            .map_err(cbor_error)?
            .i64(payload.issued_at_utc_ns)
            .map_err(cbor_error)?;
        encoder
            .u8(9)
            .map_err(cbor_error)?
            .i64(payload.not_before_utc_ns)
            .map_err(cbor_error)?;
        encoder
            .u8(10)
            .map_err(cbor_error)?
            .i64(payload.expires_at_utc_ns)
            .map_err(cbor_error)?;
        encoder
            .u8(11)
            .map_err(cbor_error)?
            .array(payload.claim_slot_ids.len() as u64)
            .map_err(cbor_error)?;
        for slot in &payload.claim_slot_ids {
            encode_id(&mut encoder, *slot)?;
        }
        encoder.u8(12).map_err(cbor_error)?;
        let mut decoder = Decoder::new(&payload.body_cbor);
        let tokens = decoder
            .tokens()
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(cbor_error)?;
        encoder.tokens(&tokens).map_err(cbor_error)?;
        Ok(bytes)
    }

    fn signed_envelope(
        signing_key: &SigningKey,
        key_id: &[u8],
        payload: &[u8],
    ) -> crate::Result<Vec<u8>> {
        let mut message = Vec::from(SIGNATURE_DOMAIN);
        message.extend_from_slice(&Sha256::digest(payload));
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
            .bytes(key_id)
            .map_err(cbor_error)?
            .u8(2)
            .map_err(cbor_error)?
            .u8(1)
            .map_err(cbor_error)?
            .u8(3)
            .map_err(cbor_error)?
            .bytes(payload)
            .map_err(cbor_error)?
            .u8(4)
            .map_err(cbor_error)?
            .bytes(&signature)
            .map_err(cbor_error)?;
        Ok(envelope)
    }

    #[test]
    fn administrative_exec_rejects_an_inconsistent_exact_mount_view() -> crate::Result<()> {
        let body = administrative_body_with_object_generation(b"bash", 2)?;
        assert!(validate_administrative_body(ADMINISTRATIVE_EXEC_KIND, &body, &[id(1)]).is_err());
        Ok(())
    }

    #[test]
    fn administrative_exec_lowers_signed_match_fields_exactly() -> crate::Result<()> {
        let body = administrative_body(b"bash")?;
        let decoded = validate_administrative_body(ADMINISTRATIVE_EXEC_KIND, &body, &[id(1)])?;
        assert_eq!(decoded.target_node_id, id(32));
        assert_eq!(decoded.authenticated_requester_principal_id, id(20));
        assert_eq!(decoded.authenticated_approver_principal_id, id(21));
        assert_eq!(decoded.cluster_uid, id(22));
        assert_eq!(decoded.namespace, b"default");
        assert_eq!(decoded.pod_uid, b"pod-uid");
        assert_eq!(decoded.container_name, b"worker");
        assert_eq!(decoded.full_container_id, vec![b'c'; 32]);
        assert_eq!(decoded.container_generation, 1);
        assert_eq!(decoded.approved_argv, [b"bash".to_vec()]);
        assert_eq!(decoded.stream_flags, 2);
        assert_eq!(decoded.approved_role_id, "admin.exec");
        assert_eq!(decoded.profile.profile_id, id(31));
        assert_eq!(decoded.profile.owner_generation, 1);
        assert_eq!(decoded.profile.artifact_sha256, [9; 32]);
        assert_eq!(decoded.resolved_executable.requested_name, b"bash");
        assert_eq!(decoded.resolved_executable.resolution_mode, 3);
        assert_eq!(
            decoded.resolved_executable.resolved_display_path,
            b"/usr/bin/bash"
        );
        assert_eq!(
            decoded.resolved_executable.container_working_directory,
            b"/workspace"
        );
        assert_eq!(
            decoded.resolved_executable.effective_path_entries,
            [b"/usr/local/bin".to_vec(), b"/usr/bin".to_vec()]
        );
        assert_eq!(
            decoded
                .resolved_executable
                .executable_object
                .mount_namespace_id,
            id(30)
        );
        assert_eq!(
            decoded
                .resolved_executable
                .executable_object
                .mount_topology_generation,
            1
        );
        assert_eq!(decoded.resolved_executable.executable_object.mount_id, 42);
        assert_eq!(decoded.resolved_executable.executable_object.inode, 100);
        assert_eq!(
            decoded
                .resolved_executable
                .executable_object
                .inode_generation,
            (1_u64 << 63) | 2
        );
        assert_eq!(
            decoded
                .resolved_executable
                .executable_object
                .filesystem_instance_id,
            id(33)
        );
        assert_eq!(
            decoded
                .resolved_executable
                .executable_object
                .exact_live_object_id,
            id(34)
        );
        assert_eq!(decoded.resolved_executable.executable_object.object_kind, 1);
        assert_eq!(
            decoded
                .resolved_executable
                .executable_object
                .backing_identity,
            id(35)
        );
        assert_eq!(
            decoded
                .resolved_executable
                .executable_object
                .live_interval_id,
            id(36)
        );
        Ok(())
    }

    #[test]
    fn execution_approval_snapshot_preserves_exact_order_and_boundaries() -> crate::Result<()> {
        let snapshot_id = id(40);
        let snapshot =
            execution_argv_snapshot(&[b"bash".as_slice(), b"-lc", b"echo value"], snapshot_id)?;
        assert!(snapshot.descriptor.is_valid());
        assert_eq!(snapshot.descriptor.snapshot_id, snapshot_id);
        assert_eq!(snapshot.descriptor.argument_count, 3);
        assert_eq!(snapshot.descriptor.total_argument_span, 20);
        assert_eq!(snapshot.descriptor.chunk_count, 1);
        assert_eq!(snapshot.chunks[0].length, 20);
        assert_eq!(snapshot.chunks[0].flags, EXECUTION_ARGV_CHUNK_TERMINAL_V1);
        assert_eq!(&snapshot.chunks[0].bytes[..20], b"bash\0-lc\0echo value\0");
        assert_ne!(
            snapshot,
            execution_argv_snapshot(&[b"bash-lc".as_slice(), b"echo value"], snapshot_id)?
        );
        assert_ne!(
            snapshot,
            execution_argv_snapshot(&[b"bash".as_slice(), b"-lcecho value"], snapshot_id)?
        );
        let large_arguments = vec![b"/run/mithril-entry-roles/control.allowed".as_slice(); 1_200];
        let large_snapshot = execution_argv_snapshot(&large_arguments, id(41))?;
        assert_eq!(large_snapshot.descriptor.argument_count, 1_200);
        assert_eq!(large_snapshot.descriptor.total_argument_span, 49_200);
        assert_eq!(large_snapshot.descriptor.chunk_count, 13);
        assert!(large_snapshot
            .chunks
            .iter()
            .enumerate()
            .all(|(index, chunk)| u32::try_from(index)
                .is_ok_and(|index| { chunk.is_valid_for(&large_snapshot.descriptor, index) })));
        Ok(())
    }

    #[test]
    fn signing_key_change_without_a_new_sequence_epoch_is_rejected() {
        let now = 10;
        let issuer = |key_id: &[u8], public_key: [u8; 32]| IssuerTrustV1 {
            issuer_id: id(1),
            key_id: key_id.to_vec(),
            public_key,
            sequence_epoch: 1,
            valid_from_utc_ns: now,
            valid_until_utc_ns: now + 1,
            revoked_at_utc_ns: None,
            allowed_intent_kinds: vec![ADMINISTRATIVE_EXEC_KIND],
            allowed_tenant_ids: vec![id(2)],
        };
        let first = SigningKey::from_bytes(&[1; 32]);
        let second = SigningKey::from_bytes(&[2; 32]);
        let trust = TrustBundleV1 {
            trust_domain_id: id(3),
            bundle_generation: 1,
            maximum_clock_skew_ns: 0,
            replay_window_size: 4096,
            issuers: vec![
                issuer(b"first", first.verifying_key().to_bytes()),
                issuer(b"second", second.verifying_key().to_bytes()),
            ],
        };
        assert!(trust.validate().is_err());
    }

    #[test]
    fn authorization_replay_004_rejects_same_proof_slot_and_sequence_after_restart(
    ) -> crate::Result<()> {
        let now = 1_000_000_000_000_i64;
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let body = administrative_body(b"bash")?;
        let administrative_exec =
            validate_administrative_body(ADMINISTRATIVE_EXEC_KIND, &body, &[id(7)])?;
        let payload = IntentPayloadV1 {
            kind: ADMINISTRATIVE_EXEC_KIND,
            proof_id: id(1),
            tenant_id: id(2),
            trust_domain_id: id(3),
            issuer_id: id(4),
            sequence_epoch: 5,
            sequence: 6,
            issued_at_utc_ns: now,
            not_before_utc_ns: now,
            expires_at_utc_ns: now + 60_000_000_000,
            claim_slot_ids: vec![id(7)],
            body_cbor: body.clone(),
            parent_proof_id: None,
            trigger_proof_ids: Vec::new(),
            administrative_exec,
        };
        let payload_bytes = encode_payload(&payload)?;
        let envelope = signed_envelope(&signing_key, b"operator-key", &payload_bytes)?;
        let trust = TrustBundleV1 {
            trust_domain_id: id(3),
            bundle_generation: 1,
            maximum_clock_skew_ns: 0,
            replay_window_size: 4096,
            issuers: vec![IssuerTrustV1 {
                issuer_id: id(4),
                key_id: b"operator-key".to_vec(),
                public_key: signing_key.verifying_key().to_bytes(),
                sequence_epoch: 5,
                valid_from_utc_ns: now - 1,
                valid_until_utc_ns: now + 120_000_000_000,
                revoked_at_utc_ns: None,
                allowed_intent_kinds: vec![ADMINISTRATIVE_EXEC_KIND],
                allowed_tenant_ids: vec![id(2)],
            }],
        };
        let target = AuthorizationTargetV1 {
            tenant_id: id(2),
            trust_domain_id: id(3),
            issuer_id: id(4),
            intent_kind: ADMINISTRATIVE_EXEC_KIND,
            body_sha256: Sha256::digest(&body).into(),
        };
        let wrong_node_state = tempfile::tempdir().map_err(|error| {
            authorization_error(format!("create wrong-node replay test directory: {error}"))
        })?;
        let mut wrong_node =
            AuthorizationProofOwner::load(wrong_node_state.path(), id(33), id(40), trust.clone())?;
        assert!(wrong_node
            .verify_and_accept(&envelope, target, now, 100)
            .is_err_and(|error| error.to_string().contains("targets another stable node")));
        let state = tempfile::tempdir().map_err(|error| {
            authorization_error(format!("create replay test directory: {error}"))
        })?;
        let mut owner = AuthorizationProofOwner::load(state.path(), id(32), id(40), trust.clone())?;
        let prepared = owner.verify_and_accept(&envelope, target, now, 100)?;
        assert_eq!(prepared.claim_slot_id, id(7));
        owner.replay.arm(
            prepared.proof_id,
            prepared.claim_slot_id,
            prepared.body_sha256,
            [8; 32],
        )?;
        owner.consume(id(1), id(7))?;
        assert!(owner.consume(id(1), id(7)).is_err());
        let mut restarted = AuthorizationProofOwner::load(state.path(), id(32), id(40), trust)?;
        assert!(restarted
            .verify_and_accept(&envelope, target, now, 100)
            .is_err());
        Ok(())
    }

    #[test]
    fn command_similarity_cannot_replace_signature_or_exact_target() -> crate::Result<()> {
        let body = administrative_body(b"bash")?;
        let administrative_exec =
            validate_administrative_body(ADMINISTRATIVE_EXEC_KIND, &body, &[id(15)])?;
        let payload = IntentPayloadV1 {
            kind: ADMINISTRATIVE_EXEC_KIND,
            proof_id: id(11),
            tenant_id: id(12),
            trust_domain_id: id(13),
            issuer_id: id(14),
            sequence_epoch: 1,
            sequence: 1,
            issued_at_utc_ns: 10,
            not_before_utc_ns: 10,
            expires_at_utc_ns: 20,
            claim_slot_ids: vec![id(15)],
            body_cbor: body,
            parent_proof_id: None,
            trigger_proof_ids: Vec::new(),
            administrative_exec,
        };
        let signing_key = SigningKey::from_bytes(&[8; 32]);
        let encoded = encode_payload(&payload)?;
        let mut envelope = signed_envelope(&signing_key, b"key", &encoded)?;
        let last = envelope
            .last_mut()
            .ok_or_else(|| authorization_error("empty signed envelope"))?;
        *last ^= 1;
        let trust = TrustBundleV1 {
            trust_domain_id: id(13),
            bundle_generation: 1,
            maximum_clock_skew_ns: 0,
            replay_window_size: 4096,
            issuers: vec![IssuerTrustV1 {
                issuer_id: id(14),
                key_id: b"key".to_vec(),
                public_key: signing_key.verifying_key().to_bytes(),
                sequence_epoch: 1,
                valid_from_utc_ns: 0,
                valid_until_utc_ns: 30,
                revoked_at_utc_ns: None,
                allowed_intent_kinds: vec![ADMINISTRATIVE_EXEC_KIND],
                allowed_tenant_ids: vec![id(12)],
            }],
        };
        let state = tempfile::tempdir().map_err(|error| {
            authorization_error(format!("create signature test directory: {error}"))
        })?;
        let mut owner = AuthorizationProofOwner::load(state.path(), id(32), id(40), trust)?;
        assert!(owner
            .verify_and_accept(
                &envelope,
                AuthorizationTargetV1 {
                    tenant_id: id(12),
                    trust_domain_id: id(13),
                    issuer_id: id(14),
                    intent_kind: ADMINISTRATIVE_EXEC_KIND,
                    body_sha256: [0; 32],
                },
                10,
                10,
            )
            .is_err());
        Ok(())
    }
}
