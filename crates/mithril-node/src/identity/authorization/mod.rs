mod replay;

use std::collections::BTreeSet;
use std::mem::{offset_of, size_of};
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    ApprovedExecArgumentKeyV1, ApprovedExecSlotKeyV1, ApprovedExecSlotStateV1, ApprovedExecSlotV1,
    BoundedAdministrativeArgvV1, ExternalRootClassV1, Id128V1,
};
use minicbor::data::Token;
use minicbor::{Decoder, Encoder};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};

use self::replay::{AcceptedProof, ReplayKey, ReplayLedger};
use zerocopy::IntoBytes as _;

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
struct AdministrativeExecIdentityV1 {
    container_generation: u64,
    approved_argv: BoundedAdministrativeArgvV1,
    resolved_mount_id: u32,
    resolved_inode: u64,
    resolved_inode_generation: u32,
}

struct ResolvedExecutableObjectV1 {
    mount_id: u32,
    inode: u64,
    inode_generation: u32,
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

pub struct AuthorizationProofOwner {
    trust: TrustBundleV1,
    replay: ReplayLedger,
}

struct DecodedEnvelope<'a> {
    key_id: &'a [u8],
    payload_bytes: &'a [u8],
    signature: &'a [u8],
}

impl AuthorizationProofOwner {
    pub fn load(state_directory: &Path, trust: TrustBundleV1) -> Result<Self> {
        trust.validate()?;
        Ok(Self {
            trust,
            replay: ReplayLedger::load(state_directory)?,
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

    pub fn arm_administrative_slot(
        &mut self,
        host: &KernelHost,
        key: ApprovedExecSlotKeyV1,
        mut slot: ApprovedExecSlotV1,
        proof: PreparedAuthorizationProofV1,
    ) -> Result<()> {
        slot.proof_id = proof.proof_id;
        slot.claim_slot_id = proof.claim_slot_id;
        slot.authorization_body_sha256 = proof.body_sha256;
        slot.deadline_boottime_ns = proof.deadline_boottime_ns;
        slot.state = ApprovedExecSlotStateV1::Armed;
        slot.transition_version = 1;
        ensure!(
            !key.node_boot_id.is_zero()
                && !key.cgroup_binding_id.is_zero()
                && !slot.cgroup_binding_nonce.is_zero()
                && slot.container_generation > 0
                && slot.container_generation == proof.administrative_exec.container_generation
                && slot.expected_argv.is_valid()
                && slot.expected_argv == proof.administrative_exec.approved_argv
                && slot.resolved_executable.mount_namespace_inode > 0
                && slot.resolved_executable.mount_id > 0
                && slot.resolved_executable.mount_id == proof.administrative_exec.resolved_mount_id
                && slot.resolved_executable.filesystem_device > 0
                && slot.resolved_executable.inode > 0
                && slot.resolved_executable.inode == proof.administrative_exec.resolved_inode
                && slot.resolved_executable.inode_generation > 0
                && slot.resolved_executable.inode_generation
                    == proof.administrative_exec.resolved_inode_generation
                && slot.approved_role_numeric_id > 0
                && slot.profile_generation_ref_id > 0
                && slot.reserved_after_exception == 0
                && slot.expected_root_class == ExternalRootClassV1::ExternalRuntimeRoot,
            AuthorizationSnafu {
                reason: "administrative slot is not an exact bounded external-root match",
            }
        );
        let intent_sha256 = administrative_slot_intent_sha256(&key, &slot);
        let argument_keys = administrative_argument_keys(slot.proof_id, &slot.expected_argv)?;
        let existing = host
            .lookup_map("approved_exec_slots", key.as_bytes())
            .context(InterceptorSnafu)?;
        ensure!(
            existing
                .as_deref()
                .is_none_or(|value| value == slot.as_bytes()),
            AuthorizationSnafu {
                reason: "live cgroup binding already has a different administrative slot",
            }
        );
        self.replay.arm(
            proof.proof_id,
            proof.claim_slot_id,
            proof.body_sha256,
            intent_sha256,
        )?;
        for argument_key in &argument_keys {
            host.update_map("approved_exec_arguments", argument_key.as_bytes(), &[1])
                .context(InterceptorSnafu)?;
            ensure!(
                host.lookup_map("approved_exec_arguments", argument_key.as_bytes())
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some([1_u8].as_slice()),
                AuthorizationSnafu {
                    reason: "administrative argument failed kernel readback",
                }
            );
        }
        if existing.is_none() {
            host.update_map("approved_exec_slots", key.as_bytes(), slot.as_bytes())
                .context(InterceptorSnafu)?;
        }
        ensure!(
            host.lookup_map("approved_exec_slots", key.as_bytes())
                .context(InterceptorSnafu)?
                .as_deref()
                == Some(slot.as_bytes()),
            AuthorizationSnafu {
                reason: "administrative slot failed kernel readback",
            }
        );
        Ok(())
    }

    pub fn reconcile_administrative_slots(&mut self, host: &KernelHost) -> Result<()> {
        let mut live_slots = BTreeSet::new();
        let mut live_proofs = BTreeSet::new();
        for key in host
            .map_keys("approved_exec_slots")
            .context(InterceptorSnafu)?
        {
            ensure!(
                key.len() == size_of::<ApprovedExecSlotKeyV1>(),
                AuthorizationSnafu {
                    reason: "administrative slot map returned a malformed key",
                }
            );
            let Some(mut value) = host
                .lookup_map("approved_exec_slots", &key)
                .context(InterceptorSnafu)?
            else {
                continue;
            };
            ensure!(
                value.len() == size_of::<ApprovedExecSlotV1>(),
                AuthorizationSnafu {
                    reason: "administrative slot map returned a malformed value",
                }
            );
            let state = read_slot_u64(&value, offset_of!(ApprovedExecSlotV1, state))?;
            let proof_id = read_slot_id(&value, offset_of!(ApprovedExecSlotV1, proof_id))?;
            let claim_slot_id =
                read_slot_id(&value, offset_of!(ApprovedExecSlotV1, claim_slot_id))?;
            let argument_keys = administrative_argument_keys_from_slot_bytes(&value)?;
            value[offset_of!(ApprovedExecSlotV1, state)
                ..offset_of!(ApprovedExecSlotV1, state) + size_of::<u64>()]
                .copy_from_slice(&(ApprovedExecSlotStateV1::Armed as u64).to_ne_bytes());
            value[offset_of!(ApprovedExecSlotV1, transition_version)
                ..offset_of!(ApprovedExecSlotV1, transition_version) + size_of::<u64>()]
                .copy_from_slice(&1_u64.to_ne_bytes());
            let intent_sha256 = administrative_slot_intent_sha256_bytes(&key, &value);
            match state {
                value if value == ApprovedExecSlotStateV1::Armed as u64 => {
                    ensure!(
                        self.replay.armed_intent(claim_slot_id) == Some(intent_sha256),
                        AuthorizationSnafu {
                            reason: "armed kernel slot differs from its durable intent",
                        }
                    );
                    ensure_administrative_arguments(host, &argument_keys)?;
                    live_slots.insert(claim_slot_id);
                    live_proofs.insert(proof_id);
                }
                value if value == ApprovedExecSlotStateV1::Consumed as u64 => {
                    self.replay
                        .reconcile_consumed(proof_id, claim_slot_id, intent_sha256)?;
                    delete_administrative_arguments(host, &argument_keys)?;
                    host.delete_map_entry("approved_exec_slots", &key)
                        .context(InterceptorSnafu)?;
                }
                value
                    if value == ApprovedExecSlotStateV1::Expired as u64
                        || value == ApprovedExecSlotStateV1::Cancelled as u64
                        || value == ApprovedExecSlotStateV1::Corrupt as u64 =>
                {
                    self.replay.close(proof_id, claim_slot_id, intent_sha256)?;
                    delete_administrative_arguments(host, &argument_keys)?;
                    host.delete_map_entry("approved_exec_slots", &key)
                        .context(InterceptorSnafu)?;
                }
                _ => {
                    return AuthorizationSnafu {
                        reason: "administrative slot is neither armed nor durably consumable"
                            .to_owned(),
                    }
                    .fail()
                }
            }
        }
        for key in host
            .map_keys("approved_exec_arguments")
            .context(InterceptorSnafu)?
        {
            ensure!(
                key.len() == size_of::<ApprovedExecArgumentKeyV1>(),
                AuthorizationSnafu {
                    reason: "administrative argument map returned a malformed key",
                }
            );
            if !live_proofs.contains(&read_slot_id(&key, 0)?) {
                host.delete_map_entry("approved_exec_arguments", &key)
                    .context(InterceptorSnafu)?;
            }
        }
        ensure!(
            self.replay
                .armed_slots()
                .into_iter()
                .all(|slot_id| live_slots.contains(&slot_id)),
            AuthorizationSnafu {
                reason: "durably armed administrative slot is missing from the kernel",
            }
        );
        Ok(())
    }
}

fn administrative_argument_keys(
    proof_id: Id128V1,
    argv: &BoundedAdministrativeArgvV1,
) -> Result<Vec<ApprovedExecArgumentKeyV1>> {
    ensure!(
        argv.is_valid(),
        AuthorizationSnafu {
            reason: "administrative argv is not canonical",
        }
    );
    let mut keys = Vec::with_capacity(usize::from(argv.argument_count));
    let mut offset = 0_usize;
    for (index, length) in argv.argument_lengths[..usize::from(argv.argument_count)]
        .iter()
        .enumerate()
    {
        let end = offset + usize::from(*length);
        let key = ApprovedExecArgumentKeyV1::from_argument(
            proof_id,
            index,
            &argv.argument_bytes[offset..end],
        )
        .ok_or_else(|| authorization_error("administrative argument key is invalid"))?;
        keys.push(key);
        offset = end;
    }
    Ok(keys)
}

fn administrative_argument_keys_from_slot_bytes(
    slot: &[u8],
) -> Result<Vec<ApprovedExecArgumentKeyV1>> {
    ensure!(
        slot.len() == size_of::<ApprovedExecSlotV1>(),
        AuthorizationSnafu {
            reason: "administrative slot is truncated",
        }
    );
    let argv_offset = offset_of!(ApprovedExecSlotV1, expected_argv);
    let mut argv = BoundedAdministrativeArgvV1 {
        argument_count: read_slot_u16(slot, argv_offset)?,
        total_argument_bytes: read_slot_u16(slot, argv_offset + size_of::<u16>())?,
        ..BoundedAdministrativeArgvV1::default()
    };
    let lengths_offset = argv_offset + 2 * size_of::<u16>();
    for (index, length) in argv.argument_lengths.iter_mut().enumerate() {
        *length = read_slot_u16(slot, lengths_offset + index * size_of::<u16>())?;
    }
    let bytes_offset = lengths_offset + size_of::<[u16; 256]>();
    let argument_bytes_len = argv.argument_bytes.len();
    argv.argument_bytes.copy_from_slice(
        slot.get(bytes_offset..bytes_offset + argument_bytes_len)
            .ok_or_else(|| authorization_error("administrative argv bytes are truncated"))?,
    );
    administrative_argument_keys(
        read_slot_id(slot, offset_of!(ApprovedExecSlotV1, proof_id))?,
        &argv,
    )
}

fn ensure_administrative_arguments(
    host: &KernelHost,
    keys: &[ApprovedExecArgumentKeyV1],
) -> Result<()> {
    for key in keys {
        ensure!(
            host.lookup_map("approved_exec_arguments", key.as_bytes())
                .context(InterceptorSnafu)?
                .as_deref()
                == Some([1_u8].as_slice()),
            AuthorizationSnafu {
                reason: "armed administrative argument is missing from the kernel",
            }
        );
    }
    Ok(())
}

fn delete_administrative_arguments(
    host: &KernelHost,
    keys: &[ApprovedExecArgumentKeyV1],
) -> Result<()> {
    for key in keys {
        if host
            .lookup_map("approved_exec_arguments", key.as_bytes())
            .context(InterceptorSnafu)?
            .is_some()
        {
            host.delete_map_entry("approved_exec_arguments", key.as_bytes())
                .context(InterceptorSnafu)?;
        }
    }
    Ok(())
}

fn administrative_slot_intent_sha256(
    key: &ApprovedExecSlotKeyV1,
    slot: &ApprovedExecSlotV1,
) -> [u8; 32] {
    administrative_slot_intent_sha256_bytes(key.as_bytes(), slot.as_bytes())
}

fn administrative_slot_intent_sha256_bytes(key: &[u8], slot: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"MITHRIL-ADMINISTRATIVE-SLOT-V1\0");
    digest.update(key);
    digest.update(slot);
    digest.finalize().into()
}

fn read_slot_u64(value: &[u8], offset: usize) -> Result<u64> {
    let bytes = value
        .get(offset..offset + size_of::<u64>())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| authorization_error("administrative slot is truncated"))?;
    Ok(u64::from_ne_bytes(bytes))
}

fn read_slot_u16(value: &[u8], offset: usize) -> Result<u16> {
    let bytes = value
        .get(offset..offset + size_of::<u16>())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| authorization_error("administrative slot is truncated"))?;
    Ok(u16::from_ne_bytes(bytes))
}

fn read_slot_id(value: &[u8], offset: usize) -> Result<Id128V1> {
    Ok(Id128V1::new(
        read_slot_u64(value, offset)?,
        read_slot_u64(value, offset + size_of::<u64>())?,
    ))
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
            reason: "only one-slot ADMINISTRATIVE_EXEC is allocated in this phase",
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
    for key in 0..=2 {
        expect_key(&mut decoder, key)?;
        let _id = decode_id(&mut decoder, "administrative principal/cluster ID")?;
    }
    expect_key(&mut decoder, 3)?;
    let namespace = decode_bytes(&mut decoder, 1, 253, true, "namespace")?;
    ensure!(
        std::str::from_utf8(namespace).is_ok(),
        AuthorizationSnafu {
            reason: "namespace is not UTF-8",
        }
    );
    expect_key(&mut decoder, 4)?;
    let _pod_uid = decode_bytes(&mut decoder, 1, 64, true, "Pod UID")?;
    expect_key(&mut decoder, 5)?;
    let container_name = decode_bytes(&mut decoder, 1, 253, true, "container name")?;
    ensure!(
        std::str::from_utf8(container_name).is_ok(),
        AuthorizationSnafu {
            reason: "container name is not UTF-8",
        }
    );
    expect_key(&mut decoder, 6)?;
    let _container_id = decode_bytes(&mut decoder, 32, 128, true, "container ID")?;
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
    ensure!(
        decode_u64(&mut decoder)? <= 0x0f,
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
    expect_key(&mut decoder, 11)?;
    validate_portable_profile_generation(&mut decoder)?;
    expect_key(&mut decoder, 12)?;
    let _target_node_id = decode_id(&mut decoder, "target node ID")?;
    expect_key(&mut decoder, 13)?;
    ensure!(
        decode_u64(&mut decoder)? == 1,
        AuthorizationSnafu {
            reason: "administrative match mode is not NEXT_MATCHING_RUNTIME_EXTERNAL_ROOT",
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
    let approved_argv = BoundedAdministrativeArgvV1::from_arguments(&arguments)
        .ok_or_else(|| authorization_error("approved argv cannot be lowered to the BPF ABI"))?;
    let resolved =
        validate_resolved_executable(&mut decoder, arguments.first().copied().unwrap_or_default())?;
    ensure!(
        decoder.position() == body.len(),
        AuthorizationSnafu {
            reason: "administrative body has trailing bytes",
        }
    );
    Ok(AdministrativeExecIdentityV1 {
        container_generation,
        approved_argv,
        resolved_mount_id: resolved.mount_id,
        resolved_inode: resolved.inode,
        resolved_inode_generation: resolved.inode_generation,
    })
}

fn validate_portable_profile_generation(decoder: &mut Decoder<'_>) -> Result<()> {
    expect_map(decoder, 3, "portable profile generation")?;
    expect_key(decoder, 0)?;
    let _profile_id = decode_id(decoder, "portable profile ID")?;
    expect_key(decoder, 1)?;
    ensure!(
        decode_u64(decoder)? > 0,
        AuthorizationSnafu {
            reason: "portable profile owner generation is zero",
        }
    );
    expect_key(decoder, 2)?;
    validate_digest(decoder, "compiled profile artifact digest")
}

fn validate_resolved_executable(
    decoder: &mut Decoder<'_>,
    command: &[u8],
) -> Result<ResolvedExecutableObjectV1> {
    expect_map(decoder, 8, "resolved administrative executable")?;
    expect_key(decoder, 0)?;
    let requested_name = decode_bytes(decoder, 1, 4096, true, "requested executable name")?;
    ensure!(
        requested_name == command,
        AuthorizationSnafu {
            reason: "resolved executable name differs from argv[0]",
        }
    );
    expect_key(decoder, 1)?;
    ensure!(
        (1..=3).contains(&decode_u64(decoder)?),
        AuthorizationSnafu {
            reason: "executable resolution mode is unallocated",
        }
    );
    expect_key(decoder, 2)?;
    let resolved = decode_bytes(decoder, 1, 4096, true, "resolved executable path")?;
    ensure!(
        resolved.first() == Some(&b'/'),
        AuthorizationSnafu {
            reason: "resolved executable path is not absolute",
        }
    );
    expect_key(decoder, 3)?;
    let working = decode_bytes(decoder, 1, 4096, true, "container working directory")?;
    ensure!(
        working.first() == Some(&b'/'),
        AuthorizationSnafu {
            reason: "container working directory is not absolute",
        }
    );
    expect_key(decoder, 4)?;
    let path_count = expect_array(decoder, 0, 64, "effective PATH entries")?;
    for _ in 0..path_count {
        let path = decode_bytes(decoder, 1, 4096, true, "effective PATH entry")?;
        ensure!(
            path.first() == Some(&b'/'),
            AuthorizationSnafu {
                reason: "effective PATH entry is not absolute",
            }
        );
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
    validate_file_object(decoder, mount_namespace, mount_topology_generation)
}

fn validate_file_object(
    decoder: &mut Decoder<'_>,
    expected_mount_namespace: Id128V1,
    expected_mount_topology_generation: u64,
) -> Result<ResolvedExecutableObjectV1> {
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
    let _filesystem_instance_id = decode_id(decoder, "filesystem instance ID")?;
    expect_key(decoder, 4)?;
    let inode = decode_u64(decoder)?;
    expect_key(decoder, 5)?;
    let inode_generation = decode_u64(decoder)?.try_into().map_err(|error| {
        authorization_error(format!(
            "executable inode generation exceeds its Linux u32 ABI: {error}"
        ))
    })?;
    ensure!(
        mount_id > 0 && inode > 0 && inode_generation > 0,
        AuthorizationSnafu {
            reason: "executable object has a zero mount, inode, or generation identity",
        }
    );
    expect_key(decoder, 6)?;
    let _exact_live_object_id = decode_id(decoder, "exact live object ID")?;
    expect_key(decoder, 7)?;
    ensure!(
        (1..=12).contains(&decode_u64(decoder)?),
        AuthorizationSnafu {
            reason: "executable object kind is unknown or unallocated",
        }
    );
    expect_key(decoder, 8)?;
    let _backing_identity = decode_id(decoder, "backing object or volume identity")?;
    expect_key(decoder, 9)?;
    let _live_interval_id = decode_id(decoder, "file-object live interval ID")?;
    Ok(ResolvedExecutableObjectV1 {
        mount_id,
        inode,
        inode_generation,
    })
}

fn validate_digest(decoder: &mut Decoder<'_>, name: &str) -> Result<()> {
    expect_map(decoder, 2, name)?;
    expect_key(decoder, 0)?;
    ensure!(
        decode_u64(decoder)? == 1,
        AuthorizationSnafu {
            reason: format!("{name} does not use SHA-256"),
        }
    );
    expect_key(decoder, 1)?;
    let _sha256 = decode_bytes(decoder, 32, 32, false, name)?;
    Ok(())
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
        administrative_argument_keys, administrative_argument_keys_from_slot_bytes,
        authorization_error, cbor_error, validate_administrative_body, AuthorizationProofOwner,
        AuthorizationTargetV1, IntentPayloadV1, IssuerTrustV1, TrustBundleV1,
        ADMINISTRATIVE_EXEC_KIND, SIGNATURE_DOMAIN,
    };
    use erebor_interceptor_abi::{ApprovedExecSlotV1, BoundedAdministrativeArgvV1, Id128V1};
    use zerocopy::IntoBytes as _;

    fn id(value: u64) -> Id128V1 {
        Id128V1::new(1, value)
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
            .u64(2)
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
        assert_eq!(decoded.container_generation, 1);
        assert_eq!(decoded.approved_argv.argument_count, 1);
        assert_eq!(&decoded.approved_argv.argument_bytes[..4], b"bash");
        assert_eq!(decoded.resolved_mount_id, 42);
        assert_eq!(decoded.resolved_inode, 100);
        assert_eq!(decoded.resolved_inode_generation, 2);
        Ok(())
    }

    #[test]
    fn administrative_argument_map_keys_preserve_exact_order() -> crate::Result<()> {
        let proof_id = id(41);
        let argv = BoundedAdministrativeArgvV1::from_arguments(&[
            b"bash".as_slice(),
            b"-lc",
            b"echo value",
        ])
        .ok_or_else(|| authorization_error("test argv is invalid"))?;
        let keys = administrative_argument_keys(proof_id, &argv)?;
        let slot = ApprovedExecSlotV1 {
            proof_id,
            expected_argv: argv,
            ..ApprovedExecSlotV1::default()
        };

        assert_eq!(
            keys,
            administrative_argument_keys_from_slot_bytes(slot.as_bytes())?
        );
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].argument_index, 0);
        assert_eq!(&keys[0].argument_bytes[..4], b"bash");
        assert_eq!(keys[1].argument_index, 1);
        assert_eq!(&keys[1].argument_bytes[..3], b"-lc");
        assert_eq!(keys[2].argument_index, 2);
        assert_eq!(&keys[2].argument_bytes[..10], b"echo value");
        assert_ne!(keys[1].as_bytes(), keys[2].as_bytes());
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
        let state = tempfile::tempdir().map_err(|error| {
            authorization_error(format!("create replay test directory: {error}"))
        })?;
        let mut owner = AuthorizationProofOwner::load(state.path(), trust.clone())?;
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
        let mut restarted = AuthorizationProofOwner::load(state.path(), trust)?;
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
        let mut owner = AuthorizationProofOwner::load(state.path(), trust)?;
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
