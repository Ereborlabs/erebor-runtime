use std::fs;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use erebor_interceptor_abi::Id128V1;
use mithril_control::{
    encode_administrative_authorization_fixture, AdministrativeExecResolution,
    AdministrativeFileObject, ResolvedAdministrativeExecutable,
};
use mithril_node::{AuthorizationProofOwner, AuthorizationTargetV1, IssuerTrustV1, TrustBundleV1};
use snafu::ResultExt as _;

use super::invalid_state;
use crate::error::{IoSnafu, NodeSnafu};

struct AuthCase {
    temp: tempfile::TempDir,
    state: PathBuf,
    now: i64,
    expires: i64,
    key: SigningKey,
    trust: TrustBundleV1,
    target: AuthorizationTargetV1,
    envelope: Vec<u8>,
    body_hash: [u8; 32],
    boot: Id128V1,
}

impl AuthCase {
    fn new() -> crate::Result<Self> {
        let temp = tempfile::tempdir()
            .map_err(|error| invalid_state(format!("create authorization state: {error}")))?;
        let state = temp.path().join("authorization-replay");
        let now = 1_000_000_000_000_i64;
        let expires = now + 60_000_000_000;
        let key = SigningKey::from_bytes(&[7; 32]);
        let (envelope, body_hash) = encode_auth(&key, 6, id(1), id(7), now, expires)?;
        let trust = TrustBundleV1 {
            trust_domain_id: id(3),
            bundle_generation: 1,
            maximum_clock_skew_ns: 0,
            replay_window_size: 4096,
            issuers: vec![IssuerTrustV1 {
                issuer_id: id(4),
                key_id: b"operator-key".to_vec(),
                public_key: key.verifying_key().to_bytes(),
                sequence_epoch: 5,
                valid_from_utc_ns: now - 1,
                valid_until_utc_ns: now + 120_000_000_000,
                revoked_at_utc_ns: None,
                allowed_intent_kinds: vec![8],
                allowed_tenant_ids: vec![id(2)],
            }],
        };
        let target = AuthorizationTargetV1 {
            tenant_id: id(2),
            trust_domain_id: id(3),
            issuer_id: id(4),
            intent_kind: 8,
            body_sha256: body_hash,
        };
        Ok(Self {
            temp,
            state,
            now,
            expires,
            key,
            trust,
            target,
            envelope,
            body_hash,
            boot: id(90),
        })
    }

    fn owner(&self, boot: Id128V1) -> crate::Result<AuthorizationProofOwner> {
        AuthorizationProofOwner::load(&self.state, id(32), boot, self.trust.clone())
            .context(NodeSnafu)
    }

    fn signed(&self, seq: u64, proof: u64, slot: u64) -> crate::Result<Vec<u8>> {
        let (envelope, body_hash) =
            encode_auth(&self.key, seq, id(proof), id(slot), self.now, self.expires)?;
        assert_eq!(body_hash, self.body_hash);
        Ok(envelope)
    }

    fn stop(self) -> crate::Result<()> {
        let root = self.temp.path().to_owned();
        self.temp
            .close()
            .map_err(|error| invalid_state(format!("remove authorization state: {error}")))?;
        assert!(!root.exists());
        Ok(())
    }
}

#[test]
fn invalid_auth_is_rejected() -> crate::Result<()> {
    let case = AuthCase::new()?;
    let mut owner = case.owner(case.boot)?;
    let bad_target = AuthorizationTargetV1 {
        body_sha256: [0x55; 32],
        ..case.target
    };

    assert!(has_error(
        owner.verify_and_accept(&case.envelope, bad_target, case.now, 100),
        "exact target does not match",
    ));
    assert!(has_error(
        owner.verify_and_accept(&case.envelope, case.target, case.expires + 1, 100),
        "outside its trusted time interval",
    ));
    let mut bad_sig = case.envelope.clone();
    *bad_sig
        .last_mut()
        .ok_or_else(|| invalid_state("signed authorization is empty"))? ^= 1;
    assert!(has_error(
        owner.verify_and_accept(&bad_sig, case.target, case.now, 100),
        "Ed25519 verification failed",
    ));
    let wal_path = case.state.join("authorization-replay-v1.jsonl");
    let wal = fs::read(&wal_path).context(IoSnafu { path: &wal_path })?;
    assert_eq!(record_count(&wal), 2);

    drop(owner);
    case.stop()
}

#[test]
fn replay_is_durable() -> crate::Result<()> {
    let case = AuthCase::new()?;
    let mut owner = case.owner(case.boot)?;
    let fresh = owner
        .verify_and_accept(&case.envelope, case.target, case.now, 100)
        .context(NodeSnafu)?;
    assert_eq!(fresh.proof_id, id(1));
    assert_eq!(fresh.claim_slot_id, id(7));
    assert_eq!(fresh.sequence_epoch, 5);
    assert_eq!(fresh.sequence, 6);
    assert_eq!(fresh.body_sha256, case.body_hash);
    assert!(has_error(
        owner.verify_and_accept(&case.envelope, case.target, case.now, 100),
        "replay WAL repeats identity",
    ));

    let seq_replay = case.signed(6, 10, 11)?;
    drop(owner);
    let mut restarted = case.owner(case.boot)?;
    assert!(has_error(
        restarted.verify_and_accept(&seq_replay, case.target, case.now, 100),
        "replay window",
    ));
    drop(restarted);

    let low = case
        .boot
        .low
        .checked_add(1)
        .unwrap_or_else(|| case.boot.low.saturating_sub(1));
    let reboot = Id128V1::new(case.boot.high, low);
    assert!(!reboot.is_zero());
    assert_ne!(reboot, case.boot);
    let mut rebooted = case.owner(reboot)?;
    assert!(has_error(
        rebooted.verify_and_accept(&case.envelope, case.target, case.now, 100),
        "replay WAL repeats identity",
    ));
    let next = case.signed(7, 8, 9)?;
    let fresh = rebooted
        .verify_and_accept(&next, case.target, case.now, 100)
        .context(NodeSnafu)?;
    assert_eq!(fresh.proof_id, id(8));
    assert_eq!(fresh.claim_slot_id, id(9));
    assert_eq!(fresh.sequence, 7);
    drop(rebooted);

    let wal_path = case.state.join("authorization-replay-v1.jsonl");
    let wal = fs::read(&wal_path).context(IoSnafu { path: &wal_path })?;
    assert!(wal.ends_with(b"\n"));
    assert_eq!(record_count(&wal), 5);
    assert_eq!(crate::digest::DigestV1::of(wal).to_hex().len(), 64);
    case.stop()
}

fn has_error<T, E: std::fmt::Display>(result: Result<T, E>, text: &str) -> bool {
    result.is_err_and(|error| error.to_string().contains(text))
}

fn record_count(wal: &[u8]) -> usize {
    wal.split(|byte| *byte == b'\n')
        .filter(|record| !record.is_empty())
        .count()
}

fn encode_auth(
    key: &SigningKey,
    seq: u64,
    proof: Id128V1,
    slot: Id128V1,
    now: i64,
    expires: i64,
) -> crate::Result<(Vec<u8>, [u8; 32])> {
    encode_administrative_authorization_fixture(
        key,
        b"operator-key",
        id(2),
        id(22),
        id(3),
        id(4),
        5,
        seq,
        proof,
        slot,
        now,
        expires,
        id(20),
        id(21),
        &admin_resolution(),
    )
    .map_err(|error| invalid_state(format!("encode authorization: {error}")))
}

fn id(value: u64) -> Id128V1 {
    Id128V1::new(1, value)
}

fn portable(value: Id128V1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&value.high.to_be_bytes());
    bytes.extend_from_slice(&value.low.to_be_bytes());
    bytes
}

fn admin_resolution() -> AdministrativeExecResolution {
    AdministrativeExecResolution {
        request_id: portable(id(19)),
        resolved: true,
        reason_code: "resolved".to_owned(),
        target_node_id: portable(id(32)),
        namespace: b"default".to_vec(),
        pod_uid: b"pod-uid".to_vec(),
        container_name: b"worker".to_vec(),
        full_container_id: vec![b'c'; 32],
        container_generation: 1,
        argv: vec![b"bash".to_vec()],
        stream_flags: 2,
        approved_role_id: "admin.exec".to_owned(),
        profile_id: portable(id(31)),
        profile_owner_generation: 1,
        profile_artifact_sha256: vec![9; 32],
        resolved_executable: Some(ResolvedAdministrativeExecutable {
            requested_name: b"bash".to_vec(),
            resolution_mode: 3,
            resolved_display_path: b"/usr/bin/bash".to_vec(),
            container_working_directory: b"/workspace".to_vec(),
            effective_path_entries: vec![b"/usr/local/bin".to_vec(), b"/usr/bin".to_vec()],
            target_mount_namespace_id: portable(id(30)),
            target_mount_topology_generation: 1,
            executable_object: Some(AdministrativeFileObject {
                mount_namespace_id: portable(id(30)),
                mount_topology_generation: 1,
                mount_id: 42,
                filesystem_instance_id: portable(id(33)),
                inode: 100,
                inode_generation: 2,
                exact_live_object_id: portable(id(34)),
                object_kind: 1,
                backing_identity: portable(id(35)),
                live_interval_id: portable(id(36)),
            }),
        }),
    }
}
