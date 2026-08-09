use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use erebor_interceptor_abi::Id128V1;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::error::{AuthorizationSnafu, IoSnafu, JsonSnafu};
use crate::Result;

const REPLAY_WINDOW_BITS: usize = 4096;
const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_BITS / u64::BITS as usize;
const MAX_REPLAY_WINDOWS: usize = 4096;
const MAX_PROOF_TOMBSTONES: usize = 65_536;
const MAX_SLOT_TOMBSTONES: usize = 262_144;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ReplayKey {
    pub trust_domain_id: Id128V1,
    pub issuer_id: Id128V1,
    pub key_id: Vec<u8>,
    pub sequence_epoch: u64,
}

#[derive(Clone, Debug)]
pub(super) struct AcceptedProof<'a> {
    pub key: ReplayKey,
    pub sequence: u64,
    pub proof_id: Id128V1,
    pub claim_slot_ids: &'a [Id128V1],
    pub expires_at_utc_ns: i64,
    pub body_sha256: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub(super) struct ReplayLedger {
    path: PathBuf,
    windows: BTreeMap<ReplayKey, ReplayWindow>,
    proofs: BTreeMap<Id128V1, i64>,
    slots: BTreeMap<Id128V1, SlotRecord>,
    poisoned: bool,
}

#[derive(Clone, Debug)]
struct ReplayWindow {
    highest_sequence: u64,
    seen: [u64; REPLAY_WINDOW_WORDS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Prepared,
    Armed { intent_sha256: [u8; 32] },
    Consumed,
    Closed { intent_sha256: [u8; 32] },
}

#[derive(Clone, Copy, Debug)]
struct SlotRecord {
    proof_id: Id128V1,
    expires_at_utc_ns: i64,
    body_sha256: [u8; 32],
    state: SlotState,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ReplayRecordV1 {
    Accept {
        schema_version: u32,
        trust_domain_id: StoredId,
        issuer_id: StoredId,
        key_id: Vec<u8>,
        sequence_epoch: u64,
        sequence: u64,
        proof_id: StoredId,
        claim_slot_ids: Vec<StoredId>,
        expires_at_utc_ns: i64,
        body_sha256: [u8; 32],
    },
    Arm {
        schema_version: u32,
        proof_id: StoredId,
        claim_slot_id: StoredId,
        slot_intent_sha256: [u8; 32],
    },
    Consume {
        schema_version: u32,
        proof_id: StoredId,
        claim_slot_id: StoredId,
    },
    Close {
        schema_version: u32,
        proof_id: StoredId,
        claim_slot_id: StoredId,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredId {
    high: u64,
    low: u64,
}

impl StoredId {
    const fn is_zero(&self) -> bool {
        self.high == 0 && self.low == 0
    }
}

impl ReplayLedger {
    pub(super) fn load(state_directory: &Path) -> Result<Self> {
        fs::create_dir_all(state_directory).context(IoSnafu {
            path: state_directory,
        })?;
        let legacy_path = state_directory.join("authorization-replay-v1.json");
        if legacy_path.exists() {
            return AuthorizationSnafu {
                reason: format!(
                    "legacy replay snapshot `{}` requires an explicit migration",
                    legacy_path.display()
                ),
            }
            .fail();
        }
        let path = state_directory.join("authorization-replay-v1.jsonl");
        if !path.exists() {
            return Ok(Self {
                path,
                ..Self::default()
            });
        }
        let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return AuthorizationSnafu {
                reason: "replay WAL ends with a torn record".to_owned(),
            }
            .fail();
        }
        let mut ledger = Self {
            path,
            ..Self::default()
        };
        let records = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        for line in records.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                return AuthorizationSnafu {
                    reason: "replay WAL contains an empty record".to_owned(),
                }
                .fail();
            }
            let record: ReplayRecordV1 =
                serde_json::from_slice(line).context(JsonSnafu { path: &ledger.path })?;
            ledger.apply_record(record)?;
        }
        Ok(ledger)
    }

    pub(super) fn accept(&mut self, proof: AcceptedProof<'_>) -> Result<()> {
        self.ensure_healthy()?;
        self.validate_accept(&proof)?;
        let mut next_window = self.windows.get(&proof.key).cloned().unwrap_or_default();
        next_window.accept(proof.sequence)?;
        let record = ReplayRecordV1::Accept {
            schema_version: 1,
            trust_domain_id: proof.key.trust_domain_id.into(),
            issuer_id: proof.key.issuer_id.into(),
            key_id: proof.key.key_id.clone(),
            sequence_epoch: proof.key.sequence_epoch,
            sequence: proof.sequence,
            proof_id: proof.proof_id.into(),
            claim_slot_ids: proof
                .claim_slot_ids
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
            expires_at_utc_ns: proof.expires_at_utc_ns,
            body_sha256: proof.body_sha256,
        };
        self.append(&record)?;
        self.install_accept(proof, next_window);
        Ok(())
    }

    pub(super) fn arm(
        &mut self,
        proof_id: Id128V1,
        slot_id: Id128V1,
        body_sha256: [u8; 32],
        slot_intent_sha256: [u8; 32],
    ) -> Result<()> {
        self.ensure_healthy()?;
        let slot = self.slots.get(&slot_id).ok_or_else(|| {
            AuthorizationSnafu {
                reason: "claim slot was not prepared".to_owned(),
            }
            .build()
        })?;
        ensure_slot_matches(slot, proof_id, body_sha256)?;
        match slot.state {
            SlotState::Armed { intent_sha256 } if intent_sha256 == slot_intent_sha256 => {
                return Ok(())
            }
            SlotState::Prepared => {}
            _ => {
                return AuthorizationSnafu {
                    reason: "claim slot is already armed differently or consumed".to_owned(),
                }
                .fail()
            }
        }
        if slot_intent_sha256 == [0; 32] {
            return AuthorizationSnafu {
                reason: "claim slot intent digest is zero".to_owned(),
            }
            .fail();
        }
        self.append(&ReplayRecordV1::Arm {
            schema_version: 1,
            proof_id: proof_id.into(),
            claim_slot_id: slot_id.into(),
            slot_intent_sha256,
        })?;
        if let Some(slot) = self.slots.get_mut(&slot_id) {
            slot.state = SlotState::Armed {
                intent_sha256: slot_intent_sha256,
            };
        }
        Ok(())
    }

    pub(super) fn consume(&mut self, proof_id: Id128V1, slot_id: Id128V1) -> Result<()> {
        self.ensure_healthy()?;
        let slot = self.slots.get(&slot_id).ok_or_else(|| {
            AuthorizationSnafu {
                reason: "claim slot was not prepared".to_owned(),
            }
            .build()
        })?;
        if slot.proof_id != proof_id || !matches!(slot.state, SlotState::Armed { .. }) {
            return AuthorizationSnafu {
                reason: "claim slot does not belong to this proof, is unarmed, or was consumed"
                    .to_owned(),
            }
            .fail();
        }
        if self.proofs.get(&proof_id) != Some(&slot.expires_at_utc_ns) {
            return AuthorizationSnafu {
                reason: "claim slot has an inconsistent proof expiry".to_owned(),
            }
            .fail();
        }
        self.append(&ReplayRecordV1::Consume {
            schema_version: 1,
            proof_id: proof_id.into(),
            claim_slot_id: slot_id.into(),
        })?;
        if let Some(slot) = self.slots.get_mut(&slot_id) {
            slot.state = SlotState::Consumed;
        }
        Ok(())
    }

    pub(super) fn reconcile_consumed(
        &mut self,
        proof_id: Id128V1,
        slot_id: Id128V1,
        slot_intent_sha256: [u8; 32],
    ) -> Result<()> {
        let slot = self.slots.get(&slot_id).ok_or_else(|| {
            AuthorizationSnafu {
                reason: "kernel consumed an unknown claim slot".to_owned(),
            }
            .build()
        })?;
        if slot.proof_id != proof_id {
            return AuthorizationSnafu {
                reason: "kernel-consumed claim slot belongs to another proof".to_owned(),
            }
            .fail();
        }
        match slot.state {
            SlotState::Armed { intent_sha256 } if intent_sha256 == slot_intent_sha256 => {
                self.consume(proof_id, slot_id)
            }
            SlotState::Consumed => Ok(()),
            _ => AuthorizationSnafu {
                reason: "kernel-consumed claim slot differs from its durable intent".to_owned(),
            }
            .fail(),
        }
    }

    pub(super) fn armed_intent(&self, slot_id: Id128V1) -> Option<[u8; 32]> {
        match self.slots.get(&slot_id)?.state {
            SlotState::Armed { intent_sha256 } => Some(intent_sha256),
            _ => None,
        }
    }

    pub(super) fn armed_slots(&self) -> Vec<Id128V1> {
        self.slots
            .iter()
            .filter_map(|(slot_id, slot)| {
                matches!(slot.state, SlotState::Armed { .. }).then_some(*slot_id)
            })
            .collect()
    }

    pub(super) fn close(
        &mut self,
        proof_id: Id128V1,
        slot_id: Id128V1,
        slot_intent_sha256: [u8; 32],
    ) -> Result<()> {
        self.ensure_healthy()?;
        let slot = self.slots.get(&slot_id).ok_or_else(|| {
            AuthorizationSnafu {
                reason: "kernel closed an unknown claim slot".to_owned(),
            }
            .build()
        })?;
        match slot.state {
            SlotState::Armed { intent_sha256 }
                if slot.proof_id == proof_id && intent_sha256 == slot_intent_sha256 => {}
            SlotState::Closed { intent_sha256 }
                if slot.proof_id == proof_id && intent_sha256 == slot_intent_sha256 =>
            {
                return Ok(())
            }
            _ => {
                return AuthorizationSnafu {
                    reason: "closed claim slot differs from its durable intent".to_owned(),
                }
                .fail()
            }
        }
        self.append(&ReplayRecordV1::Close {
            schema_version: 1,
            proof_id: proof_id.into(),
            claim_slot_id: slot_id.into(),
        })?;
        if let Some(slot) = self.slots.get_mut(&slot_id) {
            slot.state = SlotState::Closed {
                intent_sha256: slot_intent_sha256,
            };
        }
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned {
            AuthorizationSnafu {
                reason: "replay ledger is closed after a persistence failure".to_owned(),
            }
            .fail()
        } else {
            Ok(())
        }
    }

    fn append(&mut self, record: &ReplayRecordV1) -> Result<()> {
        let new_file = !self.path.exists();
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .context(IoSnafu { path: &self.path })?;
            serde_json::to_writer(&mut file, record).context(JsonSnafu { path: &self.path })?;
            file.write_all(b"\n")
                .context(IoSnafu { path: &self.path })?;
            file.sync_all().context(IoSnafu { path: &self.path })?;
            if new_file {
                let parent = self.path.parent().ok_or_else(|| {
                    AuthorizationSnafu {
                        reason: "replay ledger path has no parent directory".to_owned(),
                    }
                    .build()
                })?;
                File::open(parent)
                    .context(IoSnafu { path: parent })?
                    .sync_all()
                    .context(IoSnafu { path: parent })?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn apply_record(&mut self, record: ReplayRecordV1) -> Result<()> {
        match record {
            ReplayRecordV1::Accept {
                schema_version,
                trust_domain_id,
                issuer_id,
                key_id,
                sequence_epoch,
                sequence,
                proof_id,
                claim_slot_ids,
                expires_at_utc_ns,
                body_sha256,
            } => {
                if schema_version != 1
                    || trust_domain_id.is_zero()
                    || issuer_id.is_zero()
                    || !(1..=128).contains(&key_id.len())
                    || sequence_epoch == 0
                    || sequence == 0
                    || proof_id.is_zero()
                    || claim_slot_ids.is_empty()
                    || claim_slot_ids.iter().any(StoredId::is_zero)
                    || body_sha256 == [0; 32]
                {
                    return AuthorizationSnafu {
                        reason: "replay WAL has an invalid accept record".to_owned(),
                    }
                    .fail();
                }
                let key = ReplayKey {
                    trust_domain_id: trust_domain_id.into(),
                    issuer_id: issuer_id.into(),
                    key_id,
                    sequence_epoch,
                };
                let slots: Vec<Id128V1> = claim_slot_ids.into_iter().map(Into::into).collect();
                let accepted = AcceptedProof {
                    key: key.clone(),
                    sequence,
                    proof_id: proof_id.into(),
                    claim_slot_ids: &slots,
                    expires_at_utc_ns,
                    body_sha256,
                };
                self.validate_accept(&accepted)?;
                let mut next_window = self.windows.get(&key).cloned().unwrap_or_default();
                next_window.accept(sequence)?;
                self.install_accept(accepted, next_window);
                Ok(())
            }
            ReplayRecordV1::Arm {
                schema_version,
                proof_id,
                claim_slot_id,
                slot_intent_sha256,
            } => {
                if schema_version != 1
                    || proof_id.is_zero()
                    || claim_slot_id.is_zero()
                    || slot_intent_sha256 == [0; 32]
                {
                    return AuthorizationSnafu {
                        reason: "replay WAL has an invalid arm record".to_owned(),
                    }
                    .fail();
                }
                let proof_id = proof_id.into();
                let slot_id = claim_slot_id.into();
                let slot = self.slots.get_mut(&slot_id).ok_or_else(|| {
                    AuthorizationSnafu {
                        reason: "replay WAL arms an unknown claim slot".to_owned(),
                    }
                    .build()
                })?;
                if slot.proof_id != proof_id || slot.state != SlotState::Prepared {
                    return AuthorizationSnafu {
                        reason: "replay WAL repeats or mismatches a slot arm".to_owned(),
                    }
                    .fail();
                }
                slot.state = SlotState::Armed {
                    intent_sha256: slot_intent_sha256,
                };
                Ok(())
            }
            ReplayRecordV1::Consume {
                schema_version,
                proof_id,
                claim_slot_id,
            } => {
                if schema_version != 1 || proof_id.is_zero() || claim_slot_id.is_zero() {
                    return AuthorizationSnafu {
                        reason: "replay WAL has an invalid consume record".to_owned(),
                    }
                    .fail();
                }
                let proof_id = proof_id.into();
                let slot_id = claim_slot_id.into();
                let slot = self.slots.get_mut(&slot_id).ok_or_else(|| {
                    AuthorizationSnafu {
                        reason: "replay WAL consumes an unknown claim slot".to_owned(),
                    }
                    .build()
                })?;
                if slot.proof_id != proof_id || !matches!(slot.state, SlotState::Armed { .. }) {
                    return AuthorizationSnafu {
                        reason: "replay WAL repeats or mismatches a slot consumption".to_owned(),
                    }
                    .fail();
                }
                slot.state = SlotState::Consumed;
                Ok(())
            }
            ReplayRecordV1::Close {
                schema_version,
                proof_id,
                claim_slot_id,
            } => {
                if schema_version != 1 || proof_id.is_zero() || claim_slot_id.is_zero() {
                    return AuthorizationSnafu {
                        reason: "replay WAL has an invalid close record".to_owned(),
                    }
                    .fail();
                }
                let proof_id = proof_id.into();
                let slot_id = claim_slot_id.into();
                let slot = self.slots.get_mut(&slot_id).ok_or_else(|| {
                    AuthorizationSnafu {
                        reason: "replay WAL closes an unknown claim slot".to_owned(),
                    }
                    .build()
                })?;
                let SlotState::Armed { intent_sha256 } = slot.state else {
                    return AuthorizationSnafu {
                        reason: "replay WAL repeats or mismatches a slot close".to_owned(),
                    }
                    .fail();
                };
                if slot.proof_id != proof_id {
                    return AuthorizationSnafu {
                        reason: "replay WAL repeats or mismatches a slot close".to_owned(),
                    }
                    .fail();
                }
                slot.state = SlotState::Closed { intent_sha256 };
                Ok(())
            }
        }
    }

    fn validate_accept(&self, proof: &AcceptedProof<'_>) -> Result<()> {
        if proof.key.trust_domain_id.is_zero()
            || proof.key.issuer_id.is_zero()
            || !(1..=128).contains(&proof.key.key_id.len())
            || proof.key.sequence_epoch == 0
            || proof.sequence == 0
            || proof.proof_id.is_zero()
            || proof.claim_slot_ids.is_empty()
            || proof.claim_slot_ids.iter().any(|slot| slot.is_zero())
            || proof.body_sha256 == [0; 32]
            || proof
                .claim_slot_ids
                .iter()
                .enumerate()
                .any(|(index, slot)| proof.claim_slot_ids[..index].contains(slot))
            || self.proofs.contains_key(&proof.proof_id)
            || proof
                .claim_slot_ids
                .iter()
                .any(|slot| self.slots.contains_key(slot))
            || (!self.windows.contains_key(&proof.key) && self.windows.len() == MAX_REPLAY_WINDOWS)
            || self.proofs.len() == MAX_PROOF_TOMBSTONES
            || self
                .slots
                .len()
                .checked_add(proof.claim_slot_ids.len())
                .is_none_or(|length| length > MAX_SLOT_TOMBSTONES)
        {
            return AuthorizationSnafu {
                reason: "replay WAL repeats identity or exceeds bounded capacity".to_owned(),
            }
            .fail();
        }
        if self.windows.keys().any(|key| {
            key.trust_domain_id == proof.key.trust_domain_id
                && key.issuer_id == proof.key.issuer_id
                && key.sequence_epoch == proof.key.sequence_epoch
                && key.key_id != proof.key.key_id
        }) {
            return AuthorizationSnafu {
                reason: "signing-key rotation requires a new sequence epoch".to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    fn install_accept(&mut self, proof: AcceptedProof<'_>, next_window: ReplayWindow) {
        self.windows.insert(proof.key, next_window);
        self.proofs.insert(proof.proof_id, proof.expires_at_utc_ns);
        for slot in proof.claim_slot_ids {
            self.slots.insert(
                *slot,
                SlotRecord {
                    proof_id: proof.proof_id,
                    expires_at_utc_ns: proof.expires_at_utc_ns,
                    body_sha256: proof.body_sha256,
                    state: SlotState::Prepared,
                },
            );
        }
    }
}

fn ensure_slot_matches(slot: &SlotRecord, proof_id: Id128V1, body_sha256: [u8; 32]) -> Result<()> {
    if slot.proof_id != proof_id || slot.body_sha256 != body_sha256 {
        return AuthorizationSnafu {
            reason: "claim slot differs from its signed proof or body".to_owned(),
        }
        .fail();
    }
    Ok(())
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest_sequence: 0,
            seen: [0; REPLAY_WINDOW_WORDS],
        }
    }
}

impl ReplayWindow {
    fn accept(&mut self, sequence: u64) -> Result<()> {
        if sequence == 0 {
            return AuthorizationSnafu {
                reason: "issuer sequence must be nonzero".to_owned(),
            }
            .fail();
        }
        if self.highest_sequence == 0 {
            self.highest_sequence = sequence;
            self.seen[0] = 1;
            return Ok(());
        }
        if sequence > self.highest_sequence {
            let shift = sequence - self.highest_sequence;
            let previous = self.seen;
            self.seen.fill(0);
            if shift < REPLAY_WINDOW_BITS as u64 {
                for distance in 0..REPLAY_WINDOW_BITS - shift as usize {
                    if bit_is_set(&previous, distance) {
                        set_bit(&mut self.seen, distance + shift as usize);
                    }
                }
            }
            self.highest_sequence = sequence;
            set_bit(&mut self.seen, 0);
            return Ok(());
        }
        let distance = (self.highest_sequence - sequence) as usize;
        if distance >= REPLAY_WINDOW_BITS || bit_is_set(&self.seen, distance) {
            return AuthorizationSnafu {
                reason: "issuer sequence is outside the replay window or already used".to_owned(),
            }
            .fail();
        }
        set_bit(&mut self.seen, distance);
        Ok(())
    }
}

fn bit_is_set(bits: &[u64; REPLAY_WINDOW_WORDS], distance: usize) -> bool {
    bits[distance / u64::BITS as usize] & (1_u64 << (distance % u64::BITS as usize)) != 0
}

fn set_bit(bits: &mut [u64; REPLAY_WINDOW_WORDS], distance: usize) {
    bits[distance / u64::BITS as usize] |= 1_u64 << (distance % u64::BITS as usize);
}

impl From<StoredId> for Id128V1 {
    fn from(value: StoredId) -> Self {
        Self::new(value.high, value.low)
    }
}

impl From<Id128V1> for StoredId {
    fn from(value: Id128V1) -> Self {
        Self {
            high: value.high,
            low: value.low,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use erebor_interceptor_abi::Id128V1;

    use super::{AcceptedProof, ReplayKey, ReplayLedger, ReplayWindow};

    #[test]
    fn window_accepts_out_of_order_once_and_rejects_replay() -> crate::Result<()> {
        let mut window = ReplayWindow::default();
        window.accept(5)?;
        window.accept(3)?;
        assert!(window.accept(3).is_err());
        window.accept(4_100)?;
        assert!(window.accept(1).is_err());
        Ok(())
    }

    #[test]
    fn persisted_window_rejects_key_change_without_new_epoch() -> crate::Result<()> {
        let state = tempfile::tempdir().map_err(|error| crate::Error::Authorization {
            reason: format!("create replay test directory: {error}"),
            location: snafu::Location::default(),
        })?;
        let trust_domain_id = Id128V1::new(1, 1);
        let issuer_id = Id128V1::new(2, 2);
        let mut ledger = ReplayLedger::load(state.path())?;
        ledger.accept(AcceptedProof {
            key: ReplayKey {
                trust_domain_id,
                issuer_id,
                key_id: b"first".to_vec(),
                sequence_epoch: 3,
            },
            sequence: 1,
            proof_id: Id128V1::new(3, 1),
            claim_slot_ids: &[Id128V1::new(4, 1)],
            expires_at_utc_ns: 100,
            body_sha256: [1; 32],
        })?;

        let mut restarted = ReplayLedger::load(state.path())?;
        assert!(restarted
            .accept(AcceptedProof {
                key: ReplayKey {
                    trust_domain_id,
                    issuer_id,
                    key_id: b"second".to_vec(),
                    sequence_epoch: 3,
                },
                sequence: 2,
                proof_id: Id128V1::new(3, 2),
                claim_slot_ids: &[Id128V1::new(4, 2)],
                expires_at_utc_ns: 100,
                body_sha256: [2; 32],
            })
            .is_err());
        Ok(())
    }

    #[test]
    fn durable_wal_is_append_only_and_torn_records_fail_closed() -> crate::Result<()> {
        let state = tempfile::tempdir().map_err(|error| crate::Error::Authorization {
            reason: format!("create replay test directory: {error}"),
            location: snafu::Location::default(),
        })?;
        let mut ledger = ReplayLedger::load(state.path())?;
        let proof_id = Id128V1::new(3, 1);
        let slot_id = Id128V1::new(4, 1);
        ledger.accept(AcceptedProof {
            key: ReplayKey {
                trust_domain_id: Id128V1::new(1, 1),
                issuer_id: Id128V1::new(2, 2),
                key_id: b"key".to_vec(),
                sequence_epoch: 3,
            },
            sequence: 1,
            proof_id,
            claim_slot_ids: &[slot_id],
            expires_at_utc_ns: 100,
            body_sha256: [3; 32],
        })?;
        ledger.arm(proof_id, slot_id, [3; 32], [4; 32])?;
        ledger.consume(proof_id, slot_id)?;
        let path = state.path().join("authorization-replay-v1.jsonl");
        let wal = fs::read_to_string(&path).map_err(|error| crate::Error::Authorization {
            reason: format!("read replay WAL: {error}"),
            location: snafu::Location::default(),
        })?;
        assert_eq!(wal.lines().count(), 3);
        fs::write(&path, wal.trim_end()).map_err(|error| crate::Error::Authorization {
            reason: format!("tear replay WAL: {error}"),
            location: snafu::Location::default(),
        })?;
        assert!(ReplayLedger::load(state.path()).is_err());
        Ok(())
    }

    #[test]
    fn durable_close_reconciles_idempotently_after_restart() -> crate::Result<()> {
        let state = tempfile::tempdir().map_err(|error| crate::Error::Authorization {
            reason: format!("create replay test directory: {error}"),
            location: snafu::Location::default(),
        })?;
        let proof_id = Id128V1::new(3, 1);
        let slot_id = Id128V1::new(4, 1);
        let intent = [4; 32];
        let mut ledger = ReplayLedger::load(state.path())?;
        ledger.accept(AcceptedProof {
            key: ReplayKey {
                trust_domain_id: Id128V1::new(1, 1),
                issuer_id: Id128V1::new(2, 2),
                key_id: b"key".to_vec(),
                sequence_epoch: 3,
            },
            sequence: 1,
            proof_id,
            claim_slot_ids: &[slot_id],
            expires_at_utc_ns: 100,
            body_sha256: [3; 32],
        })?;
        ledger.arm(proof_id, slot_id, [3; 32], intent)?;
        ledger.close(proof_id, slot_id, intent)?;

        let mut restarted = ReplayLedger::load(state.path())?;
        restarted.close(proof_id, slot_id, intent)?;
        assert!(restarted.close(proof_id, slot_id, [5; 32]).is_err());
        Ok(())
    }
}
