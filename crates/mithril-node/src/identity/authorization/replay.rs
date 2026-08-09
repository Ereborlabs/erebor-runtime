use std::collections::BTreeMap;
use std::fs::{self, File};
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
    Consumed,
}

#[derive(Clone, Copy, Debug)]
struct SlotRecord {
    proof_id: Id128V1,
    expires_at_utc_ns: i64,
    state: SlotState,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplaySnapshotV1 {
    schema_version: u32,
    windows: Vec<StoredWindow>,
    proofs: Vec<StoredTombstone>,
    slots: Vec<StoredSlot>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredWindow {
    trust_domain_id: StoredId,
    issuer_id: StoredId,
    key_id: Vec<u8>,
    sequence_epoch: u64,
    highest_sequence: u64,
    seen: Vec<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredTombstone {
    id: StoredId,
    expires_at_utc_ns: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSlot {
    id: StoredId,
    proof_id: StoredId,
    expires_at_utc_ns: i64,
    consumed: bool,
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
        let path = state_directory.join("authorization-replay-v1.json");
        if !path.exists() {
            return Ok(Self {
                path,
                ..Self::default()
            });
        }
        let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
        let stored: ReplaySnapshotV1 =
            serde_json::from_slice(&bytes).context(JsonSnafu { path: &path })?;
        if stored.schema_version != 1 {
            return AuthorizationSnafu {
                reason: format!(
                    "replay snapshot schema is {}, expected 1",
                    stored.schema_version
                ),
            }
            .fail();
        }
        if stored.windows.len() > MAX_REPLAY_WINDOWS
            || stored.proofs.len() > MAX_PROOF_TOMBSTONES
            || stored.slots.len() > MAX_SLOT_TOMBSTONES
        {
            return AuthorizationSnafu {
                reason: "replay snapshot exceeds its bounded capacities".to_owned(),
            }
            .fail();
        }
        let mut ledger = Self {
            path,
            ..Self::default()
        };
        for window in stored.windows {
            if window.trust_domain_id.is_zero()
                || window.issuer_id.is_zero()
                || window.key_id.is_empty()
                || window.key_id.len() > 128
                || window.sequence_epoch == 0
                || window.highest_sequence == 0
                || window.seen.len() != REPLAY_WINDOW_WORDS
                || window.seen.first().is_none_or(|word| word & 1 == 0)
            {
                return AuthorizationSnafu {
                    reason: "replay snapshot has an invalid sequence window".to_owned(),
                }
                .fail();
            }
            let mut seen = [0_u64; REPLAY_WINDOW_WORDS];
            seen.copy_from_slice(&window.seen);
            let key = ReplayKey {
                trust_domain_id: window.trust_domain_id.into(),
                issuer_id: window.issuer_id.into(),
                key_id: window.key_id,
                sequence_epoch: window.sequence_epoch,
            };
            if ledger
                .windows
                .insert(
                    key,
                    ReplayWindow {
                        highest_sequence: window.highest_sequence,
                        seen,
                    },
                )
                .is_some()
            {
                return AuthorizationSnafu {
                    reason: "replay snapshot repeats a sequence window".to_owned(),
                }
                .fail();
            }
        }
        for proof in stored.proofs {
            if proof.id.is_zero() {
                return AuthorizationSnafu {
                    reason: "replay snapshot has a zero proof ID".to_owned(),
                }
                .fail();
            }
            if ledger
                .proofs
                .insert(proof.id.into(), proof.expires_at_utc_ns)
                .is_some()
            {
                return AuthorizationSnafu {
                    reason: "replay snapshot repeats a proof tombstone".to_owned(),
                }
                .fail();
            }
        }
        for slot in stored.slots {
            if slot.id.is_zero() || slot.proof_id.is_zero() {
                return AuthorizationSnafu {
                    reason: "replay snapshot has a zero slot or proof ID".to_owned(),
                }
                .fail();
            }
            if ledger
                .slots
                .insert(
                    slot.id.into(),
                    SlotRecord {
                        proof_id: slot.proof_id.into(),
                        expires_at_utc_ns: slot.expires_at_utc_ns,
                        state: if slot.consumed {
                            SlotState::Consumed
                        } else {
                            SlotState::Prepared
                        },
                    },
                )
                .is_some()
            {
                return AuthorizationSnafu {
                    reason: "replay snapshot repeats a claim-slot tombstone".to_owned(),
                }
                .fail();
            }
        }
        if ledger.slots.values().any(|slot| {
            ledger
                .proofs
                .get(&slot.proof_id)
                .is_none_or(|expiry| *expiry != slot.expires_at_utc_ns)
        }) {
            return AuthorizationSnafu {
                reason: "replay snapshot has an orphaned or inconsistent slot".to_owned(),
            }
            .fail();
        }
        Ok(ledger)
    }

    pub(super) fn accept(&mut self, proof: AcceptedProof<'_>) -> Result<()> {
        self.ensure_healthy()?;
        if self.proofs.contains_key(&proof.proof_id) {
            return AuthorizationSnafu {
                reason: "proof ID was already accepted".to_owned(),
            }
            .fail();
        }
        if proof
            .claim_slot_ids
            .iter()
            .any(|slot| self.slots.contains_key(slot))
        {
            return AuthorizationSnafu {
                reason: "claim-slot ID was already prepared or consumed".to_owned(),
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
        if (!self.windows.contains_key(&proof.key) && self.windows.len() == MAX_REPLAY_WINDOWS)
            || self.proofs.len() == MAX_PROOF_TOMBSTONES
            || self
                .slots
                .len()
                .checked_add(proof.claim_slot_ids.len())
                .is_none_or(|length| length > MAX_SLOT_TOMBSTONES)
        {
            return AuthorizationSnafu {
                reason: "replay state reached its bounded capacity".to_owned(),
            }
            .fail();
        }
        self.windows
            .entry(proof.key)
            .or_default()
            .accept(proof.sequence)?;
        self.proofs.insert(proof.proof_id, proof.expires_at_utc_ns);
        for slot in proof.claim_slot_ids {
            self.slots.insert(
                *slot,
                SlotRecord {
                    proof_id: proof.proof_id,
                    expires_at_utc_ns: proof.expires_at_utc_ns,
                    state: SlotState::Prepared,
                },
            );
        }
        self.persist()
    }

    pub(super) fn consume(&mut self, proof_id: Id128V1, slot_id: Id128V1) -> Result<()> {
        self.ensure_healthy()?;
        let slot = self.slots.get_mut(&slot_id).ok_or_else(|| {
            AuthorizationSnafu {
                reason: "claim slot was not prepared".to_owned(),
            }
            .build()
        })?;
        if slot.proof_id != proof_id || slot.state != SlotState::Prepared {
            return AuthorizationSnafu {
                reason: "claim slot does not belong to this proof or was already consumed"
                    .to_owned(),
            }
            .fail();
        }
        slot.state = SlotState::Consumed;
        self.persist()
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

    fn persist(&mut self) -> Result<()> {
        let snapshot = self.snapshot();
        let bytes = serde_json::to_vec(&snapshot).context(JsonSnafu { path: &self.path })?;
        let temporary = self.path.with_extension("json.tmp");
        let result = (|| -> Result<()> {
            fs::write(&temporary, bytes).context(IoSnafu { path: &temporary })?;
            File::open(&temporary)
                .context(IoSnafu { path: &temporary })?
                .sync_all()
                .context(IoSnafu { path: &temporary })?;
            fs::rename(&temporary, &self.path).context(IoSnafu { path: &self.path })?;
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
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn snapshot(&self) -> ReplaySnapshotV1 {
        ReplaySnapshotV1 {
            schema_version: 1,
            windows: self
                .windows
                .iter()
                .map(|(key, value)| StoredWindow {
                    trust_domain_id: key.trust_domain_id.into(),
                    issuer_id: key.issuer_id.into(),
                    key_id: key.key_id.clone(),
                    sequence_epoch: key.sequence_epoch,
                    highest_sequence: value.highest_sequence,
                    seen: value.seen.to_vec(),
                })
                .collect(),
            proofs: self
                .proofs
                .iter()
                .map(|(id, expires_at_utc_ns)| StoredTombstone {
                    id: (*id).into(),
                    expires_at_utc_ns: *expires_at_utc_ns,
                })
                .collect(),
            slots: self
                .slots
                .iter()
                .map(|(id, slot)| StoredSlot {
                    id: (*id).into(),
                    proof_id: slot.proof_id.into(),
                    expires_at_utc_ns: slot.expires_at_utc_ns,
                    consumed: slot.state == SlotState::Consumed,
                })
                .collect(),
        }
    }
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
            })
            .is_err());
        Ok(())
    }
}
