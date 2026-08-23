use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::{KernelHost, MapInsertResult, EXCEPTION_USE_RECEIPT_CAPACITY};
use erebor_interceptor_abi::{
    ExceptionReceiptStateV1, ExceptionRuntimeStateKeyV1, ExceptionRuntimeStateKindV1,
    ExceptionRuntimeStateV1, ExceptionUseIdentityKindV1, ExceptionUseReceiptKeyV1,
    ExceptionUseReceiptV1, Id128V1, KernelEffectFamilyV1, KernelEffectOperationV1,
};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;
use zerocopy::{IntoBytes as _, TryFromBytes as _};

use crate::error::{IdentityStateSnafu, InterceptorSnafu, IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredIdV1 {
    high: u64,
    low: u64,
}

impl From<Id128V1> for StoredIdV1 {
    fn from(value: Id128V1) -> Self {
        Self {
            high: value.high,
            low: value.low,
        }
    }
}

impl From<StoredIdV1> for Id128V1 {
    fn from(value: StoredIdV1) -> Self {
        Self::new(value.high, value.low)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredStateV1 {
    runtime_state_key_hex: String,
    node_boot_id: StoredIdV1,
    maximum_uses: u32,
    consumed_uses: u32,
    bound_profile_generation_refs: u32,
    deadline_utc_ns: i64,
    deadline_boottime_ns: u64,
    transition_version: u64,
    exception_definition_sha256_hex: String,
    state: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredReceiptV1 {
    key_hex: String,
    value_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExceptionAuthorityRecordV1 {
    schema_version: u32,
    node_id: StoredIdV1,
    state: StoredStateV1,
    receipts: Vec<StoredReceiptV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableStateV1 {
    runtime_state_key: ExceptionRuntimeStateKeyV1,
    node_boot_id: Id128V1,
    maximum_uses: u32,
    consumed_uses: u32,
    bound_profile_generation_refs: u32,
    deadline_utc_ns: i64,
    deadline_boottime_ns: u64,
    transition_version: u64,
    exception_definition_sha256: [u8; 32],
    state: ExceptionRuntimeStateKindV1,
}

pub(super) struct ExceptionAuthorityOwner {
    path: PathBuf,
    node_id: Id128V1,
    node_boot_id: Id128V1,
    states: BTreeMap<Vec<u8>, DurableStateV1>,
    receipts: BTreeMap<Vec<u8>, Vec<u8>>,
    poisoned: bool,
}

impl ExceptionAuthorityOwner {
    pub(super) const fn node_id(&self) -> Id128V1 {
        self.node_id
    }

    pub(super) fn load(
        state_directory: &Path,
        node_id: Id128V1,
        node_boot_id: Id128V1,
    ) -> Result<Self> {
        if node_id.is_zero() || node_boot_id.is_zero() {
            return IdentityStateSnafu {
                reason: "exception authority requires nonzero node identities".to_owned(),
            }
            .fail();
        }
        fs::create_dir_all(state_directory).context(IoSnafu {
            path: state_directory,
        })?;
        let path = state_directory.join("exception-authority-v1.jsonl");
        let mut owner = Self {
            path,
            node_id,
            node_boot_id,
            states: BTreeMap::new(),
            receipts: BTreeMap::new(),
            poisoned: false,
        };
        let bytes = match fs::read(&owner.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(owner),
            Err(source) => {
                return Err(crate::Error::Io {
                    path: owner.path,
                    source,
                    location: snafu::Location::default(),
                })
            }
        };
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return IdentityStateSnafu {
                reason: "exception authority WAL ends with a torn record".to_owned(),
            }
            .fail();
        }
        for line in bytes
            .strip_suffix(b"\n")
            .unwrap_or(&bytes)
            .split(|byte| *byte == b'\n')
        {
            if line.is_empty() {
                continue;
            }
            let record: ExceptionAuthorityRecordV1 =
                serde_json::from_slice(line).context(JsonSnafu { path: &owner.path })?;
            owner.apply(record)?;
        }
        Ok(owner)
    }

    pub(super) fn prepare_runtime(
        &mut self,
        key: &[u8],
        desired: ExceptionRuntimeStateV1,
        deadline_utc_ns: i64,
        live: Option<&[u8]>,
        now_utc_ns: i64,
        now_boottime_ns: u64,
    ) -> Result<ExceptionRuntimeStateV1> {
        self.ensure_healthy()?;
        let runtime_state_key = read_runtime_key(key)?;
        validate_runtime(&desired)?;
        if let Some(stored) = self.states.get(key).copied() {
            ensure_same_definition(stored, runtime_state_key, desired)?;
            if let Some(live) = live {
                if stored.node_boot_id != self.node_boot_id {
                    return IdentityStateSnafu {
                        reason: "an exception runtime map survived a node-boot identity change"
                            .to_owned(),
                    }
                    .fail();
                }
                let live = read_runtime(live, "live exception runtime state")?;
                ensure_same_definition(stored, runtime_state_key, live)?;
                self.observe_runtime(key, live, stored.deadline_utc_ns)?;
                return Ok(live);
            }

            let mut restored =
                runtime_from_durable(stored, self.node_boot_id, now_utc_ns, now_boottime_ns);
            if restored.state == ExceptionRuntimeStateKindV1::Active
                || restored.state == ExceptionRuntimeStateKindV1::ReconciliationRequired
            {
                restored.consumed_uses = restored.maximum_uses;
                restored.state = ExceptionRuntimeStateKindV1::Exhausted;
                restored.transition_version = restored.transition_version.saturating_add(1);
            }
            self.observe_runtime(key, restored, stored.deadline_utc_ns)?;
            return Ok(restored);
        }

        if live.is_some() {
            return IdentityStateSnafu {
                reason: "live exception authority has no durable predecessor".to_owned(),
            }
            .fail();
        }
        let reserved_uses = self.states.values().try_fold(0_u64, |total, state| {
            total.checked_add(u64::from(state.maximum_uses))
        });
        if reserved_uses
            .and_then(|uses| uses.checked_add(u64::from(desired.maximum_uses)))
            .is_none_or(|uses| uses > EXCEPTION_USE_RECEIPT_CAPACITY)
        {
            return IdentityStateSnafu {
                reason: "bounded exceptions exceed successful-receipt capacity".to_owned(),
            }
            .fail();
        }
        let state = DurableStateV1 {
            runtime_state_key,
            node_boot_id: self.node_boot_id,
            maximum_uses: desired.maximum_uses,
            consumed_uses: desired.consumed_uses,
            bound_profile_generation_refs: desired.bound_profile_generation_refs,
            deadline_utc_ns,
            deadline_boottime_ns: desired.deadline_boottime_ns,
            transition_version: desired.transition_version,
            exception_definition_sha256: desired.exception_definition_sha256,
            state: desired.state,
        };
        self.states.insert(key.to_vec(), state);
        self.append(key)?;
        Ok(desired)
    }

    pub(super) fn restore_receipts(&mut self, host: &KernelHost) -> Result<()> {
        let mut changed = BTreeSet::new();
        for (key, durable) in self.receipts.clone() {
            match host
                .lookup_map("exception_use_receipts", &key)
                .context(InterceptorSnafu)?
            {
                Some(live) => {
                    validate_receipt_transition(&durable, &live)?;
                    if live != durable {
                        self.receipts.insert(key.clone(), live);
                        changed.insert(key[..32].to_vec());
                    }
                }
                None => match host
                    .insert_map("exception_use_receipts", &key, &durable)
                    .context(InterceptorSnafu)?
                {
                    MapInsertResult::Inserted => {}
                    MapInsertResult::AlreadyExists => {
                        let live = host
                            .lookup_map("exception_use_receipts", &key)
                            .context(InterceptorSnafu)?
                            .ok_or_else(|| {
                                IdentityStateSnafu {
                                    reason:
                                        "concurrent exception receipt disappeared during restore"
                                            .to_owned(),
                                }
                                .build()
                            })?;
                        validate_receipt_transition(&durable, &live)?;
                        if live != durable {
                            self.receipts.insert(key.clone(), live);
                            changed.insert(key[..32].to_vec());
                        }
                    }
                },
            }
        }
        for key in changed {
            self.append(&key)?;
        }
        Ok(())
    }

    pub(super) fn reconcile(&mut self, host: &KernelHost, _now_utc_ns: i64) -> Result<()> {
        self.ensure_healthy()?;
        let mut changed = BTreeSet::new();
        for key in host
            .map_keys("exception_runtime_states")
            .context(InterceptorSnafu)?
        {
            let Some(bytes) = host
                .lookup_map_locked("exception_runtime_states", &key)
                .context(InterceptorSnafu)?
            else {
                continue;
            };
            let state = read_runtime(&bytes, "exception runtime state")?;
            let deadline_utc_ns = self
                .states
                .get(&key)
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "live exception authority has no durable predecessor".to_owned(),
                    }
                    .build()
                })?
                .deadline_utc_ns;
            if self.observe_runtime_in_memory(&key, state, deadline_utc_ns)? {
                changed.insert(key);
            }
        }
        for key in host
            .map_keys("exception_use_receipts")
            .context(InterceptorSnafu)?
        {
            let Some(value) = host
                .lookup_map("exception_use_receipts", &key)
                .context(InterceptorSnafu)?
            else {
                continue;
            };
            let receipt_key = read_receipt_key(&key)?;
            let receipt = read_receipt(&value)?;
            if let Some(old) = self.receipts.get(&key) {
                validate_receipt_transition(old, &value)?;
            }
            let runtime_key = receipt_key.runtime_state_key.as_bytes().to_vec();
            match receipt.state {
                ExceptionReceiptStateV1::Consumed => {
                    if self.receipts.get(&key) != Some(&value) {
                        self.receipts.insert(key, value);
                        changed.insert(runtime_key);
                    }
                }
                ExceptionReceiptStateV1::Claiming => {}
                ExceptionReceiptStateV1::DeniedExhausted
                | ExceptionReceiptStateV1::DeniedExpired
                | ExceptionReceiptStateV1::DeniedCorrupt
                | ExceptionReceiptStateV1::ReconciliationRequired => {
                    host.delete_map_entry("exception_use_receipts", &key)
                        .context(InterceptorSnafu)?;
                    if self.receipts.remove(&key).is_some() {
                        changed.insert(runtime_key);
                    }
                }
                ExceptionReceiptStateV1::Unknown => {
                    return IdentityStateSnafu {
                        reason: "exception receipt has an unknown state".to_owned(),
                    }
                    .fail()
                }
            }
        }
        for key in changed {
            self.append(&key)?;
        }
        Ok(())
    }

    fn observe_runtime(
        &mut self,
        key: &[u8],
        state: ExceptionRuntimeStateV1,
        deadline_utc_ns: i64,
    ) -> Result<()> {
        if self.observe_runtime_in_memory(key, state, deadline_utc_ns)? {
            self.append(key)?;
        }
        Ok(())
    }

    fn observe_runtime_in_memory(
        &mut self,
        key: &[u8],
        state: ExceptionRuntimeStateV1,
        deadline_utc_ns: i64,
    ) -> Result<bool> {
        validate_runtime(&state)?;
        let runtime_state_key = read_runtime_key(key)?;
        let next = DurableStateV1 {
            runtime_state_key,
            node_boot_id: self.node_boot_id,
            maximum_uses: state.maximum_uses,
            consumed_uses: state.consumed_uses,
            bound_profile_generation_refs: state.bound_profile_generation_refs,
            deadline_utc_ns,
            deadline_boottime_ns: state.deadline_boottime_ns,
            transition_version: state.transition_version,
            exception_definition_sha256: state.exception_definition_sha256,
            state: state.state,
        };
        if let Some(previous) = self.states.get(key).copied() {
            validate_state_transition(previous, next)?;
        }
        if self.states.get(key) == Some(&next) {
            return Ok(false);
        }
        self.states.insert(key.to_vec(), next);
        Ok(true)
    }

    fn apply(&mut self, record: ExceptionAuthorityRecordV1) -> Result<()> {
        if record.schema_version != 1 || Id128V1::from(record.node_id) != self.node_id {
            return IdentityStateSnafu {
                reason: "exception authority WAL has invalid node ownership".to_owned(),
            }
            .fail();
        }
        let state = decode_state(record.state)?;
        let key = state.runtime_state_key.as_bytes().to_vec();
        if let Some(previous) = self.states.get(&key).copied() {
            validate_state_transition(previous, state)?;
        }
        self.states.insert(key.clone(), state);
        for receipt in record.receipts {
            let receipt_key = hex::decode(receipt.key_hex).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("exception authority WAL receipt key is invalid: {error}"),
                }
                .build()
            })?;
            let value = hex::decode(receipt.value_hex).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("exception authority WAL receipt is invalid: {error}"),
                }
                .build()
            })?;
            let receipt_runtime_key = read_receipt_key(&receipt_key)?.runtime_state_key;
            if receipt_runtime_key != state.runtime_state_key {
                return IdentityStateSnafu {
                    reason: "exception authority WAL receipt belongs to another instance"
                        .to_owned(),
                }
                .fail();
            }
            if read_receipt(&value)?.state == ExceptionReceiptStateV1::Consumed {
                if let Some(old) = self.receipts.get(&receipt_key) {
                    validate_receipt_transition(old, &value)?;
                }
                self.receipts.insert(receipt_key, value);
            }
        }
        Ok(())
    }

    fn append(&mut self, key: &[u8]) -> Result<()> {
        self.ensure_healthy()?;
        let state = *self.states.get(key).ok_or_else(|| {
            IdentityStateSnafu {
                reason: "exception authority snapshot has no runtime state".to_owned(),
            }
            .build()
        })?;
        let record = ExceptionAuthorityRecordV1 {
            schema_version: 1,
            node_id: self.node_id.into(),
            state: encode_state(state),
            receipts: self
                .receipts
                .iter()
                .filter(|(receipt_key, _)| receipt_key.starts_with(key))
                .map(|(receipt_key, value)| StoredReceiptV1 {
                    key_hex: hex::encode(receipt_key),
                    value_hex: hex::encode(value),
                })
                .collect(),
        };
        let new_file = !self.path.exists();
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .context(IoSnafu { path: &self.path })?;
            serde_json::to_writer(&mut file, &record).context(JsonSnafu { path: &self.path })?;
            file.write_all(b"\n")
                .context(IoSnafu { path: &self.path })?;
            file.sync_all().context(IoSnafu { path: &self.path })?;
            if new_file {
                let parent = self.path.parent().ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "exception authority WAL path has no parent".to_owned(),
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

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned {
            return IdentityStateSnafu {
                reason: "exception authority WAL is poisoned".to_owned(),
            }
            .fail();
        }
        Ok(())
    }
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use std::fs;

    use erebor_interceptor::EXCEPTION_USE_RECEIPT_CAPACITY;
    use erebor_interceptor_abi::{
        ExceptionReceiptStateV1, ExceptionRuntimeStateKeyV1, ExceptionRuntimeStateKindV1,
        ExceptionRuntimeStateV1, ExceptionUseIdentityKindV1, ExceptionUseIdentityV1,
        ExceptionUseReceiptKeyV1, ExceptionUseReceiptV1, Id128V1,
    };
    use zerocopy::IntoBytes as _;

    use super::ExceptionAuthorityOwner;
    use crate::error::IdentityStateSnafu;

    const NODE: Id128V1 = Id128V1::new(1, 2);
    const BOOT_ONE: Id128V1 = Id128V1::new(3, 4);
    const BOOT_TWO: Id128V1 = Id128V1::new(5, 6);
    const NOW_UTC_NS: i64 = 1_000;
    const DEADLINE_UTC_NS: i64 = 10_000;
    const NOW_BOOTTIME_NS: u64 = 500;
    const DEADLINE_BOOTTIME_NS: u64 = 9_500;

    fn state_directory() -> crate::Result<tempfile::TempDir> {
        tempfile::tempdir().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("create exception authority test directory: {error}"),
            }
            .build()
        })
    }

    fn runtime_key() -> ExceptionRuntimeStateKeyV1 {
        ExceptionRuntimeStateKeyV1 {
            node_id: NODE,
            exception_instance_id: Id128V1::new(7, 8),
        }
    }

    fn runtime(consumed_uses: u32, state: ExceptionRuntimeStateKindV1) -> ExceptionRuntimeStateV1 {
        runtime_with_maximum(3, consumed_uses, state)
    }

    fn runtime_with_maximum(
        maximum_uses: u32,
        consumed_uses: u32,
        state: ExceptionRuntimeStateKindV1,
    ) -> ExceptionRuntimeStateV1 {
        ExceptionRuntimeStateV1 {
            lock: 0,
            maximum_uses,
            consumed_uses,
            bound_profile_generation_refs: 1,
            deadline_boottime_ns: DEADLINE_BOOTTIME_NS,
            transition_version: u64::from(consumed_uses) + 1,
            exception_definition_sha256: [9; 32],
            state,
            reserved: [0; 7],
        }
    }

    #[test]
    fn successful_use_capacity_is_reserved_before_activation() -> crate::Result<()> {
        let directory = state_directory()?;
        let first = runtime_key();
        let second = ExceptionRuntimeStateKeyV1 {
            node_id: NODE,
            exception_instance_id: Id128V1::new(9, 10),
        };
        let mut owner = ExceptionAuthorityOwner::load(directory.path(), NODE, BOOT_ONE)?;
        owner.prepare_runtime(
            first.as_bytes(),
            runtime_with_maximum(
                EXCEPTION_USE_RECEIPT_CAPACITY as u32,
                0,
                ExceptionRuntimeStateKindV1::Active,
            ),
            DEADLINE_UTC_NS,
            None,
            NOW_UTC_NS,
            NOW_BOOTTIME_NS,
        )?;
        assert!(owner
            .prepare_runtime(
                second.as_bytes(),
                runtime_with_maximum(1, 0, ExceptionRuntimeStateKindV1::Active),
                DEADLINE_UTC_NS,
                None,
                NOW_UTC_NS,
                NOW_BOOTTIME_NS,
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn daemon_restart_uses_the_pinned_count_without_refund() -> crate::Result<()> {
        let directory = state_directory()?;
        let key = runtime_key();
        let mut owner = ExceptionAuthorityOwner::load(directory.path(), NODE, BOOT_ONE)?;
        owner.prepare_runtime(
            key.as_bytes(),
            runtime(0, ExceptionRuntimeStateKindV1::Active),
            DEADLINE_UTC_NS,
            None,
            NOW_UTC_NS,
            NOW_BOOTTIME_NS,
        )?;
        owner.observe_runtime(
            key.as_bytes(),
            runtime(2, ExceptionRuntimeStateKindV1::Active),
            DEADLINE_UTC_NS,
        )?;
        drop(owner);

        let mut restarted = ExceptionAuthorityOwner::load(directory.path(), NODE, BOOT_ONE)?;
        let live = runtime(2, ExceptionRuntimeStateKindV1::Active);
        let restored = restarted.prepare_runtime(
            key.as_bytes(),
            runtime(0, ExceptionRuntimeStateKindV1::Active),
            DEADLINE_UTC_NS,
            Some(live.as_bytes()),
            NOW_UTC_NS,
            NOW_BOOTTIME_NS,
        )?;
        assert_eq!(restored.consumed_uses, 2);
        assert_eq!(restored.state, ExceptionRuntimeStateKindV1::Active);
        Ok(())
    }

    #[test]
    fn node_reboot_exhausts_an_unproven_remainder() -> crate::Result<()> {
        let directory = state_directory()?;
        let key = runtime_key();
        let mut owner = ExceptionAuthorityOwner::load(directory.path(), NODE, BOOT_ONE)?;
        owner.prepare_runtime(
            key.as_bytes(),
            runtime(0, ExceptionRuntimeStateKindV1::Active),
            DEADLINE_UTC_NS,
            None,
            NOW_UTC_NS,
            NOW_BOOTTIME_NS,
        )?;
        owner.observe_runtime(
            key.as_bytes(),
            runtime(1, ExceptionRuntimeStateKindV1::Active),
            DEADLINE_UTC_NS,
        )?;
        drop(owner);

        let mut rebooted = ExceptionAuthorityOwner::load(directory.path(), NODE, BOOT_TWO)?;
        let restored = rebooted.prepare_runtime(
            key.as_bytes(),
            runtime(0, ExceptionRuntimeStateKindV1::Active),
            DEADLINE_UTC_NS,
            None,
            NOW_UTC_NS + 100,
            NOW_BOOTTIME_NS,
        )?;
        assert_eq!(restored.consumed_uses, restored.maximum_uses);
        assert_eq!(restored.state, ExceptionRuntimeStateKindV1::Exhausted);
        Ok(())
    }

    #[test]
    fn maximum_use_transition_accepts_n_and_rejects_n_plus_one() -> crate::Result<()> {
        let directory = state_directory()?;
        let key = runtime_key();
        let mut owner = ExceptionAuthorityOwner::load(directory.path(), NODE, BOOT_ONE)?;
        owner.prepare_runtime(
            key.as_bytes(),
            runtime(0, ExceptionRuntimeStateKindV1::Active),
            DEADLINE_UTC_NS,
            None,
            NOW_UTC_NS,
            NOW_BOOTTIME_NS,
        )?;
        owner.observe_runtime(
            key.as_bytes(),
            runtime(3, ExceptionRuntimeStateKindV1::Exhausted),
            DEADLINE_UTC_NS,
        )?;
        assert!(owner
            .observe_runtime(
                key.as_bytes(),
                runtime(4, ExceptionRuntimeStateKindV1::Exhausted),
                DEADLINE_UTC_NS,
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn exhausted_instance_cannot_be_rewritten_as_unused_and_expired() -> crate::Result<()> {
        let directory = state_directory()?;
        let key = runtime_key();
        let mut owner = ExceptionAuthorityOwner::load(directory.path(), NODE, BOOT_ONE)?;
        owner.prepare_runtime(
            key.as_bytes(),
            runtime_with_maximum(2, 0, ExceptionRuntimeStateKindV1::Active),
            DEADLINE_UTC_NS,
            None,
            NOW_UTC_NS,
            NOW_BOOTTIME_NS,
        )?;
        owner.observe_runtime(
            key.as_bytes(),
            runtime_with_maximum(2, 2, ExceptionRuntimeStateKindV1::Exhausted),
            DEADLINE_UTC_NS,
        )?;
        let mut refunded = runtime_with_maximum(2, 0, ExceptionRuntimeStateKindV1::Expired);
        refunded.transition_version = 4;
        assert!(owner
            .observe_runtime(key.as_bytes(), refunded, DEADLINE_UTC_NS)
            .is_err());
        Ok(())
    }

    #[test]
    fn consumed_receipt_replay_is_idempotent_and_terminal() -> crate::Result<()> {
        let directory = state_directory()?;
        let key = runtime_key();
        let mut owner = ExceptionAuthorityOwner::load(directory.path(), NODE, BOOT_ONE)?;
        owner.prepare_runtime(
            key.as_bytes(),
            runtime(0, ExceptionRuntimeStateKindV1::Active),
            DEADLINE_UTC_NS,
            None,
            NOW_UTC_NS,
            NOW_BOOTTIME_NS,
        )?;
        let receipt_key = ExceptionUseReceiptKeyV1 {
            runtime_state_key: key,
            use_identity: ExceptionUseIdentityV1 {
                kind: ExceptionUseIdentityKindV1::ClaimSlot,
                claim_slot_id: Id128V1::new(10, 11),
                ..ExceptionUseIdentityV1::default()
            },
        };
        let claiming = ExceptionUseReceiptV1 {
            state: ExceptionReceiptStateV1::Claiming,
            claimed_boottime_ns: 600,
            transition_version: 1,
            ..ExceptionUseReceiptV1::default()
        };
        let consumed = ExceptionUseReceiptV1 {
            consumed_ordinal: 1,
            state: ExceptionReceiptStateV1::Consumed,
            claimed_boottime_ns: 600,
            transition_version: 2,
            ..ExceptionUseReceiptV1::default()
        };
        owner.receipts.insert(
            receipt_key.as_bytes().to_vec(),
            claiming.as_bytes().to_vec(),
        );
        super::validate_receipt_transition(claiming.as_bytes(), consumed.as_bytes())?;
        owner.receipts.insert(
            receipt_key.as_bytes().to_vec(),
            consumed.as_bytes().to_vec(),
        );
        super::validate_receipt_transition(consumed.as_bytes(), consumed.as_bytes())?;
        assert!(
            super::validate_receipt_transition(consumed.as_bytes(), claiming.as_bytes()).is_err()
        );
        owner.append(key.as_bytes())?;

        let restarted = ExceptionAuthorityOwner::load(directory.path(), NODE, BOOT_ONE)?;
        assert_eq!(
            restarted.receipts.get(receipt_key.as_bytes()),
            Some(&consumed.as_bytes().to_vec())
        );
        Ok(())
    }

    #[test]
    fn receipt_keys_accept_only_supported_exact_identities() -> crate::Result<()> {
        use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};

        let runtime_state_key = runtime_key();
        let claim = ExceptionUseReceiptKeyV1 {
            runtime_state_key,
            use_identity: ExceptionUseIdentityV1 {
                kind: ExceptionUseIdentityKindV1::ClaimSlot,
                claim_slot_id: Id128V1::new(10, 11),
                ..ExceptionUseIdentityV1::default()
            },
        };
        let open = ExceptionUseReceiptKeyV1 {
            runtime_state_key,
            use_identity: ExceptionUseIdentityV1 {
                kind: ExceptionUseIdentityKindV1::KernelEffectAttempt,
                task_cookie: 12,
                process_state_id: Id128V1::new(13, 14),
                syscall_entry_sequence: 15,
                effect_attempt_sequence: 16,
                effect_family: KernelEffectFamilyV1::File as u16,
                operation: KernelEffectOperationV1::OpenWrite as u16,
                ..ExceptionUseIdentityV1::default()
            },
        };

        assert_eq!(super::read_receipt_key(claim.as_bytes())?, claim);
        assert_eq!(super::read_receipt_key(open.as_bytes())?, open);
        for unsupported in [
            ExceptionUseReceiptKeyV1 {
                use_identity: ExceptionUseIdentityV1 {
                    effect_attempt_sequence: 0,
                    ..open.use_identity
                },
                ..open
            },
            ExceptionUseReceiptKeyV1 {
                use_identity: ExceptionUseIdentityV1 {
                    operation: KernelEffectOperationV1::Read as u16,
                    ..open.use_identity
                },
                ..open
            },
            ExceptionUseReceiptKeyV1 {
                use_identity: ExceptionUseIdentityV1 {
                    claim_slot_id: Id128V1::new(17, 18),
                    ..open.use_identity
                },
                ..open
            },
        ] {
            assert!(super::read_receipt_key(unsupported.as_bytes()).is_err());
        }
        Ok(())
    }

    #[test]
    fn torn_wal_record_fails_closed() -> crate::Result<()> {
        let directory = state_directory()?;
        let key = runtime_key();
        let mut owner = ExceptionAuthorityOwner::load(directory.path(), NODE, BOOT_ONE)?;
        owner.prepare_runtime(
            key.as_bytes(),
            runtime(0, ExceptionRuntimeStateKindV1::Active),
            DEADLINE_UTC_NS,
            None,
            NOW_UTC_NS,
            NOW_BOOTTIME_NS,
        )?;
        let path = directory.path().join("exception-authority-v1.jsonl");
        let wal = fs::read(&path).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("read exception authority test WAL: {error}"),
            }
            .build()
        })?;
        fs::write(&path, &wal[..wal.len().saturating_sub(1)]).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("tear exception authority test WAL: {error}"),
            }
            .build()
        })?;
        assert!(ExceptionAuthorityOwner::load(directory.path(), NODE, BOOT_ONE).is_err());
        Ok(())
    }
}

fn read_runtime_key(bytes: &[u8]) -> Result<ExceptionRuntimeStateKeyV1> {
    ExceptionRuntimeStateKeyV1::try_read_from_bytes(bytes).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("exception runtime key has an invalid ABI value: {error}"),
        }
        .build()
    })
}

fn read_runtime(bytes: &[u8], name: &str) -> Result<ExceptionRuntimeStateV1> {
    ExceptionRuntimeStateV1::try_read_from_bytes(bytes).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("{name} has an invalid ABI value: {error}"),
        }
        .build()
    })
}

fn read_receipt_key(bytes: &[u8]) -> Result<ExceptionUseReceiptKeyV1> {
    let key = ExceptionUseReceiptKeyV1::try_read_from_bytes(bytes).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("exception receipt key has an invalid ABI value: {error}"),
        }
        .build()
    })?;
    let identity = &key.use_identity;
    let valid = match identity.kind {
        ExceptionUseIdentityKindV1::ClaimSlot => {
            !identity.claim_slot_id.is_zero()
                && identity.task_cookie == 0
                && identity.process_state_id.is_zero()
                && identity.syscall_entry_sequence == 0
                && identity.effect_attempt_sequence == 0
                && identity.effect_family == 0
                && identity.operation == 0
        }
        ExceptionUseIdentityKindV1::KernelEffectAttempt => {
            identity.claim_slot_id.is_zero()
                && identity.task_cookie != 0
                && !identity.process_state_id.is_zero()
                && identity.syscall_entry_sequence != 0
                && identity.effect_attempt_sequence != 0
                && identity.effect_family == KernelEffectFamilyV1::File as u16
                && matches!(
                    identity.operation,
                    operation if operation == KernelEffectOperationV1::OpenRead as u16
                        || operation == KernelEffectOperationV1::OpenWrite as u16
                )
        }
        ExceptionUseIdentityKindV1::Unknown => false,
    };
    if !valid || identity.reserved_0 != [0; 7] || identity.reserved_1 != [0; 4] {
        return IdentityStateSnafu {
            reason: "exception receipt key has an unsupported use identity".to_owned(),
        }
        .fail();
    }
    Ok(key)
}

fn read_receipt(bytes: &[u8]) -> Result<ExceptionUseReceiptV1> {
    ExceptionUseReceiptV1::try_read_from_bytes(bytes).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("exception receipt has an invalid ABI value: {error}"),
        }
        .build()
    })
}

fn validate_runtime(state: &ExceptionRuntimeStateV1) -> Result<()> {
    let consistent = state.maximum_uses > 0
        && state.consumed_uses <= state.maximum_uses
        && state.bound_profile_generation_refs > 0
        && state.transition_version > 0
        && match state.state {
            ExceptionRuntimeStateKindV1::Active => state.consumed_uses < state.maximum_uses,
            ExceptionRuntimeStateKindV1::Exhausted => state.consumed_uses == state.maximum_uses,
            ExceptionRuntimeStateKindV1::Expired
            | ExceptionRuntimeStateKindV1::ReconciliationRequired => true,
            ExceptionRuntimeStateKindV1::Unknown => false,
        };
    if !consistent {
        return IdentityStateSnafu {
            reason: "exception runtime state is inconsistent".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn ensure_same_definition(
    stored: DurableStateV1,
    key: ExceptionRuntimeStateKeyV1,
    state: ExceptionRuntimeStateV1,
) -> Result<()> {
    if stored.runtime_state_key != key
        || stored.maximum_uses != state.maximum_uses
        || stored.bound_profile_generation_refs != state.bound_profile_generation_refs
        || stored.exception_definition_sha256 != state.exception_definition_sha256
    {
        return IdentityStateSnafu {
            reason: "exception instance differs from durable authority".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn validate_state_transition(previous: DurableStateV1, next: DurableStateV1) -> Result<()> {
    let definition_matches = previous.runtime_state_key == next.runtime_state_key
        && previous.maximum_uses == next.maximum_uses
        && previous.bound_profile_generation_refs == next.bound_profile_generation_refs
        && previous.deadline_utc_ns == next.deadline_utc_ns
        && previous.exception_definition_sha256 == next.exception_definition_sha256;
    let state_advances = previous.state == next.state
        || (previous.state == ExceptionRuntimeStateKindV1::Active
            && matches!(
                next.state,
                ExceptionRuntimeStateKindV1::Exhausted
                    | ExceptionRuntimeStateKindV1::Expired
                    | ExceptionRuntimeStateKindV1::ReconciliationRequired
            ))
        || (previous.state == ExceptionRuntimeStateKindV1::ReconciliationRequired
            && next.state == ExceptionRuntimeStateKindV1::Exhausted);
    if !definition_matches
        || next.consumed_uses < previous.consumed_uses
        || next.transition_version < previous.transition_version
        || !state_advances
    {
        return IdentityStateSnafu {
            reason: "exception runtime transition would refund or redefine durable authority"
                .to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn validate_receipt_transition(previous: &[u8], next: &[u8]) -> Result<()> {
    let previous = read_receipt(previous)?;
    let next = read_receipt(next)?;
    let valid = previous == next
        || (previous.state == ExceptionReceiptStateV1::Claiming
            && next.state != ExceptionReceiptStateV1::Unknown
            && next.state != ExceptionReceiptStateV1::Claiming
            && next.transition_version > previous.transition_version);
    if !valid {
        return IdentityStateSnafu {
            reason: "exception receipt has a non-monotonic durable transition".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn runtime_from_durable(
    state: DurableStateV1,
    node_boot_id: Id128V1,
    now_utc_ns: i64,
    now_boottime_ns: u64,
) -> ExceptionRuntimeStateV1 {
    let rebooted = state.node_boot_id != node_boot_id;
    let remaining = state.deadline_utc_ns.saturating_sub(now_utc_ns);
    let mut kind = state.state;
    if remaining <= 0 {
        kind = ExceptionRuntimeStateKindV1::Expired;
    }
    ExceptionRuntimeStateV1 {
        lock: 0,
        maximum_uses: state.maximum_uses,
        consumed_uses: state.consumed_uses,
        bound_profile_generation_refs: state.bound_profile_generation_refs,
        deadline_boottime_ns: if rebooted {
            now_boottime_ns.saturating_add(remaining.max(0) as u64)
        } else {
            state.deadline_boottime_ns
        },
        transition_version: state.transition_version,
        exception_definition_sha256: state.exception_definition_sha256,
        state: kind,
        reserved: [0; 7],
    }
}

fn encode_state(state: DurableStateV1) -> StoredStateV1 {
    StoredStateV1 {
        runtime_state_key_hex: hex::encode(state.runtime_state_key.as_bytes()),
        node_boot_id: state.node_boot_id.into(),
        maximum_uses: state.maximum_uses,
        consumed_uses: state.consumed_uses,
        bound_profile_generation_refs: state.bound_profile_generation_refs,
        deadline_utc_ns: state.deadline_utc_ns,
        deadline_boottime_ns: state.deadline_boottime_ns,
        transition_version: state.transition_version,
        exception_definition_sha256_hex: hex::encode(state.exception_definition_sha256),
        state: state.state as u8,
    }
}

fn decode_state(state: StoredStateV1) -> Result<DurableStateV1> {
    let key = hex::decode(state.runtime_state_key_hex).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("exception authority WAL key is invalid: {error}"),
        }
        .build()
    })?;
    let digest = hex::decode(state.exception_definition_sha256_hex).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("exception authority WAL digest is invalid: {error}"),
        }
        .build()
    })?;
    let durable = DurableStateV1 {
        runtime_state_key: read_runtime_key(&key)?,
        node_boot_id: state.node_boot_id.into(),
        maximum_uses: state.maximum_uses,
        consumed_uses: state.consumed_uses,
        bound_profile_generation_refs: state.bound_profile_generation_refs,
        deadline_utc_ns: state.deadline_utc_ns,
        deadline_boottime_ns: state.deadline_boottime_ns,
        transition_version: state.transition_version,
        exception_definition_sha256: digest.try_into().map_err(|_| {
            IdentityStateSnafu {
                reason: "exception authority WAL digest has the wrong size".to_owned(),
            }
            .build()
        })?,
        state: match state.state {
            value if value == ExceptionRuntimeStateKindV1::Active as u8 => {
                ExceptionRuntimeStateKindV1::Active
            }
            value if value == ExceptionRuntimeStateKindV1::Exhausted as u8 => {
                ExceptionRuntimeStateKindV1::Exhausted
            }
            value if value == ExceptionRuntimeStateKindV1::Expired as u8 => {
                ExceptionRuntimeStateKindV1::Expired
            }
            value if value == ExceptionRuntimeStateKindV1::ReconciliationRequired as u8 => {
                ExceptionRuntimeStateKindV1::ReconciliationRequired
            }
            _ => {
                return IdentityStateSnafu {
                    reason: "exception authority WAL state is invalid".to_owned(),
                }
                .fail()
            }
        },
    };
    validate_runtime(&ExceptionRuntimeStateV1 {
        lock: 0,
        maximum_uses: durable.maximum_uses,
        consumed_uses: durable.consumed_uses,
        bound_profile_generation_refs: durable.bound_profile_generation_refs,
        deadline_boottime_ns: durable.deadline_boottime_ns,
        transition_version: durable.transition_version,
        exception_definition_sha256: durable.exception_definition_sha256,
        state: durable.state,
        reserved: [0; 7],
    })?;
    Ok(durable)
}
