use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
#[cfg(feature = "test-fixtures")]
use std::sync::Barrier;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use erebor_telemetry::{debug, info};
use rustix::fs::{flock, FlockOperation};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::error::{ControlStoreSnafu, IoSnafu, JsonSnafu};
use crate::evidence_segment::{
    EvidenceSegmentKindV1, EvidenceSegmentOwner, EvidenceSegmentPositionV1,
    EvidenceSegmentStreamV1, EvidenceStoreLimitsV1,
};
use crate::{
    canonical_policy_spec_digest, CoverageIntakeStateV1, CoverageReport, CoverageReportInputV1,
    EvidenceBatchInputV1, EvidenceConsumptionStateV1, EvidenceConsumptionWatermarkV1,
    EvidenceIntakeIdentityV1, EvidenceRecord, EvidenceRecords, EvidenceStoreOutcomeV1,
    ExceptionActivationAcknowledgementV1, ExceptionActivationStateV1, ExceptionDeliveryCandidateV1,
    ExceptionDeliveryOperationV1, ExceptionRolloutStateV1, ExceptionSourceRevisionV1,
    ExceptionSourceStateV1, IntakeStateV1, NodeDecommissionStateV1,
    PolicyActivationAcknowledgementV1, PolicyActivationStateV1, PolicyBundleV1, PolicyDocumentV1,
    PolicyRolloutStateV1, PolicyRolloutStatusV1, PolicySourceRevisionV1, PolicySourceStateV1,
    PolicyTargetSnapshotV1, PolicyTargetV1, ProfileCandidateArtifactV1, Result,
    StoredCoverageReportV1, StoredEvidenceBatchV1, StoredNodeDecommissionV1,
    TrustGenerationAcknowledgementV1, TrustGenerationV1, MAX_PENDING_EVIDENCE_RECORDS,
};

const STORE_SCHEMA_VERSION: u32 = 4;
const STATE_DIGEST_BYTES: usize = 32;
const MAX_STATE_BYTES: usize = 64 * 1_024 * 1_024;

#[derive(Clone)]
/// Owns current Control metadata and immutable evidence segments.
pub struct ControlStore {
    inner: Arc<ControlStoreLock>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlStoreHealthV1 {
    pub commit_index: u64,
    pub source_revisions: u64,
    pub compiled_artifacts: u64,
    pub target_snapshots: u64,
    pub rollout_targets: u64,
    pub unsettled_rollout_targets: u64,
    pub exception_candidates: u64,
    pub unsettled_exception_candidates: u64,
    pub evidence_cursors: u64,
    pub pending_evidence_batches: u64,
    pub pending_evidence_records: u64,
    pub coverage_cursors: u64,
}

struct ControlStoreInner {
    root: PathBuf,
    state: ControlStoreState,
    state_file: ControlStateOwner,
    evidence_segments: EvidenceSegmentOwner,
}

struct ControlStateOwner {
    path: PathBuf,
    temporary: PathBuf,
    _lease: File,
}

impl ControlStateOwner {
    fn open(root: &Path) -> Result<(Self, ControlStoreState)> {
        fs::create_dir_all(root).context(IoSnafu { path: root })?;
        let lease_path = root.join("owner.lock");
        let lease = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lease_path)
            .context(IoSnafu { path: &lease_path })?;
        flock(&lease, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            ControlStoreSnafu {
                path: lease_path,
                reason: format!("another Control store owner holds the lease: {error}"),
            }
            .build()
        })?;
        let owner = Self {
            path: root.join("state.bin"),
            temporary: root.join("state.tmp"),
            _lease: lease,
        };
        match fs::remove_file(&owner.temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(crate::Error::Io {
                    path: owner.temporary.clone(),
                    source,
                    location: snafu::Location::default(),
                });
            }
        }
        let state = owner.read()?.unwrap_or_default();
        Ok((owner, state))
    }

    fn read(&self) -> Result<Option<ControlStoreState>> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(crate::Error::Io {
                    path: self.path.clone(),
                    source,
                    location: snafu::Location::default(),
                });
            }
        };
        let Some((stored_digest, encoded)) = bytes.split_at_checked(STATE_DIGEST_BYTES) else {
            return ControlStoreSnafu {
                path: self.path.clone(),
                reason: "the current Control state is truncated".to_owned(),
            }
            .fail();
        };
        if stored_digest != Sha256::digest(encoded).as_slice() {
            return ControlStoreSnafu {
                path: self.path.clone(),
                reason: "the current Control state checksum is invalid".to_owned(),
            }
            .fail();
        }
        if encoded.len() > MAX_STATE_BYTES {
            return ControlStoreSnafu {
                path: self.path.clone(),
                reason: "the current Control state exceeds its size bound".to_owned(),
            }
            .fail();
        }
        let durable: DurableControlStateV1 = rmp_serde::from_slice(encoded).map_err(|error| {
            ControlStoreSnafu {
                path: self.path.clone(),
                reason: format!("current Control state decoding failed: {error}"),
            }
            .build()
        })?;
        if durable.schema_version != STORE_SCHEMA_VERSION {
            return ControlStoreSnafu {
                path: self.path.clone(),
                reason: "the current Control state schema is invalid".to_owned(),
            }
            .fail();
        }
        Ok(Some(durable.state))
    }

    fn replace(&self, root: &Path, state: &ControlStoreState) -> Result<()> {
        let encoded = rmp_serde::to_vec_named(&DurableControlStateV1 {
            schema_version: STORE_SCHEMA_VERSION,
            state: state.clone(),
        })
        .map_err(|error| {
            ControlStoreSnafu {
                path: self.path.clone(),
                reason: format!("current Control state encoding failed: {error}"),
            }
            .build()
        })?;
        if encoded.len() > MAX_STATE_BYTES {
            return ControlStoreSnafu {
                path: self.path.clone(),
                reason: "the current Control state exceeds its size bound".to_owned(),
            }
            .fail();
        }
        let digest = Sha256::digest(&encoded);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&self.temporary)
            .context(IoSnafu {
                path: &self.temporary,
            })?;
        file.write_all(&digest)
            .and_then(|()| file.write_all(&encoded))
            .context(IoSnafu {
                path: &self.temporary,
            })?;
        file.sync_all().context(IoSnafu {
            path: &self.temporary,
        })?;
        fs::rename(&self.temporary, &self.path).context(IoSnafu { path: &self.path })?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .context(IoSnafu { path: root })
    }
}

impl ControlStoreInner {
    fn stream_id(&self, identity: &EvidenceIntakeIdentityV1) -> Result<u64> {
        self.state
            .evidence_stream_ids
            .get(identity)
            .copied()
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: self.root.clone(),
                    reason: "evidence stream has no durable identifier".to_owned(),
                }
                .build()
            })
    }

    fn read_evidence_records(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        batch: &StoredEvidenceBatchV1,
    ) -> Result<Vec<EvidenceRecord>> {
        let expected_kind = EvidenceSegmentKindV1::Records {
            stream_id: self.stream_id(identity)?,
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
        };
        let records: EvidenceRecords = self
            .evidence_segments
            .read_records(batch.segment, expected_kind)?;
        let expected = batch
            .last_cursor
            .checked_sub(batch.first_cursor)
            .and_then(|count| count.checked_add(1))
            .and_then(|count| usize::try_from(count).ok());
        if expected != Some(records.records.len()) {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "evidence segment record count does not match its index".to_owned(),
            }
            .fail();
        }
        Ok(records.records)
    }

    fn read_evidence_frames(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        batch: &StoredEvidenceBatchV1,
        first_cursor: u64,
        last_cursor: u64,
    ) -> Result<Vec<u8>> {
        self.evidence_segments.read_record_frames(
            batch.segment,
            EvidenceSegmentKindV1::Records {
                stream_id: self.stream_id(identity)?,
                first_cursor,
                last_cursor,
            },
        )
    }

    fn publish_evidence_segment(&mut self, transaction: ControlTransactionV1) -> Result<u64> {
        debug_assert!(transaction.is_evidence());
        let mut next_state = self.state.clone();
        apply_transaction(&mut next_state, &transaction, &self.root)?;
        // A complete synced segment range is the durable intake record. Startup rebuilds this
        // small cursor index from segment names and frames after a crash.
        self.state = next_state;
        Ok(self.state.commit_index)
    }

    fn accepted_evidence_frames(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
        last_cursor: u64,
    ) -> Result<Vec<u8>> {
        let mut frames = Vec::new();
        for (key, batch) in self.state.evidence_batches.iter().filter(|(key, _batch)| {
            &key.identity == identity
                && key.first_cursor <= last_cursor
                && key.last_cursor >= first_cursor
        }) {
            let first = first_cursor.max(key.first_cursor);
            let last = last_cursor.min(key.last_cursor);
            frames.extend(self.read_evidence_frames(identity, batch, first, last)?);
        }
        Ok(frames)
    }
}

// Evidence fsyncs can keep this owner busy. Evidence waits while Control work is active or queued
// so policy inventory and desired-state reconciliation cannot starve.
struct ControlStoreLock {
    inner: Mutex<ControlStoreInner>,
    priority_holders: Mutex<usize>,
    evidence_ready: Condvar,
    #[cfg(feature = "test-fixtures")]
    evidence_wait_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
}

struct ControlStorePriorityGuard<'a> {
    inner: MutexGuard<'a, ControlStoreInner>,
    lock: &'a ControlStoreLock,
}

impl ControlStoreLock {
    fn new(inner: ControlStoreInner) -> Self {
        Self {
            inner: Mutex::new(inner),
            priority_holders: Mutex::new(0),
            evidence_ready: Condvar::new(),
            #[cfg(feature = "test-fixtures")]
            evidence_wait_barriers: Mutex::new(None),
        }
    }

    #[cfg(feature = "test-fixtures")]
    fn pause_next_evidence_wait(&self) {
        let barriers = self
            .evidence_wait_barriers
            .lock()
            .ok()
            .and_then(|mut barriers| barriers.take());
        if let Some((entered, release)) = barriers {
            entered.wait();
            release.wait();
        }
    }

    fn priority_lock(&self) -> Option<ControlStorePriorityGuard<'_>> {
        let mut holders = self.priority_holders.lock().ok()?;
        *holders = holders.checked_add(1)?;
        drop(holders);
        match self.inner.lock() {
            Ok(inner) => Some(ControlStorePriorityGuard { inner, lock: self }),
            Err(_error) => {
                self.finish_priority();
                None
            }
        }
    }

    fn evidence_lock(&self) -> Option<MutexGuard<'_, ControlStoreInner>> {
        let holders = self.priority_holders.lock().ok()?;
        let holders = self
            .evidence_ready
            .wait_while(holders, |holders| {
                let waiting = *holders != 0;
                #[cfg(feature = "test-fixtures")]
                if waiting {
                    self.pause_next_evidence_wait();
                }
                waiting
            })
            .ok()?;
        // Keep the predicate locked until evidence owns the store. A new priority request
        // cannot pass evidence after the last prior request has released it.
        let inner = self.inner.lock().ok()?;
        drop(holders);
        Some(inner)
    }

    fn finish_priority(&self) {
        if let Ok(mut holders) = self.priority_holders.lock() {
            if *holders == 0 {
                return;
            }
            *holders -= 1;
            if *holders == 0 {
                self.evidence_ready.notify_all();
            }
        }
    }
}

impl Deref for ControlStorePriorityGuard<'_> {
    type Target = ControlStoreInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ControlStorePriorityGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Drop for ControlStorePriorityGuard<'_> {
    fn drop(&mut self) {
        self.lock.finish_priority();
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControlStoreState {
    commit_index: u64,
    source_revisions: BTreeMap<String, PolicySourceRevisionV1>,
    policy_documents: BTreeMap<String, PolicyDocumentV1>,
    latest_sources: BTreeMap<PolicyObjectKeyV1, String>,
    compiled_artifacts: BTreeMap<String, ProfileCandidateArtifactV1>,
    target_snapshots: BTreeMap<String, PolicyTargetSnapshotV1>,
    latest_desired_snapshots: BTreeMap<String, String>,
    bundles: BTreeMap<String, PolicyBundleV1>,
    rollout_states: BTreeMap<PolicyRolloutKeyV1, PolicyRolloutStateV1>,
    // Keep the complete result so a retry can reproduce the durable response.
    policy_acknowledgement_results: BTreeMap<String, PolicyAcknowledgementTransactionV1>,
    exception_source_revisions: BTreeMap<String, ExceptionSourceRevisionV1>,
    latest_exception_sources: BTreeMap<PolicyObjectKeyV1, String>,
    exception_candidates: BTreeMap<String, ExceptionDeliveryCandidateV1>,
    exception_rollout_states: BTreeMap<PolicyRolloutKeyV1, ExceptionRolloutStateV1>,
    exception_acknowledgements: BTreeMap<String, ExceptionActivationAcknowledgementV1>,
    exception_consumed_uses: BTreeMap<PolicyRolloutKeyV1, u32>,
    node_sessions: BTreeMap<String, DurableNodeSessionV1>,
    node_session_history: BTreeMap<NodePhysicalEpochV1, DurableNodeSessionV1>,
    node_decommissions: BTreeMap<[u8; 32], StoredNodeDecommissionV1>,
    trust_generations: BTreeMap<u64, TrustGenerationV1>,
    trust_acknowledgements:
        BTreeMap<(String, u64, [u8; 16], u64), TrustGenerationAcknowledgementV1>,
    evidence_cursors: Arc<BTreeMap<EvidenceIntakeIdentityV1, IntakeStateV1>>,
    evidence_stream_ids: Arc<BTreeMap<EvidenceIntakeIdentityV1, u64>>,
    evidence_segment_commits: BTreeMap<EvidenceSegmentStreamV1, EvidenceSegmentPositionV1>,
    #[serde(skip)]
    evidence_batches: Arc<BTreeMap<EvidenceBatchKeyV1, StoredEvidenceBatchV1>>,
    #[serde(skip)]
    pending_evidence_batches: Arc<BTreeMap<EvidencePendingKeyV1, StoredEvidenceBatchV1>>,
    coverage_cursors: Arc<BTreeMap<EvidenceIntakeIdentityV1, CoverageIntakeStateV1>>,
    #[serde(skip)]
    coverage_reports: Arc<BTreeMap<CoverageReportKeyV1, StoredCoverageReportV1>>,
    evidence_consumption: Arc<BTreeMap<EvidenceIntakeIdentityV1, EvidenceConsumptionStateV1>>,
    evidence_source_labels: Arc<BTreeMap<EvidenceSourceEpochKeyV1, u64>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableControlStateV1 {
    schema_version: u32,
    state: ControlStoreState,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct PolicyObjectKeyV1 {
    tenant_id: String,
    namespace_uid: String,
    object_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct PolicyRolloutKeyV1 {
    candidate_content_id: String,
    node_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct EvidenceBatchKeyV1 {
    identity: EvidenceIntakeIdentityV1,
    first_cursor: u64,
    last_cursor: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct EvidencePendingKeyV1 {
    identity: EvidenceIntakeIdentityV1,
    first_cursor: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct CoverageReportKeyV1 {
    identity: EvidenceIntakeIdentityV1,
    revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct EvidenceSourceEpochKeyV1 {
    tenant_id: [u8; 16],
    node_id: String,
    source_id: [u8; 16],
    source_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
// Each variant contains all state that must become durable in one transaction.
enum ControlTransactionV1 {
    NodeSessionAdvanced {
        advance: Box<NodeSessionAdvanceTransactionV1>,
    },
    KubernetesNodeBound {
        binding: Box<KubernetesNodeBindingTransactionV1>,
    },
    SourceAccepted {
        source_revision: Box<PolicySourceRevisionV1>,
        policy_document: Box<PolicyDocumentV1>,
        #[serde(default)]
        artifact: Option<Box<ProfileCandidateArtifactV1>>,
    },
    // Replay accepts the split transaction written before source promotion became atomic.
    Compiled {
        policy_source_revision_id: String,
        artifact: Box<ProfileCandidateArtifactV1>,
    },
    RolloutCreated {
        rollout: Box<PolicyRolloutTransactionV1>,
    },
    TargetSetReconciled {
        reconciliation: Box<PolicyTargetSetTransactionV1>,
    },
    Acknowledged {
        result: Box<PolicyAcknowledgementTransactionV1>,
    },
    ExceptionDesired {
        desired: Box<ExceptionDesiredTransactionV1>,
    },
    ExceptionAcknowledged {
        result: Box<ExceptionAcknowledgementTransactionV1>,
    },
    EvidencePending {
        stream_id: u64,
        pending: Box<EvidenceBatchTransactionV1>,
    },
    EvidenceAccepted {
        accepted: Box<EvidenceAcceptedTransactionV1>,
    },
    CoverageAccepted {
        stream_id: u64,
        report: Box<StoredCoverageReportV1>,
    },
    EvidenceConsumed {
        watermark: Box<EvidenceConsumptionWatermarkV1>,
    },
    TrustInstalled {
        generation: Box<TrustGenerationV1>,
    },
    TrustAcknowledged {
        acknowledgement: Box<TrustGenerationAcknowledgementV1>,
    },
    NodeDecommissionUpdated {
        record: Box<StoredNodeDecommissionV1>,
    },
}

impl ControlTransactionV1 {
    fn is_evidence(&self) -> bool {
        matches!(
            self,
            Self::EvidencePending { .. }
                | Self::EvidenceAccepted { .. }
                | Self::CoverageAccepted { .. }
                | Self::EvidenceConsumed { .. }
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct NodePhysicalEpochV1 {
    node_id: String,
    node_boot_id: Vec<u8>,
    label_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableNodeSessionV1 {
    pub(crate) node_id: String,
    pub(crate) node_boot_id: Vec<u8>,
    pub(crate) label_epoch: u64,
    pub(crate) kubernetes_node_name: Option<String>,
    pub(crate) kubernetes_node_uid: Option<String>,
    pub(crate) startup_absence_proof_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeSessionAdvanceTransactionV1 {
    session: DurableNodeSessionV1,
    policy_rollout_states: Vec<PolicyRolloutStateV1>,
    exception_settlements: Vec<ExceptionSessionSettlementV1>,
    observed_utc_ns: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExceptionSessionSettlementV1 {
    rollout_state: ExceptionRolloutStateV1,
    consumed_uses: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct KubernetesNodeBindingTransactionV1 {
    physical_epoch: NodePhysicalEpochV1,
    kubernetes_node_name: String,
    kubernetes_node_uid: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyRolloutTransactionV1 {
    target_snapshot: PolicyTargetSnapshotV1,
    bundles: Vec<PolicyBundleV1>,
    rollout_states: Vec<PolicyRolloutStateV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyTargetSetTransactionV1 {
    desired: PolicyRolloutTransactionV1,
    retirement: Option<PolicyRolloutTransactionV1>,
    refreshed_active_artifact: Option<ProfileCandidateArtifactV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyAcknowledgementTransactionV1 {
    acknowledgement: PolicyActivationAcknowledgementV1,
    rollout_state: PolicyRolloutStateV1,
    // Omit false so old WAL records keep their original commit digest during replay.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    terminal_chain_closure_authorized: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExceptionDesiredTransactionV1 {
    source_revision: ExceptionSourceRevisionV1,
    candidate: ExceptionDeliveryCandidateV1,
    rollout_state: ExceptionRolloutStateV1,
    // Omit the original purpose so existing commit digests remain valid during replay.
    #[serde(
        default,
        skip_serializing_if = "ExceptionDesiredPurposeV1::is_source_lifecycle"
    )]
    purpose: ExceptionDesiredPurposeV1,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum ExceptionDesiredPurposeV1 {
    #[default]
    SourceLifecycle,
    TargetRetirement,
}

impl ExceptionDesiredPurposeV1 {
    fn is_source_lifecycle(&self) -> bool {
        *self == Self::SourceLifecycle
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExceptionAcknowledgementTransactionV1 {
    acknowledgement: ExceptionActivationAcknowledgementV1,
    rollout_state: ExceptionRolloutStateV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceBatchTransactionV1 {
    identity: EvidenceIntakeIdentityV1,
    batch: StoredEvidenceBatchV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceAcceptedTransactionV1 {
    identity: EvidenceIntakeIdentityV1,
    stream_id: u64,
    batches: Vec<StoredEvidenceBatchV1>,
}

impl DurableNodeSessionV1 {
    fn physical_epoch(&self) -> NodePhysicalEpochV1 {
        NodePhysicalEpochV1 {
            node_id: self.node_id.clone(),
            node_boot_id: self.node_boot_id.clone(),
            label_epoch: self.label_epoch,
        }
    }
}

#[must_use]
pub fn startup_absence_proof_digest(
    node_id: &str,
    node_boot_id: &[u8],
    label_epoch: u64,
    policy_authority_absent: bool,
    exception_authority_absent: bool,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"MITHRIL-NODE-STARTUP-ABSENCE-V1\0");
    digest.update(
        u64::try_from(node_id.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(node_id.as_bytes());
    digest.update(node_boot_id);
    digest.update(label_epoch.to_be_bytes());
    digest.update([
        u8::from(policy_authority_absent),
        u8::from(exception_authority_absent),
    ]);
    format!("{:x}", digest.finalize())
}

impl ControlStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_evidence_limits(root, EvidenceStoreLimitsV1::default())
    }

    pub fn open_with_evidence_limits(
        root: impl Into<PathBuf>,
        evidence_limits: EvidenceStoreLimitsV1,
    ) -> Result<Self> {
        let root = root.into();
        let (state_file, mut state) = ControlStateOwner::open(&root)?;
        let mut evidence_segments = EvidenceSegmentOwner::open(&root, evidence_limits)?;
        if rebuild_evidence_indexes(&mut state, &evidence_segments, &root)? {
            state_file.replace(&root, &state)?;
        }
        evidence_segments.reclaim_unreferenced(&retained_evidence_segment_refs(&state))?;
        evidence_segments.validate_retention()?;
        info!(
            "opened the Control store",
            commit_index = %state.commit_index
        );
        Ok(Self {
            inner: Arc::new(ControlStoreLock::new(ControlStoreInner {
                root,
                state,
                state_file,
                evidence_segments,
            })),
        })
    }

    pub fn health(&self) -> Result<ControlStoreHealthV1> {
        let inner = self.lock()?;
        Ok(ControlStoreHealthV1 {
            commit_index: inner.state.commit_index,
            source_revisions: count(inner.state.source_revisions.len()),
            compiled_artifacts: count(inner.state.compiled_artifacts.len()),
            target_snapshots: count(inner.state.target_snapshots.len()),
            rollout_targets: count(inner.state.rollout_states.len()),
            unsettled_rollout_targets: count(
                inner
                    .state
                    .rollout_states
                    .values()
                    .filter(|state| {
                        matches!(
                            state.state,
                            crate::PolicyRolloutStatusV1::Pending
                                | crate::PolicyRolloutStatusV1::Delivered
                                | crate::PolicyRolloutStatusV1::Staged
                                | crate::PolicyRolloutStatusV1::Unknown
                        )
                    })
                    .count(),
            ),
            exception_candidates: count(inner.state.exception_candidates.len()),
            // The first authenticated node result settles delivery for one candidate.
            unsettled_exception_candidates: count(
                inner
                    .state
                    .exception_rollout_states
                    .values()
                    .filter(|state| {
                        state.state == crate::WorkloadProtectionExceptionStateV1::Pending
                    })
                    .count(),
            ),
            evidence_cursors: count(inner.state.evidence_cursors.len()),
            pending_evidence_batches: count(inner.state.pending_evidence_batches.len()),
            pending_evidence_records: inner.state.pending_evidence_batches.values().fold(
                0_u64,
                |total, batch| {
                    total.saturating_add(
                        batch
                            .last_cursor
                            .saturating_sub(batch.first_cursor)
                            .saturating_add(1),
                    )
                },
            ),
            coverage_cursors: count(inner.state.coverage_cursors.len()),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_node_physical_session(
        &self,
        node_id: &str,
        node_boot_id: &[u8],
        label_epoch: u64,
        kubernetes_node_name: Option<&str>,
        proof_digest: &str,
        policy_authority_absent: bool,
        exception_authority_absent: bool,
        observed_utc_ns: i64,
    ) -> Result<DurableNodeSessionV1> {
        let mut inner = self.lock()?;
        let physical_epoch = NodePhysicalEpochV1 {
            node_id: node_id.to_owned(),
            node_boot_id: node_boot_id.to_vec(),
            label_epoch,
        };
        if let Some(current) = inner.state.node_sessions.get(node_id) {
            if physical_epoch == current.physical_epoch() {
                if current.kubernetes_node_name.as_deref() != kubernetes_node_name {
                    return ControlStoreSnafu {
                        path: inner.root.clone(),
                        reason: "a reconnect changed its Kubernetes Node name".to_owned(),
                    }
                    .fail();
                }
                return Ok(current.clone());
            }
        }
        if !policy_authority_absent
            || !exception_authority_absent
            || proof_digest
                != startup_absence_proof_digest(
                    node_id,
                    node_boot_id,
                    label_epoch,
                    policy_authority_absent,
                    exception_authority_absent,
                )
        {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "a physical node-session advance has no exact startup absence proof"
                    .to_owned(),
            }
            .fail();
        }
        let session = DurableNodeSessionV1 {
            node_id: node_id.to_owned(),
            node_boot_id: node_boot_id.to_vec(),
            label_epoch,
            kubernetes_node_name: kubernetes_node_name.map(str::to_owned),
            kubernetes_node_uid: None,
            startup_absence_proof_digest: proof_digest.to_owned(),
        };
        let advance =
            node_session_advance(&inner.state, session.clone(), observed_utc_ns, &inner.root)?;
        commit(
            &mut inner,
            ControlTransactionV1::NodeSessionAdvanced {
                advance: Box::new(advance),
            },
        )?;
        Ok(session)
    }

    pub(crate) fn bind_kubernetes_node_session(
        &self,
        node_id: &str,
        node_boot_id: &[u8],
        label_epoch: u64,
        kubernetes_node_name: &str,
        kubernetes_node_uid: &str,
    ) -> Result<bool> {
        let mut inner = self.lock()?;
        let physical_epoch = NodePhysicalEpochV1 {
            node_id: node_id.to_owned(),
            node_boot_id: node_boot_id.to_vec(),
            label_epoch,
        };
        let current = inner.state.node_sessions.get(node_id).ok_or_else(|| {
            ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "a Kubernetes Node binding has no durable physical session".to_owned(),
            }
            .build()
        })?;
        if current.physical_epoch() != physical_epoch
            || current.kubernetes_node_name.as_deref() != Some(kubernetes_node_name)
        {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "a Kubernetes Node binding does not match the physical session".to_owned(),
            }
            .fail();
        }
        if current.kubernetes_node_uid.as_deref() == Some(kubernetes_node_uid) {
            return Ok(false);
        }
        commit(
            &mut inner,
            ControlTransactionV1::KubernetesNodeBound {
                binding: Box::new(KubernetesNodeBindingTransactionV1 {
                    physical_epoch,
                    kubernetes_node_name: kubernetes_node_name.to_owned(),
                    kubernetes_node_uid: kubernetes_node_uid.to_owned(),
                }),
            },
        )?;
        Ok(true)
    }

    pub(crate) fn current_node_session_matches(
        &self,
        node_id: &str,
        node_boot_id: &[u8],
        label_epoch: u64,
    ) -> Result<bool> {
        let inner = self.lock()?;
        Ok(inner
            .state
            .node_sessions
            .get(node_id)
            .is_none_or(|session| {
                session.node_boot_id == node_boot_id && session.label_epoch == label_epoch
            }))
    }

    pub(crate) fn submit_node_decommission(
        &self,
        artifact: Vec<u8>,
    ) -> Result<StoredNodeDecommissionV1> {
        let (_envelope, authorization) = crate::SignedNodeDecommissionV1::parse(&artifact)?;
        let digest: [u8; 32] = Sha256::digest(&artifact).into();
        let mut inner = self.lock()?;
        if let Some(existing) = inner.state.node_decommissions.get(&digest) {
            return Ok(existing.clone());
        }
        if inner.state.node_decommissions.len() >= 4_096 {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "the decommission artifact capacity is exhausted".to_owned(),
            }
            .fail();
        }
        if inner.state.node_decommissions.values().any(|record| {
            matches!(
                record.state,
                NodeDecommissionStateV1::Submitted
                    | NodeDecommissionStateV1::Accepted
                    | NodeDecommissionStateV1::Quarantined
            ) && record.authorization().is_ok_and(|stored| {
                stored.node_id == authorization.node_id
                    && stored.node_boot_id == authorization.node_boot_id
            })
        }) {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "decommission target already has a pending artifact".to_owned(),
            }
            .fail();
        }
        let session = inner
            .state
            .node_sessions
            .get(&authorization.node_id)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "decommission target has no durable node session".to_owned(),
                }
                .build()
            })?;
        if session.node_boot_id != authorization.node_boot_id {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "decommission target does not match the current node boot".to_owned(),
            }
            .fail();
        }
        if inner.state.node_decommissions.values().any(|record| {
            record
                .authorization()
                .is_ok_and(|stored| stored.nonce == authorization.nonce)
        }) {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "decommission nonce already names another artifact".to_owned(),
            }
            .fail();
        }
        let record = StoredNodeDecommissionV1 {
            artifact,
            state: NodeDecommissionStateV1::Submitted,
            reason_code: String::new(),
        };
        commit(
            &mut inner,
            ControlTransactionV1::NodeDecommissionUpdated {
                record: Box::new(record.clone()),
            },
        )?;
        Ok(record)
    }

    pub(crate) fn advance_node_decommission(
        &self,
        artifact_sha256: [u8; 32],
        state: NodeDecommissionStateV1,
        reason_code: String,
    ) -> Result<StoredNodeDecommissionV1> {
        let mut inner = self.lock()?;
        let mut record = inner
            .state
            .node_decommissions
            .get(&artifact_sha256)
            .cloned()
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "decommission result has no durable artifact".to_owned(),
                }
                .build()
            })?;
        if record.state == state && record.reason_code == reason_code {
            return Ok(record);
        }
        record.state = state;
        record.reason_code = reason_code;
        commit(
            &mut inner,
            ControlTransactionV1::NodeDecommissionUpdated {
                record: Box::new(record.clone()),
            },
        )?;
        Ok(record)
    }

    pub(crate) fn node_decommission(
        &self,
        artifact_sha256: [u8; 32],
    ) -> Result<Option<StoredNodeDecommissionV1>> {
        Ok(self
            .lock()?
            .state
            .node_decommissions
            .get(&artifact_sha256)
            .cloned())
    }

    pub(crate) fn node_decommission_for_session(
        &self,
        node_id: &str,
        node_boot_id: &[u8],
    ) -> Result<Option<StoredNodeDecommissionV1>> {
        let inner = self.lock()?;
        Ok(inner
            .state
            .node_decommissions
            .values()
            .filter(|record| {
                matches!(
                    record.state,
                    NodeDecommissionStateV1::Submitted
                        | NodeDecommissionStateV1::Accepted
                        | NodeDecommissionStateV1::Quarantined
                )
            })
            .find(|record| {
                record.authorization().is_ok_and(|authorization| {
                    authorization.node_id == node_id
                        && authorization.node_boot_id.as_slice() == node_boot_id
                })
            })
            .cloned())
    }

    pub(crate) fn completed_node_decommission(
        &self,
        kubernetes_node_name: &str,
        kubernetes_node_uid: &str,
    ) -> Result<bool> {
        let inner = self.lock()?;
        Ok(inner.state.node_decommissions.values().any(|record| {
            record.state == NodeDecommissionStateV1::Completed
                && record.authorization().is_ok_and(|authorization| {
                    inner
                        .state
                        .node_sessions
                        .get(&authorization.node_id)
                        .is_some_and(|session| {
                            session.node_boot_id == authorization.node_boot_id
                                && session.kubernetes_node_name.as_deref()
                                    == Some(kubernetes_node_name)
                                && session.kubernetes_node_uid.as_deref()
                                    == Some(kubernetes_node_uid)
                        })
                })
        }))
    }

    pub(crate) fn evidence_session_for_stream(
        &self,
        tenant_id: [u8; 16],
        node_id: &str,
        node_boot_id: [u8; 16],
        source_id: [u8; 16],
        source_epoch: u64,
    ) -> Result<DurableNodeSessionV1> {
        let inner = self.evidence_lock()?;
        let known_label = inner
            .state
            .evidence_source_labels
            .get(&EvidenceSourceEpochKeyV1 {
                tenant_id,
                node_id: node_id.to_owned(),
                source_id,
                source_epoch,
            });
        let mut matches = inner.state.node_session_history.values().filter(|session| {
            session.node_id == node_id
                && session.node_boot_id == node_boot_id
                && known_label.is_none_or(|label| session.label_epoch == *label)
        });
        let session = matches.next().cloned().ok_or_else(|| {
            ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "evidence does not name a durable node session".to_owned(),
            }
            .build()
        })?;
        if matches.next().is_some() {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "evidence names an ambiguous node session".to_owned(),
            }
            .fail();
        }
        Ok(session)
    }

    pub fn accept_compiled_source_revision(
        &self,
        revision: PolicySourceRevisionV1,
        policy_document: PolicyDocumentV1,
        artifact: ProfileCandidateArtifactV1,
    ) -> Result<u64> {
        let mut inner = self.lock()?;
        let key = PolicyObjectKeyV1::from(&revision);
        if inner
            .state
            .source_revisions
            .contains_key(&revision.policy_source_revision_id)
        {
            let document_matches = inner
                .state
                .policy_documents
                .get(&revision.policy_source_revision_id)
                == Some(&policy_document);
            let current_artifact = inner
                .state
                .compiled_artifacts
                .get(&revision.policy_source_revision_id);
            let legacy_upgrade = current_artifact.is_some_and(|current| {
                legacy_deletion_artifact_upgrade(&revision, &policy_document, current, &artifact)
            });
            if !document_matches || (current_artifact != Some(&artifact) && !legacy_upgrade) {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "one source revision has conflicting policy or artifact bytes"
                        .to_owned(),
                }
                .fail();
            }
            // A known revision is idempotent only while it remains the latest object revision.
            if inner.state.latest_sources.get(&key) != Some(&revision.policy_source_revision_id) {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "a historical source revision cannot replace the current source"
                        .to_owned(),
                }
                .fail();
            }
            if !legacy_upgrade {
                return Ok(inner.state.commit_index);
            }
        }
        validate_source_acceptance(&inner.state, &revision, &policy_document, &inner.root)?;
        validate_compiled_artifact(
            &inner.state,
            &revision,
            &policy_document,
            &artifact,
            &inner.root,
        )?;
        commit(
            &mut inner,
            ControlTransactionV1::SourceAccepted {
                source_revision: Box::new(revision),
                policy_document: Box::new(policy_document),
                artifact: Some(Box::new(artifact)),
            },
        )
    }

    pub fn next_policy_issuer_sequence(
        &self,
        signing_key_id: &str,
        sequence_epoch: u64,
        configured_floor: u64,
    ) -> Result<u64> {
        let inner = self.lock()?;
        let mut current = configured_floor;
        for artifact in inner
            .state
            .compiled_artifacts
            .values()
            .chain(
                inner
                    .state
                    .bundles
                    .values()
                    .map(|bundle| &bundle.profile_artifact),
            )
            .filter(|artifact| artifact.signed_profile.signing_key_id == signing_key_id)
        {
            if artifact.header.sequence_epoch > sequence_epoch {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "the configured policy-issuer epoch is stale".to_owned(),
                }
                .fail();
            }
            if artifact.header.sequence_epoch == sequence_epoch {
                current = current.max(artifact.header.issuer_sequence);
            }
        }
        current.checked_add(1).ok_or_else(|| {
            ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "the policy-issuer sequence is exhausted".to_owned(),
            }
            .build()
        })
    }

    pub fn create_rollout(
        &self,
        target_snapshot: PolicyTargetSnapshotV1,
        bundles: Vec<PolicyBundleV1>,
        rollout_states: Vec<PolicyRolloutStateV1>,
    ) -> Result<u64> {
        let mut inner = self.lock()?;
        if inner
            .state
            .target_snapshots
            .contains_key(&target_snapshot.target_snapshot_digest)
        {
            let same_bundles = bundles.iter().all(|bundle| {
                inner
                    .state
                    .bundles
                    .get(&bundle.candidate.candidate_content_id)
                    == Some(bundle)
            });
            if same_bundles {
                return Ok(inner.state.commit_index);
            }
        }
        // Commit the snapshot, signed bundles, and initial target states as one unit.
        validate_rollout_transaction(&target_snapshot, &bundles, &rollout_states, &inner.root)?;
        validate_rollout_ordering(&inner.state, &bundles, &inner.root, false)?;
        commit(
            &mut inner,
            ControlTransactionV1::RolloutCreated {
                rollout: Box::new(PolicyRolloutTransactionV1 {
                    target_snapshot,
                    bundles,
                    rollout_states,
                }),
            },
        )
    }

    pub fn reconcile_target_set(
        &self,
        desired_snapshot: PolicyTargetSnapshotV1,
        desired_bundles: Vec<PolicyBundleV1>,
        desired_states: Vec<PolicyRolloutStateV1>,
        refreshed_active_artifact: Option<ProfileCandidateArtifactV1>,
    ) -> Result<u64> {
        let mut inner = self.lock()?;
        let desired = PolicyRolloutTransactionV1 {
            target_snapshot: desired_snapshot,
            bundles: desired_bundles,
            rollout_states: desired_states,
        };
        let reconciliation = PolicyTargetSetTransactionV1 {
            desired,
            retirement: None,
            refreshed_active_artifact,
        };
        validate_target_set_reconciliation(&inner.state, &reconciliation, &inner.root)?;
        commit(
            &mut inner,
            ControlTransactionV1::TargetSetReconciled {
                reconciliation: Box::new(reconciliation),
            },
        )
    }

    pub fn acknowledge_policy(
        &self,
        acknowledgement: PolicyActivationAcknowledgementV1,
        rollout_state: PolicyRolloutStateV1,
    ) -> Result<(PolicyRolloutStateV1, bool)> {
        let mut inner = self.lock()?;
        if !node_session_matches_acknowledgement(
            &inner.state,
            &acknowledgement.node_id,
            &acknowledgement.node_boot_id,
            acknowledgement.label_epoch,
        ) {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "a policy acknowledgement belongs to an old physical session".to_owned(),
            }
            .fail();
        }
        if let Some(existing) = inner
            .state
            .policy_acknowledgement_results
            .get(&acknowledgement.acknowledgement_content_id)
        {
            if existing.acknowledgement == acknowledgement {
                return Ok((
                    existing.rollout_state.clone(),
                    existing.terminal_chain_closure_authorized,
                ));
            }
        }
        let terminal_chain_closure_authorized =
            terminal_chain_closure_can_be_authorized(&inner.state, &acknowledgement);
        let result = PolicyAcknowledgementTransactionV1 {
            acknowledgement,
            rollout_state,
            terminal_chain_closure_authorized,
        };
        validate_policy_acknowledgement(&inner.state, &result, &inner.root)?;
        let accepted = (
            result.rollout_state.clone(),
            result.terminal_chain_closure_authorized,
        );
        commit(
            &mut inner,
            ControlTransactionV1::Acknowledged {
                result: Box::new(result),
            },
        )?;
        Ok(accepted)
    }

    pub(crate) fn policy_acknowledgement_result(
        &self,
        acknowledgement: &PolicyActivationAcknowledgementV1,
    ) -> Result<Option<(PolicyRolloutStateV1, bool)>> {
        Ok(self
            .lock()?
            .state
            .policy_acknowledgement_results
            .get(&acknowledgement.acknowledgement_content_id)
            .filter(|result| result.acknowledgement == *acknowledgement)
            .map(|result| {
                (
                    result.rollout_state.clone(),
                    result.terminal_chain_closure_authorized,
                )
            }))
    }

    pub(crate) fn record_exception_desired(
        &self,
        source: ExceptionSourceRevisionV1,
        candidate: ExceptionDeliveryCandidateV1,
        rollout_state: ExceptionRolloutStateV1,
        purpose: ExceptionDesiredPurposeV1,
    ) -> Result<u64> {
        let mut inner = self.lock()?;
        if let Some(existing) = inner
            .state
            .exception_candidates
            .get(&candidate.candidate_content_id)
        {
            let rollout_key = PolicyRolloutKeyV1 {
                candidate_content_id: candidate.candidate_content_id.clone(),
                node_id: candidate.exact_target.node_id.clone(),
            };
            if existing == &candidate
                && inner
                    .state
                    .exception_source_revisions
                    .get(&source.exception_source_revision_id)
                    == Some(&source)
                && inner.state.exception_rollout_states.get(&rollout_key) == Some(&rollout_state)
            {
                return Ok(inner.state.commit_index);
            }
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "one exception candidate has conflicting immutable content".to_owned(),
            }
            .fail();
        }
        let desired = ExceptionDesiredTransactionV1 {
            source_revision: source,
            candidate,
            rollout_state,
            purpose,
        };
        validate_exception_desired(&inner.state, &desired, &inner.root)?;
        commit(
            &mut inner,
            ControlTransactionV1::ExceptionDesired {
                desired: Box::new(desired),
            },
        )
    }

    pub fn acknowledge_exception(
        &self,
        acknowledgement: ExceptionActivationAcknowledgementV1,
        rollout_state: ExceptionRolloutStateV1,
    ) -> Result<u64> {
        let mut inner = self.lock()?;
        acknowledgement.validate()?;
        if !node_session_matches_acknowledgement(
            &inner.state,
            &acknowledgement.node_id,
            &acknowledgement.node_boot_id,
            acknowledgement.label_epoch,
        ) {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "an exception acknowledgement belongs to an old physical session"
                    .to_owned(),
            }
            .fail();
        }
        if inner
            .state
            .exception_acknowledgements
            .get(&acknowledgement.acknowledgement_content_id)
            == Some(&acknowledgement)
        {
            return Ok(inner.state.commit_index);
        }
        let result = ExceptionAcknowledgementTransactionV1 {
            acknowledgement,
            rollout_state,
        };
        validate_exception_acknowledgement(&inner.state, &result, &inner.root)?;
        commit(
            &mut inner,
            ControlTransactionV1::ExceptionAcknowledged {
                result: Box::new(result),
            },
        )
    }

    pub(crate) fn exception_acknowledgement_result(
        &self,
        acknowledgement: &ExceptionActivationAcknowledgementV1,
    ) -> Result<Option<ExceptionRolloutStateV1>> {
        let inner = self.lock()?;
        let rollout = inner
            .state
            .exception_rollout_states
            .get(&PolicyRolloutKeyV1 {
                candidate_content_id: acknowledgement.candidate_content_id.clone(),
                node_id: acknowledgement.node_id.clone(),
            });
        Ok(rollout.and_then(|rollout| {
            let accepted = rollout
                .latest_acknowledgement_content_id
                .as_ref()
                .and_then(|id| inner.state.exception_acknowledgements.get(id));
            accepted
                .is_some_and(|accepted| accepted.repeats_transition(acknowledgement))
                .then(|| rollout.clone())
        }))
    }

    pub fn next_exception_distribution_sequence(
        &self,
        node_id: &str,
        exception_instance_id: &str,
        sequence_epoch: u64,
    ) -> Result<u64> {
        let inner = self.lock()?;
        let mut current = 0_u64;
        for candidate in inner
            .state
            .exception_candidates
            .values()
            .filter(|candidate| {
                candidate.exact_target.node_id == node_id
                    && candidate.exception_instance_id == exception_instance_id
            })
        {
            if candidate.distribution_sequence_epoch > sequence_epoch {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "the configured exception-distribution epoch is stale".to_owned(),
                }
                .fail();
            }
            if candidate.distribution_sequence_epoch == sequence_epoch {
                current = current.max(candidate.distribution_sequence);
            }
        }
        current.checked_add(1).ok_or_else(|| {
            ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "the exception-distribution sequence is exhausted".to_owned(),
            }
            .build()
        })
    }

    pub(crate) fn accept_evidence_batch(
        &self,
        identity: EvidenceIntakeIdentityV1,
        batch: EvidenceBatchInputV1,
    ) -> Result<EvidenceStoreOutcomeV1> {
        let mut inner = self.evidence_lock()?;
        validate_evidence_identity(&identity, &inner.root)?;
        validate_evidence_batch_input(&batch, &inner.root)?;
        validate_source_label(&inner.state, &identity, &inner.root)?;
        let consumed_cursor = inner
            .state
            .evidence_consumption
            .get(&identity)
            .copied()
            .unwrap_or_default()
            .evidence_cursor;
        if batch.last_cursor <= consumed_cursor {
            return Ok(EvidenceStoreOutcomeV1::Accepted);
        }
        let mut batch = batch;
        if batch.first_cursor <= consumed_cursor {
            let consumed_records = consumed_cursor
                .checked_sub(batch.first_cursor)
                .and_then(|count| count.checked_add(1))
                .and_then(|count| usize::try_from(count).ok())
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: inner.root.clone(),
                        reason: "an evidence retry crosses an exhausted consumer watermark"
                            .to_owned(),
                    }
                    .build()
                })?;
            batch = batch.split_off(consumed_records);
        }
        let exact_key = EvidenceBatchKeyV1 {
            identity: identity.clone(),
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
        };
        if let Some(existing) = inner.state.evidence_batches.get(&exact_key) {
            if inner.read_evidence_frames(
                &identity,
                existing,
                batch.first_cursor,
                batch.last_cursor,
            )? == batch.framed_records
            {
                return Ok(EvidenceStoreOutcomeV1::Accepted);
            }
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "an accepted evidence range has conflicting batch content".to_owned(),
            }
            .fail();
        }
        let cursor = inner
            .state
            .evidence_cursors
            .get(&identity)
            .copied()
            .unwrap_or_default();
        if batch.first_cursor <= cursor.contiguous_cursor {
            let overlap_last = batch.last_cursor.min(cursor.contiguous_cursor);
            let overlap_count = overlap_last
                .checked_sub(batch.first_cursor)
                .and_then(|count| count.checked_add(1))
                .and_then(|count| usize::try_from(count).ok())
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: inner.root.clone(),
                        reason: "an overlapping evidence range exceeds local bounds".to_owned(),
                    }
                    .build()
                })?;
            let accepted =
                inner.accepted_evidence_frames(&identity, batch.first_cursor, overlap_last)?;
            if accepted != batch.prefix_bytes(overlap_count) {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "an evidence retry conflicts with accepted record content".to_owned(),
                }
                .fail();
            }
            if batch.last_cursor <= cursor.contiguous_cursor {
                return Ok(EvidenceStoreOutcomeV1::Accepted);
            }

            // An acknowledgement can be lost while the node extends its current WAL batch.
            // Commit only the new suffix after the accepted prefix matches durable records.
            batch = batch.split_off(overlap_count);
            validate_evidence_batch_input(&batch, &inner.root)?;
        }
        while let Some(existing) = inner
            .state
            .pending_evidence_batches
            .get(&EvidencePendingKeyV1 {
                identity: identity.clone(),
                first_cursor: batch.first_cursor,
            })
            .cloned()
        {
            let existing_records =
                usize::try_from(existing.last_cursor - existing.first_cursor + 1)
                    .unwrap_or(usize::MAX);
            let shared = batch.record_count().min(existing_records);
            let existing_prefix = inner.read_evidence_frames(
                &identity,
                &existing,
                existing.first_cursor,
                existing.first_cursor + shared as u64 - 1,
            )?;
            if batch.prefix_bytes(shared) != existing_prefix {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "pending evidence ranges overlap or conflict".to_owned(),
                }
                .fail();
            }
            if batch.record_count() <= existing_records {
                return Ok(EvidenceStoreOutcomeV1::Pending);
            }

            // The node can extend an unacknowledged WAL batch. Keep the durable
            // prefix and persist only its new contiguous suffix.
            batch = batch.split_off(existing_records);
            validate_evidence_batch_input(&batch, &inner.root)?;
        }
        for (key, existing) in inner
            .state
            .pending_evidence_batches
            .iter()
            .filter(|(key, _batch)| key.identity == identity)
        {
            let overlaps =
                batch.first_cursor <= existing.last_cursor && key.first_cursor <= batch.last_cursor;
            if overlaps {
                if key.first_cursor == batch.first_cursor
                    && existing.last_cursor == batch.last_cursor
                    && inner.read_evidence_frames(
                        &identity,
                        existing,
                        batch.first_cursor,
                        batch.last_cursor,
                    )? == batch.framed_records
                {
                    return Ok(EvidenceStoreOutcomeV1::Pending);
                }
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "pending evidence ranges overlap or conflict".to_owned(),
                }
                .fail();
            }
        }
        let next = checked_store_increment(
            cursor.contiguous_cursor,
            &inner.root,
            "the evidence cursor is exhausted",
        )?;
        if batch.first_cursor != next
            && batch.last_cursor
                > cursor
                    .contiguous_cursor
                    .saturating_add(MAX_PENDING_EVIDENCE_RECORDS)
        {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "out-of-order evidence exceeds the bounded pending window".to_owned(),
            }
            .fail();
        }
        let stream_id = evidence_stream_id_for_write(&inner.state, &identity, &inner.root)?;
        let mut batches = inner.evidence_segments.write_frames(
            &identity,
            stream_id,
            batch.first_cursor,
            batch.last_cursor,
            batch.framed_records,
            batch.frame_ends,
        )?;
        let first_stored_cursor =
            batches
                .first()
                .map(|batch| batch.first_cursor)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: inner.root.clone(),
                        reason: "the evidence segment group is empty".to_owned(),
                    }
                    .build()
                })?;
        if first_stored_cursor != next {
            // A bounded gap can close when an earlier retained Node batch arrives.
            for batch in batches {
                inner.publish_evidence_segment(ControlTransactionV1::EvidencePending {
                    stream_id,
                    pending: Box::new(EvidenceBatchTransactionV1 {
                        identity: identity.clone(),
                        batch,
                    }),
                })?;
            }
            return Ok(EvidenceStoreOutcomeV1::Pending);
        }

        // Promote the new batch and every now-contiguous pending batch in one commit.
        let mut next = batches
            .last()
            .and_then(|batch| batch.last_cursor.checked_add(1));
        while let Some(first_cursor) = next {
            let Some(pending) = inner
                .state
                .pending_evidence_batches
                .get(&EvidencePendingKeyV1 {
                    identity: identity.clone(),
                    first_cursor,
                })
                .cloned()
            else {
                break;
            };
            next = pending.last_cursor.checked_add(1);
            batches.push(pending);
        }
        inner.publish_evidence_segment(ControlTransactionV1::EvidenceAccepted {
            accepted: Box::new(EvidenceAcceptedTransactionV1 {
                identity,
                stream_id,
                batches,
            }),
        })?;
        Ok(EvidenceStoreOutcomeV1::Accepted)
    }

    pub fn install_trust_generation(&self, generation: TrustGenerationV1) -> Result<u64> {
        let mut inner = self.lock()?;
        // Durable trust monotonicity survives process restart and in-memory subscriber loss.
        if let Some((_number, current)) = inner.state.trust_generations.last_key_value() {
            if generation.generation < current.generation {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "the configured trust generation rolled back durable state".to_owned(),
                }
                .fail();
            }
        }
        if let Some(existing) = inner.state.trust_generations.get(&generation.generation) {
            if existing == &generation {
                return Ok(inner.state.commit_index);
            }
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "one trust generation has conflicting immutable content".to_owned(),
            }
            .fail();
        }
        commit(
            &mut inner,
            ControlTransactionV1::TrustInstalled {
                generation: Box::new(generation),
            },
        )
    }

    pub fn current_trust_generation(&self) -> Result<Option<TrustGenerationV1>> {
        Ok(self
            .lock()?
            .state
            .trust_generations
            .last_key_value()
            .map(|(_generation, trust)| trust.clone()))
    }

    pub fn acknowledge_trust_generation(
        &self,
        acknowledgement: TrustGenerationAcknowledgementV1,
    ) -> Result<u64> {
        let mut inner = self.lock()?;
        // Trust is acknowledged for one node boot and label epoch, not only one node name.
        let key = (
            acknowledgement.node_id.clone(),
            acknowledgement.generation,
            acknowledgement.node_boot_id,
            acknowledgement.label_epoch,
        );
        if let Some(existing) = inner.state.trust_acknowledgements.get(&key) {
            if existing == &acknowledgement {
                return Ok(inner.state.commit_index);
            }
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "one node trust acknowledgement has conflicting content".to_owned(),
            }
            .fail();
        }
        commit(
            &mut inner,
            ControlTransactionV1::TrustAcknowledged {
                acknowledgement: Box::new(acknowledgement),
            },
        )
    }

    pub fn latest_trust_acknowledgement(
        &self,
        node_id: &str,
    ) -> Result<Option<TrustGenerationAcknowledgementV1>> {
        Ok(self
            .lock()?
            .state
            .trust_acknowledgements
            .iter()
            .rfind(
                |((acknowledged_node, _generation, _boot, _label), _acknowledgement)| {
                    acknowledged_node == node_id
                },
            )
            .map(|(_key, acknowledgement)| acknowledgement.clone()))
    }

    pub fn trust_acknowledgement(
        &self,
        node_id: &str,
        node_boot_id: [u8; 16],
        label_epoch: u64,
        generation: u64,
    ) -> Result<Option<TrustGenerationAcknowledgementV1>> {
        Ok(self
            .lock()?
            .state
            .trust_acknowledgements
            .get(&(node_id.to_owned(), generation, node_boot_id, label_epoch))
            .cloned())
    }

    pub(crate) fn evidence_trust_acknowledgement(
        &self,
        node_id: &str,
        node_boot_id: [u8; 16],
        label_epoch: u64,
        generation: u64,
    ) -> Result<Option<TrustGenerationAcknowledgementV1>> {
        Ok(self
            .evidence_lock()?
            .state
            .trust_acknowledgements
            .get(&(node_id.to_owned(), generation, node_boot_id, label_epoch))
            .cloned())
    }

    pub(crate) fn accept_coverage_report(&self, input: CoverageReportInputV1) -> Result<u64> {
        let mut inner = self.evidence_lock()?;
        validate_evidence_identity(&input.identity, &inner.root)?;
        validate_source_label(&inner.state, &input.identity, &inner.root)?;
        if input.report.source_epoch != input.identity.source_epoch || input.report.revision == 0 {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "coverage evidence has invalid identity or revision".to_owned(),
            }
            .fail();
        }
        let consumed_revision = inner
            .state
            .evidence_consumption
            .get(&input.identity)
            .copied()
            .unwrap_or_default()
            .coverage_revision;
        if input.report.revision <= consumed_revision {
            return Ok(inner.state.commit_index);
        }
        let state = CoverageIntakeStateV1 {
            revision: input.report.revision,
        };
        let current = inner
            .state
            .coverage_cursors
            .get(&input.identity)
            .copied()
            .unwrap_or_default();
        if current == state {
            let stored = inner
                .state
                .coverage_reports
                .get(&CoverageReportKeyV1 {
                    identity: input.identity.clone(),
                    revision: state.revision,
                })
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: inner.root.clone(),
                        reason: "the current coverage revision has no stored segment".to_owned(),
                    }
                    .build()
                })?;
            let existing = inner.evidence_segments.read_coverage(
                stored.segment,
                EvidenceSegmentKindV1::Coverage {
                    stream_id: inner.stream_id(&input.identity)?,
                    first_revision: state.revision,
                    last_revision: state.revision,
                },
            )?;
            if existing == input.report {
                return Ok(inner.state.commit_index);
            }
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "one coverage revision has conflicting immutable content".to_owned(),
            }
            .fail();
        }
        if state.revision <= current.revision {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "coverage evidence is stale or has invalid identity".to_owned(),
            }
            .fail();
        }
        let stream_id = evidence_stream_id_for_write(&inner.state, &input.identity, &inner.root)?;
        let segment = inner.evidence_segments.write_coverage(
            &input.identity,
            stream_id,
            state.revision,
            &input.report,
        )?;
        let report = StoredCoverageReportV1 {
            identity: input.identity,
            state,
            segment,
        };
        inner.publish_evidence_segment(ControlTransactionV1::CoverageAccepted {
            stream_id,
            report: Box::new(report),
        })
    }

    pub fn evidence_cursor(&self, identity: &EvidenceIntakeIdentityV1) -> Result<u64> {
        Ok(self
            .lock()?
            .state
            .evidence_cursors
            .get(identity)
            .map_or(0, |cursor| cursor.contiguous_cursor))
    }

    pub fn accepted_evidence_records(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Vec<EvidenceRecord>> {
        let inner = self.lock()?;
        let mut records = Vec::new();
        for (_key, batch) in inner
            .state
            .evidence_batches
            .iter()
            .filter(|(key, _batch)| &key.identity == identity)
        {
            records.extend(inner.read_evidence_records(identity, batch)?);
        }
        Ok(records)
    }

    pub(crate) fn acknowledge_evidence_consumption(
        &self,
        watermark: EvidenceConsumptionWatermarkV1,
    ) -> Result<u64> {
        let mut inner = self.evidence_lock()?;
        let commit_index = commit(
            &mut inner,
            ControlTransactionV1::EvidenceConsumed {
                watermark: Box::new(watermark),
            },
        )?;
        let references = retained_evidence_segment_refs(&inner.state);
        inner.evidence_segments.reclaim_unreferenced(&references)?;
        inner.evidence_segments.validate_retention()?;
        Ok(commit_index)
    }

    pub(crate) fn evidence_consumption(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<EvidenceConsumptionStateV1> {
        Ok(self
            .evidence_lock()?
            .state
            .evidence_consumption
            .get(identity)
            .copied()
            .unwrap_or_default())
    }

    pub(crate) fn latest_coverage_report(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<CoverageReport>> {
        let inner = self.lock()?;
        let stored = inner
            .state
            .coverage_cursors
            .get(identity)
            .and_then(|cursor| {
                inner
                    .state
                    .coverage_reports
                    .get(&CoverageReportKeyV1 {
                        identity: identity.clone(),
                        revision: cursor.revision,
                    })
                    .cloned()
            });
        stored
            .map(|stored| {
                inner.evidence_segments.read_coverage(
                    stored.segment,
                    EvidenceSegmentKindV1::Coverage {
                        stream_id: inner.stream_id(identity)?,
                        first_revision: stored.state.revision,
                        last_revision: stored.state.revision,
                    },
                )
            })
            .transpose()
    }

    pub fn source_revision(&self, id: &str) -> Result<Option<PolicySourceRevisionV1>> {
        Ok(self.lock()?.state.source_revisions.get(id).cloned())
    }

    pub fn active_policy_for_workload(
        &self,
        policy_source_revision_id: &str,
        workload_binding_generation_digest: &str,
    ) -> Result<Option<(PolicyBundleV1, PolicyActivationAcknowledgementV1)>> {
        let inner = self.lock()?;
        let matches = inner
            .state
            .rollout_states
            .values()
            .filter(|rollout| {
                rollout.policy_source_revision_id == policy_source_revision_id
                    && rollout.state == crate::PolicyRolloutStatusV1::Active
                    && rollout
                        .target
                        .workload_binding_generation_digests
                        .iter()
                        .any(|digest| digest == workload_binding_generation_digest)
            })
            .filter_map(|rollout| {
                let bundle = inner
                    .state
                    .bundles
                    .get(&rollout.desired_candidate_content_id)?;
                if !latest_profile_bundle(&inner.state, bundle).is_some_and(|current| {
                    current.candidate.candidate_content_id == bundle.candidate.candidate_content_id
                }) {
                    return None;
                }
                let acknowledgement = rollout
                    .latest_acknowledgement_content_id
                    .as_ref()
                    .and_then(|id| inner.state.policy_acknowledgement_results.get(id))?
                    .acknowledgement
                    .clone();
                Some((bundle.clone(), acknowledgement))
            })
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "one workload has multiple active base-policy targets".to_owned(),
            }
            .fail();
        }
        Ok(matches.into_iter().next())
    }

    pub fn latest_exception_source(
        &self,
        tenant_id: &str,
        namespace_uid: &str,
        object_name: &str,
    ) -> Result<Option<ExceptionSourceRevisionV1>> {
        let inner = self.lock()?;
        let key = PolicyObjectKeyV1 {
            tenant_id: tenant_id.to_owned(),
            namespace_uid: namespace_uid.to_owned(),
            object_name: object_name.to_owned(),
        };
        Ok(inner
            .state
            .latest_exception_sources
            .get(&key)
            .and_then(|id| inner.state.exception_source_revisions.get(id))
            .cloned())
    }

    pub fn latest_live_exception_sources(&self) -> Result<Vec<ExceptionSourceRevisionV1>> {
        let inner = self.lock()?;
        Ok(inner
            .state
            .latest_exception_sources
            .values()
            .filter_map(|source_id| {
                inner
                    .state
                    .exception_source_revisions
                    .get(source_id)
                    .filter(|source| source.state == ExceptionSourceStateV1::Accepted)
                    .cloned()
            })
            .collect())
    }

    pub fn latest_exception_candidate_for_object(
        &self,
        object_uid: &str,
    ) -> Result<Option<ExceptionDeliveryCandidateV1>> {
        let inner = self.lock()?;
        Ok(inner
            .state
            .exception_candidates
            .values()
            .filter(|candidate| candidate.exception_instance_id == object_uid)
            .max_by_key(|candidate| {
                (
                    candidate.distribution_sequence_epoch,
                    candidate.distribution_sequence,
                )
            })
            .cloned())
    }

    pub fn next_exception_candidate_for_node(
        &self,
        node_id: &str,
        known_candidate_ids: &[String],
    ) -> Result<Option<ExceptionDeliveryCandidateV1>> {
        let inner = self.lock()?;
        Ok(next_exception_candidate(&inner.state, node_id, known_candidate_ids, None).cloned())
    }

    pub(crate) fn next_exception_candidate_for_session(
        &self,
        node_id: &str,
        node_boot_id: &[u8],
        label_epoch: u64,
        known_candidate_ids: &[String],
    ) -> Result<Option<ExceptionDeliveryCandidateV1>> {
        let inner = self.lock()?;
        let session = current_physical_epoch(&inner.state, node_id, node_boot_id, label_epoch)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "exception inventory does not match the current physical session"
                        .to_owned(),
                }
                .build()
            })?;
        Ok(
            next_exception_candidate(&inner.state, node_id, known_candidate_ids, Some(&session))
                .cloned(),
        )
    }

    pub fn exception_candidate(
        &self,
        node_id: &str,
        candidate_content_id: &str,
    ) -> Result<Option<ExceptionDeliveryCandidateV1>> {
        Ok(self
            .lock()?
            .state
            .exception_candidates
            .get(candidate_content_id)
            .filter(|candidate| candidate.exact_target.node_id == node_id)
            .cloned())
    }

    pub fn exception_rollout_state(
        &self,
        candidate_content_id: &str,
        node_id: &str,
    ) -> Result<Option<ExceptionRolloutStateV1>> {
        Ok(self
            .lock()?
            .state
            .exception_rollout_states
            .get(&PolicyRolloutKeyV1 {
                candidate_content_id: candidate_content_id.to_owned(),
                node_id: node_id.to_owned(),
            })
            .cloned())
    }

    pub fn policy_document(&self, id: &str) -> Result<Option<PolicyDocumentV1>> {
        Ok(self.lock()?.state.policy_documents.get(id).cloned())
    }

    pub fn compiled_artifact(
        &self,
        policy_source_revision_id: &str,
    ) -> Result<Option<ProfileCandidateArtifactV1>> {
        Ok(self
            .lock()?
            .state
            .compiled_artifacts
            .get(policy_source_revision_id)
            .cloned())
    }

    pub fn latest_snapshot_for_source(
        &self,
        policy_source_revision_id: &str,
    ) -> Result<Option<PolicyTargetSnapshotV1>> {
        let inner = self.lock()?;
        if let Some(snapshot) = inner
            .state
            .latest_desired_snapshots
            .get(policy_source_revision_id)
            .and_then(|digest| inner.state.target_snapshots.get(digest))
        {
            return Ok(Some(snapshot.clone()));
        }
        // Legacy deletion rollouts have no desired-snapshot index.
        Ok(inner
            .state
            .target_snapshots
            .values()
            .filter(|snapshot| snapshot.policy_source_revision_id == policy_source_revision_id)
            .max_by_key(|snapshot| snapshot.rollout_generation)
            .cloned())
    }

    pub fn latest_live_sources(&self) -> Result<Vec<(PolicySourceRevisionV1, PolicyDocumentV1)>> {
        let inner = self.lock()?;
        Ok(inner
            .state
            .latest_sources
            .values()
            .filter_map(|source_id| {
                let revision = inner.state.source_revisions.get(source_id)?;
                let document = inner.state.policy_documents.get(source_id)?;
                (revision.state == PolicySourceStateV1::Accepted)
                    .then(|| (revision.clone(), document.clone()))
            })
            .collect())
    }

    pub fn next_distribution_sequence(
        &self,
        node_id: &str,
        tenant_id: &str,
        trust_domain_id: &str,
        profile_id: &str,
        sequence_epoch: u64,
    ) -> Result<u64> {
        let inner = self.lock()?;
        // Candidate distribution has a replay domain independent of policy issuer sequence.
        let mut current = 0_u64;
        for bundle in inner.state.bundles.values().filter(|bundle| {
            bundle.candidate.exact_target.node_id == node_id
                && bundle_matches_profile(bundle, tenant_id, trust_domain_id, profile_id)
        }) {
            let candidate = &bundle.candidate;
            if candidate.distribution_sequence_epoch > sequence_epoch {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "the configured candidate-distribution epoch is stale".to_owned(),
                }
                .fail();
            }
            if candidate.distribution_sequence_epoch == sequence_epoch {
                current = current.max(candidate.distribution_sequence);
            }
        }
        current.checked_add(1).ok_or_else(|| {
            ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "the candidate-distribution sequence is exhausted".to_owned(),
            }
            .build()
        })
    }

    pub(crate) fn latest_open_bundle_for_profile_node(
        &self,
        target: &PolicyTargetV1,
        tenant_id: &str,
        trust_domain_id: &str,
        profile_id: &str,
    ) -> Result<Option<PolicyBundleV1>> {
        let inner = self.lock()?;
        Ok(latest_viable_bundle(
            &inner.state,
            inner.state.bundles.values().filter(|bundle| {
                bundle
                    .candidate
                    .exact_target
                    .is_same_physical_node_epoch(target)
                    && bundle_matches_profile(bundle, tenant_id, trust_domain_id, profile_id)
            }),
        )
        .cloned())
    }

    pub fn latest_bundles_for_object(&self, object_uid: &str) -> Result<Vec<PolicyBundleV1>> {
        let inner = self.lock()?;
        Ok(latest_object_bundles(&inner.state, object_uid)
            .into_iter()
            .cloned()
            .collect())
    }

    pub fn latest_source(
        &self,
        tenant_id: &str,
        namespace_uid: &str,
        object_name: &str,
    ) -> Result<Option<PolicySourceRevisionV1>> {
        let inner = self.lock()?;
        let key = PolicyObjectKeyV1 {
            tenant_id: tenant_id.to_owned(),
            namespace_uid: namespace_uid.to_owned(),
            object_name: object_name.to_owned(),
        };
        Ok(inner
            .state
            .latest_sources
            .get(&key)
            .and_then(|id| inner.state.source_revisions.get(id))
            .cloned())
    }

    pub fn bundle_for_node(&self, node_id: &str) -> Result<Option<PolicyBundleV1>> {
        let inner = self.lock()?;
        Ok(inner
            .state
            .bundles
            .values()
            .filter(|bundle| bundle.candidate.exact_target.node_id == node_id)
            .max_by_key(|bundle| {
                (
                    bundle.candidate.distribution_sequence_epoch,
                    bundle.candidate.distribution_sequence,
                )
            })
            .cloned())
    }

    pub fn next_bundle_for_node(
        &self,
        node_id: &str,
        durable_bundle_digests: &[String],
    ) -> Result<Option<PolicyBundleV1>> {
        let inner = self.lock()?;
        Ok(next_policy_bundle(&inner.state, node_id, durable_bundle_digests, None).cloned())
    }

    pub(crate) fn policy_inventory_for_node_session(
        &self,
        node_id: &str,
        node_boot_id: &[u8],
        label_epoch: u64,
        durable_bundle_digests: &[String],
    ) -> Result<(Option<PolicyBundleV1>, Vec<String>)> {
        let inner = self.lock()?;
        let session = current_physical_epoch(&inner.state, node_id, node_boot_id, label_epoch)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "policy inventory does not match the current physical session"
                        .to_owned(),
                }
                .build()
            })?;
        let candidate = next_policy_bundle(
            &inner.state,
            node_id,
            durable_bundle_digests,
            Some(&session),
        )
        .cloned();
        let mut desired_bundle_digests = inner
            .state
            .bundles
            .values()
            .filter(|bundle| {
                bundle.candidate.exact_target.node_id == node_id
                    && policy_target_matches_epoch(&bundle.candidate.exact_target, &session)
                    && bundle_is_current_desired(&inner.state, bundle)
            })
            .map(|bundle| bundle.bundle_digest.clone())
            .collect::<Vec<_>>();
        desired_bundle_digests.sort();
        desired_bundle_digests.dedup();
        if desired_bundle_digests.len() > 256 {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "the desired policy inventory exceeds the node profile bound".to_owned(),
            }
            .fail();
        }
        Ok((candidate, desired_bundle_digests))
    }

    pub fn candidate_is_current_or_unsettled_predecessor(
        &self,
        node_id: &str,
        candidate_content_id: &str,
    ) -> Result<bool> {
        let inner = self.lock()?;
        Ok(candidate_is_current_or_unsettled_predecessor(
            &inner.state,
            node_id,
            candidate_content_id,
        ))
    }

    pub fn bundle_for_candidate(
        &self,
        node_id: &str,
        candidate_content_id: &str,
    ) -> Result<Option<PolicyBundleV1>> {
        Ok(self
            .lock()?
            .state
            .bundles
            .get(candidate_content_id)
            .filter(|bundle| bundle.candidate.exact_target.node_id == node_id)
            .cloned())
    }

    pub(crate) fn bundle_for_candidate_for_session(
        &self,
        node_id: &str,
        node_boot_id: &[u8],
        label_epoch: u64,
        candidate_content_id: &str,
    ) -> Result<Option<PolicyBundleV1>> {
        let inner = self.lock()?;
        let session = current_physical_epoch(&inner.state, node_id, node_boot_id, label_epoch)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "policy fetch does not match the current physical session".to_owned(),
                }
                .build()
            })?;
        Ok(inner
            .state
            .bundles
            .get(candidate_content_id)
            .filter(|bundle| policy_target_matches_epoch(&bundle.candidate.exact_target, &session))
            .cloned())
    }

    pub fn rollout_state(
        &self,
        candidate_content_id: &str,
        node_id: &str,
    ) -> Result<Option<PolicyRolloutStateV1>> {
        Ok(self
            .lock()?
            .state
            .rollout_states
            .get(&PolicyRolloutKeyV1 {
                candidate_content_id: candidate_content_id.to_owned(),
                node_id: node_id.to_owned(),
            })
            .cloned())
    }

    pub fn rollout_states_for_snapshot(
        &self,
        target_snapshot_digest: &str,
    ) -> Result<Vec<PolicyRolloutStateV1>> {
        Ok(self
            .lock()?
            .state
            .rollout_states
            .values()
            .filter(|state| state.target_snapshot_digest == target_snapshot_digest)
            .cloned()
            .collect())
    }

    pub fn bundles_for_snapshot(
        &self,
        target_snapshot_digest: &str,
    ) -> Result<Vec<PolicyBundleV1>> {
        let mut bundles = self
            .lock()?
            .state
            .bundles
            .values()
            .filter(|bundle| bundle.candidate.target_snapshot_digest == target_snapshot_digest)
            .cloned()
            .collect::<Vec<_>>();
        bundles.sort_by(|left, right| {
            left.candidate
                .exact_target
                .cmp(&right.candidate.exact_target)
        });
        Ok(bundles)
    }

    #[must_use]
    pub fn root(&self) -> PathBuf {
        self.inner
            .priority_lock()
            .map_or_else(PathBuf::new, |inner| inner.root.clone())
    }

    #[must_use]
    pub fn commit_index(&self) -> u64 {
        self.inner
            .priority_lock()
            .map_or(0, |inner| inner.state.commit_index)
    }

    #[cfg(feature = "test-fixtures")]
    pub fn write_retained_evidence_for_test(
        &self,
        batch_count: u64,
        records_per_batch: usize,
    ) -> Result<u64> {
        if self.commit_index() != 0 || batch_count == 0 || records_per_batch == 0 {
            return ControlStoreSnafu {
                path: self.root(),
                reason:
                    "the retained-evidence fixture requires a fresh store and valid batch bounds"
                        .to_owned(),
            }
            .fail();
        }
        let node_boot_id = [1; 16];
        let proof = startup_absence_proof_digest("node-a", &node_boot_id, 1, true, true);
        self.register_node_physical_session(
            "node-a",
            &node_boot_id,
            1,
            Some("worker-a"),
            &proof,
            true,
            true,
            1,
        )?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [2; 16],
            node_id: "node-a".to_owned(),
            node_boot_id,
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let root = self.root();
        let mut cursor = 1_u64;
        for _batch in 0..batch_count {
            let first_cursor = cursor;
            let mut records = Vec::with_capacity(records_per_batch);
            for _record in 0..records_per_batch {
                records.push(EvidenceRecord {
                    observed_boottime_ns: cursor,
                    ingested_utc_ns: i64::try_from(cursor).unwrap_or(i64::MAX),
                    coverage_interval_id: vec![4; 16].into(),
                    task_cookie: cursor,
                    process_lineage_id: vec![5; 16].into(),
                    authority_domain_id: vec![6; 16].into(),
                    execution_set_id: vec![7; 16].into(),
                    exact_object_id: vec![8; 16].into(),
                    policy_rule_id: 1,
                    reason: 1,
                    decision: 1,
                    effect_family: 1,
                    operation: 1,
                    configured_errno: -13,
                    kernel_result: -13,
                    temporal_coverage: crate::EvidenceTemporalCoverage::Complete as i32,
                    ..EvidenceRecord::default()
                });
                cursor = checked_store_increment(
                    cursor,
                    &root,
                    "the retained-evidence fixture cursor is exhausted",
                )?;
            }
            if self.accept_evidence_batch(
                identity.clone(),
                EvidenceBatchInputV1::encode(first_cursor, records)?,
            )? != EvidenceStoreOutcomeV1::Accepted
            {
                return ControlStoreSnafu {
                    path: root,
                    reason: "the retained-evidence fixture did not commit a contiguous batch"
                        .to_owned(),
                }
                .fail();
            }
        }

        let mut stored_bytes = fs::metadata(root.join("state.bin"))
            .context(IoSnafu { path: &root })?
            .len();
        let directory = root.join("evidence/segments-v2");
        for entry in fs::read_dir(&directory).context(IoSnafu { path: &directory })? {
            let path = entry.context(IoSnafu { path: &directory })?.path();
            stored_bytes = stored_bytes
                .saturating_add(fs::metadata(&path).context(IoSnafu { path: &path })?.len());
        }
        Ok(stored_bytes)
    }
    #[cfg(feature = "test-fixtures")]
    pub fn pause_next_evidence_wait_for_test(
        &self,
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    ) -> bool {
        self.inner
            .evidence_wait_barriers
            .lock()
            .map(|mut barriers| *barriers = Some((entered, release)))
            .is_ok()
    }

    #[cfg(feature = "test-fixtures")]
    pub fn hold_priority_for_test(&self, entered: &Barrier, release: &Barrier) -> Result<()> {
        let _guard = self.lock()?;
        entered.wait();
        release.wait();
        Ok(())
    }

    fn lock(&self) -> Result<ControlStorePriorityGuard<'_>> {
        self.inner.priority_lock().ok_or_else(|| {
            ControlStoreSnafu {
                path: PathBuf::from("<poisoned-control-store>"),
                reason: "the Control store lock is poisoned".to_owned(),
            }
            .build()
        })
    }

    fn evidence_lock(&self) -> Result<MutexGuard<'_, ControlStoreInner>> {
        self.inner.evidence_lock().ok_or_else(|| {
            ControlStoreSnafu {
                path: PathBuf::from("<poisoned-control-store>"),
                reason: "the Control store lock is poisoned".to_owned(),
            }
            .build()
        })
    }
}

fn current_physical_epoch(
    state: &ControlStoreState,
    node_id: &str,
    node_boot_id: &[u8],
    label_epoch: u64,
) -> Option<NodePhysicalEpochV1> {
    state.node_sessions.get(node_id).and_then(|session| {
        (session.node_boot_id == node_boot_id && session.label_epoch == label_epoch)
            .then(|| session.physical_epoch())
    })
}

fn node_session_matches_acknowledgement(
    state: &ControlStoreState,
    node_id: &str,
    node_boot_id: &[u8],
    label_epoch: u64,
) -> bool {
    state.node_sessions.get(node_id).is_none_or(|session| {
        session.node_boot_id == node_boot_id && session.label_epoch == label_epoch
    })
}

fn next_policy_bundle<'a>(
    state: &'a ControlStoreState,
    node_id: &str,
    durable_bundle_digests: &[String],
    session: Option<&NodePhysicalEpochV1>,
) -> Option<&'a PolicyBundleV1> {
    let matches_session = |bundle: &PolicyBundleV1| {
        session.is_none_or(|session| {
            policy_target_matches_epoch(&bundle.candidate.exact_target, session)
        })
    };
    let mut active_by_profile = BTreeMap::<(&str, &str, &str), &PolicyBundleV1>::new();
    for bundle in state.bundles.values().filter(|bundle| {
        bundle.candidate.exact_target.node_id == node_id
            && matches_session(bundle)
            && durable_bundle_digests.contains(&bundle.bundle_digest)
    }) {
        let key = bundle_profile_key(bundle);
        let replace = active_by_profile
            .get(&key)
            .is_none_or(|current| bundle_sequence(bundle) > bundle_sequence(current));
        if replace {
            active_by_profile.insert(key, bundle);
        }
    }
    // Only the current physical epoch can use node-reported digests as chain progress.
    state
        .bundles
        .values()
        .filter_map(|bundle| {
            if bundle.candidate.exact_target.node_id != node_id
                || !matches_session(bundle)
                || !bundle_is_current_desired(state, bundle)
                || bundle_is_in_closed_terminal_chain(state, bundle)
            {
                return None;
            }
            let rollout = state.rollout_states.get(&PolicyRolloutKeyV1 {
                candidate_content_id: bundle.candidate.candidate_content_id.clone(),
                node_id: node_id.to_owned(),
            })?;
            let eligible = match rollout.state {
                crate::PolicyRolloutStatusV1::Rejected | crate::PolicyRolloutStatusV1::Stale => {
                    false
                }
                crate::PolicyRolloutStatusV1::Active => {
                    !durable_bundle_digests.contains(&bundle.bundle_digest)
                }
                crate::PolicyRolloutStatusV1::Pending
                | crate::PolicyRolloutStatusV1::Delivered
                | crate::PolicyRolloutStatusV1::Staged
                | crate::PolicyRolloutStatusV1::Unknown => true,
            };
            let active_candidate = active_by_profile
                .get(&bundle_profile_key(bundle))
                .map(|active| active.candidate.candidate_content_id.as_str());
            let predecessor_ready = match bundle.candidate.operation {
                crate::PolicyDeliveryOperationV1::Activate => {
                    active_candidate.is_none()
                        && bundle.candidate.predecessor_candidate_content_id.is_none()
                }
                crate::PolicyDeliveryOperationV1::Replace => {
                    bundle.candidate.predecessor_candidate_content_id.is_some()
                }
                crate::PolicyDeliveryOperationV1::RetireToRestrictiveTerminal => {
                    bundle.candidate.predecessor_candidate_content_id.as_deref() == active_candidate
                }
            };
            (eligible && predecessor_ready).then_some(bundle)
        })
        .min_by_key(|bundle| {
            (
                bundle.candidate.distribution_sequence_epoch,
                bundle.candidate.distribution_sequence,
                bundle.candidate.candidate_content_id.as_str(),
            )
        })
}

fn bundle_is_current_desired(state: &ControlStoreState, bundle: &PolicyBundleV1) -> bool {
    let Some(source) = state
        .source_revisions
        .get(&bundle.candidate.policy_source_revision_id)
    else {
        return false;
    };
    current_desired_snapshot_for_object(state, source).is_some_and(|(source_id, digest)| {
        source_id == &bundle.candidate.policy_source_revision_id
            && digest == &bundle.candidate.target_snapshot_digest
    })
}

fn current_desired_snapshot_for_object<'a>(
    state: &'a ControlStoreState,
    source: &PolicySourceRevisionV1,
) -> Option<(&'a String, &'a String)> {
    let key = PolicyObjectKeyV1::from(source);
    let latest_id = state.latest_sources.get(&key)?;
    let latest = state.source_revisions.get(latest_id)?;
    if latest.state != PolicySourceStateV1::Accepted {
        return None;
    }
    if let Some(digest) = state.latest_desired_snapshots.get(latest_id) {
        return Some((latest_id, digest));
    }
    state
        .source_revisions
        .values()
        .filter(|revision| {
            revision.state == PolicySourceStateV1::Accepted
                && PolicyObjectKeyV1::from(*revision) == key
                && revision.policy_source_revision_id != *latest_id
        })
        .filter_map(|revision| {
            state
                .latest_desired_snapshots
                .get(&revision.policy_source_revision_id)
                .map(|digest| (revision, digest))
        })
        .max_by_key(|(revision, _)| revision.object_generation)
        .map(|(revision, digest)| (&revision.policy_source_revision_id, digest))
}

fn next_exception_candidate<'a>(
    state: &'a ControlStoreState,
    node_id: &str,
    known_candidate_ids: &[String],
    session: Option<&NodePhysicalEpochV1>,
) -> Option<&'a ExceptionDeliveryCandidateV1> {
    state
        .exception_candidates
        .values()
        .filter(|candidate| {
            let predecessor_ready = candidate.predecessor_candidate_content_id.as_ref().map_or(
                candidate.operation == ExceptionDeliveryOperationV1::Activate,
                |id| {
                    state
                        .exception_rollout_states
                        .get(&PolicyRolloutKeyV1 {
                            candidate_content_id: id.clone(),
                            node_id: node_id.to_owned(),
                        })
                        .is_some_and(|rollout| {
                            rollout.state != crate::WorkloadProtectionExceptionStateV1::Pending
                        })
                },
            );
            candidate.exact_target.node_id == node_id
                && session.is_none_or(|session| {
                    workload_target_matches_epoch(&candidate.exact_target, session)
                })
                && !known_candidate_ids.contains(&candidate.candidate_content_id)
                && predecessor_ready
                && state
                    .exception_rollout_states
                    .get(&PolicyRolloutKeyV1 {
                        candidate_content_id: candidate.candidate_content_id.clone(),
                        node_id: node_id.to_owned(),
                    })
                    .is_some_and(|rollout| {
                        // A node receives each candidate until its first durable state ACK.
                        rollout.state == crate::WorkloadProtectionExceptionStateV1::Pending
                    })
        })
        // Deliver the oldest ready chain member before any later revocation.
        .min_by_key(|candidate| {
            (
                candidate.issued_utc_ns,
                candidate.distribution_sequence_epoch,
                candidate.distribution_sequence,
                candidate.candidate_content_id.as_str(),
            )
        })
}

impl From<&PolicySourceRevisionV1> for PolicyObjectKeyV1 {
    fn from(revision: &PolicySourceRevisionV1) -> Self {
        Self {
            tenant_id: revision.tenant_id.clone(),
            namespace_uid: revision.namespace_uid.clone(),
            object_name: revision.object_name.clone(),
        }
    }
}

impl From<&ExceptionSourceRevisionV1> for PolicyObjectKeyV1 {
    fn from(revision: &ExceptionSourceRevisionV1) -> Self {
        Self {
            tenant_id: revision.tenant_id.clone(),
            namespace_uid: revision.namespace_uid.clone(),
            object_name: revision.object_name.clone(),
        }
    }
}

fn commit(inner: &mut ControlStoreInner, transaction: ControlTransactionV1) -> Result<u64> {
    let commit_index = checked_store_increment(
        inner.state.commit_index,
        &inner.root,
        "the Control commit index is exhausted",
    )?;
    let mut next_state = inner.state.clone();
    apply_transaction(&mut next_state, &transaction, &inner.root)?;
    next_state.commit_index = commit_index;
    inner.state_file.replace(&inner.root, &next_state)?;
    inner.state = next_state;
    debug!(
        "committed a Control store transaction",
        commit_index = %commit_index
    );
    Ok(commit_index)
}

fn checked_store_increment(value: u64, path: &Path, reason: &str) -> Result<u64> {
    value.checked_add(1).ok_or_else(|| {
        ControlStoreSnafu {
            path: path.to_owned(),
            reason: reason.to_owned(),
        }
        .build()
    })
}

fn node_session_advance(
    state: &ControlStoreState,
    session: DurableNodeSessionV1,
    observed_utc_ns: i64,
    path: &Path,
) -> Result<NodeSessionAdvanceTransactionV1> {
    let policy_rollout_states =
        stale_policy_rollouts_for_session(state, &session.physical_epoch(), observed_utc_ns, path)?;
    let exception_settlements =
        settle_exceptions_for_session(state, &session.physical_epoch(), observed_utc_ns, path)?;
    let advance = NodeSessionAdvanceTransactionV1 {
        session,
        policy_rollout_states,
        exception_settlements,
        observed_utc_ns,
    };
    validate_node_session_advance(state, &advance, path)?;
    Ok(advance)
}

fn validate_node_session_advance(
    state: &ControlStoreState,
    advance: &NodeSessionAdvanceTransactionV1,
    path: &Path,
) -> Result<()> {
    let session = &advance.session;
    let previous = state.node_sessions.get(&session.node_id);
    let identity_is_valid = crate::node_id_is_valid(&session.node_id)
        && session.node_boot_id.len() == 16
        && session.node_boot_id.iter().any(|byte| *byte != 0)
        && session.label_epoch > 0
        && session.kubernetes_node_uid.is_none()
        && session
            .kubernetes_node_name
            .as_deref()
            .is_none_or(kubernetes_node_name_is_valid)
        && session.startup_absence_proof_digest
            == startup_absence_proof_digest(
                &session.node_id,
                &session.node_boot_id,
                session.label_epoch,
                true,
                true,
            );
    // A higher label is the bounded anti-rollback counter for every physical reset.
    let epoch_is_advanced = previous.is_none_or(|previous| {
        session.label_epoch > previous.label_epoch
            && previous.kubernetes_node_name == session.kubernetes_node_name
    });
    let expected_policy = stale_policy_rollouts_for_session(
        state,
        &session.physical_epoch(),
        advance.observed_utc_ns,
        path,
    )?;
    let expected_exceptions = settle_exceptions_for_session(
        state,
        &session.physical_epoch(),
        advance.observed_utc_ns,
        path,
    )?;
    if !identity_is_valid
        || !epoch_is_advanced
        || advance.observed_utc_ns <= 0
        || advance.policy_rollout_states != expected_policy
        || advance.exception_settlements != expected_exceptions
    {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "a node-session advance is not exact, monotonic, or absence bound".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn stale_policy_rollouts_for_session(
    state: &ControlStoreState,
    session: &NodePhysicalEpochV1,
    observed_utc_ns: i64,
    path: &Path,
) -> Result<Vec<PolicyRolloutStateV1>> {
    state
        .rollout_states
        .iter()
        .filter_map(|(key, rollout)| {
            let bundle = state.bundles.get(&key.candidate_content_id)?;
            (key.node_id == session.node_id
                && !policy_target_matches_epoch(&bundle.candidate.exact_target, session)
                && !matches!(
                    rollout.state,
                    crate::PolicyRolloutStatusV1::Rejected | crate::PolicyRolloutStatusV1::Stale
                ))
            .then_some((rollout, key))
        })
        .map(|(rollout, key)| {
            Ok(PolicyRolloutStateV1 {
                state: crate::PolicyRolloutStatusV1::Stale,
                transition_version: rollout.transition_version.checked_add(1).ok_or_else(|| {
                    ControlStoreSnafu {
                        path: path.to_owned(),
                        reason: format!(
                            "policy rollout {} exhausted its session transition",
                            key.candidate_content_id
                        ),
                    }
                    .build()
                })?,
                updated_utc_ns: observed_utc_ns,
                ..rollout.clone()
            })
        })
        .collect()
}

fn settle_exceptions_for_session(
    state: &ControlStoreState,
    session: &NodePhysicalEpochV1,
    observed_utc_ns: i64,
    path: &Path,
) -> Result<Vec<ExceptionSessionSettlementV1>> {
    state
        .exception_rollout_states
        .iter()
        .filter_map(|(key, rollout)| {
            let candidate = state.exception_candidates.get(&key.candidate_content_id)?;
            (key.node_id == session.node_id
                && !workload_target_matches_epoch(&candidate.exact_target, session)
                && matches!(
                    rollout.state,
                    crate::WorkloadProtectionExceptionStateV1::Pending
                        | crate::WorkloadProtectionExceptionStateV1::Active
                ))
            .then_some((rollout, candidate, key))
        })
        .map(|(rollout, candidate, key)| {
            let source_requests_deletion = state
                .exception_source_revisions
                .get(&candidate.exception_source_revision_id)
                .is_some_and(|source| source.state == ExceptionSourceStateV1::DeletionRequested);
            let (settled_state, consumed_uses) = if candidate.operation
                == ExceptionDeliveryOperationV1::Revoke
                || source_requests_deletion
            {
                (
                    crate::WorkloadProtectionExceptionStateV1::Revoked,
                    state.exception_consumed_uses.get(key).copied().unwrap_or(0),
                )
            } else if candidate.valid_until_utc_ns <= observed_utc_ns {
                (
                    crate::WorkloadProtectionExceptionStateV1::Expired,
                    state.exception_consumed_uses.get(key).copied().unwrap_or(0),
                )
            } else {
                // Authority can have consumed its complete budget before the absence proof.
                (
                    crate::WorkloadProtectionExceptionStateV1::Consumed,
                    candidate.maximum_uses,
                )
            };
            Ok(ExceptionSessionSettlementV1 {
                rollout_state: ExceptionRolloutStateV1 {
                    state: settled_state,
                    transition_version: rollout.transition_version.checked_add(1).ok_or_else(
                        || {
                            ControlStoreSnafu {
                                path: path.to_owned(),
                                reason: format!(
                                    "exception rollout {} exhausted its session transition",
                                    key.candidate_content_id
                                ),
                            }
                            .build()
                        },
                    )?,
                    updated_utc_ns: observed_utc_ns,
                    ..rollout.clone()
                },
                consumed_uses,
            })
        })
        .collect()
}

fn policy_target_matches_epoch(
    target: &crate::PolicyTargetV1,
    session: &NodePhysicalEpochV1,
) -> bool {
    target.node_id == session.node_id
        && !target.workload_targets.is_empty()
        && target
            .workload_targets
            .iter()
            .all(|target| workload_target_matches_epoch(target, session))
}

fn workload_target_matches_epoch(
    target: &crate::WorkloadTargetFactV1,
    session: &NodePhysicalEpochV1,
) -> bool {
    target.node_id == session.node_id
        && target.kubernetes.as_ref().is_some_and(|identity| {
            identity.node_boot_id == hex::encode(&session.node_boot_id)
                && identity.label_epoch == session.label_epoch
        })
}

fn validate_kubernetes_node_binding(
    state: &ControlStoreState,
    binding: &KubernetesNodeBindingTransactionV1,
    path: &Path,
) -> Result<()> {
    let current = state.node_sessions.get(&binding.physical_epoch.node_id);
    let valid = current.is_some_and(|session| {
        session.physical_epoch() == binding.physical_epoch
            && session.kubernetes_node_name.as_deref() == Some(&binding.kubernetes_node_name)
            && session.kubernetes_node_uid.as_deref() != Some(&binding.kubernetes_node_uid)
    }) && kubernetes_node_name_is_valid(&binding.kubernetes_node_name)
        && uuid::Uuid::parse_str(&binding.kubernetes_node_uid)
            .is_ok_and(|uid| uid.hyphenated().to_string() == binding.kubernetes_node_uid);
    if !valid {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "a Kubernetes Node binding is not exact or current".to_owned(),
        }
        .fail();
    }
    Ok(())
}

pub(crate) fn kubernetes_node_name_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn validate_source_acceptance(
    state: &ControlStoreState,
    revision: &PolicySourceRevisionV1,
    policy_document: &PolicyDocumentV1,
    path: &Path,
) -> Result<()> {
    if revision.policy_document_digest != canonical_policy_spec_digest(policy_document)? {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the source revision does not bind the supplied policy document".to_owned(),
        }
        .fail();
    }
    let key = PolicyObjectKeyV1::from(revision);
    let Some(current_id) = state.latest_sources.get(&key) else {
        return Ok(());
    };
    let current = state.source_revisions.get(current_id).ok_or_else(|| {
        ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the latest source index has no source revision".to_owned(),
        }
        .build()
    })?;
    if current == revision {
        return Ok(());
    }
    if current.object_uid != revision.object_uid {
        if current.state == PolicySourceStateV1::Accepted {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "a recreated policy object arrived before retirement of the prior UID"
                    .to_owned(),
            }
            .fail();
        }
    } else if revision.object_generation < current.object_generation {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "a stale policy generation cannot replace the current source revision"
                .to_owned(),
        }
        .fail();
    } else if revision.object_generation == current.object_generation {
        // Kubernetes deletion keeps the generation and changes only the lifecycle state.
        let deletion_transition = current.state == PolicySourceStateV1::Accepted
            && revision.state == PolicySourceStateV1::DeletionRequested
            && revision.canonical_spec_digest == current.canonical_spec_digest
            && revision.policy_document_digest == current.policy_document_digest;
        if !deletion_transition {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "one policy generation has conflicting source bytes or lifecycle state"
                    .to_owned(),
            }
            .fail();
        }
    }
    Ok(())
}

fn validate_compiled_artifact(
    state: &ControlStoreState,
    source: &PolicySourceRevisionV1,
    policy_document: &PolicyDocumentV1,
    artifact: &ProfileCandidateArtifactV1,
    path: &Path,
) -> Result<()> {
    let document_is_valid = artifact.policy_document == *policy_document
        || (source.state == PolicySourceStateV1::DeletionRequested
            && artifact.policy_document == crate::restrictive_terminal_document(policy_document));
    let issuer_order_is_valid = state.compiled_artifacts.values().all(|existing| {
        existing.signed_profile.signing_key_id != artifact.signed_profile.signing_key_id
            || existing.header.sequence_epoch < artifact.header.sequence_epoch
            || (existing.header.sequence_epoch == artifact.header.sequence_epoch
                && existing.header.issuer_sequence < artifact.header.issuer_sequence)
    });
    if !document_is_valid || !issuer_order_is_valid {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the compiled artifact differs from its source or violates issuer ordering"
                .to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn validate_legacy_compiled_artifact(
    state: &ControlStoreState,
    policy_document: &PolicyDocumentV1,
    artifact: &ProfileCandidateArtifactV1,
    path: &Path,
) -> Result<()> {
    let issuer_order_is_valid = state.compiled_artifacts.values().all(|existing| {
        existing.signed_profile.signing_key_id != artifact.signed_profile.signing_key_id
            || existing.header.sequence_epoch < artifact.header.sequence_epoch
            || (existing.header.sequence_epoch == artifact.header.sequence_epoch
                && existing.header.issuer_sequence < artifact.header.issuer_sequence)
    });
    if artifact.policy_document != *policy_document || !issuer_order_is_valid {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the legacy artifact differs from its source or violates issuer ordering"
                .to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn legacy_deletion_artifact_upgrade(
    source: &PolicySourceRevisionV1,
    policy_document: &PolicyDocumentV1,
    current: &ProfileCandidateArtifactV1,
    replacement: &ProfileCandidateArtifactV1,
) -> bool {
    source.state == PolicySourceStateV1::DeletionRequested
        && current.policy_document == crate::restrictive_terminal_document(policy_document)
        && replacement.policy_document == *policy_document
        && (
            replacement.header.sequence_epoch,
            replacement.header.issuer_sequence,
        ) > (
            current.header.sequence_epoch,
            current.header.issuer_sequence,
        )
}

fn apply_transaction(
    state: &mut ControlStoreState,
    transaction: &ControlTransactionV1,
    path: &Path,
) -> Result<()> {
    if transaction.is_evidence() {
        state.validate_evidence_transaction(transaction, path)?;
        state.apply_validated_evidence_transaction(transaction);
        return Ok(());
    }
    match transaction {
        ControlTransactionV1::NodeSessionAdvanced { advance } => {
            validate_node_session_advance(state, advance, path)?;
            for rollout in &advance.policy_rollout_states {
                state.rollout_states.insert(
                    PolicyRolloutKeyV1 {
                        candidate_content_id: rollout.desired_candidate_content_id.clone(),
                        node_id: rollout.target.node_id.clone(),
                    },
                    rollout.clone(),
                );
            }
            for settlement in &advance.exception_settlements {
                let key = PolicyRolloutKeyV1 {
                    candidate_content_id: settlement.rollout_state.candidate_content_id.clone(),
                    node_id: settlement.rollout_state.node_id.clone(),
                };
                state
                    .exception_rollout_states
                    .insert(key.clone(), settlement.rollout_state.clone());
                state
                    .exception_consumed_uses
                    .insert(key, settlement.consumed_uses);
            }
            state
                .node_session_history
                .insert(advance.session.physical_epoch(), advance.session.clone());
            state
                .node_sessions
                .insert(advance.session.node_id.clone(), advance.session.clone());
        }
        ControlTransactionV1::KubernetesNodeBound { binding } => {
            validate_kubernetes_node_binding(state, binding, path)?;
            let session = state
                .node_sessions
                .get_mut(&binding.physical_epoch.node_id)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: path.to_owned(),
                        reason: "a validated Kubernetes Node binding lost its session".to_owned(),
                    }
                    .build()
                })?;
            session.kubernetes_node_uid = Some(binding.kubernetes_node_uid.clone());
            state
                .node_session_history
                .insert(session.physical_epoch(), session.clone());
        }
        ControlTransactionV1::SourceAccepted {
            source_revision,
            policy_document,
            artifact,
        } => {
            let existing_artifact = state
                .compiled_artifacts
                .get(&source_revision.policy_source_revision_id);
            let legacy_upgrade = artifact.as_deref().is_some_and(|replacement| {
                existing_artifact.is_some_and(|current| {
                    legacy_deletion_artifact_upgrade(
                        source_revision,
                        policy_document,
                        current,
                        replacement,
                    )
                })
            });
            if !legacy_upgrade {
                validate_source_acceptance(state, source_revision, policy_document, path)?;
            }
            if let Some(artifact) = artifact {
                validate_compiled_artifact(
                    state,
                    source_revision,
                    policy_document,
                    artifact,
                    path,
                )?;
            }
            let key = PolicyObjectKeyV1::from(source_revision.as_ref());
            if let Some(existing) = state
                .source_revisions
                .insert(
                    source_revision.policy_source_revision_id.clone(),
                    source_revision.as_ref().clone(),
                )
                .filter(|existing| existing != source_revision.as_ref())
            {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: format!(
                        "source revision {} conflicts with existing generation {}",
                        existing.policy_source_revision_id, existing.object_generation
                    ),
                }
                .fail();
            }
            state
                .latest_sources
                .insert(key, source_revision.policy_source_revision_id.clone());
            state.policy_documents.insert(
                source_revision.policy_source_revision_id.clone(),
                policy_document.as_ref().clone(),
            );
            if let Some(artifact) = artifact {
                let existing = state.compiled_artifacts.insert(
                    source_revision.policy_source_revision_id.clone(),
                    artifact.as_ref().clone(),
                );
                if existing.is_some_and(|existing| {
                    existing != *artifact.as_ref()
                        && !legacy_deletion_artifact_upgrade(
                            source_revision,
                            policy_document,
                            &existing,
                            artifact,
                        )
                }) {
                    return ControlStoreSnafu {
                        path: path.to_owned(),
                        reason: format!(
                            "source revision {} conflicts with a durable artifact",
                            source_revision.policy_source_revision_id
                        ),
                    }
                    .fail();
                }
            }
        }
        ControlTransactionV1::Compiled {
            policy_source_revision_id,
            artifact,
        } => {
            let _source = state
                .source_revisions
                .get(policy_source_revision_id)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: path.to_owned(),
                        reason: "the legacy artifact has no accepted source revision".to_owned(),
                    }
                    .build()
                })?;
            let document = state
                .policy_documents
                .get(policy_source_revision_id)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: path.to_owned(),
                        reason: "the legacy artifact has no accepted policy document".to_owned(),
                    }
                    .build()
                })?;
            validate_legacy_compiled_artifact(state, document, artifact, path)?;
            state
                .compiled_artifacts
                .insert(policy_source_revision_id.clone(), artifact.as_ref().clone());
        }
        ControlTransactionV1::RolloutCreated { rollout } => {
            let PolicyRolloutTransactionV1 {
                target_snapshot,
                bundles,
                rollout_states,
            } = rollout.as_ref();
            validate_rollout_transaction(target_snapshot, bundles, rollout_states, path)?;
            validate_rollout_ordering(state, bundles, path, false)?;
            apply_rollout_transaction(state, rollout);
            if state
                .source_revisions
                .get(&target_snapshot.policy_source_revision_id)
                .is_some_and(|source| source.state == PolicySourceStateV1::Accepted)
            {
                // Commit order recovers the latest desired snapshot from legacy WAL entries.
                state.latest_desired_snapshots.insert(
                    target_snapshot.policy_source_revision_id.clone(),
                    target_snapshot.target_snapshot_digest.clone(),
                );
            }
        }
        ControlTransactionV1::TargetSetReconciled { reconciliation } => {
            validate_target_set_reconciliation(state, reconciliation, path)?;
            if let Some(artifact) = &reconciliation.refreshed_active_artifact {
                state.compiled_artifacts.insert(
                    reconciliation
                        .desired
                        .target_snapshot
                        .policy_source_revision_id
                        .clone(),
                    artifact.clone(),
                );
            }
            apply_rollout_transaction(state, &reconciliation.desired);
            if let Some(retirement) = &reconciliation.retirement {
                apply_rollout_transaction(state, retirement);
            }
            state.latest_desired_snapshots.insert(
                reconciliation
                    .desired
                    .target_snapshot
                    .policy_source_revision_id
                    .clone(),
                reconciliation
                    .desired
                    .target_snapshot
                    .target_snapshot_digest
                    .clone(),
            );
        }
        ControlTransactionV1::Acknowledged { result } => {
            let PolicyAcknowledgementTransactionV1 {
                acknowledgement,
                rollout_state,
                ..
            } = result.as_ref();
            validate_policy_acknowledgement(state, result, path)?;
            state.policy_acknowledgement_results.insert(
                acknowledgement.acknowledgement_content_id.clone(),
                result.as_ref().clone(),
            );
            state.rollout_states.insert(
                PolicyRolloutKeyV1 {
                    candidate_content_id: rollout_state.desired_candidate_content_id.clone(),
                    node_id: rollout_state.target.node_id.clone(),
                },
                rollout_state.clone(),
            );
        }
        ControlTransactionV1::ExceptionDesired { desired } => {
            validate_exception_desired(state, desired, path)?;
            let key = PolicyObjectKeyV1::from(&desired.source_revision);
            state.exception_source_revisions.insert(
                desired.source_revision.exception_source_revision_id.clone(),
                desired.source_revision.clone(),
            );
            state.latest_exception_sources.insert(
                key,
                desired.source_revision.exception_source_revision_id.clone(),
            );
            state.exception_candidates.insert(
                desired.candidate.candidate_content_id.clone(),
                desired.candidate.clone(),
            );
            state.exception_rollout_states.insert(
                PolicyRolloutKeyV1 {
                    candidate_content_id: desired.candidate.candidate_content_id.clone(),
                    node_id: desired.candidate.exact_target.node_id.clone(),
                },
                desired.rollout_state.clone(),
            );
        }
        ControlTransactionV1::ExceptionAcknowledged { result } => {
            validate_exception_acknowledgement(state, result, path)?;
            state.exception_acknowledgements.insert(
                result.acknowledgement.acknowledgement_content_id.clone(),
                result.acknowledgement.clone(),
            );
            state.exception_rollout_states.insert(
                PolicyRolloutKeyV1 {
                    candidate_content_id: result.rollout_state.candidate_content_id.clone(),
                    node_id: result.rollout_state.node_id.clone(),
                },
                result.rollout_state.clone(),
            );
            let key = PolicyRolloutKeyV1 {
                candidate_content_id: result.rollout_state.candidate_content_id.clone(),
                node_id: result.rollout_state.node_id.clone(),
            };
            state
                .exception_consumed_uses
                .entry(key)
                .and_modify(|uses| *uses = (*uses).max(result.acknowledgement.consumed_uses))
                .or_insert(result.acknowledgement.consumed_uses);
        }
        ControlTransactionV1::EvidencePending { .. }
        | ControlTransactionV1::EvidenceAccepted { .. }
        | ControlTransactionV1::CoverageAccepted { .. }
        | ControlTransactionV1::EvidenceConsumed { .. } => {
            unreachable!("evidence transactions return before the main transition match")
        }
        ControlTransactionV1::TrustInstalled { generation } => {
            validate_trust_transition(state, generation, path)?;
            if state
                .trust_generations
                .insert(generation.generation, generation.as_ref().clone())
                .is_some()
            {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "a trust generation was committed more than once".to_owned(),
                }
                .fail();
            }
        }
        ControlTransactionV1::TrustAcknowledged { acknowledgement } => {
            let current = state
                .trust_generations
                .last_key_value()
                .map(|(_generation, trust)| trust)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: path.to_owned(),
                        reason: "a node acknowledged trust before any trust generation existed"
                            .to_owned(),
                    }
                    .build()
                })?;
            if !crate::node_id_is_valid(&acknowledgement.node_id)
                || acknowledgement.node_boot_id == [0; 16]
                || acknowledgement.label_epoch == 0
                || acknowledgement.generation != current.generation
                || acknowledgement.bundle_digest != current.bundle_digest
            {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "the committed node trust acknowledgement is stale or invalid"
                        .to_owned(),
                }
                .fail();
            }
            let key = (
                acknowledgement.node_id.clone(),
                acknowledgement.generation,
                acknowledgement.node_boot_id,
                acknowledgement.label_epoch,
            );
            if state
                .trust_acknowledgements
                .insert(key, acknowledgement.as_ref().clone())
                .is_some()
            {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "a node trust acknowledgement was committed more than once".to_owned(),
                }
                .fail();
            }
        }
        ControlTransactionV1::NodeDecommissionUpdated { record } => {
            validate_node_decommission_update(state, record, path)?;
            state
                .node_decommissions
                .insert(record.digest(), record.as_ref().clone());
        }
    }
    Ok(())
}

fn validate_node_decommission_update(
    state: &ControlStoreState,
    record: &StoredNodeDecommissionV1,
    path: &Path,
) -> Result<()> {
    let (_envelope, authorization) = crate::SignedNodeDecommissionV1::parse(&record.artifact)?;
    let digest = record.digest();
    if record.reason_code.len() > 128
        || record.reason_code.contains(['\r', '\n'])
        || (record.state == NodeDecommissionStateV1::Rejected) != !record.reason_code.is_empty()
    {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the decommission result reason is invalid".to_owned(),
        }
        .fail();
    }

    if let Some(current) = state.node_decommissions.get(&digest) {
        let valid_transition = current.artifact == record.artifact
            && matches!(
                (current.state, record.state),
                (
                    NodeDecommissionStateV1::Submitted,
                    NodeDecommissionStateV1::Accepted | NodeDecommissionStateV1::Rejected
                ) | (
                    NodeDecommissionStateV1::Accepted,
                    NodeDecommissionStateV1::Quarantined
                ) | (
                    NodeDecommissionStateV1::Quarantined,
                    NodeDecommissionStateV1::Completed
                )
            );
        if !valid_transition {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the decommission state transition is invalid".to_owned(),
            }
            .fail();
        }
        return Ok(());
    }

    let current_session_matches = state
        .node_sessions
        .get(&authorization.node_id)
        .is_some_and(|session| session.node_boot_id == authorization.node_boot_id);
    let nonce_is_unused = state.node_decommissions.values().all(|stored| {
        stored
            .authorization()
            .is_ok_and(|stored| stored.nonce != authorization.nonce)
    });
    let target_has_no_pending_artifact = state.node_decommissions.values().all(|stored| {
        !matches!(
            stored.state,
            NodeDecommissionStateV1::Submitted
                | NodeDecommissionStateV1::Accepted
                | NodeDecommissionStateV1::Quarantined
        ) || stored.authorization().is_ok_and(|stored| {
            stored.node_id != authorization.node_id
                || stored.node_boot_id != authorization.node_boot_id
        })
    });
    if record.state != NodeDecommissionStateV1::Submitted
        || !current_session_matches
        || !nonce_is_unused
        || !target_has_no_pending_artifact
    {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the submitted decommission artifact is stale or duplicated".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn validate_trust_transition(
    state: &ControlStoreState,
    generation: &TrustGenerationV1,
    path: &Path,
) -> Result<()> {
    let valid = generation.generation > 0
        && valid_sha256(&generation.bundle_digest)
        && generation
            .policy_signers
            .windows(2)
            .all(|pair| pair[0].signing_key_id < pair[1].signing_key_id)
        && generation.policy_signers.iter().all(|signer| {
            !signer.signing_key_id.is_empty()
                && signer.signing_key_id.len() <= 128
                && valid_sha256(&signer.ed25519_public_key_hex)
        })
        && (generation.policy_signers.is_empty()
            || (generation.policy_issuer_sequence_epoch > 0
                && generation.computed_bundle_digest() == generation.bundle_digest));
    if !valid {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the trust generation identity, digest, signer set, or issuer epoch is invalid"
                .to_owned(),
        }
        .fail();
    }
    if let Some((_current_number, current)) = state.trust_generations.last_key_value() {
        if generation.generation <= current.generation
            || generation.policy_issuer_sequence_epoch < current.policy_issuer_sequence_epoch
        {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the trust generation or policy issuer epoch rolled back".to_owned(),
            }
            .fail();
        }
    }
    // A key ID keeps the same key bytes, and revocation never reverses.
    for signer in &generation.policy_signers {
        for prior in state
            .trust_generations
            .values()
            .flat_map(|trust| trust.policy_signers.iter())
            .filter(|prior| prior.signing_key_id == signer.signing_key_id)
        {
            if prior.ed25519_public_key_hex != signer.ed25519_public_key_hex
                || (prior.revoked && !signer.revoked)
            {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "a policy signer key changed bytes or reversed revocation".to_owned(),
                }
                .fail();
            }
        }
    }
    Ok(())
}

fn validate_evidence_identity(identity: &EvidenceIntakeIdentityV1, path: &Path) -> Result<()> {
    if identity.tenant_id == [0; 16]
        || !crate::node_id_is_valid(&identity.node_id)
        || identity.node_boot_id == [0; 16]
        || identity.label_epoch == 0
        || identity.source_id == [0; 16]
        || identity.source_epoch == 0
    {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "evidence stream identity is invalid".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn validate_evidence_batch_input(batch: &EvidenceBatchInputV1, path: &Path) -> Result<()> {
    let count = batch
        .last_cursor
        .checked_sub(batch.first_cursor)
        .and_then(|count| count.checked_add(1));
    if batch.first_cursor == 0
        || batch.framed_records.is_empty()
        || count != u64::try_from(batch.record_count()).ok()
    {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "evidence batch cursor range does not match its record count".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn validate_stored_batch(batch: &StoredEvidenceBatchV1, path: &Path) -> Result<()> {
    if batch.first_cursor == 0
        || batch.last_cursor < batch.first_cursor
        || batch.segment.id == 0
        || batch.segment.offset == 0
    {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "stored evidence segment reference is invalid".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn validate_new_pending_evidence(
    state: &ControlStoreState,
    pending: &EvidenceBatchTransactionV1,
    path: &Path,
) -> Result<()> {
    let cursor = state
        .evidence_cursors
        .get(&pending.identity)
        .copied()
        .unwrap_or_default();
    let next = checked_store_increment(
        cursor.contiguous_cursor,
        path,
        "the evidence cursor is exhausted",
    )?;
    let overlaps = state
        .pending_evidence_batches
        .iter()
        .filter(|(key, _batch)| key.identity == pending.identity)
        .any(|(key, batch)| {
            pending.batch.first_cursor <= batch.last_cursor
                && key.first_cursor <= pending.batch.last_cursor
        });
    if pending.batch.first_cursor <= next
        || pending.batch.last_cursor
            > cursor
                .contiguous_cursor
                .saturating_add(MAX_PENDING_EVIDENCE_RECORDS)
        || overlaps
    {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "pending evidence range is not a bounded unoccupied gap".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn source_epoch_key(identity: &EvidenceIntakeIdentityV1) -> EvidenceSourceEpochKeyV1 {
    EvidenceSourceEpochKeyV1 {
        tenant_id: identity.tenant_id,
        node_id: identity.node_id.clone(),
        source_id: identity.source_id,
        source_epoch: identity.source_epoch,
    }
}

fn evidence_stream_id_for_write(
    state: &ControlStoreState,
    identity: &EvidenceIntakeIdentityV1,
    path: &Path,
) -> Result<u64> {
    if let Some(stream_id) = state.evidence_stream_ids.get(identity) {
        return Ok(*stream_id);
    }
    state
        .evidence_stream_ids
        .values()
        .copied()
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| {
            ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the evidence stream identifier is exhausted".to_owned(),
            }
            .build()
        })
}

fn validate_source_label(
    state: &ControlStoreState,
    identity: &EvidenceIntakeIdentityV1,
    path: &Path,
) -> Result<()> {
    // One source epoch cannot cross a label epoch and inherit a different node identity.
    if state
        .evidence_source_labels
        .get(&source_epoch_key(identity))
        .is_some_and(|label_epoch| *label_epoch != identity.label_epoch)
    {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "one evidence source epoch crossed a node label epoch".to_owned(),
        }
        .fail();
    }
    Ok(())
}

impl ControlStoreState {
    fn validate_evidence_stream_id(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        stream_id: u64,
        path: &Path,
    ) -> Result<()> {
        if stream_id != evidence_stream_id_for_write(self, identity, path)? {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "evidence stream identifier is stale or duplicated".to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    fn apply_evidence_stream_id(&mut self, identity: &EvidenceIntakeIdentityV1, stream_id: u64) {
        Arc::make_mut(&mut self.evidence_stream_ids)
            .entry(identity.clone())
            .or_insert(stream_id);
    }

    fn validate_evidence_transaction(
        &self,
        transaction: &ControlTransactionV1,
        path: &Path,
    ) -> Result<()> {
        match transaction {
            ControlTransactionV1::EvidencePending { stream_id, pending } => {
                validate_evidence_identity(&pending.identity, path)?;
                self.validate_evidence_stream_id(&pending.identity, *stream_id, path)?;
                validate_stored_batch(&pending.batch, path)?;
                validate_new_pending_evidence(self, pending, path)?;
                validate_source_label(self, &pending.identity, path)
            }
            ControlTransactionV1::EvidenceAccepted { accepted } => {
                self.validate_accepted_evidence(accepted, path)
            }
            ControlTransactionV1::CoverageAccepted { stream_id, report } => {
                validate_evidence_identity(&report.identity, path)?;
                self.validate_evidence_stream_id(&report.identity, *stream_id, path)?;
                validate_source_label(self, &report.identity, path)?;
                let current = self
                    .coverage_cursors
                    .get(&report.identity)
                    .copied()
                    .unwrap_or_default();
                if report.state.revision == 0
                    || report.segment.id == 0
                    || report.state.revision <= current.revision
                {
                    return ControlStoreSnafu {
                        path: path.to_owned(),
                        reason: "committed coverage evidence is stale or invalid".to_owned(),
                    }
                    .fail();
                }
                let key = CoverageReportKeyV1 {
                    identity: report.identity.clone(),
                    revision: report.state.revision,
                };
                if self.coverage_reports.contains_key(&key) {
                    return ControlStoreSnafu {
                        path: path.to_owned(),
                        reason: "a coverage revision was committed more than once".to_owned(),
                    }
                    .fail();
                }
                Ok(())
            }
            ControlTransactionV1::EvidenceConsumed { watermark } => {
                self.validate_evidence_consumption(watermark, path)
            }
            _ => unreachable!("only evidence transactions use evidence validation"),
        }
    }

    fn validate_evidence_consumption(
        &self,
        watermark: &EvidenceConsumptionWatermarkV1,
        path: &Path,
    ) -> Result<()> {
        validate_evidence_identity(&watermark.identity, path)?;
        let current = self
            .evidence_consumption
            .get(&watermark.identity)
            .copied()
            .unwrap_or_default();
        let intake_cursor = self
            .evidence_cursors
            .get(&watermark.identity)
            .copied()
            .unwrap_or_default()
            .contiguous_cursor;
        let coverage_revision = self
            .coverage_cursors
            .get(&watermark.identity)
            .copied()
            .unwrap_or_default()
            .revision;
        let evidence_boundary_exists = watermark.evidence_cursor == current.evidence_cursor
            || self.evidence_batches.iter().any(|(key, _batch)| {
                key.identity == watermark.identity && key.last_cursor == watermark.evidence_cursor
            });
        let coverage_boundary_exists = watermark.coverage_revision == current.coverage_revision
            || self.coverage_reports.keys().any(|key| {
                key.identity == watermark.identity && key.revision == watermark.coverage_revision
            });
        if watermark.evidence_cursor < current.evidence_cursor
            || watermark.evidence_cursor > intake_cursor
            || watermark.coverage_revision < current.coverage_revision
            || watermark.coverage_revision > coverage_revision
            || !evidence_boundary_exists
            || !coverage_boundary_exists
            || (watermark.evidence_cursor == current.evidence_cursor
                && watermark.coverage_revision == current.coverage_revision)
        {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the evidence consumer watermark is stale, uncommitted, or not on a segment boundary"
                    .to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    fn validate_accepted_evidence(
        &self,
        accepted: &EvidenceAcceptedTransactionV1,
        path: &Path,
    ) -> Result<()> {
        validate_evidence_identity(&accepted.identity, path)?;
        self.validate_evidence_stream_id(&accepted.identity, accepted.stream_id, path)?;
        validate_source_label(self, &accepted.identity, path)?;
        if accepted.batches.is_empty() {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "an accepted evidence transaction has no range".to_owned(),
            }
            .fail();
        }
        let mut cursor = self
            .evidence_cursors
            .get(&accepted.identity)
            .copied()
            .unwrap_or_default();
        for batch in &accepted.batches {
            validate_stored_batch(batch, path)?;
            if batch.first_cursor
                != checked_store_increment(
                    cursor.contiguous_cursor,
                    path,
                    "the evidence cursor is exhausted",
                )?
            {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "accepted evidence is not contiguous with its durable cursor"
                        .to_owned(),
                }
                .fail();
            }
            cursor = IntakeStateV1 {
                contiguous_cursor: batch.last_cursor,
            };
            let batch_key = EvidenceBatchKeyV1 {
                identity: accepted.identity.clone(),
                first_cursor: batch.first_cursor,
                last_cursor: batch.last_cursor,
            };
            if self.evidence_batches.contains_key(&batch_key) {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "an accepted evidence segment was committed more than once".to_owned(),
                }
                .fail();
            }
            let pending_key = EvidencePendingKeyV1 {
                identity: accepted.identity.clone(),
                first_cursor: batch.first_cursor,
            };
            if self
                .pending_evidence_batches
                .get(&pending_key)
                .is_some_and(|pending| pending != batch)
            {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "promoted pending evidence differs from its durable content".to_owned(),
                }
                .fail();
            }
        }
        Ok(())
    }

    fn apply_validated_evidence_transaction(&mut self, transaction: &ControlTransactionV1) {
        match transaction {
            ControlTransactionV1::EvidencePending { stream_id, pending } => {
                self.apply_evidence_stream_id(&pending.identity, *stream_id);
                self.evidence_segment_commits
                    .entry(EvidenceSegmentStreamV1::records(*stream_id))
                    .or_default()
                    .include(pending.batch.segment);
                Arc::make_mut(&mut self.evidence_source_labels).insert(
                    source_epoch_key(&pending.identity),
                    pending.identity.label_epoch,
                );
                Arc::make_mut(&mut self.pending_evidence_batches).insert(
                    EvidencePendingKeyV1 {
                        identity: pending.identity.clone(),
                        first_cursor: pending.batch.first_cursor,
                    },
                    pending.batch.clone(),
                );
            }
            ControlTransactionV1::EvidenceAccepted { accepted } => {
                self.apply_evidence_stream_id(&accepted.identity, accepted.stream_id);
                self.apply_validated_accepted_evidence(accepted);
            }
            ControlTransactionV1::CoverageAccepted { stream_id, report } => {
                self.apply_evidence_stream_id(&report.identity, *stream_id);
                self.evidence_segment_commits
                    .entry(EvidenceSegmentStreamV1::coverage(*stream_id))
                    .or_default()
                    .include(report.segment);
                Arc::make_mut(&mut self.evidence_source_labels).insert(
                    source_epoch_key(&report.identity),
                    report.identity.label_epoch,
                );
                Arc::make_mut(&mut self.coverage_reports).insert(
                    CoverageReportKeyV1 {
                        identity: report.identity.clone(),
                        revision: report.state.revision,
                    },
                    report.as_ref().clone(),
                );
                Arc::make_mut(&mut self.coverage_cursors)
                    .insert(report.identity.clone(), report.state);
            }
            ControlTransactionV1::EvidenceConsumed { watermark } => {
                self.apply_validated_evidence_consumption(watermark);
            }
            _ => unreachable!("only validated evidence transactions use evidence application"),
        }
    }

    fn apply_validated_evidence_consumption(&mut self, watermark: &EvidenceConsumptionWatermarkV1) {
        Arc::make_mut(&mut self.evidence_batches).retain(|key, _batch| {
            key.identity != watermark.identity || key.last_cursor > watermark.evidence_cursor
        });
        let current_coverage_revision = self
            .coverage_cursors
            .get(&watermark.identity)
            .copied()
            .unwrap_or_default()
            .revision;
        Arc::make_mut(&mut self.coverage_reports).retain(|key, _report| {
            key.identity != watermark.identity
                || key.revision > watermark.coverage_revision
                || key.revision == current_coverage_revision
        });
        Arc::make_mut(&mut self.evidence_consumption).insert(
            watermark.identity.clone(),
            EvidenceConsumptionStateV1 {
                evidence_cursor: watermark.evidence_cursor,
                coverage_revision: watermark.coverage_revision,
            },
        );
    }

    fn apply_validated_accepted_evidence(&mut self, accepted: &EvidenceAcceptedTransactionV1) {
        Arc::make_mut(&mut self.evidence_source_labels).insert(
            source_epoch_key(&accepted.identity),
            accepted.identity.label_epoch,
        );
        let mut cursor = self
            .evidence_cursors
            .get(&accepted.identity)
            .copied()
            .unwrap_or_default();
        for batch in &accepted.batches {
            self.evidence_segment_commits
                .entry(EvidenceSegmentStreamV1::records(accepted.stream_id))
                .or_default()
                .include(batch.segment);
            cursor = IntakeStateV1 {
                contiguous_cursor: batch.last_cursor,
            };
            Arc::make_mut(&mut self.evidence_batches).insert(
                EvidenceBatchKeyV1 {
                    identity: accepted.identity.clone(),
                    first_cursor: batch.first_cursor,
                    last_cursor: batch.last_cursor,
                },
                batch.clone(),
            );
            Arc::make_mut(&mut self.pending_evidence_batches).remove(&EvidencePendingKeyV1 {
                identity: accepted.identity.clone(),
                first_cursor: batch.first_cursor,
            });
        }
        Arc::make_mut(&mut self.evidence_cursors).insert(accepted.identity.clone(), cursor);
    }
}

fn validate_exception_desired(
    state: &ControlStoreState,
    desired: &ExceptionDesiredTransactionV1,
    path: &Path,
) -> Result<()> {
    let source = &desired.source_revision;
    let candidate = &desired.candidate;
    let rollout = &desired.rollout_state;
    source.validate()?;
    candidate.validate_content()?;
    let object_key = PolicyObjectKeyV1::from(source);
    let previous_source = state
        .latest_exception_sources
        .get(&object_key)
        .and_then(|id| state.exception_source_revisions.get(id));
    let previous_candidate = state
        .exception_candidates
        .values()
        .filter(|existing| existing.exception_instance_id == source.object_uid)
        .max_by_key(|existing| {
            (
                existing.distribution_sequence_epoch,
                existing.distribution_sequence,
            )
        });

    let source_transition_is_valid = match desired.purpose {
        ExceptionDesiredPurposeV1::SourceLifecycle => match (source.state, previous_source) {
            (ExceptionSourceStateV1::Accepted, None) => true,
            (ExceptionSourceStateV1::Accepted, Some(previous)) => {
                let prior_revoke_finished = state.exception_rollout_states.values().any(|entry| {
                    entry.exception_source_revision_id == previous.exception_source_revision_id
                        && entry.state == crate::WorkloadProtectionExceptionStateV1::Revoked
                });
                previous.object_uid != source.object_uid
                    && previous.state == ExceptionSourceStateV1::DeletionRequested
                    && prior_revoke_finished
            }
            (ExceptionSourceStateV1::DeletionRequested, Some(previous)) => {
                previous.object_uid == source.object_uid
                    && previous.object_generation == source.object_generation
                    && previous.state == ExceptionSourceStateV1::Accepted
                    && previous.canonical_spec_digest == source.canonical_spec_digest
                    && previous.base_policy_source_revision_id
                        == source.base_policy_source_revision_id
                    && previous.grant_id == source.grant_id
                    && previous.requested_duration_ns == source.requested_duration_ns
                    && previous.requested_uses == source.requested_uses
            }
            (ExceptionSourceStateV1::DeletionRequested, None) => false,
        },
        ExceptionDesiredPurposeV1::TargetRetirement => {
            source.state == ExceptionSourceStateV1::Accepted && previous_source == Some(source)
        }
    };
    let exact_revocation = previous_candidate.is_some_and(|previous| {
        candidate.operation == ExceptionDeliveryOperationV1::Revoke
            && candidate.predecessor_candidate_content_id.as_deref()
                == Some(previous.candidate_content_id.as_str())
            && candidate.exact_target == previous.exact_target
            && candidate.base_candidate_content_id == previous.base_candidate_content_id
            && candidate.profile_generation_ref_id == previous.profile_generation_ref_id
            && candidate.maximum_uses == previous.maximum_uses
            && candidate.valid_until_utc_ns == previous.valid_until_utc_ns
            && candidate.expires_utc_ns >= previous.valid_until_utc_ns
            && (
                candidate.distribution_sequence_epoch,
                candidate.distribution_sequence,
            ) > (
                previous.distribution_sequence_epoch,
                previous.distribution_sequence,
            )
    });
    let operation_is_valid = match desired.purpose {
        ExceptionDesiredPurposeV1::SourceLifecycle => match source.state {
            ExceptionSourceStateV1::Accepted => {
                previous_candidate.is_none()
                    && candidate.operation == ExceptionDeliveryOperationV1::Activate
                    && candidate.predecessor_candidate_content_id.is_none()
            }
            ExceptionSourceStateV1::DeletionRequested => exact_revocation,
        },
        ExceptionDesiredPurposeV1::TargetRetirement => {
            exact_revocation
                && previous_candidate.is_some_and(|previous| {
                    previous.operation == ExceptionDeliveryOperationV1::Activate
                        && state
                            .exception_rollout_states
                            .get(&PolicyRolloutKeyV1 {
                                candidate_content_id: previous.candidate_content_id.clone(),
                                node_id: previous.exact_target.node_id.clone(),
                            })
                            .is_some_and(|rollout| {
                                matches!(
                                    rollout.state,
                                    crate::WorkloadProtectionExceptionStateV1::Pending
                                        | crate::WorkloadProtectionExceptionStateV1::Active
                                )
                            })
                        // The base-policy snapshot is the durable proof that the exact
                        // scheduler target disappeared from a complete inventory.
                        && state
                            .latest_desired_snapshots
                            .get(&source.base_policy_source_revision_id)
                            .and_then(|digest| state.target_snapshots.get(digest))
                            .is_some_and(|snapshot| {
                                !snapshot.targets.iter().any(|target| {
                                    target.workload_targets.contains(&previous.exact_target)
                                })
                            })
                })
        }
    };
    let base_source = state
        .source_revisions
        .get(&source.base_policy_source_revision_id);
    let base_document = state
        .policy_documents
        .get(&source.base_policy_source_revision_id);
    let base_bundle = state.bundles.get(&candidate.base_candidate_content_id);
    let base_rollout = state.exception_base_rollout(candidate);
    let base_acknowledgement = base_rollout.and_then(|entry| {
        entry
            .latest_acknowledgement_content_id
            .as_ref()
            .and_then(|id| state.policy_acknowledgement_results.get(id))
            .map(|result| &result.acknowledgement)
    });
    let grant_is_valid = base_document.is_some_and(|document| {
        exception_grant_covers_request(
            document,
            &source.grant_id,
            source.requested_duration_ns,
            source.requested_uses,
        )
    });
    let base_binding_is_valid = base_source.is_some_and(|base| {
        base.state == PolicySourceStateV1::Accepted && base.tenant_id == source.tenant_id
    }) && base_document.is_some_and(|document| {
        document.metadata.profile_id == candidate.profile_id && grant_is_valid
    }) && base_bundle.is_some_and(|bundle| {
        bundle.candidate.policy_source_revision_id == source.base_policy_source_revision_id
            && bundle
                .candidate
                .exact_target
                .workload_targets
                .contains(&candidate.exact_target)
    });
    let active_base_is_valid = base_binding_is_valid
        && (candidate.operation == ExceptionDeliveryOperationV1::Revoke
            || (base_rollout
                .is_some_and(|entry| entry.state == crate::PolicyRolloutStatusV1::Active)
                && base_acknowledgement.is_some_and(|acknowledgement| {
                    acknowledgement.state == crate::PolicyActivationStateV1::Active
                        && acknowledgement.profile_generation_ref_id
                            == Some(candidate.profile_generation_ref_id)
                        && acknowledgement.node_id == candidate.exact_target.node_id
                        && candidate
                            .exact_target
                            .kubernetes
                            .as_ref()
                            .is_some_and(|identity| {
                                hex::encode(&acknowledgement.node_boot_id) == identity.node_boot_id
                                    && acknowledgement.label_epoch == identity.label_epoch
                            })
                })));
    let expected_valid_until = i64::try_from(source.requested_duration_ns)
        .ok()
        .and_then(|duration| candidate.issued_utc_ns.checked_add(duration));
    let candidate_binding_is_valid = candidate.tenant_id == source.tenant_id
        && candidate.exception_source_revision_id == source.exception_source_revision_id
        && candidate.base_policy_source_revision_id == source.base_policy_source_revision_id
        && candidate.grant_id == source.grant_id
        && candidate.exception_instance_id == source.object_uid
        && candidate.maximum_uses == source.requested_uses
        && (candidate.operation == ExceptionDeliveryOperationV1::Revoke
            || expected_valid_until == Some(candidate.valid_until_utc_ns));
    let rollout_is_valid = rollout.exception_source_revision_id
        == source.exception_source_revision_id
        && rollout.candidate_content_id == candidate.candidate_content_id
        && rollout.node_id == candidate.exact_target.node_id
        && rollout.state == crate::WorkloadProtectionExceptionStateV1::Pending
        && rollout.latest_acknowledgement_content_id.is_none()
        && rollout.transition_version == 0
        && rollout.updated_utc_ns == candidate.issued_utc_ns;
    let overlaps_live_grant = candidate.operation == ExceptionDeliveryOperationV1::Activate
        && state.latest_exception_sources.values().any(|source_id| {
            state
                .exception_source_revisions
                .get(source_id)
                .filter(|existing| {
                    existing.state == ExceptionSourceStateV1::Accepted
                        && existing.object_uid != source.object_uid
                        && existing.base_policy_source_revision_id
                            == source.base_policy_source_revision_id
                        && existing.grant_id == source.grant_id
                })
                .is_some_and(|existing| {
                    state.exception_candidates.values().any(|prior| {
                        let rollout = state.exception_rollout_states.get(&PolicyRolloutKeyV1 {
                            candidate_content_id: prior.candidate_content_id.clone(),
                            node_id: prior.exact_target.node_id.clone(),
                        });
                        // Only pending and active candidates still carry usable authority.
                        prior.exception_source_revision_id == existing.exception_source_revision_id
                            && prior.exact_target.workload_binding_generation_digest
                                == candidate.exact_target.workload_binding_generation_digest
                            && rollout.is_some_and(|rollout| {
                                matches!(
                                    rollout.state,
                                    crate::WorkloadProtectionExceptionStateV1::Pending
                                        | crate::WorkloadProtectionExceptionStateV1::Active
                                )
                            })
                    })
                })
        });
    if !source_transition_is_valid
        || !operation_is_valid
        || !active_base_is_valid
        || !candidate_binding_is_valid
        || !rollout_is_valid
        || overlaps_live_grant
    {
        let failed_checks = [
            (!source_transition_is_valid).then_some("source transition"),
            (!operation_is_valid).then_some("operation"),
            (!active_base_is_valid).then_some("active base policy"),
            (!candidate_binding_is_valid).then_some("candidate binding"),
            (!rollout_is_valid).then_some("rollout"),
            overlaps_live_grant.then_some("overlapping live grant"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: format!("the exception desired transaction failed: {failed_checks}"),
        }
        .fail();
    }
    Ok(())
}

fn exception_grant_covers_request(
    document: &PolicyDocumentV1,
    grant_id: &str,
    requested_duration_ns: u64,
    requested_uses: u32,
) -> bool {
    document.file_exception_grants.iter().any(|grant| {
        grant.grant_id == grant_id
            && requested_duration_ns <= grant.maximum_duration_ns
            && requested_uses <= grant.maximum_uses
    })
}

impl ControlStoreState {
    fn exception_base_rollout(
        &self,
        candidate: &ExceptionDeliveryCandidateV1,
    ) -> Option<&PolicyRolloutStateV1> {
        self.rollout_states.get(&PolicyRolloutKeyV1 {
            candidate_content_id: candidate.base_candidate_content_id.clone(),
            node_id: candidate.exact_target.node_id.clone(),
        })
    }
}

fn validate_policy_acknowledgement(
    state: &ControlStoreState,
    result: &PolicyAcknowledgementTransactionV1,
    path: &Path,
) -> Result<()> {
    let acknowledgement = &result.acknowledgement;
    let rollout = &result.rollout_state;
    acknowledgement.validate()?;
    let current = state.rollout_states.get(&PolicyRolloutKeyV1 {
        candidate_content_id: acknowledgement.candidate_content_id.clone(),
        node_id: acknowledgement.node_id.clone(),
    });
    let expected_transition = current.and_then(|entry| entry.transition_version.checked_add(1));
    let expected_state = match acknowledgement.state {
        PolicyActivationStateV1::Received => PolicyRolloutStatusV1::Delivered,
        PolicyActivationStateV1::Staged => PolicyRolloutStatusV1::Staged,
        PolicyActivationStateV1::Active => PolicyRolloutStatusV1::Active,
        PolicyActivationStateV1::Rejected => PolicyRolloutStatusV1::Rejected,
        PolicyActivationStateV1::Stale => PolicyRolloutStatusV1::Stale,
        PolicyActivationStateV1::Unknown => PolicyRolloutStatusV1::Unknown,
    };
    let transition_is_valid = current
        .is_some_and(|current| valid_policy_rollout_transition(current.state, rollout.state));
    let rollout_is_valid = current.is_some_and(|current| {
        rollout.policy_source_revision_id == current.policy_source_revision_id
            && rollout.target_snapshot_digest == current.target_snapshot_digest
            && rollout.target == current.target
            && rollout.desired_candidate_content_id == current.desired_candidate_content_id
    }) && expected_transition == Some(rollout.transition_version)
        && rollout.state == expected_state
        && rollout.latest_acknowledgement_content_id.as_deref()
            == Some(acknowledgement.acknowledgement_content_id.as_str())
        && rollout.updated_utc_ns == acknowledgement.observed_utc_ns;
    let acknowledgement_is_bound = state
        .bundles
        .get(&acknowledgement.candidate_content_id)
        .is_some_and(|bundle| {
            bundle.candidate.tenant_id == acknowledgement.tenant_id
                && bundle.candidate.policy_source_revision_id
                    == acknowledgement.policy_source_revision_id
                && bundle.candidate.target_snapshot_digest == acknowledgement.target_snapshot_digest
                && bundle.candidate.exact_target.node_id == acknowledgement.node_id
                && bundle
                    .candidate
                    .exact_target
                    .workload_targets
                    .iter()
                    .all(|target| {
                        target.kubernetes.as_ref().is_some_and(|identity| {
                            hex::encode(&acknowledgement.node_boot_id) == identity.node_boot_id
                                && acknowledgement.label_epoch == identity.label_epoch
                        })
                    })
        });
    let terminal_closure_is_valid = !result.terminal_chain_closure_authorized
        || terminal_chain_closure_can_be_authorized(state, acknowledgement);
    let current_session_is_valid = node_session_matches_acknowledgement(
        state,
        &acknowledgement.node_id,
        &acknowledgement.node_boot_id,
        acknowledgement.label_epoch,
    );
    let candidate_is_current = candidate_is_current_or_unsettled_predecessor(
        state,
        &acknowledgement.node_id,
        &acknowledgement.candidate_content_id,
    );
    if !transition_is_valid
        || !rollout_is_valid
        || !acknowledgement_is_bound
        || !terminal_closure_is_valid
        || !current_session_is_valid
        || !candidate_is_current
    {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the policy acknowledgement, rollout, or terminal closure is inconsistent"
                .to_owned(),
        }
        .fail();
    }
    Ok(())
}

const fn valid_policy_rollout_transition(
    current: PolicyRolloutStatusV1,
    next: PolicyRolloutStatusV1,
) -> bool {
    match current {
        PolicyRolloutStatusV1::Pending | PolicyRolloutStatusV1::Unknown => true,
        PolicyRolloutStatusV1::Delivered => !matches!(next, PolicyRolloutStatusV1::Pending),
        PolicyRolloutStatusV1::Staged => !matches!(
            next,
            PolicyRolloutStatusV1::Pending | PolicyRolloutStatusV1::Delivered
        ),
        PolicyRolloutStatusV1::Active => matches!(next, PolicyRolloutStatusV1::Active),
        PolicyRolloutStatusV1::Rejected => matches!(next, PolicyRolloutStatusV1::Rejected),
        PolicyRolloutStatusV1::Stale => matches!(next, PolicyRolloutStatusV1::Stale),
    }
}

fn validate_exception_acknowledgement(
    state: &ControlStoreState,
    result: &ExceptionAcknowledgementTransactionV1,
    path: &Path,
) -> Result<()> {
    let acknowledgement = &result.acknowledgement;
    let rollout = &result.rollout_state;
    acknowledgement.validate()?;
    let candidate = state
        .exception_candidates
        .get(&acknowledgement.candidate_content_id);
    let current = candidate.and_then(|candidate| {
        state.exception_rollout_states.get(&PolicyRolloutKeyV1 {
            candidate_content_id: candidate.candidate_content_id.clone(),
            node_id: candidate.exact_target.node_id.clone(),
        })
    });
    let expected_transition = current.and_then(|entry| entry.transition_version.checked_add(1));
    let transition_is_valid = current
        .is_some_and(|current| valid_exception_rollout_transition(current.state, rollout.state));
    let candidate_is_valid = candidate.is_some_and(|candidate| {
        let operation_state_is_valid = match candidate.operation {
            ExceptionDeliveryOperationV1::Activate => {
                !matches!(acknowledgement.state, ExceptionActivationStateV1::Revoked)
            }
            ExceptionDeliveryOperationV1::Revoke => matches!(
                acknowledgement.state,
                ExceptionActivationStateV1::Revoked
                    | ExceptionActivationStateV1::Rejected
                    | ExceptionActivationStateV1::Stale
            ),
        };
        let use_count_is_valid = match acknowledgement.state {
            ExceptionActivationStateV1::Consumed => {
                acknowledgement.consumed_uses == candidate.maximum_uses
            }
            ExceptionActivationStateV1::Rejected | ExceptionActivationStateV1::Stale => {
                acknowledgement.consumed_uses == 0
            }
            _ => acknowledgement.consumed_uses <= candidate.maximum_uses,
        };
        candidate.tenant_id == acknowledgement.tenant_id
            && candidate.exception_source_revision_id
                == acknowledgement.exception_source_revision_id
            && candidate.exact_target.node_id == acknowledgement.node_id
            && candidate
                .exact_target
                .kubernetes
                .as_ref()
                .is_some_and(|identity| {
                    hex::encode(&acknowledgement.node_boot_id) == identity.node_boot_id
                        && acknowledgement.label_epoch == identity.label_epoch
                })
            && operation_state_is_valid
            && use_count_is_valid
    });
    let rollout_is_valid = current.is_some()
        && expected_transition == Some(acknowledgement.transition_version)
        && rollout.exception_source_revision_id == acknowledgement.exception_source_revision_id
        && rollout.candidate_content_id == acknowledgement.candidate_content_id
        && rollout.node_id == acknowledgement.node_id
        && rollout.state == crate::WorkloadProtectionExceptionStateV1::from(acknowledgement.state)
        && rollout.latest_acknowledgement_content_id.as_deref()
            == Some(acknowledgement.acknowledgement_content_id.as_str())
        && rollout.transition_version == acknowledgement.transition_version
        && rollout.updated_utc_ns == acknowledgement.observed_utc_ns;
    let current_session_is_valid = node_session_matches_acknowledgement(
        state,
        &acknowledgement.node_id,
        &acknowledgement.node_boot_id,
        acknowledgement.label_epoch,
    );
    let consumed_uses_are_monotonic = state
        .exception_consumed_uses
        .get(&PolicyRolloutKeyV1 {
            candidate_content_id: acknowledgement.candidate_content_id.clone(),
            node_id: acknowledgement.node_id.clone(),
        })
        .is_none_or(|consumed| acknowledgement.consumed_uses >= *consumed);
    if !candidate_is_valid
        || !rollout_is_valid
        || !transition_is_valid
        || !current_session_is_valid
        || !consumed_uses_are_monotonic
    {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason:
                "the exception acknowledgement does not match its candidate and current rollout"
                    .to_owned(),
        }
        .fail();
    }
    Ok(())
}

const fn valid_exception_rollout_transition(
    current: crate::WorkloadProtectionExceptionStateV1,
    next: crate::WorkloadProtectionExceptionStateV1,
) -> bool {
    use crate::WorkloadProtectionExceptionStateV1 as State;

    match current {
        State::Pending => true,
        State::Active => matches!(
            next,
            State::Active | State::Consumed | State::Expired | State::Failed
        ),
        State::Consumed => matches!(next, State::Consumed),
        State::Expired => matches!(next, State::Expired),
        State::Revoked => matches!(next, State::Revoked),
        State::Failed => matches!(next, State::Failed),
    }
}

fn apply_rollout_transaction(state: &mut ControlStoreState, rollout: &PolicyRolloutTransactionV1) {
    state.target_snapshots.insert(
        rollout.target_snapshot.target_snapshot_digest.clone(),
        rollout.target_snapshot.clone(),
    );
    for bundle in &rollout.bundles {
        state.bundles.insert(
            bundle.candidate.candidate_content_id.clone(),
            bundle.clone(),
        );
    }
    for rollout_state in &rollout.rollout_states {
        state.rollout_states.insert(
            PolicyRolloutKeyV1 {
                candidate_content_id: rollout_state.desired_candidate_content_id.clone(),
                node_id: rollout_state.target.node_id.clone(),
            },
            rollout_state.clone(),
        );
    }
}

fn validate_target_set_reconciliation(
    state: &ControlStoreState,
    reconciliation: &PolicyTargetSetTransactionV1,
    path: &Path,
) -> Result<()> {
    let source_id = &reconciliation
        .desired
        .target_snapshot
        .policy_source_revision_id;
    let source = state.source_revisions.get(source_id).ok_or_else(|| {
        ControlStoreSnafu {
            path: path.to_owned(),
            reason: "a target-set reconciliation has no accepted source revision".to_owned(),
        }
        .build()
    })?;
    let document = state.policy_documents.get(source_id).ok_or_else(|| {
        ControlStoreSnafu {
            path: path.to_owned(),
            reason: "a target-set reconciliation has no accepted policy document".to_owned(),
        }
        .build()
    })?;
    let active_artifact = reconciliation
        .refreshed_active_artifact
        .as_ref()
        .or_else(|| state.compiled_artifacts.get(source_id))
        .ok_or_else(|| {
            ControlStoreSnafu {
                path: path.to_owned(),
                reason: "a target-set reconciliation has no active artifact".to_owned(),
            }
            .build()
        })?;
    let desired = &reconciliation.desired;
    validate_rollout_transaction(
        &desired.target_snapshot,
        &desired.bundles,
        &desired.rollout_states,
        path,
    )?;
    validate_rollout_ordering(state, &desired.bundles, path, false)?;
    let active_digest = artifact_digest(active_artifact, path)?;
    let desired_nodes = desired
        .target_snapshot
        .targets
        .iter()
        .map(|target| target.node_id.as_str())
        .collect::<BTreeSet<_>>();
    let desired_is_valid = source.state == PolicySourceStateV1::Accepted
        && active_artifact.policy_document == *document
        && desired.target_snapshot.signed_profile_digest == active_digest
        && desired.target_snapshot.rollout_generation == document.rollout.rollout_generation
        && desired_nodes.len() == desired.target_snapshot.targets.len()
        && desired.bundles.iter().all(|bundle| {
            bundle.profile_artifact == *active_artifact
                && bundle.candidate.operation
                    != crate::PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
        });
    if !desired_is_valid {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the desired target set does not match its accepted source and active artifact"
                .to_owned(),
        }
        .fail();
    }
    if let Some(refreshed) = &reconciliation.refreshed_active_artifact {
        validate_new_artifact_sequence(state, refreshed, path)?;
    }

    // Replay validates terminal retirement transactions written by older versions.
    let mut required_retirement_targets = latest_object_bundles(state, &source.object_uid)
        .into_iter()
        .filter(|bundle| {
            !desired_nodes.contains(bundle.candidate.exact_target.node_id.as_str())
                && bundle_requires_retirement(state, bundle)
        })
        .map(|bundle| bundle.candidate.exact_target.clone())
        .collect::<Vec<_>>();
    required_retirement_targets.sort();
    required_retirement_targets.dedup();
    let Some(retirement) = &reconciliation.retirement else {
        return Ok(());
    };
    if retirement.target_snapshot.targets != required_retirement_targets {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "a target-set reconciliation does not retire every exact removed-node head"
                .to_owned(),
        }
        .fail();
    }
    validate_rollout_transaction(
        &retirement.target_snapshot,
        &retirement.bundles,
        &retirement.rollout_states,
        path,
    )?;
    validate_rollout_ordering(state, &retirement.bundles, path, true)?;
    let Some(terminal_artifact) = retirement
        .bundles
        .first()
        .map(|bundle| &bundle.profile_artifact)
    else {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "a retirement rollout has no terminal artifact".to_owned(),
        }
        .fail();
    };
    validate_new_artifact_sequence(state, terminal_artifact, path)?;
    let terminal_digest = artifact_digest(terminal_artifact, path)?;
    let refreshed_precedes_terminal = reconciliation
        .refreshed_active_artifact
        .as_ref()
        .is_none_or(|active| artifact_sequence(active) < artifact_sequence(terminal_artifact));
    let retirement_is_valid = retirement.target_snapshot.policy_source_revision_id == *source_id
        && retirement.target_snapshot.signed_profile_digest == terminal_digest
        && retirement.target_snapshot.rollout_generation == document.rollout.rollout_generation
        && terminal_artifact.policy_document == crate::restrictive_terminal_document(document)
        && refreshed_precedes_terminal
        && retirement.bundles.iter().all(|bundle| {
            bundle.profile_artifact == *terminal_artifact
                && bundle.candidate.operation
                    == crate::PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
                && bundle.candidate.expires_utc_ns == i64::MAX
                && !desired_nodes.contains(bundle.candidate.exact_target.node_id.as_str())
                && latest_profile_bundle(state, bundle).is_some_and(|previous| {
                    bundle.candidate.predecessor_candidate_content_id.as_deref()
                        == Some(previous.candidate.candidate_content_id.as_str())
                        && previous.candidate.exact_target == bundle.candidate.exact_target
                })
        });
    if !retirement_is_valid {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "a removed-node retirement is not exact, terminal, or predecessor bound"
                .to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn validate_new_artifact_sequence(
    state: &ControlStoreState,
    artifact: &ProfileCandidateArtifactV1,
    path: &Path,
) -> Result<()> {
    let sequence = artifact_sequence(artifact);
    let newer = state
        .compiled_artifacts
        .values()
        .chain(
            state
                .bundles
                .values()
                .map(|bundle| &bundle.profile_artifact),
        )
        .filter(|existing| {
            existing.signed_profile.signing_key_id == artifact.signed_profile.signing_key_id
        })
        .all(|existing| artifact_sequence(existing) < sequence);
    if !newer {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "a target-set artifact violates policy-issuer ordering".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn artifact_sequence(artifact: &ProfileCandidateArtifactV1) -> (u64, u64) {
    (
        artifact.header.sequence_epoch,
        artifact.header.issuer_sequence,
    )
}

fn artifact_digest(artifact: &ProfileCandidateArtifactV1, path: &Path) -> Result<String> {
    let bytes = serde_json::to_vec(artifact).context(JsonSnafu { path })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn latest_profile_bundle<'a>(
    state: &'a ControlStoreState,
    candidate: &PolicyBundleV1,
) -> Option<&'a PolicyBundleV1> {
    latest_viable_bundle(
        state,
        state.bundles.values().filter(|existing| {
            existing.candidate.exact_target.node_id == candidate.candidate.exact_target.node_id
                && bundle_profile_key(existing) == bundle_profile_key(candidate)
        }),
    )
}

fn latest_object_bundles<'a>(
    state: &'a ControlStoreState,
    object_uid: &str,
) -> Vec<&'a PolicyBundleV1> {
    let mut latest = BTreeMap::<&str, &PolicyBundleV1>::new();
    for bundle in state.bundles.values().filter(|bundle| {
        state
            .source_revisions
            .get(&bundle.candidate.policy_source_revision_id)
            .is_some_and(|source| source.object_uid == object_uid)
            && bundle_chain_is_viable(state, bundle)
    }) {
        let node_id = bundle.candidate.exact_target.node_id.as_str();
        if latest
            .get(node_id)
            .is_none_or(|current| bundle_sequence(bundle) > bundle_sequence(current))
        {
            latest.insert(node_id, bundle);
        }
    }
    latest.into_values().collect()
}

fn validate_rollout_transaction(
    snapshot: &PolicyTargetSnapshotV1,
    bundles: &[PolicyBundleV1],
    states: &[PolicyRolloutStateV1],
    path: &Path,
) -> Result<()> {
    let valid = bundles.len() == snapshot.targets.len()
        && states.len() == snapshot.targets.len()
        && bundles.iter().all(|bundle| {
            bundle.candidate.policy_source_revision_id == snapshot.policy_source_revision_id
                && bundle.candidate.target_snapshot_digest == snapshot.target_snapshot_digest
                && snapshot.targets.contains(&bundle.candidate.exact_target)
        })
        && states.iter().all(|state| {
            state.policy_source_revision_id == snapshot.policy_source_revision_id
                && state.target_snapshot_digest == snapshot.target_snapshot_digest
                && snapshot.targets.contains(&state.target)
                && bundles.iter().any(|bundle| {
                    bundle.candidate.candidate_content_id == state.desired_candidate_content_id
                        && bundle.candidate.exact_target == state.target
                })
        });
    if !valid {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the rollout snapshot, bundles, and per-target states are inconsistent"
                .to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn validate_rollout_ordering(
    state: &ControlStoreState,
    bundles: &[PolicyBundleV1],
    path: &Path,
    accepted_retirement: bool,
) -> Result<()> {
    for bundle in bundles {
        if state.bundles.get(&bundle.candidate.candidate_content_id) == Some(bundle) {
            continue;
        }
        let candidate = &bundle.candidate;
        let source = state
            .source_revisions
            .get(&candidate.policy_source_revision_id)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "a rollout candidate has no accepted source revision".to_owned(),
                }
                .build()
            })?;
        let document = state
            .policy_documents
            .get(&source.policy_source_revision_id)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "a rollout source has no policy document".to_owned(),
                }
                .build()
            })?;
        let profile_bundles = || {
            state.bundles.values().filter(|existing| {
                existing.candidate.exact_target.node_id == candidate.exact_target.node_id
                    && bundle_matches_profile(
                        existing,
                        &source.tenant_id,
                        &document.metadata.trust_domain_id,
                        &document.metadata.profile_id,
                    )
            })
        };
        let latest_sequence = profile_bundles().map(bundle_sequence).max();
        let previous = latest_viable_bundle(
            state,
            profile_bundles().filter(|existing| {
                existing
                    .candidate
                    .exact_target
                    .is_same_physical_node_epoch(&candidate.exact_target)
            }),
        );
        // Abandoned branches still reserve their distribution sequence numbers.
        let ordering_is_valid = latest_sequence.is_none_or(|previous| {
            (
                candidate.distribution_sequence_epoch,
                candidate.distribution_sequence,
            ) > previous
        });
        let predecessor_is_valid = previous.map_or_else(
            || {
                candidate.operation == crate::PolicyDeliveryOperationV1::Activate
                    && candidate.predecessor_candidate_content_id.is_none()
            },
            |previous| {
                candidate.operation != crate::PolicyDeliveryOperationV1::Activate
                    && candidate.predecessor_candidate_content_id.as_deref()
                        == Some(previous.candidate.candidate_content_id.as_str())
            },
        );
        let deletion_is_valid = match source.state {
            PolicySourceStateV1::DeletionRequested => {
                candidate.operation == crate::PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
            }
            PolicySourceStateV1::Accepted if accepted_retirement => {
                candidate.operation == crate::PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
            }
            PolicySourceStateV1::Accepted => {
                candidate.operation != crate::PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
            }
        };
        if !ordering_is_valid || !predecessor_is_valid || !deletion_is_valid {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "a rollout candidate failed ordering, predecessor, or deletion checks"
                    .to_owned(),
            }
            .fail();
        }
    }
    Ok(())
}

fn bundle_matches_profile(
    bundle: &PolicyBundleV1,
    tenant_id: &str,
    trust_domain_id: &str,
    profile_id: &str,
) -> bool {
    bundle.candidate.tenant_id == tenant_id
        && bundle
            .profile_artifact
            .policy_document
            .metadata
            .trust_domain_id
            == trust_domain_id
        && bundle.profile_artifact.policy_document.metadata.profile_id == profile_id
}

fn bundle_profile_key(bundle: &PolicyBundleV1) -> (&str, &str, &str) {
    (
        &bundle.candidate.tenant_id,
        &bundle
            .profile_artifact
            .policy_document
            .metadata
            .trust_domain_id,
        &bundle.profile_artifact.policy_document.metadata.profile_id,
    )
}

fn bundle_sequence(bundle: &PolicyBundleV1) -> (u64, u64) {
    (
        bundle.candidate.distribution_sequence_epoch,
        bundle.candidate.distribution_sequence,
    )
}

fn latest_viable_bundle<'a>(
    state: &ControlStoreState,
    bundles: impl Iterator<Item = &'a PolicyBundleV1>,
) -> Option<&'a PolicyBundleV1> {
    bundles
        .filter(|bundle| bundle_chain_is_viable(state, bundle))
        .max_by_key(|bundle| bundle_sequence(bundle))
}

fn bundle_chain_is_viable(state: &ControlStoreState, bundle: &PolicyBundleV1) -> bool {
    // A rejected, stale, or closed ancestor abandons its complete dependent branch.
    let mut current = bundle;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current.candidate.candidate_content_id.as_str())
            || bundle_is_in_closed_terminal_chain(state, current)
        {
            return false;
        }
        let rollout = state.rollout_states.get(&PolicyRolloutKeyV1 {
            candidate_content_id: current.candidate.candidate_content_id.clone(),
            node_id: current.candidate.exact_target.node_id.clone(),
        });
        if rollout.is_none_or(|rollout| {
            matches!(
                rollout.state,
                crate::PolicyRolloutStatusV1::Rejected | crate::PolicyRolloutStatusV1::Stale
            )
        }) {
            return false;
        }
        let Some(predecessor_id) = current
            .candidate
            .predecessor_candidate_content_id
            .as_deref()
        else {
            return true;
        };
        let Some(predecessor) = state.bundles.get(predecessor_id) else {
            return false;
        };
        if predecessor.candidate.exact_target.node_id != current.candidate.exact_target.node_id
            || bundle_profile_key(predecessor) != bundle_profile_key(current)
        {
            return false;
        }
        current = predecessor;
    }
}

fn bundle_requires_retirement(state: &ControlStoreState, bundle: &PolicyBundleV1) -> bool {
    if bundle.candidate.operation != crate::PolicyDeliveryOperationV1::RetireToRestrictiveTerminal {
        return true;
    }
    state
        .rollout_states
        .get(&PolicyRolloutKeyV1 {
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            node_id: bundle.candidate.exact_target.node_id.clone(),
        })
        .is_some_and(|rollout| {
            rollout.state == crate::PolicyRolloutStatusV1::Active
                && !terminal_chain_is_closed(state, bundle)
        })
}

fn terminal_chain_closure_can_be_authorized(
    state: &ControlStoreState,
    acknowledgement: &PolicyActivationAcknowledgementV1,
) -> bool {
    acknowledgement.state == PolicyActivationStateV1::Active
        && state
            .bundles
            .get(&acknowledgement.candidate_content_id)
            .is_some_and(|terminal| {
                terminal.candidate.operation
                    == crate::PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
                    && !has_later_dependent_successor(state, terminal)
            })
}

fn has_later_dependent_successor(state: &ControlStoreState, terminal: &PolicyBundleV1) -> bool {
    state.bundles.values().any(|successor| {
        successor.candidate.exact_target.node_id == terminal.candidate.exact_target.node_id
            && bundle_profile_key(successor) == bundle_profile_key(terminal)
            && bundle_sequence(successor) > bundle_sequence(terminal)
            && successor
                .candidate
                .predecessor_candidate_content_id
                .as_deref()
                == Some(terminal.candidate.candidate_content_id.as_str())
    })
}

fn terminal_chain_is_closed(state: &ControlStoreState, terminal: &PolicyBundleV1) -> bool {
    state.policy_acknowledgement_results.values().any(|result| {
        result.terminal_chain_closure_authorized
            && result.acknowledgement.candidate_content_id
                == terminal.candidate.candidate_content_id
    })
}

fn bundle_is_in_closed_terminal_chain(state: &ControlStoreState, bundle: &PolicyBundleV1) -> bool {
    state
        .policy_acknowledgement_results
        .values()
        .filter(|result| result.terminal_chain_closure_authorized)
        .any(|result| {
            let mut candidate_id = Some(result.acknowledgement.candidate_content_id.as_str());
            let mut visited = BTreeSet::new();
            while let Some(current_id) = candidate_id {
                if current_id == bundle.candidate.candidate_content_id {
                    return true;
                }
                if !visited.insert(current_id) {
                    return false;
                }
                candidate_id = state.bundles.get(current_id).and_then(|current| {
                    current
                        .candidate
                        .predecessor_candidate_content_id
                        .as_deref()
                });
            }
            false
        })
}

fn candidate_is_current_or_unsettled_predecessor(
    state: &ControlStoreState,
    node_id: &str,
    candidate_content_id: &str,
) -> bool {
    let Some(candidate) = state
        .bundles
        .get(candidate_content_id)
        .filter(|bundle| bundle.candidate.exact_target.node_id == node_id)
    else {
        return false;
    };
    let profile = bundle_profile_key(candidate);
    let Some(mut current) = state
        .bundles
        .values()
        .filter(|bundle| {
            bundle.candidate.exact_target.node_id == node_id
                && bundle_profile_key(bundle) == profile
        })
        .max_by_key(|bundle| bundle_sequence(bundle))
    else {
        return false;
    };
    if current.candidate.candidate_content_id == candidate_content_id {
        return true;
    }

    let mut visited = BTreeSet::new();
    while visited.insert(current.candidate.candidate_content_id.as_str()) {
        let Some(rollout) = state.rollout_states.get(&PolicyRolloutKeyV1 {
            candidate_content_id: current.candidate.candidate_content_id.clone(),
            node_id: node_id.to_owned(),
        }) else {
            return false;
        };
        // An active successor closes delayed acknowledgements for every older candidate.
        if rollout.state == crate::PolicyRolloutStatusV1::Active {
            return false;
        }
        let Some(predecessor_id) = current
            .candidate
            .predecessor_candidate_content_id
            .as_deref()
        else {
            return false;
        };
        if predecessor_id == candidate_content_id {
            return true;
        }
        let Some(predecessor) = state.bundles.get(predecessor_id).filter(|bundle| {
            bundle.candidate.exact_target.node_id == node_id
                && bundle_profile_key(bundle) == profile
        }) else {
            return false;
        };
        current = predecessor;
    }
    false
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn rebuild_evidence_indexes(
    state: &mut ControlStoreState,
    segments: &EvidenceSegmentOwner,
    root: &Path,
) -> Result<bool> {
    let mut recovered = false;
    for (stream_id, identity) in segments.identities() {
        validate_evidence_identity(identity, root)?;
        if state
            .evidence_stream_ids
            .iter()
            .any(|(existing, id)| *id == stream_id && existing != identity)
        {
            return ControlStoreSnafu {
                path: root.to_owned(),
                reason: "an evidence segment stream identifier conflicts with durable state"
                    .to_owned(),
            }
            .fail();
        }
        match state.evidence_stream_ids.get(identity) {
            Some(existing) if *existing != stream_id => {
                return ControlStoreSnafu {
                    path: root.to_owned(),
                    reason: "an evidence segment identity conflicts with its durable identifier"
                        .to_owned(),
                }
                .fail();
            }
            Some(_) => {}
            None => {
                Arc::make_mut(&mut state.evidence_stream_ids).insert(identity.clone(), stream_id);
                recovered = true;
            }
        }
    }
    let mut identities = BTreeMap::new();
    for (identity, stream_id) in state.evidence_stream_ids.iter() {
        validate_evidence_identity(identity, root)?;
        if *stream_id == 0 || identities.insert(*stream_id, identity.clone()).is_some() {
            return ControlStoreSnafu {
                path: root.to_owned(),
                reason: "durable evidence stream identifiers are zero or duplicated".to_owned(),
            }
            .fail();
        }
    }

    for (stream, position) in segments.positions() {
        if !identities.contains_key(&stream.stream_id) {
            return ControlStoreSnafu {
                path: root.to_owned(),
                reason: "an evidence segment position has no stream identity".to_owned(),
            }
            .fail();
        }
        let committed = state.evidence_segment_commits.entry(stream).or_default();
        if position > *committed {
            *committed = position;
            recovered = true;
        }
    }

    let descriptors = segments.descriptors().collect::<Vec<_>>();
    let durable_streams = state.evidence_stream_ids.as_ref().clone();
    for (identity, stream_id) in &durable_streams {
        let current = state
            .evidence_cursors
            .get(identity)
            .copied()
            .unwrap_or_default()
            .contiguous_cursor;
        let mut cursor = current;
        let mut ranges = descriptors
            .iter()
            .filter_map(|descriptor| match descriptor.kind {
                EvidenceSegmentKindV1::Records {
                    stream_id: candidate,
                    first_cursor,
                    last_cursor,
                } if candidate == *stream_id => Some((first_cursor, last_cursor)),
                _ => None,
            })
            .collect::<Vec<_>>();
        ranges.sort_unstable();
        for (first_cursor, last_cursor) in ranges {
            if first_cursor <= cursor.saturating_add(1) && last_cursor > cursor {
                cursor = last_cursor;
            }
        }
        if cursor > current {
            Arc::make_mut(&mut state.evidence_cursors).insert(
                identity.clone(),
                IntakeStateV1 {
                    contiguous_cursor: cursor,
                },
            );
            recovered = true;
        }

        let current_coverage = state
            .coverage_cursors
            .get(identity)
            .copied()
            .unwrap_or_default()
            .revision;
        let recovered_coverage = descriptors
            .iter()
            .filter_map(|descriptor| match descriptor.kind {
                EvidenceSegmentKindV1::Coverage {
                    stream_id: candidate,
                    last_revision,
                    ..
                } if candidate == *stream_id => Some(last_revision),
                _ => None,
            })
            .max()
            .unwrap_or(current_coverage);
        if recovered_coverage > current_coverage {
            Arc::make_mut(&mut state.coverage_cursors).insert(
                identity.clone(),
                CoverageIntakeStateV1 {
                    revision: recovered_coverage,
                },
            );
            recovered = true;
        }
    }

    let mut batches = BTreeMap::new();
    let mut pending = BTreeMap::new();
    let mut coverage = BTreeMap::new();
    for descriptor in descriptors {
        let identity = identities
            .get(&descriptor.kind.stream_id())
            .cloned()
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: root.to_owned(),
                    reason: "an evidence segment has no durable stream identity".to_owned(),
                }
                .build()
            })?;
        let consumed = state
            .evidence_consumption
            .get(&identity)
            .copied()
            .unwrap_or_default();
        match descriptor.kind {
            EvidenceSegmentKindV1::Records {
                first_cursor,
                last_cursor,
                ..
            } => {
                if last_cursor <= consumed.evidence_cursor {
                    continue;
                }
                let first_cursor = first_cursor.max(consumed.evidence_cursor.saturating_add(1));
                let batch = StoredEvidenceBatchV1 {
                    first_cursor,
                    last_cursor,
                    segment: descriptor.reference,
                };
                let intake = state
                    .evidence_cursors
                    .get(&identity)
                    .copied()
                    .unwrap_or_default()
                    .contiguous_cursor;
                if last_cursor <= intake {
                    let key = EvidenceBatchKeyV1 {
                        identity,
                        first_cursor,
                        last_cursor,
                    };
                    if batches.insert(key, batch).is_some() {
                        return ControlStoreSnafu {
                            path: root.to_owned(),
                            reason: "an accepted evidence range is duplicated".to_owned(),
                        }
                        .fail();
                    }
                } else {
                    if first_cursor <= intake {
                        return ControlStoreSnafu {
                            path: root.to_owned(),
                            reason: "an evidence segment crosses its intake cursor".to_owned(),
                        }
                        .fail();
                    }
                    let key = EvidencePendingKeyV1 {
                        identity,
                        first_cursor,
                    };
                    if pending.insert(key, batch).is_some() {
                        return ControlStoreSnafu {
                            path: root.to_owned(),
                            reason: "a pending evidence range is duplicated".to_owned(),
                        }
                        .fail();
                    }
                }
            }
            EvidenceSegmentKindV1::Coverage {
                first_revision,
                last_revision,
                ..
            } => {
                let current = state
                    .coverage_cursors
                    .get(&identity)
                    .copied()
                    .unwrap_or_default()
                    .revision;
                for revision in first_revision..=last_revision {
                    if revision <= consumed.coverage_revision && revision != current {
                        continue;
                    }
                    let key = CoverageReportKeyV1 {
                        identity: identity.clone(),
                        revision,
                    };
                    if coverage
                        .insert(
                            key,
                            StoredCoverageReportV1 {
                                identity: identity.clone(),
                                state: CoverageIntakeStateV1 { revision },
                                segment: segments
                                    .reference_at(descriptor.reference.id, revision)?,
                            },
                        )
                        .is_some()
                    {
                        return ControlStoreSnafu {
                            path: root.to_owned(),
                            reason: "a coverage revision is duplicated".to_owned(),
                        }
                        .fail();
                    }
                }
            }
        }
    }
    state.evidence_batches = Arc::new(batches);
    state.pending_evidence_batches = Arc::new(pending);
    state.coverage_reports = Arc::new(coverage);
    validate_rebuilt_evidence_indexes(state, root)?;
    Ok(recovered)
}

fn validate_rebuilt_evidence_indexes(state: &ControlStoreState, root: &Path) -> Result<()> {
    for (identity, intake) in state.evidence_cursors.iter() {
        if !state.evidence_stream_ids.contains_key(identity) {
            return ControlStoreSnafu {
                path: root.to_owned(),
                reason: "an evidence cursor has no durable stream identity".to_owned(),
            }
            .fail();
        }
        let consumed = state
            .evidence_consumption
            .get(identity)
            .copied()
            .unwrap_or_default()
            .evidence_cursor;
        if consumed > intake.contiguous_cursor {
            return ControlStoreSnafu {
                path: root.to_owned(),
                reason: "an evidence consumer watermark is newer than its intake cursor".to_owned(),
            }
            .fail();
        }
        let mut ranges = state
            .evidence_batches
            .keys()
            .filter(|key| &key.identity == identity)
            .map(|key| (key.first_cursor, key.last_cursor))
            .collect::<Vec<_>>();
        ranges.sort_unstable();
        let mut expected = consumed.checked_add(1).ok_or_else(|| {
            ControlStoreSnafu {
                path: root.to_owned(),
                reason: "the consumed evidence cursor is exhausted".to_owned(),
            }
            .build()
        })?;
        for (first_cursor, last_cursor) in ranges {
            if first_cursor != expected {
                return ControlStoreSnafu {
                    path: root.to_owned(),
                    reason: "retained evidence does not cover its durable cursor interval"
                        .to_owned(),
                }
                .fail();
            }
            expected = last_cursor.checked_add(1).ok_or_else(|| {
                ControlStoreSnafu {
                    path: root.to_owned(),
                    reason: "the retained evidence cursor is exhausted".to_owned(),
                }
                .build()
            })?;
        }
        if expected != intake.contiguous_cursor.saturating_add(1) {
            return ControlStoreSnafu {
                path: root.to_owned(),
                reason: "retained evidence ends before its durable intake cursor".to_owned(),
            }
            .fail();
        }
    }

    for identity in state.evidence_stream_ids.keys() {
        let intake = state
            .evidence_cursors
            .get(identity)
            .copied()
            .unwrap_or_default()
            .contiguous_cursor;
        let mut last = None;
        for (key, batch) in state
            .pending_evidence_batches
            .iter()
            .filter(|(key, _batch)| &key.identity == identity)
        {
            if key.first_cursor <= intake.saturating_add(1)
                || batch.last_cursor > intake.saturating_add(MAX_PENDING_EVIDENCE_RECORDS)
                || last.is_some_and(|last_cursor| key.first_cursor <= last_cursor)
            {
                return ControlStoreSnafu {
                    path: root.to_owned(),
                    reason: "a recovered pending evidence range is invalid or overlapping"
                        .to_owned(),
                }
                .fail();
            }
            last = Some(batch.last_cursor);
        }
    }

    for (identity, current) in state.coverage_cursors.iter() {
        let consumed = state
            .evidence_consumption
            .get(identity)
            .copied()
            .unwrap_or_default()
            .coverage_revision;
        if !state.evidence_stream_ids.contains_key(identity)
            || consumed > current.revision
            || (current.revision > 0
                && !state.coverage_reports.contains_key(&CoverageReportKeyV1 {
                    identity: identity.clone(),
                    revision: current.revision,
                }))
        {
            return ControlStoreSnafu {
                path: root.to_owned(),
                reason: "coverage latest state has no matching durable segment".to_owned(),
            }
            .fail();
        }
    }
    Ok(())
}

fn retained_evidence_segment_refs(
    state: &ControlStoreState,
) -> BTreeSet<crate::evidence_segment::EvidenceSegmentRefV1> {
    state
        .evidence_batches
        .values()
        .map(|batch| batch.segment)
        .chain(
            state
                .pending_evidence_batches
                .values()
                .map(|batch| batch.segment),
        )
        .chain(state.coverage_reports.values().map(|report| report.segment))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use snafu::ResultExt as _;

    use crate::{
        canonical_policy_spec_digest, workload_target_fact_digest, ContainerKindV1,
        ExceptionDeliveryCandidateV1, ExceptionDeliveryOperationV1, ExceptionRolloutStateV1,
        ExceptionSourceRevisionV1, ExceptionSourceStateV1, KubernetesWorkloadIdentityV1,
        NodeDecommissionAuthorizationV1, NodeDecommissionStateV1,
        PolicyActivationAcknowledgementV1, PolicyActivationStateV1, PolicyBundleV1, PolicyCompiler,
        PolicyDeliveryCandidateV1, PolicyDeliveryOperationV1, PolicyDocumentV1,
        PolicyRolloutStateV1, PolicyRolloutStatusV1, PolicySourceRevisionV1, PolicySourceStateV1,
        PolicyTargetSnapshotV1, PolicyTargetV1, ProfileCandidateArtifactV1, ProfileSealRequestV1,
        RegistryDigestsV1, SignedNodeDecommissionV1, WorkloadProtectionExceptionStateV1,
        WorkloadTargetFactV1,
    };
    use tempfile::TempDir;

    #[test]
    fn policy_validation_clone_shares_retained_evidence_maps() {
        let mut state = super::ControlStoreState::default();
        let key = super::EvidenceBatchKeyV1 {
            identity: crate::EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "node-a".to_owned(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            first_cursor: 1,
            last_cursor: 1,
        };
        Arc::make_mut(&mut state.evidence_batches).insert(
            key.clone(),
            crate::StoredEvidenceBatchV1 {
                first_cursor: 1,
                last_cursor: 1,
                segment: crate::evidence_segment::EvidenceSegmentRefV1 { id: 4, offset: 8 },
            },
        );

        let mut validation = state.clone();
        assert!(Arc::ptr_eq(
            &state.evidence_batches,
            &validation.evidence_batches
        ));
        Arc::make_mut(&mut validation.evidence_batches).remove(&key);
        assert!(state.evidence_batches.contains_key(&key));
        assert!(!validation.evidence_batches.contains_key(&key));
    }

    fn signed_artifact(
        document: &PolicyDocumentV1,
        issuer_sequence: u64,
    ) -> crate::Result<ProfileCandidateArtifactV1> {
        let digest = "00".repeat(32);
        ProfileCandidateArtifactV1::sign(
            document,
            PolicyCompiler.compile(document)?,
            ProfileSealRequestV1 {
                signing_key_id: "test-key".to_owned(),
                issuer_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                sequence_epoch: 1,
                issuer_sequence,
                rollback_authorization_id: None,
                registry_digests: RegistryDigestsV1 {
                    provider_numeric_registry_bundle_digest: digest.clone(),
                    required_capability_schema_digest: digest.clone(),
                    source_selector_registry_digest: digest.clone(),
                    object_classifier_registry_digest: digest.clone(),
                    reason_code_registry_digest: digest.clone(),
                    correlation_package_registry_digest: digest.clone(),
                    provider_vocabulary_registry_digest: digest,
                },
            },
            &SigningKey::from_bytes(&[7; 32]),
        )
    }

    fn source_revision(
        document: &PolicyDocumentV1,
        state: PolicySourceStateV1,
        generation: u64,
        revision_id: char,
    ) -> crate::Result<PolicySourceRevisionV1> {
        Ok(PolicySourceRevisionV1 {
            schema_version: 1,
            tenant_id: "10000000-0000-4000-8000-000000000001".to_owned(),
            cluster_uid: "20000000-0000-4000-8000-000000000001".to_owned(),
            namespace_uid: "30000000-0000-4000-8000-000000000001".to_owned(),
            object_uid: "40000000-0000-4000-8000-000000000001".to_owned(),
            namespace_name: "tenant-a".to_owned(),
            object_name: "profile".to_owned(),
            api_version: crate::POLICY_API_VERSION.to_owned(),
            kind: crate::POLICY_KIND.to_owned(),
            object_generation: generation,
            opaque_resource_version: generation.to_be_bytes().to_vec(),
            canonical_spec_digest: "1".repeat(64),
            policy_document_digest: canonical_policy_spec_digest(document)?,
            state,
            policy_source_revision_id: revision_id.to_string().repeat(64),
        })
    }

    fn target(source: &PolicySourceRevisionV1, node_id: &str, digest: char) -> PolicyTargetV1 {
        PolicyTargetV1 {
            tenant_id: source.tenant_id.clone(),
            cluster_uid: source.cluster_uid.clone(),
            node_id: node_id.to_owned(),
            workload_binding_generation_digests: vec![digest.to_string().repeat(64)],
            workload_targets: Vec::new(),
        }
    }

    fn kubernetes_target(
        source: &PolicySourceRevisionV1,
        document: &PolicyDocumentV1,
        kubernetes_node_uid: &str,
        boot_byte: u8,
        label_epoch: u64,
    ) -> crate::Result<PolicyTargetV1> {
        let mut workload = WorkloadTargetFactV1 {
            node_id: "node-a".to_owned(),
            workload_binding_generation_digest: String::new(),
            execution_set_id: "50000000-0000-4000-8000-000000000001".to_owned(),
            cluster_uid: source.cluster_uid.clone(),
            namespace_uid: source.namespace_uid.clone(),
            controller_uid: "60000000-0000-4000-8000-000000000001".to_owned(),
            service_account_uid: "70000000-0000-4000-8000-000000000001".to_owned(),
            pod_uid: "80000000-0000-4000-8000-000000000001".to_owned(),
            container_id: "containerd://converter".to_owned(),
            container_name: "converter".to_owned(),
            container_kind: ContainerKindV1::Application,
            image_digest: format!("sha256:{}", "a".repeat(64)),
            pod_labels: BTreeMap::from([("app".to_owned(), "converter".to_owned())]),
            kubernetes: Some(KubernetesWorkloadIdentityV1 {
                namespace_name: source.namespace_name.clone(),
                pod_name: "converter-pod".to_owned(),
                profile_id: document.metadata.profile_id.clone(),
                policy_source_revision_id: source.policy_source_revision_id.clone(),
                binding_id: "90000000-0000-4000-8000-000000000001".to_owned(),
                protected_scope_id: "a0000000-0000-4000-8000-000000000001".to_owned(),
                workload_selector_id: "b0000000-0000-4000-8000-000000000001".to_owned(),
                kubernetes_node_name: "worker-a.example".to_owned(),
                kubernetes_node_uid: kubernetes_node_uid.to_owned(),
                node_boot_id: hex::encode([boot_byte; 16]),
                label_epoch,
            }),
        };
        workload.workload_binding_generation_digest = workload_target_fact_digest(&workload)?;
        Ok(PolicyTargetV1 {
            tenant_id: source.tenant_id.clone(),
            cluster_uid: source.cluster_uid.clone(),
            node_id: workload.node_id.clone(),
            workload_binding_generation_digests: vec![workload
                .workload_binding_generation_digest
                .clone()],
            workload_targets: vec![workload],
        })
    }

    fn durable_session(boot_byte: u8, label_epoch: u64) -> super::DurableNodeSessionV1 {
        super::DurableNodeSessionV1 {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![boot_byte; 16],
            label_epoch,
            kubernetes_node_name: Some("worker-a.example".to_owned()),
            kubernetes_node_uid: None,
            startup_absence_proof_digest: super::startup_absence_proof_digest(
                "node-a",
                &[boot_byte; 16],
                label_epoch,
                true,
                true,
            ),
        }
    }

    fn exception_candidate(
        candidate_id: char,
        source_id: char,
        operation: ExceptionDeliveryOperationV1,
        valid_until_utc_ns: i64,
        target: &WorkloadTargetFactV1,
    ) -> ExceptionDeliveryCandidateV1 {
        ExceptionDeliveryCandidateV1 {
            schema_version: 1,
            tenant_id: "10000000-0000-4000-8000-000000000001".to_owned(),
            exception_source_revision_id: source_id.to_string().repeat(64),
            base_policy_source_revision_id: "8".repeat(64),
            base_candidate_content_id: "7".repeat(64),
            profile_id: "40000000-0000-4000-8000-000000000001".to_owned(),
            profile_generation_ref_id: 1,
            grant_id: "temporary-file-access".to_owned(),
            exception_instance_id: "c0000000-0000-4000-8000-000000000001".to_owned(),
            exact_target: target.clone(),
            operation,
            maximum_uses: 5,
            valid_until_utc_ns,
            predecessor_candidate_content_id: None,
            distribution_sequence_epoch: 1,
            distribution_sequence: u64::from(candidate_id as u32),
            issued_utc_ns: 1,
            expires_utc_ns: i64::MAX,
            signing_key_id: "test-key".to_owned(),
            candidate_content_id: candidate_id.to_string().repeat(64),
            signature: vec![1; 64],
        }
    }

    fn exception_session_advance_fixture() -> crate::Result<(
        super::ControlStoreState,
        super::NodeSessionAdvanceTransactionV1,
        [String; 3],
    )> {
        let (mut state, _reconciliation) = target_set_validation_fixture()?;
        state
            .node_sessions
            .insert("node-a".to_owned(), durable_session(1, 1));
        let source = state
            .source_revisions
            .values()
            .next()
            .cloned()
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: Path::new("exception-session").to_owned(),
                    reason: "the exception session fixture has no policy source".to_owned(),
                }
                .build()
            })?;
        let document = state
            .policy_documents
            .values()
            .next()
            .cloned()
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: Path::new("exception-session").to_owned(),
                    reason: "the exception session fixture has no policy document".to_owned(),
                }
                .build()
            })?;
        let target = kubernetes_target(
            &source,
            &document,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            1,
        )?
        .workload_targets
        .into_iter()
        .next()
        .ok_or_else(|| {
            crate::error::ControlStoreSnafu {
                path: Path::new("exception-session").to_owned(),
                reason: "the exception session fixture has no workload target".to_owned(),
            }
            .build()
        })?;
        let accepted_source_id = "c".repeat(64);
        let deletion_source_id = "d".repeat(64);
        for (id, source_state) in [
            (&accepted_source_id, ExceptionSourceStateV1::Accepted),
            (
                &deletion_source_id,
                ExceptionSourceStateV1::DeletionRequested,
            ),
        ] {
            state.exception_source_revisions.insert(
                id.clone(),
                ExceptionSourceRevisionV1 {
                    schema_version: 1,
                    tenant_id: source.tenant_id.clone(),
                    cluster_uid: source.cluster_uid.clone(),
                    namespace_uid: source.namespace_uid.clone(),
                    object_uid: "c0000000-0000-4000-8000-000000000001".to_owned(),
                    namespace_name: source.namespace_name.clone(),
                    object_name: "temporary-file-access".to_owned(),
                    api_version: crate::POLICY_API_VERSION.to_owned(),
                    kind: crate::EXCEPTION_KIND.to_owned(),
                    object_generation: 1,
                    opaque_resource_version: vec![1],
                    canonical_spec_digest: "1".repeat(64),
                    base_policy_source_revision_id: source.policy_source_revision_id.clone(),
                    grant_id: "temporary-file-access".to_owned(),
                    requested_duration_ns: 100,
                    requested_uses: 5,
                    state: source_state,
                    exception_source_revision_id: id.clone(),
                },
            );
        }
        let candidates = [
            exception_candidate(
                'e',
                'c',
                ExceptionDeliveryOperationV1::Activate,
                101,
                &target,
            ),
            exception_candidate(
                'f',
                'c',
                ExceptionDeliveryOperationV1::Activate,
                100,
                &target,
            ),
            exception_candidate('9', 'd', ExceptionDeliveryOperationV1::Revoke, 101, &target),
        ];
        let candidate_ids = candidates
            .each_ref()
            .map(|candidate| candidate.candidate_content_id.clone());
        for (index, candidate) in candidates.into_iter().enumerate() {
            let key = super::PolicyRolloutKeyV1 {
                candidate_content_id: candidate.candidate_content_id.clone(),
                node_id: candidate.exact_target.node_id.clone(),
            };
            state.exception_rollout_states.insert(
                key.clone(),
                ExceptionRolloutStateV1 {
                    exception_source_revision_id: candidate.exception_source_revision_id.clone(),
                    candidate_content_id: candidate.candidate_content_id.clone(),
                    node_id: candidate.exact_target.node_id.clone(),
                    state: if index == 0 {
                        WorkloadProtectionExceptionStateV1::Active
                    } else {
                        WorkloadProtectionExceptionStateV1::Pending
                    },
                    latest_acknowledgement_content_id: None,
                    transition_version: 1,
                    updated_utc_ns: 1,
                },
            );
            if index > 0 {
                state
                    .exception_consumed_uses
                    .insert(key, u32::try_from(index).unwrap_or(u32::MAX));
            }
            state
                .exception_candidates
                .insert(candidate.candidate_content_id.clone(), candidate);
        }
        let advance =
            super::node_session_advance(&state, durable_session(2, 2), 100, Path::new("advance"))?;
        Ok((state, advance, candidate_ids))
    }

    fn rollout_transaction(
        source: &PolicySourceRevisionV1,
        artifact: &ProfileCandidateArtifactV1,
        targets: Vec<(PolicyTargetV1, Option<String>)>,
        operation: PolicyDeliveryOperationV1,
        rollout_generation: u64,
        distribution_sequence: u64,
        signing_key: &SigningKey,
    ) -> crate::Result<super::PolicyRolloutTransactionV1> {
        let snapshot = PolicyTargetSnapshotV1::new(
            source.policy_source_revision_id.clone(),
            super::artifact_digest(artifact, Path::new("test-rollout"))?,
            rollout_generation,
            targets.iter().map(|(target, _)| target.clone()).collect(),
        )?;
        let mut bundles = Vec::with_capacity(targets.len());
        let mut rollout_states = Vec::with_capacity(targets.len());
        for (target, predecessor) in targets {
            let candidate = PolicyDeliveryCandidateV1::sign(
                source.tenant_id.clone(),
                source.policy_source_revision_id.clone(),
                snapshot.signed_profile_digest.clone(),
                &snapshot,
                target.clone(),
                operation,
                predecessor,
                1,
                distribution_sequence,
                1,
                if operation == PolicyDeliveryOperationV1::RetireToRestrictiveTerminal {
                    i64::MAX
                } else {
                    100
                },
                "test-key".to_owned(),
                signing_key,
            )?;
            bundles.push(PolicyBundleV1::new(
                candidate.clone(),
                artifact.clone(),
                signing_key.verifying_key().to_bytes().to_vec(),
            )?);
            rollout_states.push(PolicyRolloutStateV1 {
                policy_source_revision_id: source.policy_source_revision_id.clone(),
                target_snapshot_digest: snapshot.target_snapshot_digest.clone(),
                target,
                desired_candidate_content_id: candidate.candidate_content_id,
                state: PolicyRolloutStatusV1::Pending,
                latest_acknowledgement_content_id: None,
                transition_version: 1,
                updated_utc_ns: 1,
            });
        }
        Ok(super::PolicyRolloutTransactionV1 {
            target_snapshot: snapshot,
            bundles,
            rollout_states,
        })
    }

    fn active_acknowledgement_transaction(
        bundle: &PolicyBundleV1,
        rollout: &PolicyRolloutStateV1,
        terminal_chain_closure_authorized: bool,
    ) -> crate::Result<super::PolicyAcknowledgementTransactionV1> {
        let acknowledgement = PolicyActivationAcknowledgementV1 {
            acknowledgement_content_id: String::new(),
            tenant_id: bundle.candidate.tenant_id.clone(),
            node_id: bundle.candidate.exact_target.node_id.clone(),
            node_boot_id: vec![1; 16],
            label_epoch: 1,
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
            target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
            state: PolicyActivationStateV1::Active,
            node_bound_generation_digest: Some("1".repeat(64)),
            profile_generation_ref_id: Some(1),
            readback_digest: Some("2".repeat(64)),
            probe_result_digest: Some("3".repeat(64)),
            reason_code: None,
            observed_utc_ns: 2,
            authenticated_channel_receipt_digest: "4".repeat(64),
        }
        .finalize()?;
        Ok(super::PolicyAcknowledgementTransactionV1 {
            rollout_state: PolicyRolloutStateV1 {
                state: PolicyRolloutStatusV1::Active,
                latest_acknowledgement_content_id: Some(
                    acknowledgement.acknowledgement_content_id.clone(),
                ),
                transition_version: rollout.transition_version + 1,
                updated_utc_ns: acknowledgement.observed_utc_ns,
                ..rollout.clone()
            },
            acknowledgement,
            terminal_chain_closure_authorized,
        })
    }

    fn rejected_acknowledgement_transaction(
        bundle: &PolicyBundleV1,
        rollout: &PolicyRolloutStateV1,
    ) -> crate::Result<super::PolicyAcknowledgementTransactionV1> {
        let acknowledgement = PolicyActivationAcknowledgementV1 {
            acknowledgement_content_id: String::new(),
            tenant_id: bundle.candidate.tenant_id.clone(),
            node_id: bundle.candidate.exact_target.node_id.clone(),
            node_boot_id: vec![1; 16],
            label_epoch: 1,
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
            target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
            state: PolicyActivationStateV1::Rejected,
            node_bound_generation_digest: None,
            profile_generation_ref_id: None,
            readback_digest: None,
            probe_result_digest: None,
            reason_code: Some("CANDIDATE_REJECTED".to_owned()),
            observed_utc_ns: 3,
            authenticated_channel_receipt_digest: "4".repeat(64),
        }
        .finalize()?;
        Ok(super::PolicyAcknowledgementTransactionV1 {
            rollout_state: PolicyRolloutStateV1 {
                state: PolicyRolloutStatusV1::Rejected,
                latest_acknowledgement_content_id: Some(
                    acknowledgement.acknowledgement_content_id.clone(),
                ),
                transition_version: rollout.transition_version + 1,
                updated_utc_ns: acknowledgement.observed_utc_ns,
                ..rollout.clone()
            },
            acknowledgement,
            terminal_chain_closure_authorized: false,
        })
    }

    fn target_set_validation_fixture() -> crate::Result<(
        super::ControlStoreState,
        super::PolicyTargetSetTransactionV1,
    )> {
        let document = PolicyDocumentV1::parse(
            Path::new("policy-v1.yaml"),
            include_bytes!("../tests/fixtures/policy-v1.yaml"),
        )?;
        let source = source_revision(&document, PolicySourceStateV1::Accepted, 1, '7')?;
        let initial_artifact = signed_artifact(&document, 1)?;
        let refreshed_artifact = signed_artifact(&document, 2)?;
        let terminal_artifact =
            signed_artifact(&crate::restrictive_terminal_document(&document), 3)?;
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut state = super::ControlStoreState::default();
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::SourceAccepted {
                source_revision: Box::new(source.clone()),
                policy_document: Box::new(document.clone()),
                artifact: Some(Box::new(initial_artifact.clone())),
            },
            Path::new("source"),
        )?;

        let node_a = target(&source, "node-a", '1');
        let node_b = target(&source, "node-b", '2');
        let node_c = target(&source, "node-c", '3');
        let initial = rollout_transaction(
            &source,
            &initial_artifact,
            vec![
                (node_a.clone(), None),
                (node_b.clone(), None),
                (node_c.clone(), None),
            ],
            PolicyDeliveryOperationV1::Activate,
            document.rollout.rollout_generation,
            1,
            &signing_key,
        )?;
        let predecessors = initial
            .bundles
            .iter()
            .map(|bundle| {
                (
                    bundle.candidate.exact_target.node_id.clone(),
                    bundle.candidate.candidate_content_id.clone(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::RolloutCreated {
                rollout: Box::new(initial),
            },
            Path::new("initial-rollout"),
        )?;

        let desired = rollout_transaction(
            &source,
            &refreshed_artifact,
            vec![(node_a, predecessors.get("node-a").cloned())],
            PolicyDeliveryOperationV1::Replace,
            document.rollout.rollout_generation,
            2,
            &signing_key,
        )?;
        let retirement = rollout_transaction(
            &source,
            &terminal_artifact,
            vec![
                (node_b, predecessors.get("node-b").cloned()),
                (node_c, predecessors.get("node-c").cloned()),
            ],
            PolicyDeliveryOperationV1::RetireToRestrictiveTerminal,
            document.rollout.rollout_generation,
            2,
            &signing_key,
        )?;
        Ok((
            state,
            super::PolicyTargetSetTransactionV1 {
                desired,
                retirement: Some(retirement),
                refreshed_active_artifact: Some(refreshed_artifact),
            },
        ))
    }

    fn required_rejection(
        result: crate::Result<()>,
        reason: &'static str,
    ) -> crate::Result<crate::error::Error> {
        result.err().ok_or_else(|| {
            crate::error::ControlStoreSnafu {
                path: Path::new("tampered-target-set").to_owned(),
                reason: reason.to_owned(),
            }
            .build()
        })
    }

    #[test]
    fn durable_sequence_increment_rejects_exhaustion() {
        assert_eq!(
            super::checked_store_increment(41, Path::new("store"), "exhausted").ok(),
            Some(42)
        );
        assert!(super::checked_store_increment(u64::MAX, Path::new("store"), "exhausted").is_err());
    }

    #[test]
    fn exception_request_must_fit_the_current_grant() -> crate::Result<()> {
        let mut document = PolicyDocumentV1::parse(
            Path::new("policy-v1.yaml"),
            include_bytes!("../tests/fixtures/policy-v1.yaml"),
        )?;
        document.file_exception_grants = vec![crate::FileExceptionGrantTemplateV1 {
            grant_id: "temporary-file-access".to_owned(),
            denied_file_rule_ids: vec!["deny-service-account-files".to_owned()],
            maximum_duration_ns: 180_000_000_000,
            maximum_uses: 1,
        }];

        assert!(!super::exception_grant_covers_request(
            &document,
            "temporary-file-access",
            240_000_000_000,
            1,
        ));
        assert!(super::exception_grant_covers_request(
            &document,
            "temporary-file-access",
            180_000_000_000,
            1,
        ));
        Ok(())
    }

    #[test]
    fn rollout_state_machines_do_not_regress_terminal_authority() {
        use crate::{
            PolicyRolloutStatusV1 as Policy, WorkloadProtectionExceptionStateV1 as Exception,
        };

        assert!(super::valid_policy_rollout_transition(
            Policy::Staged,
            Policy::Active
        ));
        assert!(!super::valid_policy_rollout_transition(
            Policy::Active,
            Policy::Staged
        ));
        assert!(super::valid_exception_rollout_transition(
            Exception::Active,
            Exception::Consumed
        ));
        assert!(!super::valid_exception_rollout_transition(
            Exception::Consumed,
            Exception::Active
        ));
        assert!(!super::valid_exception_rollout_transition(
            Exception::Revoked,
            Exception::Active
        ));
    }

    #[test]
    fn control_store_lease_allows_one_durable_owner() -> crate::Result<()> {
        let directory = TempDir::new().map_err(|error| {
            crate::error::ControlStoreSnafu {
                path: Path::new("single-writer-test").to_owned(),
                reason: error.to_string(),
            }
            .build()
        })?;
        let first = super::ControlStore::open(directory.path())?;
        assert!(super::ControlStore::open(directory.path()).is_err());
        let first_proof = super::startup_absence_proof_digest("node-a", &[1; 16], 1, true, true);
        first.register_node_physical_session(
            "node-a",
            &[1; 16],
            1,
            Some("worker-a.example"),
            &first_proof,
            true,
            true,
            1,
        )?;

        drop(first);
        let replayed = super::ControlStore::open(directory.path())?;
        assert_eq!(replayed.commit_index(), 1);
        assert!(replayed.current_node_session_matches("node-a", &[1; 16], 1)?);
        assert!(!replayed.current_node_session_matches("node-a", &[2; 16], 1)?);
        let stale_proof = super::startup_absence_proof_digest("node-b", &[2; 16], 1, true, true);
        replayed.register_node_physical_session(
            "node-b",
            &[2; 16],
            1,
            Some("worker-b.example"),
            &stale_proof,
            true,
            true,
            2,
        )?;
        assert_eq!(replayed.commit_index(), 2);
        Ok(())
    }

    #[test]
    fn decommission_replay_requires_each_durable_transition_and_exact_node_boot(
    ) -> crate::Result<()> {
        let directory = TempDir::new().map_err(|error| {
            crate::error::ControlStoreSnafu {
                path: Path::new("decommission-store-test").to_owned(),
                reason: error.to_string(),
            }
            .build()
        })?;
        let store = super::ControlStore::open(directory.path())?;
        let proof = super::startup_absence_proof_digest("node-a", &[1; 16], 1, true, true);
        store.register_node_physical_session(
            "node-a",
            &[1; 16],
            1,
            Some("worker-a.example"),
            &proof,
            true,
            true,
            1,
        )?;
        store.bind_kubernetes_node_session(
            "node-a",
            &[1; 16],
            1,
            "worker-a.example",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )?;
        let key = SigningKey::from_bytes(&[7; 32]);
        let artifact = SignedNodeDecommissionV1::sign(
            &NodeDecommissionAuthorizationV1::new(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "node-a".to_owned(),
                "01010101-0101-0101-0101-010101010101",
                i64::MAX,
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            )?,
            "offline-decommission-v1".to_owned(),
            &key,
        )?
        .to_bytes()?;
        let submitted = store.submit_node_decommission(artifact.clone())?;
        let digest = submitted.digest();
        assert!(store
            .advance_node_decommission(digest, NodeDecommissionStateV1::Completed, String::new(),)
            .is_err());
        assert!(store.submit_node_decommission(artifact.clone()).is_ok());

        let second = SignedNodeDecommissionV1::sign(
            &NodeDecommissionAuthorizationV1::new(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "node-a".to_owned(),
                "01010101-0101-0101-0101-010101010101",
                i64::MAX,
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            )?,
            "offline-decommission-v1".to_owned(),
            &key,
        )?
        .to_bytes()?;
        assert!(store.submit_node_decommission(second).is_err());

        store.advance_node_decommission(
            digest,
            NodeDecommissionStateV1::Accepted,
            String::new(),
        )?;
        assert!(store
            .advance_node_decommission(
                digest,
                NodeDecommissionStateV1::Rejected,
                "LATE_REJECTION".to_owned(),
            )
            .is_err());
        store.advance_node_decommission(
            digest,
            NodeDecommissionStateV1::Quarantined,
            String::new(),
        )?;
        store.advance_node_decommission(
            digest,
            NodeDecommissionStateV1::Completed,
            String::new(),
        )?;
        assert!(store.completed_node_decommission(
            "worker-a.example",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        )?);
        drop(store);

        let reopened = super::ControlStore::open(directory.path())?;
        assert_eq!(
            reopened
                .node_decommission(digest)?
                .map(|record| record.state),
            Some(NodeDecommissionStateV1::Completed)
        );
        assert!(reopened
            .advance_node_decommission(digest, NodeDecommissionStateV1::Quarantined, String::new(),)
            .is_err());
        Ok(())
    }

    #[test]
    fn kubernetes_outage_evidence_fast_path_matches_durable_replay() -> crate::Result<()> {
        let directory = TempDir::new().map_err(|error| {
            crate::error::ControlStoreSnafu {
                path: Path::new("evidence-fast-path-test").to_owned(),
                reason: error.to_string(),
            }
            .build()
        })?;
        let store = super::ControlStore::open(directory.path())?;
        let absence_proof = super::startup_absence_proof_digest("node-a", &[1; 16], 1, true, true);
        store.register_node_physical_session(
            "node-a",
            &[1; 16],
            1,
            Some("worker-a.example"),
            &absence_proof,
            true,
            true,
            1,
        )?;
        let identity = super::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".to_owned(),
            node_boot_id: [1; 16],
            label_epoch: 1,
            source_id: [2; 16],
            source_epoch: 1,
        };
        let records = (1_u64..=3)
            .map(|cursor| crate::EvidenceRecord {
                observed_boottime_ns: cursor,
                ingested_utc_ns: i64::try_from(cursor).unwrap_or_default(),
                coverage_interval_id: vec![3; 16].into(),
                task_cookie: cursor,
                reason: 1,
                decision: 1,
                effect_family: 1,
                operation: 1,
                configured_errno: -13,
                kernel_result: -13,
                temporal_coverage: crate::EvidenceTemporalCoverage::Complete as i32,
                ..crate::EvidenceRecord::default()
            })
            .collect::<Vec<_>>();
        let pending = super::EvidenceBatchInputV1::encode(3, records[2..].to_vec())?;
        assert_eq!(
            store.accept_evidence_batch(identity.clone(), pending)?,
            super::EvidenceStoreOutcomeV1::Pending
        );
        let contiguous = super::EvidenceBatchInputV1::encode(1, records[..2].to_vec())?;
        assert_eq!(
            store.accept_evidence_batch(identity.clone(), contiguous)?,
            super::EvidenceStoreOutcomeV1::Accepted
        );
        let counters = crate::CoverageCounters {
            attempted: 3,
            requested: 3,
            emitted: 3,
            next_sequence: 4,
            ..crate::CoverageCounters::default()
        };
        let coverage = crate::CoverageReport {
            source_id: identity.source_id.to_vec(),
            cpu_id: 0,
            source_epoch: identity.source_epoch,
            revision: 1,
            intervals: vec![crate::CoverageInterval {
                interval_id: vec![3; 16],
                source_epoch: identity.source_epoch,
                revision: 1,
                state: "HEALTHY".to_owned(),
                first_sequence: 1,
                last_sequence: Some(3),
                opening_counters: Some(crate::CoverageCounters::default()),
                closing_counters: Some(counters),
                gap_reasons: Vec::new(),
                current: true,
            }],
        };
        store.accept_coverage_report(super::CoverageReportInputV1 {
            identity: identity.clone(),
            report: coverage.clone(),
        })?;

        let live_health = store.health()?;
        let live_records = store.accepted_evidence_records(&identity)?;
        assert_eq!(store.evidence_cursor(&identity)?, 3);
        assert_eq!(
            store.latest_coverage_report(&identity)?,
            Some(coverage.clone())
        );
        drop(store);

        let replayed = super::ControlStore::open(directory.path())?;
        assert_eq!(replayed.health()?, live_health);
        assert_eq!(replayed.accepted_evidence_records(&identity)?, live_records);
        assert_eq!(replayed.evidence_cursor(&identity)?, 3);
        assert_eq!(replayed.latest_coverage_report(&identity)?, Some(coverage));
        assert!(replayed.current_node_session_matches("node-a", &[1; 16], 1)?);
        Ok(())
    }

    #[test]
    fn rejected_evidence_never_survives_as_a_durable_segment() -> crate::Result<()> {
        let directory = TempDir::new().map_err(|error| {
            crate::error::ControlStoreSnafu {
                path: Path::new("rejected-evidence-segment-test").to_owned(),
                reason: error.to_string(),
            }
            .build()
        })?;
        let identity = super::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".to_owned(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let cursor = super::MAX_PENDING_EVIDENCE_RECORDS + 1;
        let store = super::ControlStore::open(directory.path())?;
        for _ in 0..2 {
            assert!(store
                .accept_evidence_batch(
                    identity.clone(),
                    super::EvidenceBatchInputV1::encode(
                        cursor,
                        vec![crate::EvidenceRecord {
                            observed_boottime_ns: cursor,
                            task_cookie: cursor,
                            coverage_interval_id: vec![4; 16].into(),
                            reason: 1,
                            decision: 1,
                            effect_family: 1,
                            operation: 1,
                            configured_errno: -13,
                            kernel_result: -13,
                            temporal_coverage: crate::EvidenceTemporalCoverage::Complete as i32,
                            ..crate::EvidenceRecord::default()
                        }],
                    )?,
                )
                .is_err());
        }
        store.accept_coverage_report(super::CoverageReportInputV1 {
            identity: identity.clone(),
            report: crate::CoverageReport {
                source_id: identity.source_id.to_vec(),
                source_epoch: identity.source_epoch,
                revision: 1,
                ..crate::CoverageReport::default()
            },
        })?;
        drop(store);

        let reopened = super::ControlStore::open(directory.path())?;
        assert!(reopened.accepted_evidence_records(&identity)?.is_empty());
        assert_eq!(
            std::fs::read_dir(directory.path().join("evidence/segments-v2"))
                .map_err(|error| crate::Error::Io {
                    path: directory.path().to_owned(),
                    source: error,
                    location: snafu::Location::default(),
                })?
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn segments_retain_every_record_and_meet_the_storage_target() -> crate::Result<()> {
        const BATCHES: u64 = 130;
        const RECORDS_PER_BATCH: u64 = 64;
        const LEGACY_BYTES_PER_RECORD: u64 = 16_776;

        let directory = TempDir::new().map_err(|error| {
            crate::error::ControlStoreSnafu {
                path: Path::new("latest-state-test").to_owned(),
                reason: error.to_string(),
            }
            .build()
        })?;
        let store = super::ControlStore::open(directory.path())?;
        let state = directory.path().join("state.bin");
        let identity = crate::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".to_owned(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        for batch_index in 0..BATCHES {
            let first_cursor = batch_index * RECORDS_PER_BATCH + 1;
            let records = (first_cursor..first_cursor + RECORDS_PER_BATCH)
                .map(|cursor| crate::EvidenceRecord {
                    observed_boottime_ns: cursor,
                    ingested_utc_ns: i64::try_from(cursor).unwrap_or_default(),
                    coverage_interval_id: vec![4; 16].into(),
                    task_cookie: cursor,
                    reason: 1,
                    decision: 1,
                    effect_family: 1,
                    operation: 1,
                    configured_errno: -13,
                    kernel_result: -13,
                    temporal_coverage: crate::EvidenceTemporalCoverage::Complete as i32,
                    ..crate::EvidenceRecord::default()
                })
                .collect();
            assert_eq!(
                store.accept_evidence_batch(
                    identity.clone(),
                    crate::EvidenceBatchInputV1::encode(first_cursor, records)?,
                )?,
                crate::EvidenceStoreOutcomeV1::Accepted
            );
        }
        let segments = directory.path().join("evidence/segments-v2");
        let segment_count = std::fs::read_dir(&segments)
            .map_err(|error| crate::Error::Io {
                path: segments.clone(),
                source: error,
                location: snafu::Location::default(),
            })?
            .count();
        assert_eq!(segment_count, 1);
        assert!(!state.exists());
        assert!(!directory.path().join("commits").exists());

        let mut stored_bytes = 0_u64;
        for entry in std::fs::read_dir(&segments).map_err(|error| crate::Error::Io {
            path: segments.clone(),
            source: error,
            location: snafu::Location::default(),
        })? {
            let path = entry
                .map_err(|error| crate::Error::Io {
                    path: segments.clone(),
                    source: error,
                    location: snafu::Location::default(),
                })?
                .path();
            stored_bytes = stored_bytes.saturating_add(
                std::fs::metadata(&path)
                    .map_err(|error| crate::Error::Io {
                        path,
                        source: error,
                        location: snafu::Location::default(),
                    })?
                    .len(),
            );
        }
        let record_count = BATCHES * RECORDS_PER_BATCH;
        assert!(stored_bytes * 100 <= LEGACY_BYTES_PER_RECORD * record_count);

        drop(store);
        let started = std::time::Instant::now();
        let reopened = super::ControlStore::open(directory.path())?;
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(reopened.commit_index(), 0);
        assert_eq!(
            reopened.accepted_evidence_records(&identity)?.len() as u64,
            record_count
        );
        assert_eq!(
            std::fs::read_dir(&segments)
                .map_err(|error| crate::Error::Io {
                    path: segments.clone(),
                    source: error,
                    location: snafu::Location::default(),
                })?
                .count() as u64,
            1
        );
        drop(reopened);

        let segment = std::fs::read_dir(&segments)
            .map_err(|error| crate::Error::Io {
                path: segments.clone(),
                source: error,
                location: snafu::Location::default(),
            })?
            .next()
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: directory.path().to_owned(),
                    reason: "latest-state test did not write an evidence segment".to_owned(),
                }
                .build()
            })?
            .map_err(|error| crate::Error::Io {
                path: segments,
                source: error,
                location: snafu::Location::default(),
            })?
            .path();
        std::fs::remove_file(&segment).map_err(|error| crate::Error::Io {
            path: segment,
            source: error,
            location: snafu::Location::default(),
        })?;
        assert!(super::ControlStore::open(directory.path()).is_err());
        Ok(())
    }

    #[test]
    fn restart_recovers_a_complete_segment_tail_without_a_state_high_watermark() -> crate::Result<()>
    {
        let directory = TempDir::new().map_err(|error| {
            crate::error::ControlStoreSnafu {
                path: Path::new("uncommitted-segment-test").to_owned(),
                reason: error.to_string(),
            }
            .build()
        })?;
        let identity = crate::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".to_owned(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let store = super::ControlStore::open(directory.path())?;
        store.accept_evidence_batch(
            identity.clone(),
            crate::EvidenceBatchInputV1::encode(
                1,
                vec![crate::EvidenceRecord {
                    observed_boottime_ns: 1,
                    task_cookie: 1,
                    coverage_interval_id: vec![4; 16].into(),
                    reason: 1,
                    decision: 1,
                    effect_family: 1,
                    operation: 1,
                    configured_errno: -13,
                    kernel_result: -13,
                    temporal_coverage: crate::EvidenceTemporalCoverage::Complete as i32,
                    ..crate::EvidenceRecord::default()
                }],
            )?,
        )?;
        drop(store);

        let mut segments = crate::evidence_segment::EvidenceSegmentOwner::open(
            directory.path(),
            crate::EvidenceStoreLimitsV1::default(),
        )?;
        segments.write_records(
            &identity,
            1,
            2,
            2,
            &crate::EvidenceRecords {
                records: vec![crate::EvidenceRecord {
                    observed_boottime_ns: 2,
                    task_cookie: 2,
                    coverage_interval_id: vec![4; 16].into(),
                    reason: 1,
                    decision: 1,
                    effect_family: 1,
                    operation: 1,
                    configured_errno: -13,
                    kernel_result: -13,
                    temporal_coverage: crate::EvidenceTemporalCoverage::Complete as i32,
                    ..crate::EvidenceRecord::default()
                }],
            },
        )?;
        drop(segments);

        let reopened = super::ControlStore::open(directory.path())?;
        assert_eq!(reopened.evidence_cursor(&identity)?, 2);
        assert_eq!(reopened.accepted_evidence_records(&identity)?.len(), 2);
        assert_eq!(
            std::fs::read_dir(directory.path().join("evidence/segments-v2"))
                .map_err(|error| crate::Error::Io {
                    path: directory.path().to_owned(),
                    source: error,
                    location: snafu::Location::default(),
                })?
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn evidence_capacity_reclaims_only_consumed_segments_or_retains_them() -> crate::Result<()> {
        let identity = crate::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".to_owned(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let batch = |cursor| {
            crate::EvidenceBatchInputV1::encode(
                cursor,
                vec![crate::EvidenceRecord {
                    observed_boottime_ns: cursor,
                    task_cookie: cursor,
                    coverage_interval_id: vec![4; 16].into(),
                    reason: 1,
                    decision: 1,
                    effect_family: 1,
                    operation: 1,
                    configured_errno: -13,
                    kernel_result: -13,
                    temporal_coverage: crate::EvidenceTemporalCoverage::Complete as i32,
                    ..crate::EvidenceRecord::default()
                }],
            )
        };
        let limits = |capacity_policy| crate::EvidenceStoreLimitsV1 {
            maximum_retained_bytes: crate::MAX_EVIDENCE_SEGMENT_BYTES as u64,
            maximum_retained_records: 1,
            capacity_policy,
        };

        let blocked = TempDir::new().map_err(|error| {
            crate::error::ControlStoreSnafu {
                path: Path::new("blocked-evidence-store").to_owned(),
                reason: error.to_string(),
            }
            .build()
        })?;
        let store = super::ControlStore::open_with_evidence_limits(
            blocked.path(),
            limits(crate::EvidenceStoreCapacityPolicyV1::Block),
        )?;
        assert!(store
            .acknowledge_evidence_consumption(crate::EvidenceConsumptionWatermarkV1 {
                identity: identity.clone(),
                evidence_cursor: 1,
                coverage_revision: 0,
            })
            .is_err());
        store.accept_evidence_batch(identity.clone(), batch(1)?)?;
        assert!(store
            .accept_evidence_batch(identity.clone(), batch(2)?)
            .is_err());
        assert_eq!(
            std::fs::read_dir(blocked.path().join("evidence/segments-v2"))
                .map_err(|error| crate::Error::Io {
                    path: blocked.path().to_owned(),
                    source: error,
                    location: snafu::Location::default(),
                })?
                .count(),
            1
        );
        store.acknowledge_evidence_consumption(crate::EvidenceConsumptionWatermarkV1 {
            identity: identity.clone(),
            evidence_cursor: 1,
            coverage_revision: 0,
        })?;
        assert!(store.accepted_evidence_records(&identity)?.is_empty());
        assert_eq!(store.evidence_cursor(&identity)?, 1);
        assert_eq!(
            std::fs::read_dir(blocked.path().join("evidence/segments-v2"))
                .map_err(|error| crate::Error::Io {
                    path: blocked.path().to_owned(),
                    source: error,
                    location: snafu::Location::default(),
                })?
                .count(),
            0
        );
        assert_eq!(
            store.accept_evidence_batch(identity.clone(), batch(1)?)?,
            crate::EvidenceStoreOutcomeV1::Accepted
        );
        store.accept_evidence_batch(identity.clone(), batch(2)?)?;
        assert_eq!(
            std::fs::read_dir(blocked.path().join("evidence/segments-v2"))
                .map_err(|error| crate::Error::Io {
                    path: blocked.path().to_owned(),
                    source: error,
                    location: snafu::Location::default(),
                })?
                .count(),
            1
        );
        drop(store);
        let reopened = super::ControlStore::open_with_evidence_limits(
            blocked.path(),
            limits(crate::EvidenceStoreCapacityPolicyV1::Block),
        )?;
        assert_eq!(
            reopened.evidence_consumption(&identity)?,
            crate::EvidenceConsumptionStateV1 {
                evidence_cursor: 1,
                coverage_revision: 0,
            }
        );
        assert_eq!(reopened.accepted_evidence_records(&identity)?.len(), 1);

        let retained = TempDir::new().map_err(|error| {
            crate::error::ControlStoreSnafu {
                path: Path::new("retained-evidence-store").to_owned(),
                reason: error.to_string(),
            }
            .build()
        })?;
        let store = super::ControlStore::open_with_evidence_limits(
            retained.path(),
            limits(crate::EvidenceStoreCapacityPolicyV1::Retain),
        )?;
        store.accept_evidence_batch(identity.clone(), batch(1)?)?;
        store.accept_evidence_batch(identity.clone(), batch(2)?)?;
        drop(store);
        let reopened = super::ControlStore::open_with_evidence_limits(
            retained.path(),
            limits(crate::EvidenceStoreCapacityPolicyV1::Retain),
        )?;
        assert_eq!(reopened.accepted_evidence_records(&identity)?.len(), 2);
        assert_eq!(
            std::fs::read_dir(retained.path().join("evidence/segments-v2"))
                .map_err(|error| crate::Error::Io {
                    path: retained.path().to_owned(),
                    source: error,
                    location: snafu::Location::default(),
                })?
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn uid_rebind_preserves_the_chain_and_physical_reset_restarts_it() -> crate::Result<()> {
        let directory = TempDir::new().map_err(|error| {
            crate::error::ControlStoreSnafu {
                path: Path::new("session-test").to_owned(),
                reason: error.to_string(),
            }
            .build()
        })?;
        let store = super::ControlStore::open(directory.path())?;
        let first_proof = super::startup_absence_proof_digest("node-a", &[1; 16], 1, true, true);
        store.register_node_physical_session(
            "node-a",
            &[1; 16],
            1,
            Some("worker-a.example"),
            &first_proof,
            true,
            true,
            1,
        )?;
        store.bind_kubernetes_node_session(
            "node-a",
            &[1; 16],
            1,
            "worker-a.example",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )?;

        let document = PolicyDocumentV1::parse(
            Path::new("policy-v1.yaml"),
            include_bytes!("../tests/fixtures/policy-v1.yaml"),
        )?;
        let source = source_revision(&document, PolicySourceStateV1::Accepted, 1, '8')?;
        let artifact = signed_artifact(&document, 1)?;
        store.accept_compiled_source_revision(
            source.clone(),
            document.clone(),
            artifact.clone(),
        )?;
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let initial = rollout_transaction(
            &source,
            &artifact,
            vec![(
                kubernetes_target(
                    &source,
                    &document,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    1,
                    1,
                )?,
                None,
            )],
            PolicyDeliveryOperationV1::Activate,
            document.rollout.rollout_generation,
            1,
            &signing_key,
        )?;
        let initial_bundle = initial.bundles[0].clone();
        let initial_rollout = initial.rollout_states[0].clone();
        store.create_rollout(
            initial.target_snapshot,
            initial.bundles,
            initial.rollout_states,
        )?;
        let initial_ack =
            active_acknowledgement_transaction(&initial_bundle, &initial_rollout, false)?;
        store.acknowledge_policy(
            initial_ack.acknowledgement.clone(),
            initial_ack.rollout_state.clone(),
        )?;

        store.bind_kubernetes_node_session(
            "node-a",
            &[1; 16],
            1,
            "worker-a.example",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        )?;
        let rebound = rollout_transaction(
            &source,
            &artifact,
            vec![(
                kubernetes_target(
                    &source,
                    &document,
                    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    1,
                    1,
                )?,
                Some(initial_bundle.candidate.candidate_content_id.clone()),
            )],
            PolicyDeliveryOperationV1::Replace,
            document.rollout.rollout_generation,
            2,
            &signing_key,
        )?;
        let rebound_bundle = rebound.bundles[0].clone();
        store.create_rollout(
            rebound.target_snapshot,
            rebound.bundles,
            rebound.rollout_states,
        )?;
        assert_eq!(
            rebound_bundle
                .candidate
                .predecessor_candidate_content_id
                .as_deref(),
            Some(initial_bundle.candidate.candidate_content_id.as_str())
        );
        // A Kubernetes UID change does not change the physical enforcement epoch.
        assert!(store
            .acknowledge_policy(
                initial_ack.acknowledgement.clone(),
                initial_ack.rollout_state.clone(),
            )
            .is_ok());

        let reset_proof = super::startup_absence_proof_digest("node-a", &[2; 16], 2, true, true);
        store.register_node_physical_session(
            "node-a",
            &[2; 16],
            2,
            Some("worker-a.example"),
            &reset_proof,
            true,
            true,
            10,
        )?;
        for candidate_id in [
            &initial_bundle.candidate.candidate_content_id,
            &rebound_bundle.candidate.candidate_content_id,
        ] {
            assert_eq!(
                store
                    .rollout_state(candidate_id, "node-a")?
                    .ok_or_else(|| crate::error::ControlStoreSnafu {
                        path: Path::new("session-test").to_owned(),
                        reason: "a stale rollout is absent".to_owned(),
                    }
                    .build())?
                    .state,
                PolicyRolloutStatusV1::Stale
            );
        }
        assert!(store
            .acknowledge_policy(initial_ack.acknowledgement, initial_ack.rollout_state)
            .is_err());
        assert!(store
            .policy_inventory_for_node_session(
                "node-a",
                &[2; 16],
                2,
                &[
                    initial_bundle.bundle_digest.clone(),
                    rebound_bundle.bundle_digest
                ],
            )?
            .0
            .is_none());

        store.bind_kubernetes_node_session(
            "node-a",
            &[2; 16],
            2,
            "worker-a.example",
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        )?;
        let restarted = rollout_transaction(
            &source,
            &artifact,
            vec![(
                kubernetes_target(
                    &source,
                    &document,
                    "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    2,
                    2,
                )?,
                None,
            )],
            PolicyDeliveryOperationV1::Activate,
            document.rollout.rollout_generation,
            3,
            &signing_key,
        )?;
        let restarted_bundle = restarted.bundles[0].clone();
        store.create_rollout(
            restarted.target_snapshot,
            restarted.bundles,
            restarted.rollout_states,
        )?;
        assert!(restarted_bundle
            .candidate
            .predecessor_candidate_content_id
            .is_none());
        let (candidate, desired) =
            store.policy_inventory_for_node_session("node-a", &[2; 16], 2, &[])?;
        assert_eq!(candidate, Some(restarted_bundle.clone()));
        assert_eq!(desired, vec![restarted_bundle.bundle_digest.clone()]);
        let committed = store.commit_index();
        drop(store);

        let replayed = super::ControlStore::open(directory.path())?;
        assert_eq!(replayed.commit_index(), committed);
        assert_eq!(
            replayed.policy_inventory_for_node_session("node-a", &[2; 16], 2, &[])?,
            (
                Some(restarted_bundle.clone()),
                vec![restarted_bundle.bundle_digest]
            )
        );
        assert!(replayed
            .policy_inventory_for_node_session("node-a", &[1; 16], 1, &[])
            .is_err());
        Ok(())
    }

    #[test]
    fn physical_reset_settles_exception_authority_by_proven_terminal_reason() -> crate::Result<()> {
        let (state, advance, candidate_ids) = exception_session_advance_fixture()?;
        let settlements = advance
            .exception_settlements
            .iter()
            .map(|settlement| {
                (
                    settlement.rollout_state.candidate_content_id.as_str(),
                    (settlement.rollout_state.state, settlement.consumed_uses),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            settlements.get(candidate_ids[0].as_str()),
            Some(&(WorkloadProtectionExceptionStateV1::Consumed, 5))
        );
        assert_eq!(
            settlements.get(candidate_ids[1].as_str()),
            Some(&(WorkloadProtectionExceptionStateV1::Expired, 1))
        );
        assert_eq!(
            settlements.get(candidate_ids[2].as_str()),
            Some(&(WorkloadProtectionExceptionStateV1::Revoked, 2))
        );

        let transaction = super::ControlTransactionV1::NodeSessionAdvanced {
            advance: Box::new(advance),
        };
        let mut live = state.clone();
        super::apply_transaction(&mut live, &transaction, Path::new("live-reset"))?;
        let encoded = serde_json::to_vec(&transaction).context(crate::error::JsonSnafu {
            path: Path::new("replayed-reset"),
        })?;
        let replayed_transaction =
            serde_json::from_slice(&encoded).context(crate::error::JsonSnafu {
                path: Path::new("replayed-reset"),
            })?;
        let mut replayed = state;
        super::apply_transaction(
            &mut replayed,
            &replayed_transaction,
            Path::new("replayed-reset"),
        )?;
        assert_eq!(live.node_sessions, replayed.node_sessions);
        assert_eq!(
            live.exception_rollout_states,
            replayed.exception_rollout_states
        );
        assert_eq!(
            live.exception_consumed_uses,
            replayed.exception_consumed_uses
        );
        Ok(())
    }

    #[test]
    fn physical_reset_rejects_omitted_or_tampered_derived_settlements() -> crate::Result<()> {
        let (state, advance, _candidate_ids) = exception_session_advance_fixture()?;

        let mut omitted_policy = advance.clone();
        omitted_policy.policy_rollout_states.clear();
        assert!(super::apply_transaction(
            &mut state.clone(),
            &super::ControlTransactionV1::NodeSessionAdvanced {
                advance: Box::new(omitted_policy),
            },
            Path::new("omitted-policy-session-settlement"),
        )
        .is_err());

        let mut omitted_exception = advance.clone();
        omitted_exception.exception_settlements.pop();
        assert!(super::apply_transaction(
            &mut state.clone(),
            &super::ControlTransactionV1::NodeSessionAdvanced {
                advance: Box::new(omitted_exception),
            },
            Path::new("omitted-exception-session-settlement"),
        )
        .is_err());

        let mut refunded = advance.clone();
        let consumed = refunded
            .exception_settlements
            .iter_mut()
            .find(|settlement| {
                settlement.rollout_state.state == WorkloadProtectionExceptionStateV1::Consumed
            })
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: Path::new("refunded-session-settlement").to_owned(),
                    reason: "the reset fixture has no consumed exception".to_owned(),
                }
                .build()
            })?;
        consumed.consumed_uses -= 1;
        assert!(super::apply_transaction(
            &mut state.clone(),
            &super::ControlTransactionV1::NodeSessionAdvanced {
                advance: Box::new(refunded),
            },
            Path::new("refunded-session-settlement"),
        )
        .is_err());

        let mut wrong_epoch = advance;
        wrong_epoch.session.label_epoch = 1;
        wrong_epoch.session.startup_absence_proof_digest = super::startup_absence_proof_digest(
            "node-a",
            &wrong_epoch.session.node_boot_id,
            1,
            true,
            true,
        );
        assert!(super::apply_transaction(
            &mut state.clone(),
            &super::ControlTransactionV1::NodeSessionAdvanced {
                advance: Box::new(wrong_epoch),
            },
            Path::new("non-monotonic-session"),
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn closed_terminal_rejects_a_dependent_replace_and_accepts_a_root() -> crate::Result<()> {
        let (mut state, reconciliation) = target_set_validation_fixture()?;
        let source = state
            .source_revisions
            .values()
            .next()
            .cloned()
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: Path::new("terminal-closure").to_owned(),
                    reason: "the test state has no source revision".to_owned(),
                }
                .build()
            })?;
        let artifact = reconciliation
            .refreshed_active_artifact
            .clone()
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: Path::new("terminal-closure").to_owned(),
                    reason: "the test reconciliation has no active artifact".to_owned(),
                }
                .build()
            })?;
        let terminal_transaction = reconciliation.retirement.as_ref().ok_or_else(|| {
            crate::error::ControlStoreSnafu {
                path: Path::new("terminal-closure").to_owned(),
                reason: "the test reconciliation has no retirement".to_owned(),
            }
            .build()
        })?;
        let terminal = terminal_transaction.bundles[0].clone();
        let terminal_rollout = terminal_transaction.rollout_states[0].clone();
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::TargetSetReconciled {
                reconciliation: Box::new(reconciliation),
            },
            Path::new("terminal-rollout"),
        )?;
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::Acknowledged {
                result: Box::new(active_acknowledgement_transaction(
                    &terminal,
                    &terminal_rollout,
                    true,
                )?),
            },
            Path::new("terminal-acknowledgement"),
        )?;

        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let dependent = rollout_transaction(
            &source,
            &artifact,
            vec![(
                terminal.candidate.exact_target.clone(),
                Some(terminal.candidate.candidate_content_id.clone()),
            )],
            PolicyDeliveryOperationV1::Replace,
            artifact.policy_document.rollout.rollout_generation,
            terminal.candidate.distribution_sequence + 1,
            &signing_key,
        )?;
        assert!(super::apply_transaction(
            &mut state.clone(),
            &super::ControlTransactionV1::RolloutCreated {
                rollout: Box::new(dependent),
            },
            Path::new("dependent-replace"),
        )
        .is_err());

        let root = rollout_transaction(
            &source,
            &artifact,
            vec![(terminal.candidate.exact_target.clone(), None)],
            PolicyDeliveryOperationV1::Activate,
            artifact.policy_document.rollout.rollout_generation,
            terminal.candidate.distribution_sequence + 1,
            &signing_key,
        )?;
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::RolloutCreated {
                rollout: Box::new(root),
            },
            Path::new("root-activation"),
        )?;
        Ok(())
    }

    #[test]
    fn rejected_branch_rejects_tampered_predecessor_and_accepts_active_head() -> crate::Result<()> {
        let (mut state, reconciliation) = target_set_validation_fixture()?;
        let source = state
            .source_revisions
            .values()
            .next()
            .cloned()
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: Path::new("rejected-branch").to_owned(),
                    reason: "the test state has no source revision".to_owned(),
                }
                .build()
            })?;
        let artifact = reconciliation
            .refreshed_active_artifact
            .clone()
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: Path::new("rejected-branch").to_owned(),
                    reason: "the test reconciliation has no active artifact".to_owned(),
                }
                .build()
            })?;
        let rejected = reconciliation.desired.bundles[0].clone();
        let rejected_rollout = reconciliation.desired.rollout_states[0].clone();
        let active_id = rejected
            .candidate
            .predecessor_candidate_content_id
            .clone()
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: Path::new("rejected-branch").to_owned(),
                    reason: "the desired candidate has no predecessor".to_owned(),
                }
                .build()
            })?;
        let active = state.bundles.get(&active_id).cloned().ok_or_else(|| {
            crate::error::ControlStoreSnafu {
                path: Path::new("rejected-branch").to_owned(),
                reason: "the predecessor bundle is absent".to_owned(),
            }
            .build()
        })?;
        let active_rollout = state
            .rollout_states
            .get(&super::PolicyRolloutKeyV1 {
                candidate_content_id: active_id.clone(),
                node_id: active.candidate.exact_target.node_id.clone(),
            })
            .cloned()
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: Path::new("rejected-branch").to_owned(),
                    reason: "the predecessor rollout is absent".to_owned(),
                }
                .build()
            })?;
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::TargetSetReconciled {
                reconciliation: Box::new(reconciliation),
            },
            Path::new("rejected-branch-rollout"),
        )?;

        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let dependent = rollout_transaction(
            &source,
            &artifact,
            vec![(
                rejected.candidate.exact_target.clone(),
                Some(rejected.candidate.candidate_content_id.clone()),
            )],
            PolicyDeliveryOperationV1::Replace,
            artifact.policy_document.rollout.rollout_generation,
            rejected.candidate.distribution_sequence + 1,
            &signing_key,
        )?;
        let dependent_bundle = dependent.bundles[0].clone();
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::RolloutCreated {
                rollout: Box::new(dependent),
            },
            Path::new("dependent-branch"),
        )?;
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::Acknowledged {
                result: Box::new(active_acknowledgement_transaction(
                    &active,
                    &active_rollout,
                    false,
                )?),
            },
            Path::new("active-predecessor"),
        )?;
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::Acknowledged {
                result: Box::new(rejected_acknowledgement_transaction(
                    &rejected,
                    &rejected_rollout,
                )?),
            },
            Path::new("rejected-successor"),
        )?;

        let tampered = rollout_transaction(
            &source,
            &artifact,
            vec![(
                rejected.candidate.exact_target.clone(),
                Some(dependent_bundle.candidate.candidate_content_id.clone()),
            )],
            PolicyDeliveryOperationV1::Replace,
            artifact.policy_document.rollout.rollout_generation,
            dependent_bundle.candidate.distribution_sequence + 1,
            &signing_key,
        )?;
        assert!(super::apply_transaction(
            &mut state.clone(),
            &super::ControlTransactionV1::RolloutCreated {
                rollout: Box::new(tampered),
            },
            Path::new("tampered-dependent-head"),
        )
        .is_err());

        let recovered = rollout_transaction(
            &source,
            &artifact,
            vec![(rejected.candidate.exact_target, Some(active_id))],
            PolicyDeliveryOperationV1::Replace,
            artifact.policy_document.rollout.rollout_generation,
            dependent_bundle.candidate.distribution_sequence + 1,
            &signing_key,
        )?;
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::RolloutCreated {
                rollout: Box::new(recovered),
            },
            Path::new("recovered-active-head"),
        )?;
        Ok(())
    }

    #[test]
    fn legacy_acknowledgement_replay_defaults_terminal_closure_to_denied() -> crate::Result<()> {
        let (mut state, reconciliation) = target_set_validation_fixture()?;
        let terminal_transaction = reconciliation.retirement.as_ref().ok_or_else(|| {
            crate::error::ControlStoreSnafu {
                path: Path::new("legacy-terminal-acknowledgement").to_owned(),
                reason: "the test reconciliation has no retirement".to_owned(),
            }
            .build()
        })?;
        let terminal = terminal_transaction.bundles[0].clone();
        let terminal_rollout = terminal_transaction.rollout_states[0].clone();
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::TargetSetReconciled {
                reconciliation: Box::new(reconciliation),
            },
            Path::new("legacy-terminal-rollout"),
        )?;
        let transaction = super::ControlTransactionV1::Acknowledged {
            result: Box::new(active_acknowledgement_transaction(
                &terminal,
                &terminal_rollout,
                false,
            )?),
        };
        let encoded = serde_json::to_value(&transaction).context(crate::error::JsonSnafu {
            path: Path::new("legacy-terminal-acknowledgement"),
        })?;
        assert!(encoded
            .pointer("/result/terminal_chain_closure_authorized")
            .is_none());
        let decoded = serde_json::from_value(encoded).context(crate::error::JsonSnafu {
            path: Path::new("legacy-terminal-acknowledgement"),
        })?;
        super::apply_transaction(
            &mut state,
            &decoded,
            Path::new("legacy-terminal-acknowledgement"),
        )?;
        assert!(!super::terminal_chain_is_closed(&state, &terminal));
        Ok(())
    }

    #[test]
    fn target_set_reconciliation_accepts_withdrawal_and_rejects_legacy_subset() -> crate::Result<()>
    {
        let (state, reconciliation) = target_set_validation_fixture()?;
        super::validate_target_set_reconciliation(
            &state,
            &reconciliation,
            Path::new("complete-retirement"),
        )?;

        let mut omitted = reconciliation.clone();
        omitted.retirement = None;
        super::apply_transaction(
            &mut state.clone(),
            &super::ControlTransactionV1::TargetSetReconciled {
                reconciliation: Box::new(omitted),
            },
            Path::new("desired-withdrawal"),
        )?;

        let mut subset = reconciliation;
        let subset_retirement = subset.retirement.as_mut().ok_or_else(|| {
            crate::error::ControlStoreSnafu {
                path: Path::new("subset-retirement").to_owned(),
                reason: "the test reconciliation has no retirement".to_owned(),
            }
            .build()
        })?;
        subset_retirement.target_snapshot.targets.pop();
        subset_retirement.bundles.pop();
        subset_retirement.rollout_states.pop();
        let subset_error = required_rejection(
            super::apply_transaction(
                &mut state.clone(),
                &super::ControlTransactionV1::TargetSetReconciled {
                    reconciliation: Box::new(subset),
                },
                Path::new("subset-retirement"),
            ),
            "every absent node must have a retirement",
        )?;
        assert!(subset_error
            .to_string()
            .contains("does not retire every exact removed-node head"));
        Ok(())
    }

    #[test]
    fn target_set_reconciliation_rejects_wrong_snapshot_generations() -> crate::Result<()> {
        let (state, reconciliation) = target_set_validation_fixture()?;

        let mut wrong_desired = reconciliation.clone();
        wrong_desired.desired.target_snapshot.rollout_generation += 1;
        let desired_error = required_rejection(
            super::apply_transaction(
                &mut state.clone(),
                &super::ControlTransactionV1::TargetSetReconciled {
                    reconciliation: Box::new(wrong_desired),
                },
                Path::new("wrong-desired-generation"),
            ),
            "the desired snapshot generation must match its policy",
        )?;
        assert!(desired_error
            .to_string()
            .contains("does not match its accepted source"));

        let mut wrong_retirement = reconciliation;
        wrong_retirement
            .retirement
            .as_mut()
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: Path::new("wrong-retirement-generation").to_owned(),
                    reason: "the test reconciliation has no retirement".to_owned(),
                }
                .build()
            })?
            .target_snapshot
            .rollout_generation += 1;
        let retirement_error = required_rejection(
            super::apply_transaction(
                &mut state.clone(),
                &super::ControlTransactionV1::TargetSetReconciled {
                    reconciliation: Box::new(wrong_retirement),
                },
                Path::new("wrong-retirement-generation"),
            ),
            "the retirement snapshot generation must match its policy",
        )?;
        assert!(retirement_error
            .to_string()
            .contains("not exact, terminal, or predecessor bound"));
        Ok(())
    }

    #[test]
    fn replay_rejects_a_stale_source_transition() -> crate::Result<()> {
        let document = PolicyDocumentV1::parse(
            Path::new("policy-v1.yaml"),
            include_bytes!("../tests/fixtures/policy-v1.yaml"),
        )?;
        let mut first = source_revision(&document, PolicySourceStateV1::Accepted, 1, '2')?;
        let mut state = super::ControlStoreState::default();
        let first_artifact = signed_artifact(&document, 1)?;
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::SourceAccepted {
                source_revision: Box::new(first.clone()),
                policy_document: Box::new(document.clone()),
                artifact: Some(Box::new(first_artifact)),
            },
            Path::new("first-commit"),
        )?;
        first.object_generation = 2;
        first.opaque_resource_version = b"two".to_vec();
        first.policy_source_revision_id = "3".repeat(64);
        let second_artifact = signed_artifact(&document, 2)?;
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::SourceAccepted {
                source_revision: Box::new(first.clone()),
                policy_document: Box::new(document.clone()),
                artifact: Some(Box::new(second_artifact)),
            },
            Path::new("second-commit"),
        )?;

        first.object_generation = 1;
        first.opaque_resource_version = b"stale".to_vec();
        first.policy_source_revision_id = "4".repeat(64);
        let stale_artifact = signed_artifact(&document, 3)?;
        assert!(super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::SourceAccepted {
                source_revision: Box::new(first),
                policy_document: Box::new(document),
                artifact: Some(Box::new(stale_artifact)),
            },
            Path::new("stale-commit"),
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn legacy_restrictive_artifact_upgrades_to_the_source_policy() -> crate::Result<()> {
        let document = PolicyDocumentV1::parse(
            Path::new("policy-v1.yaml"),
            include_bytes!("../tests/fixtures/policy-v1.yaml"),
        )?;
        let source = source_revision(&document, PolicySourceStateV1::DeletionRequested, 1, '5')?;
        let terminal_document = crate::restrictive_terminal_document(&document);
        let terminal_artifact = signed_artifact(&terminal_document, 1)?;
        let active_artifact = signed_artifact(&document, 2)?;
        let mut state = super::ControlStoreState::default();

        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::SourceAccepted {
                source_revision: Box::new(source.clone()),
                policy_document: Box::new(document.clone()),
                artifact: Some(Box::new(terminal_artifact)),
            },
            Path::new("legacy-terminal-source"),
        )?;
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::SourceAccepted {
                source_revision: Box::new(source.clone()),
                policy_document: Box::new(document),
                artifact: Some(Box::new(active_artifact.clone())),
            },
            Path::new("desired-inventory-upgrade"),
        )?;

        assert_eq!(
            state
                .compiled_artifacts
                .get(&source.policy_source_revision_id),
            Some(&active_artifact)
        );
        Ok(())
    }

    #[test]
    fn legacy_rollouts_rebuild_the_latest_desired_snapshot_in_commit_order() -> crate::Result<()> {
        let document = PolicyDocumentV1::parse(
            Path::new("policy-v1.yaml"),
            include_bytes!("../tests/fixtures/policy-v1.yaml"),
        )?;
        let source = source_revision(&document, PolicySourceStateV1::Accepted, 1, '6')?;
        let artifact = signed_artifact(&document, 1)?;
        let artifact_digest = super::artifact_digest(&artifact, Path::new("legacy-rollout"))?;
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut state = super::ControlStoreState::default();
        super::apply_transaction(
            &mut state,
            &super::ControlTransactionV1::SourceAccepted {
                source_revision: Box::new(source.clone()),
                policy_document: Box::new(document),
                artifact: Some(Box::new(artifact.clone())),
            },
            Path::new("legacy-source"),
        )?;

        let first_target = PolicyTargetV1 {
            tenant_id: source.tenant_id.clone(),
            cluster_uid: source.cluster_uid.clone(),
            node_id: "node-a".to_owned(),
            workload_binding_generation_digests: vec!["1".repeat(64)],
            workload_targets: Vec::new(),
        };
        let first_snapshot = PolicyTargetSnapshotV1::new(
            source.policy_source_revision_id.clone(),
            artifact_digest.clone(),
            1,
            vec![first_target.clone()],
        )?;
        let first_candidate = PolicyDeliveryCandidateV1::sign(
            source.tenant_id.clone(),
            source.policy_source_revision_id.clone(),
            artifact_digest.clone(),
            &first_snapshot,
            first_target.clone(),
            PolicyDeliveryOperationV1::Activate,
            None,
            1,
            1,
            1,
            100,
            "test-key".to_owned(),
            &signing_key,
        )?;
        let first_bundle = PolicyBundleV1::new(
            first_candidate.clone(),
            artifact.clone(),
            signing_key.verifying_key().to_bytes().to_vec(),
        )?;
        let first_rollout = super::ControlTransactionV1::RolloutCreated {
            rollout: Box::new(super::PolicyRolloutTransactionV1 {
                target_snapshot: first_snapshot,
                bundles: vec![first_bundle],
                rollout_states: vec![PolicyRolloutStateV1 {
                    policy_source_revision_id: source.policy_source_revision_id.clone(),
                    target_snapshot_digest: first_candidate.target_snapshot_digest.clone(),
                    target: first_target,
                    desired_candidate_content_id: first_candidate.candidate_content_id.clone(),
                    state: PolicyRolloutStatusV1::Pending,
                    latest_acknowledgement_content_id: None,
                    transition_version: 1,
                    updated_utc_ns: 1,
                }],
            }),
        };
        // Decode the old JSON shape before replay so this test covers durable compatibility.
        let first_bytes = serde_json::to_vec(&first_rollout).context(crate::error::JsonSnafu {
            path: Path::new("legacy-rollout-1"),
        })?;
        let first_rollout =
            serde_json::from_slice(&first_bytes).context(crate::error::JsonSnafu {
                path: Path::new("legacy-rollout-1"),
            })?;
        super::apply_transaction(&mut state, &first_rollout, Path::new("legacy-rollout-1"))?;

        let second_target = PolicyTargetV1 {
            tenant_id: source.tenant_id.clone(),
            cluster_uid: source.cluster_uid.clone(),
            node_id: "node-a".to_owned(),
            workload_binding_generation_digests: vec!["2".repeat(64)],
            workload_targets: Vec::new(),
        };
        let second_snapshot = PolicyTargetSnapshotV1::new(
            source.policy_source_revision_id.clone(),
            artifact_digest.clone(),
            1,
            vec![second_target.clone()],
        )?;
        let second_candidate = PolicyDeliveryCandidateV1::sign(
            source.tenant_id.clone(),
            source.policy_source_revision_id.clone(),
            artifact_digest,
            &second_snapshot,
            second_target.clone(),
            PolicyDeliveryOperationV1::Replace,
            Some(first_candidate.candidate_content_id),
            1,
            2,
            2,
            100,
            "test-key".to_owned(),
            &signing_key,
        )?;
        let second_bundle = PolicyBundleV1::new(
            second_candidate.clone(),
            artifact,
            signing_key.verifying_key().to_bytes().to_vec(),
        )?;
        let expected_digest = second_snapshot.target_snapshot_digest.clone();
        let second_rollout = super::ControlTransactionV1::RolloutCreated {
            rollout: Box::new(super::PolicyRolloutTransactionV1 {
                target_snapshot: second_snapshot,
                bundles: vec![second_bundle],
                rollout_states: vec![PolicyRolloutStateV1 {
                    policy_source_revision_id: source.policy_source_revision_id.clone(),
                    target_snapshot_digest: second_candidate.target_snapshot_digest.clone(),
                    target: second_target,
                    desired_candidate_content_id: second_candidate.candidate_content_id,
                    state: PolicyRolloutStatusV1::Pending,
                    latest_acknowledgement_content_id: None,
                    transition_version: 1,
                    updated_utc_ns: 2,
                }],
            }),
        };
        let second_bytes =
            serde_json::to_vec(&second_rollout).context(crate::error::JsonSnafu {
                path: Path::new("legacy-rollout-2"),
            })?;
        let second_rollout =
            serde_json::from_slice(&second_bytes).context(crate::error::JsonSnafu {
                path: Path::new("legacy-rollout-2"),
            })?;
        super::apply_transaction(&mut state, &second_rollout, Path::new("legacy-rollout-2"))?;

        assert_eq!(
            state
                .latest_desired_snapshots
                .get(&source.policy_source_revision_id),
            Some(&expected_digest)
        );
        Ok(())
    }
}
