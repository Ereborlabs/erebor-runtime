use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::error::{ControlStoreSnafu, IoSnafu, JsonSnafu};
use crate::{
    canonical_policy_spec_digest, CoverageIntakeStateV1, EvidenceIntakeIdentityV1,
    EvidenceStoreOutcomeV1, ExceptionActivationAcknowledgementV1, ExceptionActivationStateV1,
    ExceptionDeliveryCandidateV1, ExceptionDeliveryOperationV1, ExceptionRolloutStateV1,
    ExceptionSourceRevisionV1, ExceptionSourceStateV1, IntakeStateV1,
    PolicyActivationAcknowledgementV1, PolicyBundleV1, PolicyDocumentV1, PolicyRolloutStateV1,
    PolicySourceRevisionV1, PolicySourceStateV1, PolicyTargetSnapshotV1,
    ProfileCandidateArtifactV1, Result, StoredCoverageReportV1, StoredEvidenceBatchV1,
    StoredRecordV1, TrustGenerationAcknowledgementV1, TrustGenerationV1,
    MAX_PENDING_EVIDENCE_RECORDS,
};

const STORE_SCHEMA_VERSION: u32 = 1;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone)]
/// Owns the append-only Control commit chain and its replayed in-memory index.
pub struct ControlStore {
    inner: Arc<Mutex<ControlStoreInner>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlStoreHealthV1 {
    pub commit_index: u64,
    pub source_revisions: u64,
    pub compiled_artifacts: u64,
    pub target_snapshots: u64,
    pub rollout_targets: u64,
    pub unsettled_rollout_targets: u64,
    pub evidence_cursors: u64,
    pub pending_evidence_batches: u64,
    pub pending_evidence_records: u64,
    pub coverage_cursors: u64,
}

struct ControlStoreInner {
    root: PathBuf,
    state: ControlStoreState,
}

#[derive(Clone, Default)]
struct ControlStoreState {
    // This state is a cache. Startup rebuilds every field from verified commits.
    commit_index: u64,
    last_commit_digest: String,
    source_revisions: BTreeMap<String, PolicySourceRevisionV1>,
    policy_documents: BTreeMap<String, PolicyDocumentV1>,
    latest_sources: BTreeMap<PolicyObjectKeyV1, String>,
    compiled_artifacts: BTreeMap<String, ProfileCandidateArtifactV1>,
    target_snapshots: BTreeMap<String, PolicyTargetSnapshotV1>,
    bundles: BTreeMap<String, PolicyBundleV1>,
    rollout_states: BTreeMap<PolicyRolloutKeyV1, PolicyRolloutStateV1>,
    acknowledgements: BTreeMap<String, PolicyActivationAcknowledgementV1>,
    exception_source_revisions: BTreeMap<String, ExceptionSourceRevisionV1>,
    latest_exception_sources: BTreeMap<PolicyObjectKeyV1, String>,
    exception_candidates: BTreeMap<String, ExceptionDeliveryCandidateV1>,
    exception_rollout_states: BTreeMap<PolicyRolloutKeyV1, ExceptionRolloutStateV1>,
    exception_acknowledgements: BTreeMap<String, ExceptionActivationAcknowledgementV1>,
    trust_generations: BTreeMap<u64, TrustGenerationV1>,
    trust_acknowledgements:
        BTreeMap<(String, u64, [u8; 16], u64), TrustGenerationAcknowledgementV1>,
    evidence_cursors: BTreeMap<EvidenceIntakeIdentityV1, IntakeStateV1>,
    evidence_records: BTreeMap<EvidenceRecordKeyV1, StoredRecordV1>,
    evidence_batch_receipts: BTreeMap<EvidenceBatchKeyV1, [u8; 32]>,
    pending_evidence_batches: BTreeMap<EvidencePendingKeyV1, StoredEvidenceBatchV1>,
    coverage_cursors: BTreeMap<EvidenceIntakeIdentityV1, CoverageIntakeStateV1>,
    coverage_reports: BTreeMap<CoverageReportKeyV1, StoredCoverageReportV1>,
    evidence_source_labels: BTreeMap<EvidenceSourceEpochKeyV1, u64>,
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
struct EvidenceRecordKeyV1 {
    identity: EvidenceIntakeIdentityV1,
    cursor: u64,
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
#[serde(deny_unknown_fields)]
struct ControlCommitV1 {
    schema_version: u32,
    commit_index: u64,
    previous_commit_digest: String,
    transaction: ControlTransactionV1,
    commit_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
// Each variant contains all state that must become durable in one transaction.
enum ControlTransactionV1 {
    SourceAccepted {
        source_revision: Box<PolicySourceRevisionV1>,
        policy_document: Box<PolicyDocumentV1>,
    },
    Compiled {
        policy_source_revision_id: String,
        artifact: Box<ProfileCandidateArtifactV1>,
    },
    RolloutCreated {
        rollout: Box<PolicyRolloutTransactionV1>,
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
        pending: Box<EvidenceBatchTransactionV1>,
    },
    EvidenceAccepted {
        accepted: Box<EvidenceAcceptedTransactionV1>,
    },
    CoverageAccepted {
        report: Box<StoredCoverageReportV1>,
    },
    TrustInstalled {
        generation: Box<TrustGenerationV1>,
    },
    TrustAcknowledged {
        acknowledgement: Box<TrustGenerationAcknowledgementV1>,
    },
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
struct PolicyAcknowledgementTransactionV1 {
    acknowledgement: PolicyActivationAcknowledgementV1,
    rollout_state: PolicyRolloutStateV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExceptionDesiredTransactionV1 {
    source_revision: ExceptionSourceRevisionV1,
    candidate: ExceptionDeliveryCandidateV1,
    rollout_state: ExceptionRolloutStateV1,
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
    batches: Vec<StoredEvidenceBatchV1>,
}

impl ControlStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("commits")).context(IoSnafu {
            path: root.join("commits"),
        })?;
        let mut state = ControlStoreState {
            last_commit_digest: ZERO_DIGEST.to_owned(),
            ..ControlStoreState::default()
        };
        let mut paths = fs::read_dir(root.join("commits"))
            .context(IoSnafu {
                path: root.join("commits"),
            })?
            .map(|entry| {
                entry.map(|entry| entry.path()).context(IoSnafu {
                    path: root.join("commits"),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        paths.sort();
        // Replay in lexical index order and reject any gap, digest break, or unknown file.
        for path in paths {
            if path.extension().and_then(|value| value.to_str()) == Some("tmp") {
                fs::remove_file(&path).context(IoSnafu { path: &path })?;
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                return ControlStoreSnafu {
                    path,
                    reason: "the commits directory contains an unknown file".to_owned(),
                }
                .fail();
            }
            let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
            let commit: ControlCommitV1 =
                serde_json::from_slice(&bytes).context(JsonSnafu { path: &path })?;
            verify_commit(&commit, &state, &path)?;
            apply_transaction(&mut state, &commit.transaction, &path)?;
            state.commit_index = commit.commit_index;
            state.last_commit_digest = commit.commit_digest;
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(ControlStoreInner { root, state })),
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
            evidence_cursors: count(inner.state.evidence_cursors.len()),
            pending_evidence_batches: count(inner.state.pending_evidence_batches.len()),
            pending_evidence_records: inner
                .state
                .pending_evidence_batches
                .values()
                .fold(0_u64, |total, batch| {
                    total.saturating_add(count(batch.records.len()))
                }),
            coverage_cursors: count(inner.state.coverage_cursors.len()),
        })
    }

    pub fn accept_source_revision(
        &self,
        revision: PolicySourceRevisionV1,
        policy_document: PolicyDocumentV1,
    ) -> Result<u64> {
        let mut inner = self.lock()?;
        let key = PolicyObjectKeyV1::from(&revision);
        if inner
            .state
            .source_revisions
            .contains_key(&revision.policy_source_revision_id)
        {
            if inner
                .state
                .policy_documents
                .get(&revision.policy_source_revision_id)
                != Some(&policy_document)
            {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "one source revision has conflicting policy bytes".to_owned(),
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
            return Ok(inner.state.commit_index);
        }
        let document_digest = canonical_policy_spec_digest(&policy_document)?;
        if revision.policy_document_digest != document_digest {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "the source revision does not bind the supplied policy document".to_owned(),
            }
            .fail();
        }
        // Object UID, generation, and lifecycle state form the monotonic source history.
        if let Some(current_id) = inner.state.latest_sources.get(&key) {
            let current = inner
                .state
                .source_revisions
                .get(current_id)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: inner.root.clone(),
                        reason: "the latest source index has no source revision".to_owned(),
                    }
                    .build()
                })?;
            if current.object_uid != revision.object_uid {
                if current.state == crate::PolicySourceStateV1::Accepted {
                    return ControlStoreSnafu {
                        path: inner.root.clone(),
                        reason:
                            "a recreated policy object arrived before retirement of the prior UID"
                                .to_owned(),
                    }
                    .fail();
                }
            } else if revision.object_generation < current.object_generation {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "a stale policy generation cannot replace the current source revision"
                        .to_owned(),
                }
                .fail();
            } else if revision.object_generation == current.object_generation {
                // Kubernetes deletion does not increment metadata.generation.
                let deletion_transition = current.state == crate::PolicySourceStateV1::Accepted
                    && revision.state == crate::PolicySourceStateV1::DeletionRequested
                    && revision.canonical_spec_digest == current.canonical_spec_digest
                    && revision.policy_document_digest == current.policy_document_digest;
                if !deletion_transition {
                    return ControlStoreSnafu {
                        path: inner.root.clone(),
                        reason:
                            "one policy generation has conflicting source bytes or lifecycle state"
                                .to_owned(),
                    }
                    .fail();
                }
            }
        }
        commit(
            &mut inner,
            ControlTransactionV1::SourceAccepted {
                source_revision: Box::new(revision),
                policy_document: Box::new(policy_document),
            },
        )
    }

    pub fn record_compiled_artifact(
        &self,
        policy_source_revision_id: &str,
        artifact: ProfileCandidateArtifactV1,
    ) -> Result<u64> {
        let mut inner = self.lock()?;
        if let Some(current) = inner
            .state
            .compiled_artifacts
            .get(policy_source_revision_id)
        {
            if current == &artifact {
                return Ok(inner.state.commit_index);
            }
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "one source revision has more than one compiled artifact".to_owned(),
            }
            .fail();
        }
        let document = inner
            .state
            .policy_documents
            .get(policy_source_revision_id)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "the compiled artifact has no accepted source revision".to_owned(),
                }
                .build()
            })?;
        if artifact.policy_document != *document {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "the compiled artifact does not contain the accepted policy document"
                    .to_owned(),
            }
            .fail();
        }
        // Issuer sequence is global to one signing key and cannot repeat after restart.
        let header = &artifact.header;
        for existing in inner.state.compiled_artifacts.values() {
            if existing.signed_profile.signing_key_id == artifact.signed_profile.signing_key_id
                && (existing.header.sequence_epoch > header.sequence_epoch
                    || (existing.header.sequence_epoch == header.sequence_epoch
                        && existing.header.issuer_sequence >= header.issuer_sequence))
            {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "the compiled artifact failed policy-issuer anti-rollback".to_owned(),
                }
                .fail();
            }
        }
        commit(
            &mut inner,
            ControlTransactionV1::Compiled {
                policy_source_revision_id: policy_source_revision_id.to_owned(),
                artifact: Box::new(artifact),
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
        validate_rollout_ordering(&inner.state, &bundles, &inner.root)?;
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

    pub fn acknowledge_policy(
        &self,
        acknowledgement: PolicyActivationAcknowledgementV1,
        rollout_state: PolicyRolloutStateV1,
    ) -> Result<u64> {
        let mut inner = self.lock()?;
        if inner
            .state
            .acknowledgements
            .get(&acknowledgement.acknowledgement_content_id)
            == Some(&acknowledgement)
        {
            return Ok(inner.state.commit_index);
        }
        acknowledgement.validate()?;
        let key = PolicyRolloutKeyV1 {
            candidate_content_id: acknowledgement.candidate_content_id.clone(),
            node_id: acknowledgement.node_id.clone(),
        };
        let current = inner.state.rollout_states.get(&key).ok_or_else(|| {
            ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "the acknowledgement has no current rollout target".to_owned(),
            }
            .build()
        })?;
        // The transition version is the compare-and-swap guard for concurrent or stale replies.
        let expected_transition_version = checked_store_increment(
            current.transition_version,
            &inner.root,
            "the rollout transition version is exhausted",
        )?;
        if rollout_state.transition_version != expected_transition_version
            || rollout_state.target != current.target
            || rollout_state.desired_candidate_content_id != current.desired_candidate_content_id
            || rollout_state.policy_source_revision_id != current.policy_source_revision_id
            || rollout_state.target_snapshot_digest != current.target_snapshot_digest
            || rollout_state.latest_acknowledgement_content_id.as_deref()
                != Some(&acknowledgement.acknowledgement_content_id)
        {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "the rollout acknowledgement failed its compare-and-swap transition"
                    .to_owned(),
            }
            .fail();
        }
        commit(
            &mut inner,
            ControlTransactionV1::Acknowledged {
                result: Box::new(PolicyAcknowledgementTransactionV1 {
                    acknowledgement,
                    rollout_state,
                }),
            },
        )
    }

    pub fn record_exception_desired(
        &self,
        source: ExceptionSourceRevisionV1,
        candidate: ExceptionDeliveryCandidateV1,
        rollout_state: ExceptionRolloutStateV1,
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
        validate_exception_desired(
            &inner.state,
            &source,
            &candidate,
            &rollout_state,
            &inner.root,
        )?;
        commit(
            &mut inner,
            ControlTransactionV1::ExceptionDesired {
                desired: Box::new(ExceptionDesiredTransactionV1 {
                    source_revision: source,
                    candidate,
                    rollout_state,
                }),
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
        if inner
            .state
            .exception_acknowledgements
            .get(&acknowledgement.acknowledgement_content_id)
            == Some(&acknowledgement)
        {
            return Ok(inner.state.commit_index);
        }
        let key = PolicyRolloutKeyV1 {
            candidate_content_id: acknowledgement.candidate_content_id.clone(),
            node_id: acknowledgement.node_id.clone(),
        };
        let current = inner
            .state
            .exception_rollout_states
            .get(&key)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "the exception acknowledgement has no current rollout target"
                        .to_owned(),
                }
                .build()
            })?;
        if rollout_state.transition_version
            != checked_store_increment(
                current.transition_version,
                &inner.root,
                "the exception transition version is exhausted",
            )?
            || rollout_state.candidate_content_id != current.candidate_content_id
            || rollout_state.exception_source_revision_id != current.exception_source_revision_id
            || rollout_state.node_id != current.node_id
            || rollout_state.latest_acknowledgement_content_id.as_deref()
                != Some(&acknowledgement.acknowledgement_content_id)
        {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "the exception acknowledgement failed its compare-and-swap transition"
                    .to_owned(),
            }
            .fail();
        }
        commit(
            &mut inner,
            ControlTransactionV1::ExceptionAcknowledged {
                result: Box::new(ExceptionAcknowledgementTransactionV1 {
                    acknowledgement,
                    rollout_state,
                }),
            },
        )
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
        batch: StoredEvidenceBatchV1,
    ) -> Result<EvidenceStoreOutcomeV1> {
        let mut inner = self.lock()?;
        validate_evidence_identity(&identity, &inner.root)?;
        validate_stored_batch(&batch, &inner.root)?;
        validate_source_label(&inner.state, &identity, &inner.root)?;
        let receipt_key = EvidenceBatchKeyV1 {
            identity: identity.clone(),
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
        };
        // An accepted range is idempotent only when its complete digest is unchanged.
        if let Some(digest) = inner.state.evidence_batch_receipts.get(&receipt_key) {
            if digest == &batch.batch_sha256 {
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
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "an evidence range overlaps the accepted contiguous cursor".to_owned(),
            }
            .fail();
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
                if key.first_cursor == batch.first_cursor && existing == &batch {
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
        if batch.first_cursor != next {
            // Persist bounded reordering without advancing the contiguous acknowledgement.
            if batch.last_cursor
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
            commit(
                &mut inner,
                ControlTransactionV1::EvidencePending {
                    pending: Box::new(EvidenceBatchTransactionV1 { identity, batch }),
                },
            )?;
            return Ok(EvidenceStoreOutcomeV1::Pending);
        }

        // Promote the new batch and every now-contiguous pending batch in one commit.
        let mut batches = vec![batch];
        let mut next = batches[0].last_cursor.checked_add(1);
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
        commit(
            &mut inner,
            ControlTransactionV1::EvidenceAccepted {
                accepted: Box::new(EvidenceAcceptedTransactionV1 { identity, batches }),
            },
        )?;
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

    pub(crate) fn accept_coverage_report(&self, report: StoredCoverageReportV1) -> Result<u64> {
        let mut inner = self.lock()?;
        validate_evidence_identity(&report.identity, &inner.root)?;
        validate_source_label(&inner.state, &report.identity, &inner.root)?;
        let current = inner
            .state
            .coverage_cursors
            .get(&report.identity)
            .copied()
            .unwrap_or_default();
        if current == report.state {
            let key = CoverageReportKeyV1 {
                identity: report.identity.clone(),
                revision: report.state.revision,
            };
            if inner.state.coverage_reports.get(&key) == Some(&report) {
                return Ok(inner.state.commit_index);
            }
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "one coverage revision has conflicting immutable content".to_owned(),
            }
            .fail();
        }
        if report.state.source_epoch < current.source_epoch
            || (report.state.source_epoch == current.source_epoch
                && report.state.revision <= current.revision)
            || report.state.source_epoch != report.identity.source_epoch
            || report.state.revision == 0
            || report.state.report_sha256 == [0; 32]
            || report.encoded_report.is_empty()
        {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "coverage evidence is stale or has invalid identity".to_owned(),
            }
            .fail();
        }
        commit(
            &mut inner,
            ControlTransactionV1::CoverageAccepted {
                report: Box::new(report),
            },
        )
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
    ) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .lock()?
            .state
            .evidence_records
            .iter()
            .filter(|(key, _record)| &key.identity == identity)
            .map(|(_key, record)| record.payload.clone())
            .collect())
    }

    pub(crate) fn latest_coverage_report(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<StoredCoverageReportV1>> {
        let inner = self.lock()?;
        Ok(inner
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
            }))
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
                let acknowledgement = rollout
                    .latest_acknowledgement_content_id
                    .as_ref()
                    .and_then(|id| inner.state.acknowledgements.get(id))?;
                Some((bundle.clone(), acknowledgement.clone()))
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
        Ok(inner
            .state
            .exception_candidates
            .values()
            .filter(|candidate| {
                candidate.exact_target.node_id == node_id
                    && !known_candidate_ids.contains(&candidate.candidate_content_id)
                    && inner
                        .state
                        .exception_rollout_states
                        .get(&PolicyRolloutKeyV1 {
                            candidate_content_id: candidate.candidate_content_id.clone(),
                            node_id: node_id.to_owned(),
                        })
                        .is_some_and(|rollout| {
                            !matches!(
                                rollout.state,
                                crate::WorkloadProtectionExceptionStateV1::Failed
                                    | crate::WorkloadProtectionExceptionStateV1::Consumed
                                    | crate::WorkloadProtectionExceptionStateV1::Expired
                                    | crate::WorkloadProtectionExceptionStateV1::Revoked
                            )
                        })
            })
            .max_by_key(|candidate| {
                (
                    candidate.distribution_sequence_epoch,
                    candidate.distribution_sequence,
                )
            })
            .cloned())
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
        Ok(self
            .lock()?
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

    pub fn latest_bundle_for_profile_node(
        &self,
        node_id: &str,
        tenant_id: &str,
        trust_domain_id: &str,
        profile_id: &str,
    ) -> Result<Option<PolicyBundleV1>> {
        let inner = self.lock()?;
        Ok(inner
            .state
            .bundles
            .values()
            .filter(|bundle| {
                bundle.candidate.exact_target.node_id == node_id
                    && bundle_matches_profile(bundle, tenant_id, trust_domain_id, profile_id)
            })
            .max_by_key(|bundle| {
                (
                    bundle.candidate.distribution_sequence_epoch,
                    bundle.candidate.distribution_sequence,
                )
            })
            .cloned())
    }

    pub fn latest_bundles_for_object(&self, object_uid: &str) -> Result<Vec<PolicyBundleV1>> {
        let inner = self.lock()?;
        let mut latest = BTreeMap::<String, PolicyBundleV1>::new();
        for bundle in inner.state.bundles.values().filter(|bundle| {
            inner
                .state
                .source_revisions
                .get(&bundle.candidate.policy_source_revision_id)
                .is_some_and(|source| source.object_uid == object_uid)
        }) {
            let node_id = bundle.candidate.exact_target.node_id.clone();
            let replace = latest.get(&node_id).is_none_or(|current| {
                (
                    bundle.candidate.distribution_sequence_epoch,
                    bundle.candidate.distribution_sequence,
                ) > (
                    current.candidate.distribution_sequence_epoch,
                    current.candidate.distribution_sequence,
                )
            });
            if replace {
                latest.insert(node_id, bundle.clone());
            }
        }
        Ok(latest.into_values().collect())
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
        active_candidate_content_id: &str,
        durable_bundle_digests: &[String],
    ) -> Result<Option<PolicyBundleV1>> {
        let inner = self.lock()?;
        // Prefer unsettled work. Redeliver an active bundle only when the node lost it.
        Ok(inner
            .state
            .bundles
            .values()
            .filter_map(|bundle| {
                if bundle.candidate.exact_target.node_id != node_id {
                    return None;
                }
                let rollout = inner.state.rollout_states.get(&PolicyRolloutKeyV1 {
                    candidate_content_id: bundle.candidate.candidate_content_id.clone(),
                    node_id: node_id.to_owned(),
                })?;
                let eligible = match rollout.state {
                    crate::PolicyRolloutStatusV1::Rejected
                    | crate::PolicyRolloutStatusV1::Stale => false,
                    crate::PolicyRolloutStatusV1::Active => {
                        bundle.candidate.candidate_content_id != active_candidate_content_id
                            && !durable_bundle_digests.contains(&bundle.bundle_digest)
                    }
                    crate::PolicyRolloutStatusV1::Pending
                    | crate::PolicyRolloutStatusV1::Delivered
                    | crate::PolicyRolloutStatusV1::Staged
                    | crate::PolicyRolloutStatusV1::Unknown => true,
                };
                eligible.then_some((bundle, rollout))
            })
            .max_by_key(|(bundle, rollout)| {
                (
                    u8::from(rollout.state != crate::PolicyRolloutStatusV1::Active),
                    rollout.updated_utc_ns,
                    bundle.candidate.candidate_content_id.as_str(),
                )
            })
            .map(|(bundle, _rollout)| bundle.clone()))
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
            .lock()
            .map_or_else(|_| PathBuf::new(), |inner| inner.root.clone())
    }

    #[must_use]
    pub fn commit_index(&self) -> u64 {
        self.inner
            .lock()
            .map_or(0, |inner| inner.state.commit_index)
    }

    fn lock(&self) -> Result<MutexGuard<'_, ControlStoreInner>> {
        self.inner.lock().map_err(|_| {
            ControlStoreSnafu {
                path: PathBuf::from("<poisoned-control-store>"),
                reason: "the Control store lock is poisoned".to_owned(),
            }
            .build()
        })
    }
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
    let mut record = ControlCommitV1 {
        schema_version: STORE_SCHEMA_VERSION,
        commit_index,
        previous_commit_digest: inner.state.last_commit_digest.clone(),
        transaction,
        commit_digest: String::new(),
    };
    record.commit_digest = commit_digest(&record)?;
    let path = commit_path(&inner.root, commit_index);
    // Validate on a clone, make the record durable, then publish the new in-memory state.
    let mut next_state = inner.state.clone();
    apply_transaction(&mut next_state, &record.transaction, &path)?;
    write_commit(&path, &record)?;
    next_state.commit_index = commit_index;
    next_state.last_commit_digest = record.commit_digest;
    inner.state = next_state;
    Ok(commit_index)
}

fn verify_commit(commit: &ControlCommitV1, state: &ControlStoreState, path: &Path) -> Result<()> {
    let expected_index = checked_store_increment(
        state.commit_index,
        path,
        "the Control commit index is exhausted",
    )?;
    if commit.schema_version != STORE_SCHEMA_VERSION
        || commit.commit_index != expected_index
        || commit.previous_commit_digest != state.last_commit_digest
        || commit.commit_digest != commit_digest(commit)?
    {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the commit schema, sequence, chain, or digest is invalid".to_owned(),
        }
        .fail();
    }
    Ok(())
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

fn apply_transaction(
    state: &mut ControlStoreState,
    transaction: &ControlTransactionV1,
    path: &Path,
) -> Result<()> {
    // Use the same transition code before a write and during startup replay.
    match transaction {
        ControlTransactionV1::SourceAccepted {
            source_revision,
            policy_document,
        } => {
            let digest = canonical_policy_spec_digest(policy_document)?;
            if source_revision.policy_document_digest != digest {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "the committed source does not bind its policy document".to_owned(),
                }
                .fail();
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
        }
        ControlTransactionV1::Compiled {
            policy_source_revision_id,
            artifact,
        } => {
            let document = state
                .policy_documents
                .get(policy_source_revision_id)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: path.to_owned(),
                        reason: "the committed artifact has no source policy".to_owned(),
                    }
                    .build()
                })?;
            if &artifact.policy_document != document {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "the committed artifact differs from its source policy".to_owned(),
                }
                .fail();
            }
            if state.compiled_artifacts.values().any(|existing| {
                existing.signed_profile.signing_key_id == artifact.signed_profile.signing_key_id
                    && (existing.header.sequence_epoch > artifact.header.sequence_epoch
                        || (existing.header.sequence_epoch == artifact.header.sequence_epoch
                            && existing.header.issuer_sequence >= artifact.header.issuer_sequence))
            }) {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "the committed artifact violates policy-issuer ordering".to_owned(),
                }
                .fail();
            }
            if let Some(existing) = state
                .compiled_artifacts
                .insert(policy_source_revision_id.clone(), artifact.as_ref().clone())
                .filter(|existing| existing != artifact.as_ref())
            {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: format!(
                        "source revision {policy_source_revision_id} conflicts with artifact sequence {}",
                        existing.header.issuer_sequence
                    ),
                }
                .fail();
            }
        }
        ControlTransactionV1::RolloutCreated { rollout } => {
            let PolicyRolloutTransactionV1 {
                target_snapshot,
                bundles,
                rollout_states,
            } = rollout.as_ref();
            validate_rollout_transaction(target_snapshot, bundles, rollout_states, path)?;
            validate_rollout_ordering(state, bundles, path)?;
            state.target_snapshots.insert(
                target_snapshot.target_snapshot_digest.clone(),
                target_snapshot.clone(),
            );
            for bundle in bundles.iter() {
                state.bundles.insert(
                    bundle.candidate.candidate_content_id.clone(),
                    bundle.clone(),
                );
            }
            for rollout in rollout_states.iter() {
                state.rollout_states.insert(
                    PolicyRolloutKeyV1 {
                        candidate_content_id: rollout.desired_candidate_content_id.clone(),
                        node_id: rollout.target.node_id.clone(),
                    },
                    rollout.clone(),
                );
            }
        }
        ControlTransactionV1::Acknowledged { result } => {
            let PolicyAcknowledgementTransactionV1 {
                acknowledgement,
                rollout_state,
            } = result.as_ref();
            state.acknowledgements.insert(
                acknowledgement.acknowledgement_content_id.clone(),
                acknowledgement.clone(),
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
            validate_exception_desired(
                state,
                &desired.source_revision,
                &desired.candidate,
                &desired.rollout_state,
                path,
            )?;
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
        }
        ControlTransactionV1::EvidencePending { pending } => {
            validate_evidence_identity(&pending.identity, path)?;
            validate_stored_batch(&pending.batch, path)?;
            bind_source_label(state, &pending.identity, path)?;
            let key = EvidencePendingKeyV1 {
                identity: pending.identity.clone(),
                first_cursor: pending.batch.first_cursor,
            };
            if state
                .pending_evidence_batches
                .insert(key, pending.batch.clone())
                .is_some()
            {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "a pending evidence range was committed more than once".to_owned(),
                }
                .fail();
            }
        }
        ControlTransactionV1::EvidenceAccepted { accepted } => {
            apply_accepted_evidence(state, accepted, path)?;
        }
        ControlTransactionV1::CoverageAccepted { report } => {
            validate_evidence_identity(&report.identity, path)?;
            bind_source_label(state, &report.identity, path)?;
            let current = state
                .coverage_cursors
                .get(&report.identity)
                .copied()
                .unwrap_or_default();
            if report.state.source_epoch != report.identity.source_epoch
                || report.state.revision == 0
                || report.state.report_sha256 == [0; 32]
                || report.encoded_report.is_empty()
                || report.state.source_epoch < current.source_epoch
                || (report.state.source_epoch == current.source_epoch
                    && report.state.revision <= current.revision)
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
            if state
                .coverage_reports
                .insert(key, report.as_ref().clone())
                .is_some()
            {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "a coverage revision was committed more than once".to_owned(),
                }
                .fail();
            }
            state
                .coverage_cursors
                .insert(report.identity.clone(), report.state);
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

fn validate_stored_batch(batch: &StoredEvidenceBatchV1, path: &Path) -> Result<()> {
    let valid = batch.first_cursor > 0
        && batch.last_cursor >= batch.first_cursor
        && batch.batch_sha256 != [0; 32]
        && batch.last_cursor - batch.first_cursor + 1
            == u64::try_from(batch.records.len()).unwrap_or(u64::MAX)
        && !batch.records.is_empty()
        && batch.records.iter().enumerate().all(|(index, record)| {
            record.cursor
                == batch
                    .first_cursor
                    .saturating_add(u64::try_from(index).unwrap_or(u64::MAX))
                && record.observation_id.len() == 32
                && !record.payload.is_empty()
                && record.payload_sha256.len() == 32
                && record.previous_record_sha256.len() == 32
                && record.record_sha256.len() == 32
        });
    if !valid {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "stored evidence batch identity or bounds are invalid".to_owned(),
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

fn bind_source_label(
    state: &mut ControlStoreState,
    identity: &EvidenceIntakeIdentityV1,
    path: &Path,
) -> Result<()> {
    validate_source_label(state, identity, path)?;
    state
        .evidence_source_labels
        .insert(source_epoch_key(identity), identity.label_epoch);
    Ok(())
}

fn apply_accepted_evidence(
    state: &mut ControlStoreState,
    accepted: &EvidenceAcceptedTransactionV1,
    path: &Path,
) -> Result<()> {
    validate_evidence_identity(&accepted.identity, path)?;
    bind_source_label(state, &accepted.identity, path)?;
    if accepted.batches.is_empty() {
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "an accepted evidence transaction has no batches".to_owned(),
        }
        .fail();
    }
    let mut cursor = state
        .evidence_cursors
        .get(&accepted.identity)
        .copied()
        .unwrap_or_default();
    // Records, receipts, and the contiguous cursor advance in this one transaction.
    for batch in &accepted.batches {
        validate_stored_batch(batch, path)?;
        let supplied_previous = batch
            .records
            .first()
            .and_then(|record| record.previous_record_sha256.as_slice().try_into().ok());
        if batch.first_cursor
            != checked_store_increment(
                cursor.contiguous_cursor,
                path,
                "the evidence cursor is exhausted",
            )?
            || supplied_previous != Some(cursor.last_record_sha256)
        {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "accepted evidence is not contiguous with its durable cursor".to_owned(),
            }
            .fail();
        }
        for record in &batch.records {
            let key = EvidenceRecordKeyV1 {
                identity: accepted.identity.clone(),
                cursor: record.cursor,
            };
            if state.evidence_records.insert(key, record.clone()).is_some() {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "an immutable evidence cursor was committed more than once".to_owned(),
                }
                .fail();
            }
        }
        let last_record_sha256 = batch
            .records
            .last()
            .and_then(|record| record.record_sha256.as_slice().try_into().ok())
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "an accepted evidence batch has no final record digest".to_owned(),
                }
                .build()
            })?;
        cursor = IntakeStateV1 {
            contiguous_cursor: batch.last_cursor,
            last_first_cursor: batch.first_cursor,
            last_batch_sha256: batch.batch_sha256,
            last_record_sha256,
        };
        let receipt_key = EvidenceBatchKeyV1 {
            identity: accepted.identity.clone(),
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
        };
        if state
            .evidence_batch_receipts
            .insert(receipt_key, batch.batch_sha256)
            .is_some()
        {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "an accepted evidence receipt was committed more than once".to_owned(),
            }
            .fail();
        }
        let pending_key = EvidencePendingKeyV1 {
            identity: accepted.identity.clone(),
            first_cursor: batch.first_cursor,
        };
        if let Some(pending) = state.pending_evidence_batches.remove(&pending_key) {
            if pending != *batch {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "promoted pending evidence differs from its durable content".to_owned(),
                }
                .fail();
            }
        }
    }
    state
        .evidence_cursors
        .insert(accepted.identity.clone(), cursor);
    Ok(())
}

fn validate_exception_desired(
    state: &ControlStoreState,
    source: &ExceptionSourceRevisionV1,
    candidate: &ExceptionDeliveryCandidateV1,
    rollout: &ExceptionRolloutStateV1,
    path: &Path,
) -> Result<()> {
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

    let source_transition_is_valid = match (source.state, previous_source) {
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
                && previous.base_policy_source_revision_id == source.base_policy_source_revision_id
                && previous.grant_id == source.grant_id
                && previous.requested_duration_ns == source.requested_duration_ns
                && previous.requested_uses == source.requested_uses
        }
        (ExceptionSourceStateV1::DeletionRequested, None) => false,
    };
    let operation_is_valid = match (source.state, previous_candidate) {
        (ExceptionSourceStateV1::Accepted, None) => {
            candidate.operation == ExceptionDeliveryOperationV1::Activate
                && candidate.predecessor_candidate_content_id.is_none()
        }
        (ExceptionSourceStateV1::DeletionRequested, Some(previous)) => {
            candidate.operation == ExceptionDeliveryOperationV1::Revoke
                && candidate.predecessor_candidate_content_id.as_deref()
                    == Some(previous.candidate_content_id.as_str())
                && candidate.exact_target == previous.exact_target
                && candidate.base_candidate_content_id == previous.base_candidate_content_id
                && candidate.profile_generation_ref_id == previous.profile_generation_ref_id
                && candidate.maximum_uses == previous.maximum_uses
                && candidate.valid_until_utc_ns == previous.valid_until_utc_ns
                && (
                    candidate.distribution_sequence_epoch,
                    candidate.distribution_sequence,
                ) > (
                    previous.distribution_sequence_epoch,
                    previous.distribution_sequence,
                )
        }
        _ => false,
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
            .and_then(|id| state.acknowledgements.get(id))
    });
    let grant_is_valid = base_document.is_some_and(|document| {
        document.file_exception_grants.iter().any(|grant| {
            grant.grant_id == source.grant_id
                && source.requested_duration_ns <= grant.maximum_duration_ns
                && source.requested_uses <= grant.maximum_uses
        })
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
    let overlaps_live_grant = source.state == ExceptionSourceStateV1::Accepted
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
                        prior.exception_source_revision_id == existing.exception_source_revision_id
                            && prior.exact_target.workload_binding_generation_digest
                                == candidate.exact_target.workload_binding_generation_digest
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
        return ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the exception source, active base policy, grant, target, or rollout is inconsistent"
                .to_owned(),
        }
        .fail();
    }
    Ok(())
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
    if !candidate_is_valid || !rollout_is_valid {
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
) -> Result<()> {
    for bundle in bundles {
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
        let previous = state
            .bundles
            .values()
            .filter(|existing| {
                existing.candidate.exact_target.node_id == candidate.exact_target.node_id
                    && bundle_matches_profile(
                        existing,
                        &source.tenant_id,
                        &document.metadata.trust_domain_id,
                        &document.metadata.profile_id,
                    )
            })
            .max_by_key(|existing| {
                (
                    existing.candidate.distribution_sequence_epoch,
                    existing.candidate.distribution_sequence,
                )
            });
        // Require both numeric ordering and the exact predecessor content identity.
        let ordering_is_valid = previous.is_none_or(|previous| {
            (
                candidate.distribution_sequence_epoch,
                candidate.distribution_sequence,
            ) > (
                previous.candidate.distribution_sequence_epoch,
                previous.candidate.distribution_sequence,
            )
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
        let deletion_is_valid = if source.state == PolicySourceStateV1::DeletionRequested {
            candidate.operation == crate::PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
        } else {
            candidate.operation != crate::PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
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

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn commit_digest(commit: &ControlCommitV1) -> Result<String> {
    let mut unsigned = commit.clone();
    unsigned.commit_digest.clear();
    let bytes = serde_json::to_vec(&unsigned).context(JsonSnafu {
        path: PathBuf::from("<control-commit>"),
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn commit_path(root: &Path, index: u64) -> PathBuf {
    root.join("commits").join(format!("{index:020}.json"))
}

fn write_commit(path: &Path, commit: &ControlCommitV1) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        ControlStoreSnafu {
            path: path.to_owned(),
            reason: "the commit path has no parent".to_owned(),
        }
        .build()
    })?;
    let temporary = path.with_extension("tmp");
    let bytes = serde_json::to_vec(commit).context(JsonSnafu { path })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context(IoSnafu { path: &temporary })?;
    file.write_all(&bytes)
        .context(IoSnafu { path: &temporary })?;
    file.sync_all().context(IoSnafu { path: &temporary })?;
    // Rename publishes the complete file; parent fsync makes the directory entry durable.
    fs::rename(&temporary, path).context(IoSnafu { path })?;
    File::open(parent)
        .context(IoSnafu { path: parent })?
        .sync_all()
        .context(IoSnafu { path: parent })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn durable_sequence_increment_rejects_exhaustion() {
        assert_eq!(
            super::checked_store_increment(41, Path::new("store"), "exhausted").ok(),
            Some(42)
        );
        assert!(super::checked_store_increment(u64::MAX, Path::new("store"), "exhausted").is_err());
    }
}
