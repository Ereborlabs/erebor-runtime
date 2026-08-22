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
    canonical_policy_spec_digest, PolicyActivationAcknowledgementV1, PolicyBundleV1,
    PolicyDocumentV1, PolicyRolloutStateV1, PolicySourceRevisionV1, PolicySourceStateV1,
    PolicyTargetSnapshotV1, ProfileCandidateArtifactV1, Result,
};

const STORE_SCHEMA_VERSION: u32 = 1;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone)]
pub struct ControlStore {
    inner: Arc<Mutex<ControlStoreInner>>,
}

struct ControlStoreInner {
    root: PathBuf,
    state: ControlStoreState,
}

#[derive(Clone, Default)]
struct ControlStoreState {
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

    pub fn accept_source_revision(
        &self,
        revision: PolicySourceRevisionV1,
        policy_document: PolicyDocumentV1,
    ) -> Result<u64> {
        let mut inner = self.lock()?;
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
            return Ok(inner.state.commit_index);
        }
        let document_digest = canonical_policy_spec_digest(&policy_document)?;
        if revision.canonical_spec_digest != document_digest
            || revision.policy_document_digest != document_digest
        {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "the source revision does not bind the supplied policy document".to_owned(),
            }
            .fail();
        }
        let key = PolicyObjectKeyV1::from(&revision);
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
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "one policy generation has conflicting source bytes or deletion state"
                        .to_owned(),
                }
                .fail();
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
        if rollout_state.transition_version != current.transition_version.saturating_add(1)
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

    pub fn source_revision(&self, id: &str) -> Result<Option<PolicySourceRevisionV1>> {
        Ok(self.lock()?.state.source_revisions.get(id).cloned())
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
        object_uid: &str,
        sequence_epoch: u64,
    ) -> Result<u64> {
        let inner = self.lock()?;
        let mut current = 0_u64;
        for bundle in inner.state.bundles.values().filter(|bundle| {
            bundle.candidate.exact_target.node_id == node_id
                && inner
                    .state
                    .source_revisions
                    .get(&bundle.candidate.policy_source_revision_id)
                    .is_some_and(|source| source.object_uid == object_uid)
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

    pub fn latest_bundle_for_object_node(
        &self,
        object_uid: &str,
        node_id: &str,
    ) -> Result<Option<PolicyBundleV1>> {
        let inner = self.lock()?;
        Ok(inner
            .state
            .bundles
            .values()
            .filter(|bundle| {
                bundle.candidate.exact_target.node_id == node_id
                    && inner
                        .state
                        .source_revisions
                        .get(&bundle.candidate.policy_source_revision_id)
                        .is_some_and(|source| source.object_uid == object_uid)
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

fn commit(inner: &mut ControlStoreInner, transaction: ControlTransactionV1) -> Result<u64> {
    let commit_index = inner.state.commit_index.saturating_add(1);
    if commit_index == 0 {
        return ControlStoreSnafu {
            path: inner.root.clone(),
            reason: "the Control commit index is exhausted".to_owned(),
        }
        .fail();
    }
    let mut record = ControlCommitV1 {
        schema_version: STORE_SCHEMA_VERSION,
        commit_index,
        previous_commit_digest: inner.state.last_commit_digest.clone(),
        transaction,
        commit_digest: String::new(),
    };
    record.commit_digest = commit_digest(&record)?;
    let path = commit_path(&inner.root, commit_index);
    write_commit(&path, &record)?;
    apply_transaction(&mut inner.state, &record.transaction, &path)?;
    inner.state.commit_index = commit_index;
    inner.state.last_commit_digest = record.commit_digest;
    Ok(commit_index)
}

fn verify_commit(commit: &ControlCommitV1, state: &ControlStoreState, path: &Path) -> Result<()> {
    let expected_index = state.commit_index.saturating_add(1);
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

fn apply_transaction(
    state: &mut ControlStoreState,
    transaction: &ControlTransactionV1,
    path: &Path,
) -> Result<()> {
    match transaction {
        ControlTransactionV1::SourceAccepted {
            source_revision,
            policy_document,
        } => {
            let digest = canonical_policy_spec_digest(policy_document)?;
            if source_revision.canonical_spec_digest != digest
                || source_revision.policy_document_digest != digest
            {
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
        let previous = state
            .bundles
            .values()
            .filter(|existing| {
                existing.candidate.exact_target.node_id == candidate.exact_target.node_id
                    && state
                        .source_revisions
                        .get(&existing.candidate.policy_source_revision_id)
                        .is_some_and(|existing_source| {
                            existing_source.object_uid == source.object_uid
                        })
            })
            .max_by_key(|existing| {
                (
                    existing.candidate.distribution_sequence_epoch,
                    existing.candidate.distribution_sequence,
                )
            });
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
    fs::rename(&temporary, path).context(IoSnafu { path })?;
    File::open(parent)
        .context(IoSnafu { path: parent })?
        .sync_all()
        .context(IoSnafu { path: parent })
}
