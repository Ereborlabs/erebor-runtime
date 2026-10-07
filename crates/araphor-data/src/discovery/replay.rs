use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::model::{require, InputByteLimit};
use super::*;
use crate::{AnalysisContextVersionV1, ContextSensitivityV1, DiscoveryEncodingSnafu, Result};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryReplayV1 {
    Available(Box<BehaviorSnapshotV1>),
    Unavailable {
        first_cursor: u64,
        last_cursor: u64,
        reason: String,
    },
}

impl DiscoveryOwner {
    pub fn replay(&self, profile: &DiscoveryProfileV1) -> Result<DiscoveryReplayV1> {
        profile.validate()?;
        let unavailable = |reason: &str| DiscoveryReplayV1::Unavailable {
            first_cursor: profile
                .snapshot
                .coverage
                .iter()
                .map(|range| range.first_cursor)
                .min()
                .unwrap_or(0),
            last_cursor: profile
                .snapshot
                .coverage
                .iter()
                .map(|range| range.last_cursor)
                .max()
                .unwrap_or(0),
            reason: reason.into(),
        };
        let Some(input) = self.replay_input(profile)? else {
            return Ok(unavailable("FROZEN_INPUT_UNAVAILABLE"));
        };
        let mut snapshot = Self::derive_recorded(&input)?.snapshot;
        if !snapshot
            .unresolved
            .iter()
            .map(|item| &item.record_id)
            .eq(profile
                .snapshot
                .unresolved
                .iter()
                .map(|item| &item.record_id))
        {
            return Ok(unavailable("FROZEN_SNAPSHOT_MISMATCH"));
        }
        snapshot.unresolved = profile.snapshot.unresolved.clone();
        if snapshot != profile.snapshot {
            return Ok(unavailable("FROZEN_SNAPSHOT_MISMATCH"));
        }
        Ok(DiscoveryReplayV1::Available(Box::new(snapshot)))
    }

    pub(super) fn replay_input(
        &self,
        profile: &DiscoveryProfileV1,
    ) -> Result<Option<DiscoveryInputManifestV1>> {
        profile.validate()?;
        if profile.snapshot.accepted_records > self.config.interval_records as u64 {
            return Ok(None);
        }
        let mut facts = Vec::new();
        for reference in &profile.context_refs {
            let Some(version) = self.store.context_version(&reference.key)? else {
                return Ok(None);
            };
            if version.key.owner_id != "discovery-facts-v1" {
                continue;
            }
            if version.key.lifetime_key != profile.scope.identity.key()
                || version.body.len() > DISCOVERY_PIN_BYTES
                || version.sensitivity != ContextSensitivityV1::Tenant
                || version.valid_from_utc_ns.is_some()
                || version.valid_until_utc_ns.is_some()
            {
                return Ok(None);
            }
            facts.push(retained_binding(&version, profile)?);
        }
        let mut atoms = BTreeMap::<_, Vec<&BehaviorAtomV1>>::new();
        for atom in &profile.snapshot.atoms {
            let key = &atom.key;
            atoms
                .entry((
                    &key.stream,
                    key.cpu_id,
                    key.generation,
                    key.coverage_interval_id,
                    key.temporal_coverage,
                    &key.effect,
                ))
                .or_default()
                .push(atom);
        }
        let unavailable: BTreeSet<_> = profile
            .snapshot
            .unresolved
            .iter()
            .chain(&profile.snapshot.excluded)
            .map(|item| &item.record_id)
            .collect();
        let mut input = DiscoveryInputManifestV1 {
            schema_version: profile.schema_version,
            tenant_id: profile.snapshot.tenant_id,
            source_revision: profile.snapshot.source_revision.clone(),
            proof_kind: profile.snapshot.proof_kind,
            coverage: profile.snapshot.coverage.clone(),
            contexts: Vec::new(),
            records: Vec::new(),
            exclusions: profile.snapshot.excluded.clone(),
            lifecycle: profile.snapshot.lifecycle.clone(),
        };
        let mut budget = InputByteLimit(self.config.input_bytes);
        for range in &profile.snapshot.coverage {
            let Some(status) = self.store.source_status(&range.stream)? else {
                return Ok(None);
            };
            if status.receipt.cpu_id != range.cpu_id
                || status.receipt.contiguous_cursor < range.last_cursor
            {
                return Ok(None);
            }
            let mut cursor = range.first_cursor;
            while cursor <= range.last_cursor {
                let page = match self.store.read_page(&range.stream, cursor) {
                    Ok(page) => page,
                    Err(crate::Error::RetainedRangeExpired { .. }) => return Ok(None),
                    Err(error) => return Err(error),
                };
                if page.first_cursor != cursor || page.records.is_empty() {
                    return Ok(None);
                }
                for stored in page.records {
                    if stored.cursor != cursor {
                        return Ok(None);
                    }
                    if stored.cursor > range.last_cursor {
                        break;
                    }
                    if input.records.len() >= self.config.interval_records {
                        return Ok(None);
                    }
                    let Some(remaining) = budget.0.checked_sub(stored.framed_record.len()) else {
                        return Ok(None);
                    };
                    budget.0 = remaining;
                    let record =
                        DiscoveryRecordV1::try_from((&range.stream, range.cpu_id, &stored))?;
                    let wire = record.decode()?;
                    if wire.coverage_interval_id.as_ref() != range.coverage_interval_id {
                        return Ok(None);
                    }
                    if !unavailable.contains(&record.id) {
                        let effect = DiscoveryEffectKeyV1::from(&wire);
                        let candidates = atoms.get(&(
                            &record.id.stream,
                            record.id.cpu_id,
                            wire.profile_generation_ref_id.unwrap_or_default(),
                            range.coverage_interval_id,
                            wire.temporal_coverage,
                            &effect,
                        ));
                        let mut matches = candidates
                            .into_iter()
                            .flatten()
                            .filter(|atom| source_matches(atom, &record, &wire));
                        let Some(atom) = matches.next() else {
                            return Ok(None);
                        };
                        if matches.next().is_some() {
                            return Ok(None);
                        }
                        let binding = DiscoveryContextBindingV1::from((&record.id, &atom.key));
                        if !facts.iter().any(|fact| fact_matches(fact, &binding)) {
                            return Ok(None);
                        }
                        if serde_json::to_writer(&mut budget, &binding).is_err() {
                            return Ok(None);
                        }
                        input.contexts.push(binding);
                    }
                    input.records.push(record);
                    let Some(next) = cursor.checked_add(1) else {
                        return Ok(None);
                    };
                    cursor = next;
                }
            }
        }
        if input.records.len() as u64 != profile.snapshot.accepted_records {
            return Ok(None);
        }
        if serde_json::to_writer(InputByteLimit(DISCOVERY_INPUT_BYTES), &input).is_err() {
            return Ok(None);
        }
        input.validate()?;
        Ok(Some(input))
    }
}

impl From<(&DiscoveryRecordIdV1, &BehaviorAtomKeyV1)> for DiscoveryContextBindingV1 {
    fn from((record_id, key): (&DiscoveryRecordIdV1, &BehaviorAtomKeyV1)) -> Self {
        Self {
            record_id: record_id.clone(),
            subject_revision: key.subject_revision.clone(),
            image_digest: key.image_digest.clone(),
            configuration_digest: key.configuration_digest.clone(),
            process_instance_id: key.process_instance_id,
            entry_instance_id: key.entry_instance_id,
            binding_id: key.binding_id,
            role_id: key.role_id,
            state_id: key.state_id,
            entry_rule_id: key.entry_rule_id,
            catalog_revision: key.catalog_revision,
            static_key: key.static_key.clone(),
            policy_revision: key.policy_revision.clone(),
        }
    }
}

fn source_matches(
    atom: &BehaviorAtomV1,
    record: &DiscoveryRecordV1,
    wire: &crate::EvidenceRecord,
) -> bool {
    if record.id.durable_cursor < atom.first_cursor || record.id.durable_cursor > atom.last_cursor {
        return false;
    }
    match &wire.decision_context {
        Some(context) => {
            context.process_instance_id.as_ref() == atom.key.process_instance_id
                && context.entry_instance_id.as_ref() == atom.key.entry_instance_id
                && context.binding_id.as_ref() == atom.key.binding_id
                && context.role_id == atom.key.role_id
                && context.state_id == atom.key.state_id
                && context.entry_rule_id == atom.key.entry_rule_id
                && record.original_kernel_sequence == Some(context.original_kernel_sequence)
        }
        None => atom.key.proof_kind != DiscoveryProofKindV1::ObservedRuntime,
    }
}

fn fact_matches(left: &DiscoveryContextBindingV1, right: &DiscoveryContextBindingV1) -> bool {
    left.subject_revision == right.subject_revision
        && left.image_digest == right.image_digest
        && left.configuration_digest == right.configuration_digest
        && left.process_instance_id == right.process_instance_id
        && left.entry_instance_id == right.entry_instance_id
        && left.binding_id == right.binding_id
        && left.role_id == right.role_id
        && left.state_id == right.state_id
        && left.entry_rule_id == right.entry_rule_id
        && left.catalog_revision == right.catalog_revision
        && left.static_key == right.static_key
        && left.policy_revision == right.policy_revision
}

fn retained_binding(
    version: &AnalysisContextVersionV1,
    profile: &DiscoveryProfileV1,
) -> Result<DiscoveryContextBindingV1> {
    let value = serde_json::from_slice(&version.body).context(DiscoveryEncodingSnafu)?;
    let serde_json::Value::Object(mut binding) = value else {
        return crate::DiscoveryInvalidSnafu {
            field: "frozen fact object",
        }
        .fail();
    };
    let mut pinned = serde_json::Map::new();
    for field in [
        "workload",
        "policy_source_revision_id",
        "target_snapshot_digest",
        "signed_profile_digest",
        "control_commit_index",
    ] {
        pinned.insert(
            field.into(),
            binding.remove(field).ok_or_else(|| {
                crate::DiscoveryInvalidSnafu {
                    field: "frozen fact field",
                }
                .build()
            })?,
        );
    }
    binding.insert(
        "record_id".into(),
        serde_json::to_value(DiscoveryRecordIdV1 {
            stream: profile.scope.identity.clone(),
            cpu_id: profile
                .snapshot
                .coverage
                .first()
                .map_or(0, |range| range.cpu_id),
            durable_cursor: profile
                .snapshot
                .coverage
                .first()
                .map_or(1, |range| range.first_cursor),
        })
        .context(DiscoveryEncodingSnafu)?,
    );
    pinned.insert("binding".into(), serde_json::Value::Object(binding));
    let pinned: DiscoveryPinnedContextV1 =
        serde_json::from_value(serde_json::Value::Object(pinned))
            .context(DiscoveryEncodingSnafu)?;
    pinned.validate()?;
    require(
        pinned.control_commit_index == version.key.owner_revision,
        "frozen fact revision",
    )?;
    Ok(pinned.binding)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;
    use crate::{
        AnalysisStore, ContainerKindV1, EvidenceRetentionOwner, RetentionLimitsV1,
        ValidatedEvidenceBatchV1, WorkloadTargetFactV1,
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    struct FrozenProvider {
        pinned: DiscoveryPinnedContextV1,
        calls: AtomicUsize,
    }

    impl DiscoveryContextProvider for FrozenProvider {
        fn context(&self, record: &DiscoveryRecordV1) -> Result<DiscoveryContextJoinV1> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if record.id == self.pinned.binding.record_id {
                Ok(DiscoveryContextJoinV1::Available(Box::new(
                    self.pinned.clone(),
                )))
            } else {
                Ok(DiscoveryContextJoinV1::Unresolved(
                    DiscoveryContextUnavailableV1::MissingWorkloadFact,
                ))
            }
        }
    }

    struct ReplayFixture {
        _directory: tempfile::TempDir,
        store: Arc<AnalysisStore>,
        provider: Arc<FrozenProvider>,
        owner: DiscoveryOwner,
        profile: DiscoveryProfileV1,
    }

    impl ReplayFixture {
        fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
            let input = DiscoveryInputManifestV1::try_from(
                include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
            )?;
            let directory = tempfile::tempdir()?;
            let store = Arc::new(AnalysisStore::open_with_limits(
                directory.path().join("analysis"),
                RetentionLimitsV1 {
                    raw_max_age_ns: 1,
                    raw_max_bytes: 1_048_576,
                },
                Default::default(),
            )?);
            let binding = input.contexts[0].clone();
            let provider = Arc::new(FrozenProvider {
                pinned: DiscoveryPinnedContextV1 {
                    workload: WorkloadTargetFactV1 {
                        node_id: binding.record_id.stream.node_id.clone(),
                        workload_binding_generation_digest: binding.subject_revision.clone(),
                        execution_set_id: binding.static_key.execution_set_id.clone(),
                        cluster_uid: "fixture-cluster".into(),
                        namespace_uid: "fixture-namespace".into(),
                        controller_uid: "fixture-controller".into(),
                        service_account_uid: "fixture-account".into(),
                        pod_uid: "fixture-pod".into(),
                        container_id: "fixture-container".into(),
                        container_name: "fixture".into(),
                        container_kind: ContainerKindV1::Application,
                        image_digest: binding.image_digest.clone(),
                        pod_labels: BTreeMap::new(),
                        kubernetes: None,
                    },
                    policy_source_revision_id: binding.policy_revision.source_revision_id.clone(),
                    target_snapshot_digest: "fixture-target".into(),
                    signed_profile_digest: binding.policy_revision.signed_profile_digest.clone(),
                    control_commit_index: 1,
                    binding,
                },
                calls: AtomicUsize::new(0),
            });
            let records: BTreeMap<_, _> = input
                .records
                .iter()
                .map(|record| (&record.id, record))
                .collect();
            for (id, record) in records {
                let frame = if id == &provider.pinned.binding.record_id {
                    let binding = &provider.pinned.binding;
                    let mut wire = record.decode()?;
                    wire.decision_context = Some(crate::EvidenceDecisionContext {
                        schema_version: 1,
                        original_kernel_sequence: record
                            .original_kernel_sequence
                            .ok_or("the fixture kernel sequence is absent")?,
                        process_instance_id: binding.process_instance_id.to_vec(),
                        entry_instance_id: binding.entry_instance_id.to_vec(),
                        binding_id: binding.binding_id.to_vec(),
                        profile_generation_ref_id: wire
                            .profile_generation_ref_id
                            .ok_or("the fixture generation is absent")?,
                        role_id: binding.role_id,
                        state_id: binding.state_id,
                        entry_rule_id: binding.entry_rule_id,
                        ..Default::default()
                    });
                    Vec::<u8>::try_from(&wire)?
                } else {
                    record.wire_record.clone()
                };
                store.accept_validated_batch(
                    id.stream.clone(),
                    ValidatedEvidenceBatchV1 {
                        cpu_id: id.cpu_id,
                        first_cursor: id.durable_cursor,
                        last_cursor: id.durable_cursor,
                        intake_utc_ns: id.durable_cursor,
                        frame_ends: vec![frame.len()],
                        framed_records: frame.into(),
                    },
                )?;
            }
            let owner = DiscoveryOwner::new(
                store.clone(),
                provider.clone(),
                DiscoveryConfigV1 {
                    interval_records: 3,
                    witness_age_ns: 1,
                    ..Default::default()
                },
            )?;
            assert_eq!(owner.process(10)?, 3);
            let profile = owner
                .profile(&input.records[0].id.stream)?
                .ok_or("profile absent")?;
            assert!(profile.sealed);
            assert_eq!(profile.snapshot.included_records, 1);
            assert_eq!(profile.snapshot.unresolved_records, 2);
            Ok(Self {
                _directory: directory,
                store,
                provider,
                owner,
                profile,
            })
        }
    }

    #[test]
    fn discovery_replay_frozen_facts() -> TestResult {
        let fixture = ReplayFixture::new()?;
        let calls = fixture.provider.calls.load(Ordering::SeqCst);
        assert_eq!(
            fixture.owner.replay(&fixture.profile)?,
            DiscoveryReplayV1::Available(Box::new(fixture.profile.snapshot.clone()))
        );
        let mut profile = fixture.profile.clone();
        profile.snapshot.unresolved[0].reason = "FROZEN_REASON".into();
        let mut excluded = profile
            .snapshot
            .unresolved
            .pop()
            .ok_or("unresolved absent")?;
        excluded.reason = "FROZEN_EXCLUSION".into();
        profile.snapshot.excluded.push(excluded);
        profile.snapshot.unresolved_records -= 1;
        profile.snapshot.excluded_records += 1;
        profile.snapshot.lifecycle[1].state = DiscoveryLifecycleStateV1::Recorded {
            records: vec![profile.snapshot.atoms[0].evidence_sample[0].clone()],
        };
        assert_eq!(
            fixture.owner.replay(&profile)?,
            DiscoveryReplayV1::Available(Box::new(profile.snapshot.clone()))
        );
        assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), calls);
        Ok(())
    }

    #[test]
    fn discovery_replay_missing_manifest() -> TestResult {
        let fixture = ReplayFixture::new()?;
        let mut profile = fixture.profile.clone();
        profile.context_refs.clear();
        assert!(matches!(
            fixture.owner.replay(&profile)?,
            DiscoveryReplayV1::Unavailable { .. }
        ));
        let mut profile = fixture.profile.clone();
        profile.context_refs[0].key.entity_key = vec![17; 16];
        assert!(matches!(
            fixture.owner.replay(&profile)?,
            DiscoveryReplayV1::Unavailable { .. }
        ));
        let mut profile = fixture.profile.clone();
        let mut atom = profile.snapshot.atoms[0].clone();
        atom.key.image_digest.push_str("-ambiguous");
        atom.last_cursor = 2;
        atom.evidence_sample[0].durable_cursor = 2;
        profile.snapshot.atoms.push(atom);
        profile
            .snapshot
            .atoms
            .sort_by(|left, right| left.key.cmp(&right.key));
        profile.snapshot.included_records += 1;
        profile.snapshot.unresolved.remove(0);
        profile.snapshot.unresolved_records -= 1;
        assert!(matches!(
            fixture.owner.replay(&profile)?,
            DiscoveryReplayV1::Unavailable { .. }
        ));
        let mut profile = fixture.profile.clone();
        profile.snapshot.atoms[0].last_cursor = 3;
        assert!(matches!(
            fixture.owner.replay(&profile)?,
            DiscoveryReplayV1::Unavailable {
                ref reason,
                ..
            } if reason == "FROZEN_SNAPSHOT_MISMATCH"
        ));
        Ok(())
    }

    #[test]
    fn discovery_replay_input_bounds() -> TestResult {
        let fixture = ReplayFixture::new()?;
        let input = fixture
            .owner
            .replay_input(&fixture.profile)?
            .ok_or("input absent")?;
        let bytes = input
            .records
            .iter()
            .map(|record| record.wire_record.len())
            .sum::<usize>()
            + serde_json::to_vec(&input.contexts[0])?.len();
        for config in [
            DiscoveryConfigV1 {
                input_bytes: bytes - 1,
                ..Default::default()
            },
            DiscoveryConfigV1 {
                interval_records: 2,
                ..Default::default()
            },
        ] {
            let owner =
                DiscoveryOwner::new(fixture.store.clone(), fixture.provider.clone(), config)?;
            assert!(matches!(
                owner.replay(&fixture.profile)?,
                DiscoveryReplayV1::Unavailable { .. }
            ));
        }
        let owner = DiscoveryOwner::new(
            fixture.store.clone(),
            fixture.provider.clone(),
            DiscoveryConfigV1 {
                input_bytes: bytes,
                ..Default::default()
            },
        )?;
        assert!(matches!(
            owner.replay(&fixture.profile)?,
            DiscoveryReplayV1::Available(_)
        ));
        Ok(())
    }

    #[test]
    fn discovery_replay_retained_counts() -> TestResult {
        let fixture = ReplayFixture::new()?;
        let calls = fixture.provider.calls.load(Ordering::SeqCst);
        let removed = EvidenceRetentionOwner::new(&fixture.store)
            .retain(&fixture.profile.scope.identity, 100)?;
        assert_eq!(removed.removed_records, 3);
        assert!(matches!(
            fixture.owner.replay(&fixture.profile)?,
            DiscoveryReplayV1::Unavailable {
                first_cursor: 1,
                last_cursor: 3,
                ..
            }
        ));
        assert_eq!(
            fixture.owner.profile(&fixture.profile.scope.identity)?,
            Some(fixture.profile)
        );
        assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), calls);
        Ok(())
    }
}
