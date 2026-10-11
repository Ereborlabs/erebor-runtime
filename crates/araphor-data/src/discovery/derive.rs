#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use super::model::{add, require};
use super::*;
#[cfg(test)]
use crate::EvidenceRecord;
use crate::Result;

impl BehaviorSnapshotV1 {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema_version == DISCOVERY_SCHEMA_VERSION,
            "snapshot schema",
        )?;
        require(
            self.tenant_id != [0; 16]
                && !self.source_revision.is_empty()
                && self.source_revision.len() <= 128
                && self.atoms.len() <= MAX_DISCOVERY_ATOMS
                && self.coverage.len() <= 4096
                && self.accepted_records <= MAX_DISCOVERY_RECORDS as u64
                && self.unresolved_records == self.unresolved.len() as u64
                && self.excluded_records == self.excluded.len() as u64,
            "snapshot bounds",
        )?;
        require(
            self.included_records
                .checked_add(self.unresolved_records)
                .and_then(|count| count.checked_add(self.excluded_records))
                == Some(self.accepted_records),
            "snapshot accounting",
        )?;
        let mut included = 0;
        let mut records = BTreeSet::new();
        for atom in &self.atoms {
            atom.key.validate()?;
            add(&mut included, atom.count)?;
            require(
                atom.count > 0
                    && atom.first_cursor > 0
                    && atom.last_cursor >= atom.first_cursor
                    && atom.count <= atom.last_cursor - atom.first_cursor + 1
                    && atom.evidence_sample.len() <= MAX_DISCOVERY_SAMPLES
                    && !atom.evidence_sample.is_empty()
                    && atom.evidence_sample.len() as u64 <= atom.count
                    && atom.key.proof_kind == self.proof_kind
                    && atom.key.stream.tenant_id == self.tenant_id
                    && atom
                        .evidence_sample
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                    && atom.evidence_sample.iter().all(|id| {
                        id.stream == atom.key.stream
                            && id.cpu_id == atom.key.cpu_id
                            && id.durable_cursor >= atom.first_cursor
                            && id.durable_cursor <= atom.last_cursor
                            && records.insert(id)
                            && self.coverage.iter().any(|range| {
                                range.stream == id.stream
                                    && range.cpu_id == id.cpu_id
                                    && range.coverage_interval_id == atom.key.coverage_interval_id
                                    && range.first_cursor <= id.durable_cursor
                                    && id.durable_cursor <= range.last_cursor
                            })
                    }),
                "snapshot atom",
            )?;
        }
        require(included == self.included_records, "snapshot atom count")?;
        require(
            self.atoms.windows(2).all(|pair| pair[0].key < pair[1].key),
            "snapshot atom order",
        )?;
        for range in &self.coverage {
            range.validate()?;
            require(
                range.stream.tenant_id == self.tenant_id,
                "snapshot range tenant",
            )?;
        }
        require(
            self.coverage.windows(2).all(|pair| {
                pair[0] < pair[1]
                    && (pair[0].stream != pair[1].stream
                        || pair[0].cpu_id != pair[1].cpu_id
                        || pair[0].last_cursor < pair[1].first_cursor)
            }),
            "snapshot range order",
        )?;
        for item in self.unresolved.iter().chain(&self.excluded) {
            item.record_id.validate()?;
            require(
                !item.reason.is_empty()
                    && item.reason.len() <= 128
                    && item.record_id.stream.tenant_id == self.tenant_id
                    && records.insert(&item.record_id),
                "snapshot disposition",
            )?;
            require(
                self.coverage.iter().any(|range| {
                    range.stream == item.record_id.stream
                        && range.cpu_id == item.record_id.cpu_id
                        && range.first_cursor <= item.record_id.durable_cursor
                        && item.record_id.durable_cursor <= range.last_cursor
                }),
                "snapshot disposition range",
            )?;
        }
        require(
            self.unresolved
                .windows(2)
                .all(|pair| pair[0].record_id < pair[1].record_id)
                && self
                    .excluded
                    .windows(2)
                    .all(|pair| pair[0].record_id < pair[1].record_id),
            "snapshot disposition order",
        )?;
        for entry in &self.lifecycle {
            match &entry.state {
                DiscoveryLifecycleStateV1::Recorded { records } => {
                    require(
                        !records.is_empty()
                            && records.len() <= 64
                            && records.windows(2).all(|pair| pair[0] < pair[1]),
                        "snapshot lifecycle records",
                    )?;
                    for id in records {
                        id.validate()?;
                        require(
                            id.stream.tenant_id == self.tenant_id
                                && self.coverage.iter().any(|range| {
                                    range.stream == id.stream
                                        && range.cpu_id == id.cpu_id
                                        && range.first_cursor <= id.durable_cursor
                                        && id.durable_cursor <= range.last_cursor
                                }),
                            "snapshot lifecycle range",
                        )?;
                    }
                }
                DiscoveryLifecycleStateV1::Declared { reason }
                | DiscoveryLifecycleStateV1::NotApplicable { reason }
                | DiscoveryLifecycleStateV1::Unsupported { reason } => require(
                    !reason.is_empty() && reason.len() <= 128,
                    "snapshot lifecycle reason",
                )?,
                DiscoveryLifecycleStateV1::Missing => {}
            }
        }
        require(
            self.lifecycle.len() == DiscoveryLifecycleCaseV1::ALL.len()
                && self
                    .lifecycle
                    .iter()
                    .map(|entry| entry.case)
                    .eq(DiscoveryLifecycleCaseV1::ALL),
            "snapshot lifecycle",
        )
    }
}

#[cfg(test)]
mod tests {
    mod baseline;

    use serde::Deserialize;

    use super::*;

    type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    pub(super) fn input() -> TestResult<DiscoveryInputManifestV1> {
        DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )
        .map_err(Into::into)
    }

    fn edit_record(
        record: &mut DiscoveryRecordV1,
        edit: impl FnOnce(&mut EvidenceRecord),
    ) -> TestResult<()> {
        let mut wire = record.decode()?;
        edit(&mut wire);
        record.wire_record = Vec::<u8>::try_from(&wire)?;
        Ok(())
    }

    #[test]
    fn discovery_derivation_replay_counts() -> TestResult<()> {
        let original = input()?;
        let result = DiscoveryOwner::derive_recorded(&original)?;
        assert_eq!(result.duplicate_deliveries, 1);
        assert_eq!(result.snapshot.accepted_records, 3);
        assert_eq!(result.snapshot.included_records, 2);
        assert_eq!(result.snapshot.unresolved_records, 1);
        assert_eq!(result.snapshot.atoms.len(), 1);
        assert_eq!(result.snapshot.atoms[0].count, 2);
        assert_eq!(
            result.snapshot.atoms[0].key.physical_result,
            DiscoveryPhysicalResultV1::Prevented
        );
        let encoded = serde_json::to_value(&result.snapshot.atoms[0])?;
        assert_eq!(
            encoded
                .as_object()
                .ok_or("atom object absent")?
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "key",
                "count",
                "first_cursor",
                "last_cursor",
                "evidence_sample"
            ])
        );
        for field in [
            "source_reason",
            "source_decision",
            "kernel_result",
            "physical_result",
            "static_key",
        ] {
            let mut changed = encoded.clone();
            changed[field] = serde_json::Value::Null;
            assert!(serde_json::from_value::<BehaviorAtomV1>(changed).is_err());
        }
        let retained: BehaviorSnapshotV1 =
            serde_json::from_slice(&serde_json::to_vec(&result.snapshot)?)?;
        retained.validate()?;
        assert_eq!(retained, result.snapshot);
        let mut permuted = original.clone();
        permuted.records.reverse();
        permuted.contexts.reverse();
        assert_eq!(
            DiscoveryOwner::derive_recorded(&permuted)?.snapshot,
            result.snapshot
        );
        permuted.records.extend(original.records);
        assert_eq!(
            DiscoveryOwner::derive_recorded(&permuted)?.snapshot,
            result.snapshot
        );
        let encoded = serde_json::to_vec(&permuted)?;
        assert_eq!(
            DiscoveryInputManifestV1::try_from(encoded.as_slice())?,
            permuted
        );
        Ok(())
    }

    #[test]
    fn discovery_derivation_conflicting_input() -> TestResult<()> {
        let mut changed = input()?;
        edit_record(&mut changed.records[3], |wire| wire.kernel_result = 0)?;
        assert!(matches!(
            DiscoveryOwner::derive_recorded(&changed),
            Err(crate::Error::DiscoveryConflict {
                kind: "record bytes",
                ..
            })
        ));
        changed = input()?;
        changed.contexts.push(changed.contexts[0].clone());
        changed
            .contexts
            .last_mut()
            .ok_or("context absent")?
            .state_id = 2;
        assert!(matches!(
            DiscoveryOwner::derive_recorded(&changed),
            Err(crate::Error::DiscoveryConflict {
                kind: "context values",
                ..
            })
        ));
        changed = input()?;
        changed.contexts[0].record_id.stream.node_id = "another-node".into();
        assert!(DiscoveryOwner::derive_recorded(&changed).is_err());
        changed = input()?;
        changed.records[0].id.stream.tenant_id = [9; 16];
        assert!(changed.validate().is_err());
        Ok(())
    }

    #[test]
    fn discovery_derivation_distinct_keys() -> TestResult<()> {
        for change in 0..6 {
            let mut changed = input()?;
            match change {
                0 => edit_record(&mut changed.records[1], |wire| wire.kernel_result = -1)?,
                1 => edit_record(&mut changed.records[1], |wire| wire.task_cookie += 1)?,
                2 => changed.contexts[1].image_digest = "sha256:new-image".into(),
                3 => edit_record(&mut changed.records[1], |wire| {
                    wire.exact_object_id = vec![31; 16].into()
                })?,
                4 => {
                    changed.contexts[1].policy_revision.signed_profile_digest =
                        "replacement-profile".into()
                }
                _ => changed.contexts[1].entry_instance_id[15] += 1,
            }
            assert_eq!(
                DiscoveryOwner::derive_recorded(&changed)?
                    .snapshot
                    .atoms
                    .len(),
                2,
                "change {change}"
            );
        }
        let mut changed = input()?;
        edit_record(&mut changed.records[1], |wire| {
            wire.decision = 0;
            wire.kernel_result = -5;
        })?;
        let result = DiscoveryOwner::derive_recorded(&changed)?;
        assert!(result
            .snapshot
            .atoms
            .iter()
            .any(|atom| atom.key.effect.kernel_result == -5
                && atom.key.physical_result == DiscoveryPhysicalResultV1::Unknown));
        changed = input()?;
        changed.proof_kind = DiscoveryProofKindV1::RecordedInput;
        assert_ne!(
            DiscoveryOwner::derive_recorded(&changed)?.snapshot,
            DiscoveryOwner::derive_recorded(&input()?)?.snapshot
        );
        Ok(())
    }

    #[test]
    fn discovery_derivation_missing_generation() -> TestResult<()> {
        let mut input = input()?;
        input.records.truncate(1);
        input.contexts.truncate(1);
        input.coverage[0].last_cursor = 1;
        input.coverage[0].expected_records = 1;
        let sequence = input.records[0]
            .original_kernel_sequence
            .unwrap_or_default();
        edit_record(&mut input.records[0], |wire| {
            wire.profile_generation_ref_id = None;
            wire.decision_context = Some(crate::EvidenceDecisionContext {
                schema_version: 1,
                original_kernel_sequence: sequence,
                profile_generation_ref_id: 0,
                ..Default::default()
            });
        })?;
        input.records[0].decode()?;
        let snapshot = DiscoveryOwner::derive_recorded(&input)?.snapshot;
        assert_eq!(snapshot.unresolved_records, 1);
        assert_eq!(snapshot.included_records, 0);
        assert_eq!(
            snapshot.unresolved[0].reason,
            "MISSING_EXACT_OBJECT_OR_GENERATION"
        );
        input.proof_kind = DiscoveryProofKindV1::ObservedRuntime;
        edit_record(&mut input.records[0], |wire| {
            wire.profile_generation_ref_id = Some(7);
            wire.decision_context = None;
        })?;
        let snapshot = DiscoveryOwner::derive_recorded(&input)?.snapshot;
        assert_eq!(snapshot.unresolved_records, 1);
        assert_eq!(snapshot.unresolved[0].reason, "MISSING_DECISION_CONTEXT");
        Ok(())
    }

    #[test]
    fn discovery_derivation_disposition_accounting() -> TestResult<()> {
        let mut changed = input()?;
        changed.exclusions.push(DiscoveryUnresolvedV1 {
            record_id: changed.records[1].id.clone(),
            reason: "DECLARED_FILTER".into(),
        });
        let result = DiscoveryOwner::derive_recorded(&changed)?;
        assert_eq!(result.snapshot.included_records, 1);
        assert_eq!(result.snapshot.excluded_records, 1);
        assert_eq!(result.snapshot.unresolved_records, 1);
        assert_eq!(result.snapshot.accepted_records, 3);
        assert_eq!(result.duplicate_deliveries, 1);
        assert_eq!(result.snapshot.excluded[0].reason, "DECLARED_FILTER");
        changed
            .records
            .retain(|record| record.id.durable_cursor != 3);
        let result = DiscoveryOwner::derive_recorded(&changed)?;
        assert_eq!(
            result.snapshot.coverage[0].state,
            DiscoveryCoverageStateV1::Gapped
        );
        assert!(result.snapshot.coverage[0]
            .gap_reasons
            .iter()
            .any(|reason| reason == "INPUT_RANGE_INCOMPLETE"));
        let mut count = u64::MAX;
        assert!(add(&mut count, 1).is_err());
        assert_eq!(count, u64::MAX);
        Ok(())
    }

    #[test]
    fn discovery_derivation_page_merge() -> TestResult<()> {
        let input = input()?;
        let complete = DiscoveryOwner::derive_recorded(&input)?.snapshot;
        let mut first = input.clone();
        first.records.retain(|record| record.id.durable_cursor == 1);
        first
            .contexts
            .retain(|context| context.record_id.durable_cursor == 1);
        first.coverage[0].last_cursor = 1;
        first.coverage[0].expected_records = 1;
        let mut second = input.clone();
        second
            .records
            .retain(|record| record.id.durable_cursor != 1);
        second
            .contexts
            .retain(|context| context.record_id.durable_cursor != 1);
        second.coverage[0].first_cursor = 2;
        second.coverage[0].expected_records = 2;
        let first = DiscoveryOwner::derive_recorded(&first)?.snapshot;
        let second = DiscoveryOwner::derive_recorded(&second)?.snapshot;
        assert_eq!(first.merge(&second)?, complete);
        assert_eq!(second.merge(&first)?, complete);
        assert_eq!(complete.merge(&complete)?, complete);
        assert!(complete.merge(&first).is_err());
        assert!(!serde_json::to_string(&complete)?.contains("wire_record"));
        Ok(())
    }

    #[test]
    fn discovery_derivation_lifecycle_schema() -> TestResult<()> {
        let mut input = input()?;
        let missing = DiscoveryOwner::derive_recorded(&input)?.snapshot;
        assert_eq!(missing.lifecycle.len(), 9);
        assert!(missing
            .lifecycle
            .iter()
            .all(|entry| entry.state == DiscoveryLifecycleStateV1::Missing));
        input.lifecycle = vec![
            DiscoveryLifecycleEntryV1 {
                case: DiscoveryLifecycleCaseV1::Startup,
                state: DiscoveryLifecycleStateV1::Recorded {
                    records: vec![input.records[0].id.clone()],
                },
            },
            DiscoveryLifecycleEntryV1 {
                case: DiscoveryLifecycleCaseV1::ScheduledWork,
                state: DiscoveryLifecycleStateV1::NotApplicable {
                    reason: "NO_SCHEDULED_WORK".into(),
                },
            },
        ];
        let snapshot = DiscoveryOwner::derive_recorded(&input)?.snapshot;
        assert!(matches!(
            snapshot.lifecycle[0].state,
            DiscoveryLifecycleStateV1::Recorded { .. }
        ));
        assert_eq!(
            snapshot.lifecycle[1].state,
            DiscoveryLifecycleStateV1::Missing
        );
        assert_eq!(snapshot.lifecycle[7].state, input.lifecycle[1].state);
        input.schema_version = DISCOVERY_SCHEMA_VERSION - 1;
        assert!(input.validate().is_err());
        input.schema_version = DISCOVERY_SCHEMA_VERSION;
        let mut json = serde_json::to_value(input)?;
        json["contexts"][0]["static_key"]["authority"] = serde_json::json!("allow");
        assert!(DiscoveryInputManifestV1::try_from(serde_json::to_vec(&json)?.as_slice()).is_err());
        Ok(())
    }

    #[test]
    fn discovery_comparison_reviewed_changes() -> TestResult<()> {
        let original = input()?;
        let snapshot = DiscoveryOwner::derive_recorded(&original)?.snapshot;
        let baseline = DiscoveryReviewedBaselineV1 {
            reviewer: "operator".into(),
            reviewed_utc_ns: 3000,
            forbidden: vec![snapshot.atoms[0].key.static_key.clone()],
            snapshot: snapshot.clone(),
        };
        let mut changed = original.clone();
        changed
            .records
            .retain(|record| record.id.durable_cursor != 2);
        changed
            .contexts
            .retain(|context| context.record_id.durable_cursor != 2);
        changed.coverage[0].expected_records = 2;
        let repeated = DiscoveryOwner::derive_recorded(&changed)?.snapshot;
        let comparison = repeated.compare(&baseline)?;
        assert!(comparison.added.is_empty());
        assert_eq!(comparison.changed_counts.len(), 1);
        assert_eq!(comparison.forbidden_groups.len(), 1);
        let mut changed = original.clone();
        edit_record(&mut changed.records[1], |wire| wire.kernel_result = -1)?;
        let comparison = DiscoveryOwner::derive_recorded(&changed)?
            .snapshot
            .compare(&baseline)?;
        assert_eq!(comparison.added.len(), 1);
        assert_eq!(comparison.changed_results.len(), 1);
        changed
            .records
            .retain(|record| record.id.durable_cursor != 1);
        changed
            .contexts
            .retain(|context| context.record_id.durable_cursor != 1);
        changed.coverage[0].expected_records = 2;
        let comparison = DiscoveryOwner::derive_recorded(&changed)?
            .snapshot
            .compare(&baseline)?;
        assert_eq!(comparison.changed_results.len(), 1);
        let mut changed = original;
        changed.contexts[0].image_digest = "replacement-image".into();
        changed.contexts[1].image_digest = "replacement-image".into();
        let comparison = DiscoveryOwner::derive_recorded(&changed)?
            .snapshot
            .compare(&baseline)?;
        assert_eq!(comparison.changed_identities.len(), 1);
        assert_eq!(baseline.snapshot, snapshot);
        let mut unreviewed = baseline;
        unreviewed.reviewer.clear();
        assert!(snapshot.compare(&unreviewed).is_err());
        Ok(())
    }

    #[derive(Deserialize)]
    struct Corpus {
        version: u32,
        proof_kind: DiscoveryProofKindV1,
        splits: BTreeMap<String, Split>,
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Split {
        workload_id: String,
        start_utc_ns: i64,
        end_utc_ns: i64,
    }

    #[derive(Deserialize)]
    struct Case {
        id: String,
        partition: String,
        groups: Vec<Group>,
        expected: Expected,
    }

    #[derive(Deserialize)]
    struct Group {
        count: u64,
        label: String,
        variation: Variation,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    enum Variation {
        Routine,
        Denied,
        State,
        Release,
        Entry,
        MissingContext,
        Gapped,
        ReplicaGapped,
        Unknown,
        MissingObject,
        Outbound,
    }

    #[derive(Deserialize)]
    struct Expected {
        accepted: u64,
        atoms: usize,
        unresolved: u64,
        prevented: u64,
        coverage: DiscoveryCoverageStateV1,
    }

    fn case_input(case: &Case, split: &Split) -> TestResult<DiscoveryInputManifestV1> {
        let mut input = input()?;
        let seed = input.records[0].clone();
        let mut binding = input.contexts[0].clone();
        binding.subject_revision = format!("{}/revision-1", split.workload_id);
        binding.static_key.workload_selector_id = split.workload_id.clone();
        input.source_revision = format!("synthetic-pilot-v1/{}", case.id);
        input.records.clear();
        input.contexts.clear();
        for (ordinal, group) in case.groups.iter().enumerate() {
            assert!(!group.label.is_empty());
            assert!((1..=10_000).contains(&group.count));
            for _ in 0..group.count {
                let cursor = input.records.len() as u64 + 1;
                let mut record = seed.clone();
                record.id.durable_cursor = cursor;
                record.original_kernel_sequence = Some(cursor + 100);
                let mut wire = seed.decode()?;
                wire.observed_boottime_ns = cursor + 1000;
                wire.ingested_utc_ns = split
                    .start_utc_ns
                    .checked_add(cursor.try_into()?)
                    .ok_or("timestamp overflow")?;
                assert!(wire.ingested_utc_ns < split.end_utc_ns);
                wire.decision = 0;
                wire.kernel_result = 0;
                wire.configured_errno = 0;
                let mut context = binding.clone();
                context.record_id = record.id.clone();
                match group.variation {
                    Variation::Routine | Variation::MissingContext => {}
                    Variation::Denied => {
                        wire.decision = 1;
                        wire.kernel_result = -13;
                        wire.configured_errno = -13;
                    }
                    Variation::State => context.state_id += ordinal as u32 + 1,
                    Variation::Release => {
                        context.image_digest = "sha256:replacement-image".into();
                        context.configuration_digest = "replacement-configuration".into();
                        context.subject_revision = format!("{}/revision-2", split.workload_id);
                    }
                    Variation::Entry => {
                        context.entry_instance_id[15] += 1;
                        context.entry_rule_id += 1;
                    }
                    Variation::Gapped => wire.temporal_coverage = 2,
                    Variation::ReplicaGapped => {
                        record.id.stream.node_id = "node-b".into();
                        context.record_id = record.id.clone();
                        context.subject_revision =
                            format!("{}-replica/revision-1", split.workload_id);
                        context.process_instance_id[15] += 1;
                        context.entry_instance_id[15] += 1;
                        context.binding_id[15] += 1;
                        wire.temporal_coverage = 2;
                    }
                    Variation::Unknown => wire.temporal_coverage = 0,
                    Variation::MissingObject => wire.exact_object_id = Default::default(),
                    Variation::Outbound => {
                        wire.effect_family = 3;
                        wire.operation = 12;
                        wire.exact_object_id = Default::default();
                        wire.destination_id = 31;
                        context.static_key.effect_family = 3;
                        context.static_key.operation = 12;
                        context.static_key.operation_id = "CONNECT".into();
                        context.static_key.object_selector = "DESTINATION:fixture-api".into();
                    }
                }
                record.wire_record = Vec::<u8>::try_from(&wire)?;
                if !matches!(group.variation, Variation::MissingContext) {
                    input.contexts.push(context);
                }
                input.records.push(record);
            }
        }
        let seed = input.coverage[0].clone();
        input.coverage.clear();
        for record in &input.records {
            if let Some(range) = input
                .coverage
                .iter_mut()
                .find(|range| range.stream == record.id.stream)
            {
                range.last_cursor = record.id.durable_cursor;
                range.expected_records += 1;
            } else {
                let mut range = seed.clone();
                range.stream = record.id.stream.clone();
                range.first_cursor = record.id.durable_cursor;
                range.last_cursor = record.id.durable_cursor;
                range.expected_records = 1;
                input.coverage.push(range);
            }
        }
        Ok(input)
    }

    #[test]
    fn discovery_derivation_corpus_parity() -> TestResult<()> {
        let corpus: Corpus = serde_json::from_slice(include_bytes!(
            "../../../mithril-e2e/fixtures/discovery/pilot.json"
        ))?;
        assert_eq!(corpus.version, 1);
        assert_eq!(corpus.proof_kind, DiscoveryProofKindV1::Synthetic);
        assert_eq!(corpus.cases.len(), 21);
        for case in corpus.cases {
            let mut input = case_input(
                &case,
                corpus.splits.get(&case.partition).ok_or("split absent")?,
            )?;
            let result = DiscoveryOwner::derive_recorded(&input)?.snapshot;
            assert_eq!(
                result.accepted_records, case.expected.accepted,
                "{}",
                case.id
            );
            assert_eq!(result.atoms.len(), case.expected.atoms, "{}", case.id);
            assert_eq!(
                result.unresolved_records, case.expected.unresolved,
                "{}",
                case.id
            );
            assert!(
                result
                    .coverage
                    .iter()
                    .any(|range| range.state == case.expected.coverage),
                "{}",
                case.id
            );
            assert_eq!(
                result.included_records + result.unresolved_records + result.excluded_records,
                result.accepted_records
            );
            assert_eq!(
                result
                    .atoms
                    .iter()
                    .filter(|atom| atom.key.physical_result == DiscoveryPhysicalResultV1::Prevented)
                    .map(|atom| atom.count)
                    .sum::<u64>(),
                case.expected.prevented,
                "{}",
                case.id
            );
            input.records.reverse();
            input.contexts.reverse();
            input.records.extend(input.records.clone());
            let replay = DiscoveryOwner::derive_recorded(&input)?;
            assert_eq!(replay.duplicate_deliveries, case.expected.accepted);
            assert_eq!(replay.snapshot, result, "{}", case.id);
        }
        Ok(())
    }
}
