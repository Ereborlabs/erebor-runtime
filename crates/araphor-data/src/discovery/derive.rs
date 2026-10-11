use std::collections::{BTreeMap, BTreeSet};

use super::model::{add, require, same};
use super::*;
use crate::{EvidenceRecord, Result};

impl DiscoveryOwner {
    pub fn derive_recorded(input: &DiscoveryInputManifestV1) -> Result<DiscoveryRecordedResultV1> {
        input.validate()?;
        let mut records = BTreeMap::new();
        let mut duplicates = 0;
        for record in &input.records {
            if let Some(previous) = records.insert(&record.id, record) {
                same(previous == record, "record bytes")?;
                add(&mut duplicates, 1)?;
            }
        }
        let mut contexts = BTreeMap::new();
        for context in &input.contexts {
            require(records.contains_key(&context.record_id), "orphan context")?;
            if let Some(previous) = contexts.insert(&context.record_id, context) {
                same(previous == context, "context values")?;
            }
        }
        let mut exclusions = BTreeMap::new();
        for exclusion in &input.exclusions {
            require(
                records.contains_key(&exclusion.record_id),
                "orphan exclusion",
            )?;
            if let Some(previous) = exclusions.insert(&exclusion.record_id, &exclusion.reason) {
                same(previous == &exclusion.reason, "exclusion reason")?;
            }
        }
        let mut coverage = input.coverage.clone();
        let mut atoms = BTreeMap::<BehaviorAtomKeyV1, BehaviorAtomV1>::new();
        let mut unresolved = Vec::new();
        let mut excluded = Vec::new();
        let mut included = 0;
        let mut range_counts = vec![(0, false, false); coverage.len()];
        for (id, record) in records {
            let wire = record.decode()?;
            let range_index = coverage
                .iter()
                .position(|range| {
                    range.stream == id.stream
                        && range.cpu_id == id.cpu_id
                        && range.first_cursor <= id.durable_cursor
                        && range.last_cursor >= id.durable_cursor
                })
                .ok_or_else(|| {
                    crate::DiscoveryInvalidSnafu {
                        field: "record range",
                    }
                    .build()
                })?;
            let range = &mut range_counts[range_index];
            add(&mut range.0, 1)?;
            range.1 |= wire.temporal_coverage == 2;
            range.2 |= wire.temporal_coverage == 0;
            if let Some(reason) = exclusions.get(id) {
                excluded.push(DiscoveryUnresolvedV1 {
                    record_id: id.clone(),
                    reason: (*reason).clone(),
                });
                continue;
            }
            let Some(context) = contexts.get(id) else {
                unresolved.push(DiscoveryUnresolvedV1 {
                    record_id: id.clone(),
                    reason: "MISSING_RECORDED_CONTEXT".into(),
                });
                continue;
            };
            if let Some(reason) = unresolved_reason(record, &wire, context, input.proof_kind) {
                unresolved.push(DiscoveryUnresolvedV1 {
                    record_id: id.clone(),
                    reason: reason.into(),
                });
                continue;
            }
            let physical_result = physical_result(&wire);
            let key = BehaviorAtomKeyV1 {
                stream: id.stream.clone(),
                cpu_id: id.cpu_id,
                subject_revision: context.subject_revision.clone(),
                image_digest: context.image_digest.clone(),
                configuration_digest: context.configuration_digest.clone(),
                process_instance_id: context.process_instance_id,
                entry_instance_id: context.entry_instance_id,
                binding_id: context.binding_id,
                role_id: context.role_id,
                state_id: context.state_id,
                entry_rule_id: context.entry_rule_id,
                catalog_revision: context.catalog_revision,
                static_key: context.static_key.clone(),
                policy_revision: context.policy_revision.clone(),
                generation: wire.profile_generation_ref_id.unwrap_or_default(),
                coverage_interval_id: coverage[range_index].coverage_interval_id,
                temporal_coverage: wire.temporal_coverage,
                effect: (&wire).into(),
                physical_result,
                proof_kind: input.proof_kind,
            };
            let atom = atoms.entry(key.clone()).or_insert_with(|| BehaviorAtomV1 {
                key,
                count: 0,
                first_cursor: id.durable_cursor,
                last_cursor: id.durable_cursor,
                evidence_sample: Vec::new(),
            });
            add(&mut atom.count, 1)?;
            atom.first_cursor = atom.first_cursor.min(id.durable_cursor);
            atom.last_cursor = atom.last_cursor.max(id.durable_cursor);
            if atom.evidence_sample.len() < MAX_DISCOVERY_SAMPLES {
                atom.evidence_sample.push(id.clone());
            }
            add(&mut included, 1)?;
            require(atoms.len() <= MAX_DISCOVERY_ATOMS, "atom count")?;
        }
        for (range, (count, gapped, unknown)) in coverage.iter_mut().zip(range_counts) {
            if count != range.expected_records {
                range.state = DiscoveryCoverageStateV1::Gapped;
                range.gap_reasons.push("INPUT_RANGE_INCOMPLETE".into());
            }
            if gapped {
                range.state = DiscoveryCoverageStateV1::Gapped;
                range.gap_reasons.push("OBSERVATION_COVERAGE_GAPPED".into());
            }
            if unknown {
                if range.state != DiscoveryCoverageStateV1::Gapped {
                    range.state = DiscoveryCoverageStateV1::Unknown;
                }
                range
                    .gap_reasons
                    .push("OBSERVATION_COVERAGE_UNKNOWN".into());
            }
            range.gap_reasons.sort();
            range.gap_reasons.dedup();
        }
        let coverage = merge_coverage(coverage)?;
        let lifecycle = DiscoveryLifecycleCaseV1::ALL
            .into_iter()
            .map(|case| {
                let mut state = input
                    .lifecycle
                    .iter()
                    .find(|entry| entry.case == case)
                    .map_or(DiscoveryLifecycleStateV1::Missing, |entry| {
                        entry.state.clone()
                    });
                if let DiscoveryLifecycleStateV1::Recorded { records } = &mut state {
                    records.sort();
                }
                DiscoveryLifecycleEntryV1 { case, state }
            })
            .collect();
        let accepted_records = included
            .checked_add(unresolved.len() as u64)
            .and_then(|count| count.checked_add(excluded.len() as u64))
            .ok_or_else(|| crate::DiscoveryInvalidSnafu { field: "count" }.build())?;
        let snapshot = BehaviorSnapshotV1 {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            tenant_id: input.tenant_id,
            source_revision: input.source_revision.clone(),
            proof_kind: input.proof_kind,
            accepted_records,
            included_records: included,
            unresolved_records: unresolved.len() as u64,
            excluded_records: excluded.len() as u64,
            coverage,
            atoms: atoms.into_values().collect(),
            unresolved,
            excluded,
            lifecycle,
        };
        snapshot.validate()?;
        Ok(DiscoveryRecordedResultV1 {
            snapshot,
            duplicate_deliveries: duplicates,
        })
    }
}

fn physical_result(wire: &EvidenceRecord) -> DiscoveryPhysicalResultV1 {
    if wire.decision == 1 && wire.kernel_result < 0 {
        DiscoveryPhysicalResultV1::Prevented
    } else {
        DiscoveryPhysicalResultV1::Unknown
    }
}

fn unresolved_reason(
    record: &DiscoveryRecordV1,
    wire: &EvidenceRecord,
    context: &DiscoveryContextBindingV1,
    proof: DiscoveryProofKindV1,
) -> Option<&'static str> {
    if wire.profile_generation_ref_id.is_none() || wire.exact_object_id.is_empty() {
        return Some("MISSING_EXACT_OBJECT_OR_GENERATION");
    }
    if context.static_key.effect_family as u32 != wire.effect_family
        || context.static_key.operation as u32 != wire.operation
        || (!context.static_key.argument_wildcard
            && context.static_key.operation_argument != wire.operation_argument.unwrap_or_default())
    {
        return Some("CONTEXT_OPERATION_MISMATCH");
    }
    if let Some(source) = &wire.decision_context {
        if source.process_instance_id.is_empty()
            || source.entry_instance_id.is_empty()
            || source.binding_id.is_empty()
            || source.role_id == 0
            || source.state_id == 0
            || source.entry_rule_id == 0
        {
            return Some("MISSING_SOURCE_LIFETIME");
        }
        if source.process_instance_id.as_slice() != context.process_instance_id
            || source.entry_instance_id.as_slice() != context.entry_instance_id
            || source.binding_id.as_slice() != context.binding_id
            || source.role_id != context.role_id
            || source.state_id != context.state_id
            || source.entry_rule_id != context.entry_rule_id
            || source.original_kernel_sequence
                != record.original_kernel_sequence.unwrap_or_default()
        {
            return Some("CONTRADICTORY_SOURCE_CONTEXT");
        }
    } else if proof == DiscoveryProofKindV1::ObservedRuntime {
        return Some("MISSING_DECISION_CONTEXT");
    }
    None
}

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

    pub fn merge(&self, next: &Self) -> Result<Self> {
        self.validate()?;
        next.validate()?;
        same(
            self.tenant_id == next.tenant_id
                && self.source_revision == next.source_revision
                && self.proof_kind == next.proof_kind,
            "snapshot source",
        )?;
        if self == next {
            return Ok(self.clone());
        }
        let mut coverage = self.coverage.clone();
        coverage.extend(next.coverage.clone());
        coverage.sort();
        for pair in coverage.windows(2) {
            same(
                pair[0].stream != pair[1].stream
                    || pair[0].cpu_id != pair[1].cpu_id
                    || pair[0].last_cursor < pair[1].first_cursor,
                "snapshot overlap",
            )?;
        }
        let mut output = self.clone();
        add(&mut output.accepted_records, next.accepted_records)?;
        add(&mut output.included_records, next.included_records)?;
        add(&mut output.unresolved_records, next.unresolved_records)?;
        add(&mut output.excluded_records, next.excluded_records)?;
        let mut atoms: BTreeMap<_, _> = output
            .atoms
            .into_iter()
            .map(|atom| (atom.key.clone(), atom))
            .collect();
        for atom in &next.atoms {
            if let Some(known) = atoms.get_mut(&atom.key) {
                add(&mut known.count, atom.count)?;
                known.first_cursor = known.first_cursor.min(atom.first_cursor);
                known.last_cursor = known.last_cursor.max(atom.last_cursor);
                known.evidence_sample.extend(atom.evidence_sample.clone());
                known.evidence_sample.sort();
                known.evidence_sample.dedup();
                known.evidence_sample.truncate(MAX_DISCOVERY_SAMPLES);
            } else {
                atoms.insert(atom.key.clone(), atom.clone());
            }
        }
        output.atoms = atoms.into_values().collect();
        output.unresolved.extend(next.unresolved.clone());
        output
            .unresolved
            .sort_by(|left, right| left.record_id.cmp(&right.record_id));
        output.excluded.extend(next.excluded.clone());
        output
            .excluded
            .sort_by(|left, right| left.record_id.cmp(&right.record_id));
        output.coverage = merge_coverage(coverage)?;
        for (entry, incoming) in output.lifecycle.iter_mut().zip(&next.lifecycle) {
            match (&mut entry.state, &incoming.state) {
                (state @ DiscoveryLifecycleStateV1::Missing, incoming) => *state = incoming.clone(),
                (_, DiscoveryLifecycleStateV1::Missing) => {}
                (
                    DiscoveryLifecycleStateV1::Recorded { records },
                    DiscoveryLifecycleStateV1::Recorded { records: incoming },
                ) => {
                    records.extend(incoming.clone());
                    records.sort();
                    records.dedup();
                    require(records.len() <= 64, "lifecycle records")?;
                }
                (state, incoming) => same(state == incoming, "lifecycle state")?,
            }
        }
        output.validate()?;
        Ok(output)
    }

    pub fn display_groups(&self) -> Result<Vec<BehaviorDisplayGroupV1>> {
        self.validate()?;
        let mut groups = BTreeMap::<BehaviorDisplayKeyV1, BehaviorDisplayGroupV1>::new();
        for atom in &self.atoms {
            let key = BehaviorDisplayKeyV1::from(&atom.key);
            let group = groups
                .entry(key.clone())
                .or_insert_with(|| BehaviorDisplayGroupV1 {
                    key,
                    count: 0,
                    members: Vec::new(),
                    evidence_sample: Vec::new(),
                    coverage: Vec::new(),
                });
            add(&mut group.count, atom.count)?;
            group.members.push(atom.key.clone());
            group.evidence_sample.extend(atom.evidence_sample.clone());
            for range in &self.coverage {
                if range.stream == atom.key.stream
                    && range.cpu_id == atom.key.cpu_id
                    && range.coverage_interval_id == atom.key.coverage_interval_id
                    && range.first_cursor <= atom.last_cursor
                    && range.last_cursor >= atom.first_cursor
                {
                    group.coverage.push(range.clone());
                }
            }
        }
        for group in groups.values_mut() {
            group.evidence_sample.sort();
            group.evidence_sample.dedup();
            group.evidence_sample.truncate(MAX_DISCOVERY_SAMPLES);
            group.coverage.sort();
            group.coverage.dedup();
        }
        Ok(groups.into_values().collect())
    }

    pub fn compare(&self, baseline: &DiscoveryReviewedBaselineV1) -> Result<DiscoveryComparisonV1> {
        self.validate()?;
        baseline.snapshot.validate()?;
        require(
            !baseline.reviewer.is_empty()
                && baseline.reviewer.len() <= 256
                && baseline.reviewed_utc_ns > 0
                && baseline.forbidden.len() <= MAX_DISCOVERY_ATOMS,
            "reviewed baseline",
        )?;
        same(
            self.tenant_id == baseline.snapshot.tenant_id,
            "baseline tenant",
        )?;
        let current = self.display_groups()?;
        let reviewed = baseline.snapshot.display_groups()?;
        let old: BTreeMap<_, _> = reviewed.iter().map(|group| (&group.key, group)).collect();
        let new: BTreeMap<_, _> = current.iter().map(|group| (&group.key, group)).collect();
        let added: Vec<_> = current
            .iter()
            .filter(|group| !old.contains_key(&group.key))
            .cloned()
            .collect();
        let removed: Vec<_> = reviewed
            .iter()
            .filter(|group| !new.contains_key(&group.key))
            .cloned()
            .collect();
        let changed_counts = current
            .iter()
            .filter_map(|group| {
                let previous = old.get(&group.key)?;
                (previous.count != group.count).then(|| DiscoveryGroupChangeV1 {
                    before: (*previous).clone(),
                    after: group.clone(),
                })
            })
            .collect();
        let mut outcomes = BTreeMap::<_, Vec<_>>::new();
        let mut identities = BTreeMap::<_, Vec<_>>::new();
        for group in &reviewed {
            outcomes
                .entry(outcome_basis(&group.key))
                .or_default()
                .push(group);
            identities
                .entry(identity_basis(&group.key))
                .or_default()
                .push(group);
        }
        let mut changed_results = Vec::new();
        let mut changed_identities = Vec::new();
        for group in &added {
            if let Some(previous) = outcomes.get(&outcome_basis(&group.key)) {
                for before in previous {
                    changed_results.push(DiscoveryGroupChangeV1 {
                        before: (*before).clone(),
                        after: group.clone(),
                    });
                }
            }
            if let Some(previous) = identities.get(&identity_basis(&group.key)) {
                for before in previous {
                    if before.key.subject_revision != group.key.subject_revision
                        || before.key.image_digest != group.key.image_digest
                        || before.key.configuration_digest != group.key.configuration_digest
                        || before.key.policy_revision != group.key.policy_revision
                    {
                        changed_identities.push(DiscoveryGroupChangeV1 {
                            before: (*before).clone(),
                            after: group.clone(),
                        });
                    }
                }
            }
        }
        let resources: BTreeSet<_> = baseline
            .snapshot
            .atoms
            .iter()
            .map(|atom| {
                (
                    &atom.key.subject_revision,
                    &atom.key.static_key,
                    &atom.key.binding_id,
                    &atom.key.effect.exact_object_id,
                    &atom.key.effect.exact_file_object,
                )
            })
            .collect();
        let new_resources = self
            .atoms
            .iter()
            .filter(|atom| {
                !resources.contains(&(
                    &atom.key.subject_revision,
                    &atom.key.static_key,
                    &atom.key.binding_id,
                    &atom.key.effect.exact_object_id,
                    &atom.key.effect.exact_file_object,
                ))
            })
            .map(|atom| atom.key.clone())
            .collect();
        let changed_coverage = self.coverage != baseline.snapshot.coverage;
        let changed_lifecycle = self.lifecycle != baseline.snapshot.lifecycle;
        let forbidden_groups = current
            .into_iter()
            .filter(|group| baseline.forbidden.contains(&group.key.static_key))
            .collect();
        Ok(DiscoveryComparisonV1 {
            added,
            removed,
            changed_counts,
            changed_results,
            changed_identities,
            new_resources,
            coverage_before: if changed_coverage {
                baseline.snapshot.coverage.clone()
            } else {
                Vec::new()
            },
            coverage_after: if changed_coverage {
                self.coverage.clone()
            } else {
                Vec::new()
            },
            lifecycle_before: if changed_lifecycle {
                baseline.snapshot.lifecycle.clone()
            } else {
                Vec::new()
            },
            lifecycle_after: if changed_lifecycle {
                self.lifecycle.clone()
            } else {
                Vec::new()
            },
            forbidden_groups,
        })
    }
}

type OutcomeBasis<'a> = (
    &'a str,
    &'a str,
    &'a str,
    u32,
    u32,
    u32,
    &'a DiscoveryPolicyKeyV1,
    &'a DiscoveryPolicyRevisionV1,
    DiscoveryProofKindV1,
);

fn outcome_basis(key: &BehaviorDisplayKeyV1) -> OutcomeBasis<'_> {
    (
        &key.subject_revision,
        &key.image_digest,
        &key.configuration_digest,
        key.role_id,
        key.state_id,
        key.entry_rule_id,
        &key.static_key,
        &key.policy_revision,
        key.proof_kind,
    )
}

type IdentityBasis<'a> = (
    u32,
    u32,
    u32,
    &'a DiscoveryPolicyKeyV1,
    u32,
    u32,
    i32,
    DiscoveryPhysicalResultV1,
    DiscoveryProofKindV1,
);

fn identity_basis(key: &BehaviorDisplayKeyV1) -> IdentityBasis<'_> {
    (
        key.role_id,
        key.state_id,
        key.entry_rule_id,
        &key.static_key,
        key.source_reason,
        key.source_decision,
        key.kernel_result,
        key.physical_result,
        key.proof_kind,
    )
}

fn merge_coverage(mut input: Vec<DiscoveryCoverageV1>) -> Result<Vec<DiscoveryCoverageV1>> {
    input.sort();
    let mut output: Vec<DiscoveryCoverageV1> = Vec::new();
    for range in input {
        if let Some(previous) = output.last_mut() {
            if previous.stream == range.stream
                && previous.cpu_id == range.cpu_id
                && previous.last_cursor.checked_add(1) == Some(range.first_cursor)
                && previous.coverage_revision == range.coverage_revision
                && previous.coverage_interval_id == range.coverage_interval_id
            {
                previous.last_cursor = range.last_cursor;
                add(&mut previous.expected_records, range.expected_records)?;
                previous.state = match (previous.state, range.state) {
                    (DiscoveryCoverageStateV1::Gapped, _)
                    | (_, DiscoveryCoverageStateV1::Gapped) => DiscoveryCoverageStateV1::Gapped,
                    (DiscoveryCoverageStateV1::Unknown, _)
                    | (_, DiscoveryCoverageStateV1::Unknown) => DiscoveryCoverageStateV1::Unknown,
                    (DiscoveryCoverageStateV1::Closed, _)
                    | (_, DiscoveryCoverageStateV1::Closed) => DiscoveryCoverageStateV1::Closed,
                    _ => DiscoveryCoverageStateV1::Healthy,
                };
                previous.gap_reasons.extend(range.gap_reasons);
                previous.gap_reasons.sort();
                previous.gap_reasons.dedup();
                continue;
            }
        }
        output.push(range);
    }
    Ok(output)
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
