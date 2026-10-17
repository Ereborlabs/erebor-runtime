use std::collections::BTreeMap;

use crate::Rows;
use araphor_analysis_sdk as sdk;

use super::{
    BehaviorAtomKeyV1, BehaviorAtomV1 as Atom, Context, Counts, Discovery,
    DiscoveryCoverageStateV1 as CoverageState, DiscoveryCoverageV1 as Coverage,
    DiscoveryLifecycleEntryV1 as Lifecycle, DiscoveryPhysicalResultV1,
    DiscoveryUnresolvedV1 as Disposition, Record,
};

struct Atoms {
    values: BTreeMap<BehaviorAtomKeyV1, Atom>,
    unresolved: Vec<Disposition>,
    excluded: Vec<Disposition>,
    counts: Counts,
    ranges: Vec<(u64, bool, bool)>,
}

impl Discovery {
    pub(super) fn atoms(input: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        let rows = Record::read(input)?;
        let mut coverage = Rows::input::<Coverage>(input, "coverage")?;
        let observed = Rows::input::<bool>(input, "observed")?;
        Self::require(observed.len() == 1, "proof kind")?;
        let mut state = Atoms {
            values: BTreeMap::new(),
            unresolved: Vec::new(),
            excluded: Vec::new(),
            counts: Counts::default(),
            ranges: vec![(0, false, false); coverage.len()],
        };
        let mut records = BTreeMap::new();
        for record in &rows {
            if let Some(previous) = records.insert(&record.id, record) {
                Self::same(previous.bytes == record.bytes, "record bytes")?;
                Self::add(&mut state.counts.duplicates, 1)?;
            }
        }
        let contexts = Rows::input::<Context>(input, "contexts")?;
        let mut context_map = BTreeMap::new();
        for context in &contexts {
            Self::require(records.contains_key(&context.record_id), "orphan context")?;
            if let Some(previous) = context_map.insert(&context.record_id, context) {
                Self::same(previous == context, "context values")?;
            }
        }
        let exclusions = Rows::input::<Disposition>(input, "exclusions")?;
        let mut exclusion_map = BTreeMap::new();
        for exclusion in &exclusions {
            Self::require(
                records.contains_key(&exclusion.record_id),
                "orphan exclusion",
            )?;
            if let Some(previous) = exclusion_map.insert(&exclusion.record_id, &exclusion.reason) {
                Self::same(previous == &exclusion.reason, "exclusion reason")?;
            }
        }
        let ranges: BTreeMap<_, _> = coverage
            .iter()
            .enumerate()
            .map(|(index, range)| {
                (
                    (&range.stream, range.cpu_id, range.first_cursor),
                    (index, range.last_cursor),
                )
            })
            .collect();
        for record in records.into_values() {
            let range = ranges
                .range(
                    ..=(
                        &record.id.stream,
                        record.id.cpu_id,
                        record.id.durable_cursor,
                    ),
                )
                .next_back()
                .filter(|((stream, cpu, _), (_, last))| {
                    *stream == &record.id.stream
                        && *cpu == record.id.cpu_id
                        && *last >= record.id.durable_cursor
                })
                .map(|(_, (index, _))| *index)
                .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "record range"))?;
            state.record(
                record,
                range,
                context_map.get(&record.id).copied(),
                exclusion_map.get(&record.id).copied(),
                observed[0],
            )?;
        }
        drop(ranges);
        state.coverage(&mut coverage);
        let coverage = Self::merge_coverage(coverage)?;
        let lifecycle = Self::merge_lifecycle(Rows::input::<Lifecycle>(input, "lifecycle")?)?;
        Ok(sdk::Output {
            datasets: vec![
                Self::write(
                    input,
                    "atoms",
                    &state.values.into_values().collect::<Vec<_>>(),
                )?,
                Self::write(input, "coverage", &coverage)?,
                Self::write(input, "unresolved", &state.unresolved)?,
                Self::write(input, "excluded", &state.excluded)?,
                Self::write(input, "lifecycle", &lifecycle)?,
                Self::write(input, "counts", &[state.counts])?,
            ],
            ..sdk::Output::default()
        })
    }
}

impl Atoms {
    fn record(
        &mut self,
        record: &Record,
        range: usize,
        context: Option<&Context>,
        exclusion: Option<&String>,
        observed: bool,
    ) -> sdk::Result<()> {
        let range = self
            .ranges
            .get_mut(range)
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "record range"))?;
        Discovery::add(&mut range.0, 1)?;
        range.1 |= record.temporal == 2;
        range.2 |= record.temporal == 0;
        Discovery::add(&mut self.counts.accepted, 1)?;
        if let Some(reason) = exclusion {
            self.excluded.push(Disposition {
                record_id: record.id.clone(),
                reason: reason.clone(),
            });
            Discovery::add(&mut self.counts.excluded, 1)?;
            return Ok(());
        }
        if let Some(reason) = Self::unresolved(record, context, observed) {
            self.unresolved.push(Disposition {
                record_id: record.id.clone(),
                reason: reason.into(),
            });
            Discovery::add(&mut self.counts.unresolved, 1)?;
            return Ok(());
        }
        let key = context
            .and_then(|context| context.atom_key.as_ref())
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "atom key"))?;
        let mut key = key.clone();
        key.physical_result = if record.effect.decision == 1 && record.effect.kernel_result < 0 {
            DiscoveryPhysicalResultV1::Prevented
        } else {
            DiscoveryPhysicalResultV1::Unknown
        };
        let atom = self.values.entry(key.clone()).or_insert_with(|| Atom {
            key: key.clone(),
            count: 0,
            first_cursor: record.id.durable_cursor,
            last_cursor: record.id.durable_cursor,
            evidence_sample: Vec::new(),
        });
        Discovery::add(&mut atom.count, 1)?;
        atom.first_cursor = atom.first_cursor.min(record.id.durable_cursor);
        atom.last_cursor = atom.last_cursor.max(record.id.durable_cursor);
        if atom.evidence_sample.len() < 8 {
            atom.evidence_sample.push(record.id.clone());
        }
        Discovery::add(&mut self.counts.included, 1)?;
        Discovery::require(self.values.len() <= 50_000, "atom count")
    }

    fn unresolved(
        record: &Record,
        context: Option<&Context>,
        observed: bool,
    ) -> Option<&'static str> {
        let Some(context) = context else {
            return Some("MISSING_RECORDED_CONTEXT");
        };
        if record.generation.is_none() || record.effect.exact_object_id.is_empty() {
            return Some("MISSING_EXACT_OBJECT_OR_GENERATION");
        }
        let expected = context.atom_key.as_ref()?;
        if u32::from(expected.static_key.effect_family) != record.effect.effect_family
            || u32::from(expected.static_key.operation) != record.effect.operation
            || (!expected.static_key.argument_wildcard
                && expected.static_key.operation_argument
                    != record.effect.operation_argument.unwrap_or_default())
        {
            return Some("CONTEXT_OPERATION_MISMATCH");
        }
        if let Some(source) = &record.source {
            if source.process.is_empty()
                || source.entry.is_empty()
                || source.binding.is_empty()
                || source.role == 0
                || source.state == 0
                || source.rule == 0
            {
                return Some("MISSING_SOURCE_LIFETIME");
            }
            if source.process != expected.process_instance_id
                || source.entry != expected.entry_instance_id
                || source.binding != expected.binding_id
                || source.role != expected.role_id
                || source.state != expected.state_id
                || source.rule != expected.entry_rule_id
                || source.sequence != record.original_sequence.unwrap_or_default()
            {
                return Some("CONTRADICTORY_SOURCE_CONTEXT");
            }
        } else if observed {
            return Some("MISSING_DECISION_CONTEXT");
        }
        None
    }

    fn coverage(&self, coverage: &mut [Coverage]) {
        for (range, &(count, gapped, unknown)) in coverage.iter_mut().zip(&self.ranges) {
            if count != range.expected_records {
                range.state = CoverageState::Gapped;
                range.gap_reasons.push("INPUT_RANGE_INCOMPLETE".into());
            }
            if gapped {
                range.state = CoverageState::Gapped;
                range.gap_reasons.push("OBSERVATION_COVERAGE_GAPPED".into());
            }
            if unknown {
                if range.state != CoverageState::Gapped {
                    range.state = CoverageState::Unknown;
                }
                range
                    .gap_reasons
                    .push("OBSERVATION_COVERAGE_UNKNOWN".into());
            }
            range.gap_reasons.sort();
            range.gap_reasons.dedup();
        }
    }
}
