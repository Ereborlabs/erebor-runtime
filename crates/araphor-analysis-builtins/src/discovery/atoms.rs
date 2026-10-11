use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;

use super::{
    Atom, Context, Counts, Coverage, CoverageState, Discovery, Disposition, Lifecycle, Record,
};

struct Atoms {
    values: BTreeMap<String, Atom>,
    unresolved: Vec<Disposition>,
    excluded: Vec<Disposition>,
    counts: Counts,
    ranges: Vec<(u64, bool, bool)>,
}

impl Discovery {
    pub(super) fn atoms(input: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        let rows = Self::read::<Record>(input, "records")?;
        let mut coverage = Self::read::<Coverage>(input, "coverage")?;
        let observed = Self::read::<bool>(input, "observed")?;
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
            if let Some(previous) = records.insert(&record.id.value, record) {
                Self::same(previous.bytes == record.bytes, "record bytes")?;
                Self::add(&mut state.counts.duplicates, 1)?;
            }
        }
        let contexts = Self::read::<Context>(input, "contexts")?;
        let mut context_map = BTreeMap::new();
        for context in &contexts {
            Self::require(records.contains_key(&context.record), "orphan context")?;
            if let Some(previous) = context_map.insert(&context.record, context) {
                Self::same(previous == context, "context values")?;
            }
        }
        let exclusions = Self::read::<Disposition>(input, "exclusions")?;
        let mut exclusion_map = BTreeMap::new();
        for exclusion in &exclusions {
            Self::require(
                records.contains_key(&exclusion.id.value),
                "orphan exclusion",
            )?;
            if let Some(previous) = exclusion_map.insert(&exclusion.id.value, &exclusion.reason) {
                Self::same(previous == &exclusion.reason, "exclusion reason")?;
            }
        }
        let mut records: Vec<_> = records.into_values().collect();
        records.sort_by(|left, right| left.id.cmp(&right.id));
        for record in records {
            state.record(
                record,
                context_map.get(&record.id.value).copied(),
                exclusion_map.get(&record.id.value).copied(),
                observed[0],
            )?;
        }
        state.coverage(&mut coverage);
        let coverage = Self::merge_coverage(coverage)?;
        let lifecycle = Self::merge_lifecycle(Self::read::<Lifecycle>(input, "lifecycle")?)?;
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
        context: Option<&Context>,
        exclusion: Option<&String>,
        observed: bool,
    ) -> sdk::Result<()> {
        let range = usize::try_from(record.range)
            .ok()
            .and_then(|index| self.ranges.get_mut(index))
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "record range"))?;
        Discovery::add(&mut range.0, 1)?;
        range.1 |= record.temporal == 2;
        range.2 |= record.temporal == 0;
        Discovery::add(&mut self.counts.accepted, 1)?;
        if let Some(reason) = exclusion {
            self.excluded.push(Disposition {
                id: record.id.clone(),
                reason: reason.clone(),
            });
            Discovery::add(&mut self.counts.excluded, 1)?;
            return Ok(());
        }
        if let Some(reason) = Self::unresolved(record, context, observed) {
            self.unresolved.push(Disposition {
                id: record.id.clone(),
                reason: reason.into(),
            });
            Discovery::add(&mut self.counts.unresolved, 1)?;
            return Ok(());
        }
        let key = context
            .and_then(|context| context.atom_key.as_ref())
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "atom key"))?;
        let atom = self.values.entry(key.clone()).or_insert_with(|| Atom {
            key: key.clone(),
            count: 0,
            first: record.cursor,
            last: record.cursor,
            samples: Vec::new(),
            prevented: record.decision == 1 && record.kernel_result < 0,
        });
        Discovery::add(&mut atom.count, 1)?;
        atom.first = atom.first.min(record.cursor);
        atom.last = atom.last.max(record.cursor);
        if atom.samples.len() < 8 {
            atom.samples.push(record.id.clone());
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
        if record.generation.is_none() || record.object.is_empty() {
            return Some("MISSING_EXACT_OBJECT_OR_GENERATION");
        }
        if context.operation.family != record.operation.family
            || context.operation.operation != record.operation.operation
            || (!context.operation.wildcard
                && context.operation.argument != record.operation.argument)
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
            let expected = &context.lifetime;
            if source.process != expected.process
                || source.entry != expected.entry
                || source.binding != expected.binding
                || source.role != expected.role
                || source.state != expected.state
                || source.rule != expected.rule
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
            if count != range.expected {
                range.state = CoverageState::Gapped;
                range.gaps.push("INPUT_RANGE_INCOMPLETE".into());
            }
            if gapped {
                range.state = CoverageState::Gapped;
                range.gaps.push("OBSERVATION_COVERAGE_GAPPED".into());
            }
            if unknown {
                if range.state != CoverageState::Gapped {
                    range.state = CoverageState::Unknown;
                }
                range.gaps.push("OBSERVATION_COVERAGE_UNKNOWN".into());
            }
            range.gaps.sort();
            range.gaps.dedup();
        }
    }
}
