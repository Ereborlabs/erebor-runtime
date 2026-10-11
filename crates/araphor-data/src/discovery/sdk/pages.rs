use std::collections::BTreeMap;
use std::ops::Range;

use crate::{
    AnalysisReadControl, DiscoveryContextBindingV1, DiscoveryCoverageV1, DiscoveryInputManifestV1,
    DiscoveryInvalidSnafu, DiscoveryLifecycleEntryV1, DiscoveryLifecycleStateV1,
    DiscoveryRecordIdV1, DiscoveryRecordV1, DiscoveryUnresolvedV1, Result,
};

pub(super) struct RecordedPages<'a> {
    input: &'a DiscoveryInputManifestV1,
    control: &'a AnalysisReadControl,
    groups: Vec<RecordGroup<'a>>,
    coverage: Vec<CoveragePage<'a>>,
    size: usize,
    position: usize,
    finished: bool,
}

struct RecordGroup<'a> {
    id: &'a DiscoveryRecordIdV1,
    records: Vec<&'a DiscoveryRecordV1>,
    contexts: Vec<&'a DiscoveryContextBindingV1>,
    exclusions: Vec<&'a DiscoveryUnresolvedV1>,
}

struct CoveragePage<'a> {
    original: &'a DiscoveryCoverageV1,
    groups: Option<Range<usize>>,
    cursor: u64,
    expected: u64,
}

impl<'a> RecordedPages<'a> {
    pub(super) fn new(
        input: &'a DiscoveryInputManifestV1,
        size: usize,
        control: &'a AnalysisReadControl,
    ) -> Result<Self> {
        control.check()?;
        crate::discovery::model::require(size > 0, "recorded page size")?;
        input.validate()?;
        control.check()?;
        let groups = RecordGroup::read(input, control)?;
        let coverage = CoveragePage::read(input, &groups, control)?;
        Ok(Self {
            input,
            control,
            groups,
            coverage,
            size,
            position: 0,
            finished: false,
        })
    }

    fn page(&mut self) -> Result<DiscoveryInputManifestV1> {
        self.control.check()?;
        let end = self
            .position
            .saturating_add(self.size)
            .min(self.groups.len());
        let span = self.position..end;
        let mut page = DiscoveryInputManifestV1 {
            schema_version: self.input.schema_version,
            tenant_id: self.input.tenant_id,
            source_revision: self.input.source_revision.clone(),
            proof_kind: self.input.proof_kind,
            coverage: Vec::new(),
            contexts: Vec::new(),
            records: Vec::new(),
            exclusions: Vec::new(),
            lifecycle: self.lifecycle(&self.groups[span.clone()])?,
        };
        for group in &self.groups[span.clone()] {
            group.copy_to(&mut page, self.control)?;
        }
        for range in &mut self.coverage {
            self.control.check()?;
            if let Some(range) = range.slice(&self.groups, &span)? {
                page.coverage.push(range);
            }
        }
        self.control.check()?;
        self.position = end;
        Ok(page)
    }

    fn lifecycle(&self, groups: &[RecordGroup<'_>]) -> Result<Vec<DiscoveryLifecycleEntryV1>> {
        let mut output = Vec::new();
        for entry in &self.input.lifecycle {
            self.control.check()?;
            let mut entry = entry.clone();
            if let DiscoveryLifecycleStateV1::Recorded { records } = &mut entry.state {
                records.retain(|id| groups.binary_search_by(|group| group.id.cmp(id)).is_ok());
                if records.is_empty() {
                    entry.state = DiscoveryLifecycleStateV1::Missing;
                }
            }
            output.push(entry);
        }
        Ok(output)
    }
}

impl Iterator for RecordedPages<'_> {
    type Item = Result<DiscoveryInputManifestV1>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let page = self.page();
        self.finished = page.is_err() || self.position == self.groups.len();
        Some(page)
    }
}

impl<'a> RecordGroup<'a> {
    fn read(
        input: &'a DiscoveryInputManifestV1,
        control: &AnalysisReadControl,
    ) -> Result<Vec<Self>> {
        let mut groups = BTreeMap::<_, Self>::new();
        for record in &input.records {
            control.check()?;
            groups
                .entry(&record.id)
                .or_insert_with(|| Self {
                    id: &record.id,
                    records: Vec::new(),
                    contexts: Vec::new(),
                    exclusions: Vec::new(),
                })
                .records
                .push(record);
        }
        for context in &input.contexts {
            control.check()?;
            groups
                .get_mut(&context.record_id)
                .ok_or_else(|| {
                    DiscoveryInvalidSnafu {
                        field: "orphan context",
                    }
                    .build()
                })?
                .contexts
                .push(context);
        }
        for exclusion in &input.exclusions {
            control.check()?;
            groups
                .get_mut(&exclusion.record_id)
                .ok_or_else(|| {
                    DiscoveryInvalidSnafu {
                        field: "orphan exclusion",
                    }
                    .build()
                })?
                .exclusions
                .push(exclusion);
        }
        Ok(groups.into_values().collect())
    }

    fn copy_to(
        &self,
        page: &mut DiscoveryInputManifestV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        for record in &self.records {
            control.check()?;
            page.records.push((*record).clone());
        }
        for context in &self.contexts {
            control.check()?;
            page.contexts.push((*context).clone());
        }
        for exclusion in &self.exclusions {
            control.check()?;
            page.exclusions.push((*exclusion).clone());
        }
        Ok(())
    }
}

impl<'a> CoveragePage<'a> {
    fn read(
        input: &'a DiscoveryInputManifestV1,
        groups: &[RecordGroup<'_>],
        control: &AnalysisReadControl,
    ) -> Result<Vec<Self>> {
        let mut coverage: Vec<_> = input
            .coverage
            .iter()
            .map(|original| Self {
                original,
                groups: None,
                cursor: original.first_cursor,
                expected: original.expected_records,
            })
            .collect();
        coverage.sort_by(|left, right| {
            (
                &left.original.stream,
                left.original.cpu_id,
                left.original.first_cursor,
            )
                .cmp(&(
                    &right.original.stream,
                    right.original.cpu_id,
                    right.original.first_cursor,
                ))
        });
        let mut range = 0;
        for (index, group) in groups.iter().enumerate() {
            control.check()?;
            while coverage
                .get(range)
                .is_some_and(|range| !range.contains(group.id))
            {
                control.check()?;
                range += 1;
            }
            let range = coverage.get_mut(range).ok_or_else(|| {
                DiscoveryInvalidSnafu {
                    field: "record outside range",
                }
                .build()
            })?;
            match &mut range.groups {
                Some(groups) => groups.end = index + 1,
                None => range.groups = Some(index..index + 1),
            }
        }
        Ok(coverage)
    }

    fn contains(&self, id: &DiscoveryRecordIdV1) -> bool {
        self.original.stream == id.stream
            && self.original.cpu_id == id.cpu_id
            && self.original.first_cursor <= id.durable_cursor
            && id.durable_cursor <= self.original.last_cursor
    }

    fn slice(
        &mut self,
        groups: &[RecordGroup<'_>],
        page: &Range<usize>,
    ) -> Result<Option<DiscoveryCoverageV1>> {
        let Some(members) = &self.groups else {
            return Ok((page.start == 0).then(|| self.original.clone()));
        };
        let start = page.start.max(members.start);
        let end = page.end.min(members.end);
        if start >= end {
            return Ok(None);
        }
        let next = if end < members.end {
            Some(
                groups
                    .get(end)
                    .ok_or_else(|| {
                        DiscoveryInvalidSnafu {
                            field: "recorded page range",
                        }
                        .build()
                    })?
                    .id
                    .durable_cursor,
            )
        } else {
            None
        };
        let last = next.map_or(self.original.last_cursor, |cursor| cursor - 1);
        let width = last - self.cursor + 1;
        let after = self.original.last_cursor - last;
        // Keep the declared total within the remaining cursor bounds.
        let expected = ((end - start) as u64).clamp(
            self.expected.saturating_sub(after),
            self.expected.min(width),
        );
        let mut range = self.original.clone();
        range.first_cursor = self.cursor;
        range.last_cursor = last;
        range.expected_records = expected;
        range.validate()?;
        self.expected -= expected;
        if let Some(cursor) = next {
            self.cursor = cursor;
        }
        Ok(Some(range))
    }
}

#[cfg(test)]
mod tests;
