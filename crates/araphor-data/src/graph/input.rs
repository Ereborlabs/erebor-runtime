use std::collections::{BTreeMap, BTreeSet};

use super::window::{WindowHead, WindowHeads};
use super::*;
use crate::{AnalysisSourceStatusV1, DiscoveryRecordIdV1, GraphInvalidSnafu, StorePositionV1};

impl GraphAndFindingOwner {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit_chunk(
        &self,
        status: &AnalysisSourceStatusV1,
        heads: &WindowHeads,
        first: u64,
        read_first: u64,
        consumed: u64,
        advance: bool,
        now: u64,
        notice: u64,
        records: &[DiscoveryRecordV1],
        positions: &[(DiscoveryRecordIdV1, StorePositionV1)],
        by_record: &BTreeMap<DiscoveryRecordIdV1, Vec<AnalysisContextVersionV1>>,
    ) -> Result<Option<bool>> {
        let (chunk_first, _) = Self::chunk_bounds(records)?;
        let selected: BTreeSet<_> = records.iter().map(|record| record.id.clone()).collect();
        let positions = positions
            .iter()
            .filter(|(id, _)| selected.contains(id))
            .cloned()
            .collect();
        let previous = heads.get(&first);
        let prior = heads
            .get(&chunk_first)
            .or_else(|| (chunk_first == read_first).then_some(previous).flatten());
        let missing_ranges = Self::chunk_missing_ranges(
            status,
            previous.is_none(),
            first,
            read_first,
            chunk_first,
            prior,
        );
        let deadline = Self::window_deadline(heads, &selected, now)?;
        let header_first = if chunk_first == read_first {
            first
        } else {
            chunk_first
        };
        let input = self.replay_chunk(status, heads, records, by_record, missing_ranges)?;
        self.commit_bounded_window(
            status,
            header_first,
            consumed,
            advance,
            now,
            notice,
            deadline,
            positions,
            input,
            prior,
        )
    }

    fn replay_chunk(
        &self,
        status: &AnalysisSourceStatusV1,
        heads: &WindowHeads,
        records: &[DiscoveryRecordV1],
        by_record: &BTreeMap<DiscoveryRecordIdV1, Vec<AnalysisContextVersionV1>>,
        missing_ranges: Vec<(u64, u64)>,
    ) -> Result<GraphReplayInputV1> {
        let frozen_coverage: Vec<_> = heads
            .values()
            .flat_map(|(_, snapshot, _)| &snapshot.input_manifest.coverage)
            .cloned()
            .collect();
        let (coverage, coverage_keys) = self.coverage(status, records, &frozen_coverage)?;
        Ok(GraphReplayInputV1 {
            source: status.receipt.identity.clone(),
            records: records.to_vec(),
            coverage,
            coverage_keys,
            facts: records
                .iter()
                .flat_map(|record| by_record.get(&record.id).into_iter().flatten().cloned())
                .collect(),
            missing_ranges,
        })
    }

    fn chunk_missing_ranges(
        status: &AnalysisSourceStatusV1,
        without_previous: bool,
        first: u64,
        read_first: u64,
        chunk_first: u64,
        prior: Option<&WindowHead>,
    ) -> Vec<(u64, u64)> {
        let mut ranges =
            prior.map_or_else(Vec::new, |(_, snapshot, _)| snapshot.missing_ranges.clone());
        if status.receipt.retained_floor >= first && without_previous {
            ranges.push((1, status.receipt.retained_floor));
        }
        if chunk_first > read_first {
            ranges.push((read_first, chunk_first - 1));
        }
        ranges.sort();
        ranges.dedup();
        ranges
    }

    pub(super) fn read_window(
        &self,
        status: &AnalysisSourceStatusV1,
        first: u64,
        last: u64,
    ) -> Result<Vec<(DiscoveryRecordV1, StorePositionV1)>> {
        let mut records = Vec::new();
        let mut cursor = first;
        while cursor <= last {
            let page = self.store.read_page(&status.receipt.identity, cursor)?;
            let mut read = 0;
            for accepted in page
                .records
                .into_iter()
                .take_while(|record| record.cursor <= last)
            {
                let record = crate::DiscoveryRecordV1::try_from((
                    &status.receipt.identity,
                    status.receipt.cpu_id,
                    &accepted,
                ))?;
                cursor = accepted.cursor.checked_add(1).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "read cursor",
                    }
                    .build()
                })?;
                records.push((record, accepted.position));
                read += 1;
            }
            if read == 0 {
                return GraphInvalidSnafu {
                    field: "contiguous graph input",
                }
                .fail();
            }
        }
        Ok(records)
    }

    pub(super) fn window_context(
        &self,
        records: &[DiscoveryRecordV1],
        heads: &BTreeMap<u64, (String, GraphSnapshotV1, u64)>,
    ) -> Result<BTreeMap<DiscoveryRecordIdV1, Vec<AnalysisContextVersionV1>>> {
        let mut facts = BTreeMap::new();
        let record_ids: BTreeSet<_> = records.iter().map(|record| record.id.clone()).collect();
        for (_, snapshot, _) in heads.values() {
            for key in &snapshot.input_manifest.context {
                let fact = self.store.context_version(key)?.ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "frozen context version",
                    }
                    .build()
                })?;
                if record_ids.contains(&GraphFactV1::try_from(&fact)?.record_id) {
                    facts.insert(key.clone(), fact);
                }
            }
        }
        for record in records {
            for fact in self.provider.facts(record)? {
                if facts
                    .insert(fact.key.clone(), fact.clone())
                    .is_some_and(|previous| previous != fact)
                {
                    return GraphInvalidSnafu {
                        field: "changed immutable context",
                    }
                    .fail();
                }
            }
        }
        let mut by_record: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for fact in facts.into_values() {
            by_record
                .entry(GraphFactV1::try_from(&fact)?.record_id)
                .or_default()
                .push(fact);
        }
        Ok(by_record)
    }
}
