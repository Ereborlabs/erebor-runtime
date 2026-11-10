use std::path::Path;

use rpds::RedBlackTreeMapSync;

use super::{RawEntry, RawIdentity, RawReceipt, RawSource, RawSourceState};
use crate::{AnalysisSourceReceiptV1, Result};

#[derive(Clone, Default)]
pub(in crate::analysis) struct RawIndex {
    pub(in crate::analysis) sources: RedBlackTreeMapSync<Vec<u8>, RawSource>,
    pub(in crate::analysis) entries: RedBlackTreeMapSync<u64, RawEntry>,
    pub(in crate::analysis) ranges: RedBlackTreeMapSync<(Vec<u8>, u64), (u64, usize)>,
    pub(in crate::analysis) revision: u64,
    pub(in crate::analysis) evidence_revision: u64,
    pub(in crate::analysis) binding_revision: u64,
}

impl RawIndex {
    pub(in crate::analysis) fn selection_revision(
        &self,
        selection: &super::super::AnalysisSelectionV1,
        revision: u64,
        control: &super::super::AnalysisReadControl,
    ) -> Result<u64> {
        let mut latest = 0;
        for identity in selection.sources.as_slice() {
            control.check()?;
            let key = identity.key();
            for (_, &(id, _)) in self.ranges.range((key.clone(), 0)..=(key, u64::MAX)) {
                control.check()?;
                if id > revision || id <= latest {
                    continue;
                }
                let entry = &self.entries[&id];
                if &entry.identity == identity
                    && selection.time_range().is_some_and(|(from, until)| {
                        entry.commit.intake >= from && entry.commit.intake <= until
                    })
                {
                    latest = id;
                }
            }
        }
        for identity in selection.traces.as_slice() {
            control.check()?;
            let key = RawIdentity::Diagnostic(identity.clone()).key();
            for (_, &(id, _)) in self.ranges.range((key.clone(), 0)..=(key, u64::MAX)) {
                control.check()?;
                if id <= revision
                    && id > latest
                    && self.entries[&id].identity == RawIdentity::Diagnostic(identity.clone())
                {
                    latest = id;
                }
            }
        }
        Ok(latest)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The captured index uses the caller's path for storage errors."
    )]
    pub(in crate::analysis) fn source_state(
        &self,
        root: &Path,
        receipt: &AnalysisSourceReceiptV1,
        revision: u64,
        expired: &[super::super::AnalysisGapV1],
        retired: &[super::super::AnalysisGapV1],
        control: &super::super::AnalysisReadControl,
        budget: (usize, usize),
    ) -> Result<RawSourceState> {
        let key = receipt.identity.key();
        let live = self
            .ranges
            .range((key.clone(), 0)..=(key, u64::MAX))
            .filter_map(|(_, &(id, index))| {
                let span = &self.entries[&id].commit.spans[index];
                (id <= revision).then_some((span.first, span.last))
            });
        let expired = expired
            .iter()
            .map(|span| (span.first_cursor, span.last_cursor));
        let retired = retired
            .iter()
            .map(|span| (span.first_cursor, span.last_cursor));
        let ranges = Self::merge_ranges(Self::merge_ranges(live, expired), retired);
        let mut state = RawSourceState {
            covered: 0,
            pending: Vec::new(),
        };
        let mut previous = 0;
        let mut next = receipt.contiguous_cursor.checked_add(1);
        let mut allocated = 0;
        for (first, last) in ranges {
            control.check()?;
            if first == 0 || last < first || first <= previous {
                return Err(crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the accepted source ranges overlap or are invalid",
                }
                .build());
            }
            previous = last;
            if first <= receipt.contiguous_cursor {
                state.covered = state
                    .covered
                    .checked_add(last.min(receipt.contiguous_cursor) - first + 1)
                    .ok_or_else(|| {
                        crate::AnalysisStateSnafu {
                            path: root,
                            reason: "the accepted source count overflows",
                        }
                        .build()
                    })?;
            }
            if let Some(begin) = next.filter(|_| last > receipt.contiguous_cursor) {
                if first > begin {
                    allocated += super::super::AnalysisExtractionV1::grow(
                        &mut state.pending,
                        budget.0.saturating_add(allocated),
                        budget.1,
                    )?;
                    state.pending.push(super::super::AnalysisGapV1 {
                        first_cursor: begin,
                        last_cursor: first - 1,
                        commit_revision: revision,
                    });
                }
                next = last.checked_add(1);
            }
        }
        Ok(state)
    }

    fn merge_ranges(
        left: impl Iterator<Item = (u64, u64)>,
        right: impl Iterator<Item = (u64, u64)>,
    ) -> impl Iterator<Item = (u64, u64)> {
        let (mut left, mut right) = (left.peekable(), right.peekable());
        std::iter::from_fn(move || {
            if left
                .peek()
                .is_some_and(|value| right.peek().is_none_or(|other| value <= other))
            {
                left.next()
            } else {
                right.next()
            }
        })
    }

    pub(in crate::analysis) fn prepare(
        &self,
        entry: RawEntry,
        receipt: RawReceipt,
        root: &Path,
    ) -> Result<Self> {
        if !entry.identity.valid() {
            return Err(crate::AnalysisStateSnafu {
                path: root,
                reason: "the raw source identity is invalid",
            }
            .build());
        }
        let key = entry.identity.key();
        let revision = entry.commit.revision;
        if self.entries.contains_key(&revision) {
            return Err(crate::AnalysisStateSnafu {
                path: root,
                reason: "the raw revision is duplicated",
            }
            .build());
        }
        if !self.sources.contains_key(&key)
            && entry.identity.evidence().is_some_and(|identity| {
                self.sources
                    .values()
                    .filter_map(|source| source.receipt.evidence())
                    .any(|source| {
                        let saved = &source.identity;
                        saved.tenant_id == identity.tenant_id
                            && saved.node_id == identity.node_id
                            && saved.source_id == identity.source_id
                            && saved.source_epoch == identity.source_epoch
                            && saved != identity
                    })
            })
        {
            return Err(crate::AnalysisStateSnafu {
                path: root,
                reason: "one raw source epoch changed its boot or label",
            }
            .build());
        }
        for span in &entry.commit.spans {
            if self
                .ranges
                .range((key.clone(), 0)..=(key.clone(), span.last))
                .next_back()
                .is_some_and(|(_, &(prior, offset))| {
                    self.entries[&prior].commit.spans[offset].last >= span.first
                })
            {
                return Err(crate::AnalysisStateSnafu {
                    path: root,
                    reason: "raw cursor ranges overlap",
                }
                .build());
            }
        }
        if self.sources.get(&key).is_some_and(|source| {
            !source.receipt.matches(&entry.identity)
                || source.receipt.cpu() != entry.commit.kind.cpu()
        }) {
            return crate::AnalysisStateSnafu {
                path: root,
                reason: "the recovered raw source binding conflicts",
            }
            .fail();
        }
        let mut next = self.clone();
        if entry.identity.evidence().is_some() {
            next.evidence_revision = next.evidence_revision.max(revision);
            if !next.sources.contains_key(&key) {
                next.binding_revision = next.binding_revision.max(revision);
            }
        }
        if !next.sources.contains_key(&key) {
            next.sources.insert_mut(
                key.clone(),
                RawSource {
                    receipt: receipt.clone(),
                    written: true,
                    active: None,
                },
            );
        }
        let source = next.sources.get_mut(&key).ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the raw source is absent",
            }
            .build()
        })?;
        if let RawReceipt::Diagnostic(next) = receipt {
            let RawReceipt::Diagnostic(saved) = &source.receipt else {
                return Err(crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the raw source kind changed",
                }
                .build());
            };
            if next.last_sequence < saved.last_sequence
                || next.output_bytes < saved.output_bytes
                || saved
                    .terminal
                    .as_ref()
                    .is_some_and(|terminal| next.terminal.as_ref() != Some(terminal))
            {
                return Err(crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the raw diagnostic receipt regressed",
                }
                .build());
            }
            source.receipt = RawReceipt::Diagnostic(next);
        }
        source.written = true;
        next.revision = next.revision.max(revision);
        for (index, span) in entry.commit.spans.iter().enumerate() {
            next.ranges
                .insert_mut((key.clone(), span.first), (revision, index));
        }
        next.entries.insert_mut(revision, entry);
        Ok(next)
    }

    pub(in crate::analysis) fn refresh_source(&mut self, key: &[u8]) -> Result<()> {
        let mut contiguous = self
            .sources
            .get(key)
            .map_or(0, |source| source.receipt.cursor());
        for (_, &(revision, index)) in self
            .ranges
            .range((key.to_vec(), contiguous.saturating_add(1))..=(key.to_vec(), u64::MAX))
        {
            let span = &self.entries[&revision].commit.spans[index];
            if span.first > contiguous.saturating_add(1) {
                break;
            }
            contiguous = contiguous.max(span.last);
        }
        if let Some(source) = self.sources.get_mut(key) {
            if let RawReceipt::Evidence(receipt) = &mut source.receipt {
                receipt.contiguous_cursor = contiguous;
            }
        }
        Ok(())
    }

    pub(in crate::analysis) fn refresh_receipts(&mut self) -> Result<()> {
        let keys: Vec<_> = self.sources.keys().cloned().collect();
        for key in keys {
            self.refresh_source(&key)?;
        }
        Ok(())
    }
}
