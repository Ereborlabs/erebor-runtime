use std::path::Path;

use super::*;
use crate::{AnalysisResultCommitV1, DiscoveryProfileV1};

impl DataView {
    pub(super) fn progress_inputs<'a>(
        &self,
        input: &AnalysisResultCommitV1,
        profile: Option<&'a DiscoveryProfileV1>,
        class: ProcessorClassV1,
        root: &Path,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<&'a [AnalysisGapV1]> {
        let receipt = self
            .source_receipt(&input.scope.identity)?
            .ok_or_else(|| Code::Missing.error("processor source"))?;
        if input.consumed_cursor > receipt.contiguous_cursor
            || input.coverage_revision > receipt.coverage_revision
        {
            return crate::Error::reject_path(
                root,
                "the result claims unavailable source or coverage progress",
            );
        }
        let gaps: &'a [AnalysisGapV1] = profile.map_or(&[], |profile| {
            &profile.gaps[profile
                .gaps
                .partition_point(|gap| gap.last_cursor <= input.expected_cursor)..]
        });
        if !gaps.is_empty()
            && (input.scope.processor_id != crate::DISCOVERY_PROCESSOR
                || class != ProcessorClassV1::Optional)
        {
            return crate::Error::reject_path(
                root,
                "only optional Discovery can consume expired input",
            );
        }
        if input.expected_cursor >= input.consumed_cursor {
            if input.expected_cursor == input.consumed_cursor && gaps.is_empty() {
                return Ok(gaps);
            }
            return crate::Error::reject_path(
                root,
                "the processor result skips unavailable raw input",
            );
        }
        let first = input.expected_cursor + 1;
        let last = input.consumed_cursor;
        let events = super::super::events::Events::new(self);
        let mut available = 0_u64;
        let mut pending: Option<AnalysisGapV1> = None;
        let mut group = None;
        let mut next = 0;
        for row in events.spans(&input.scope.identity, first, last)? {
            check()?;
            let (key, value) = row.context(crate::NativeStorageSnafu {
                operation: "read processor input spans",
            })?;
            let (span_first, index) =
                super::super::events::Events::decode_span(&input.scope.identity, &key, &value)?;
            let entry = events.batch(index.revision)?;
            entry.check_span(&input.scope.identity, span_first, &index)?;
            let span = &entry.meta.spans[index.slot];
            if span.last < first {
                continue;
            }
            let from = span.first.max(first);
            let until = span.last.min(last);
            let expired = events.expiry(entry.meta.revision)?;
            if let Some(expired) = expired {
                if profile.is_none() {
                    return crate::Error::reject_path(
                        root,
                        "the processor result skips unavailable raw input",
                    );
                }
                let current = (entry.meta.revision, entry.meta.intake, expired.revision);
                if group == Some(current)
                    && pending
                        .as_ref()
                        .is_some_and(|gap| gap.last_cursor.checked_add(1) == Some(from))
                {
                    if let Some(gap) = &mut pending {
                        gap.last_cursor = until;
                    }
                } else {
                    Self::match_gap(gaps, &mut next, pending.take(), root)?;
                    pending = Some(AnalysisGapV1 {
                        first_cursor: from,
                        last_cursor: until,
                        commit_revision: expired.revision,
                    });
                    group = Some(current);
                }
            } else {
                Self::match_gap(gaps, &mut next, pending.take(), root)?;
                group = None;
                available = available
                    .checked_add(until - from + 1)
                    .ok_or_else(|| Code::Invalid.error("processor input coverage"))?;
            }
        }
        Self::match_gap(gaps, &mut next, pending, root)?;
        if next != gaps.len() {
            return crate::Error::reject_path(
                root,
                "the discovery gap differs from its captured expiry",
            );
        }
        let missing = gaps.iter().try_fold(0_u64, |count, gap| {
            count
                .checked_add(gap.last_cursor - gap.first_cursor + 1)
                .ok_or_else(|| Code::Invalid.error("processor input coverage"))
        })?;
        if available.checked_add(missing) != Some(last - input.expected_cursor) {
            return crate::Error::reject_path(
                root,
                "the processor result skips unavailable raw input",
            );
        }
        Ok(gaps)
    }

    fn match_gap(
        gaps: &[AnalysisGapV1],
        next: &mut usize,
        actual: Option<AnalysisGapV1>,
        root: &Path,
    ) -> Result<()> {
        if let Some(actual) = actual {
            if gaps.get(*next) != Some(&actual) {
                return crate::Error::reject_path(
                    root,
                    "the discovery gap differs from its captured expiry",
                );
            }
            *next += 1;
        }
        Ok(())
    }
}
