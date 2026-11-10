use std::path::Path;

use super::{RawIndex, RawJournal, RawRead, RawReceipt};
use crate :: { AnalysisReadControl , AnalysisReadPageV1 , Result } ;

pub(in crate::analysis) struct RawPage {
    first_cursor: u64,
    accepted: u64,
    revision: u64,
    count: usize,
    frozen: Vec<RawRead>,
}

impl RawJournal {
    pub(in crate::analysis) fn freeze_page(
        &self,
        captured: &RawIndex,
        receipt: &RawReceipt,
        first_cursor: u64,
        through: u64,
        control: &AnalysisReadControl,
        max_records: usize,
    ) -> Result<RawPage> {
        let key = match receipt {
            RawReceipt::Evidence(receipt) => receipt.identity.key(),
            RawReceipt::Diagnostic(receipt) => {
                super::RawIdentity::Diagnostic(receipt.identity.clone()).key()
            }
        };
        if first_cursor == 0 || first_cursor > receipt.cursor().saturating_add(1) {
            return crate::Error::reject_path(
                &self.root,
                "the evidence read cursor is outside the accepted range",
            );
        }
        let expired = self
            .budget
            .expired
            .range((key.clone(), 0)..=(key.clone(), first_cursor))
            .next_back()
            .map(|(_, &last)| last)
            .filter(|last| *last >= first_cursor);
        if first_cursor <= receipt.floor() || expired.is_some() {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor,
                last_cursor: expired.unwrap_or(receipt.floor()),
            }
            .fail();
        }
        let expiry = self
            .budget
            .expired
            .range((key.clone(), first_cursor)..=(key.clone(), u64::MAX))
            .next()
            .map(|((_, first), _)| *first)
            .filter(|first| *first <= receipt.cursor());
        let page_end = expiry.map_or(receipt.cursor(), |first| first - 1);
        let mut frozen = Vec::new();
        let mut count = 0;
        let mut bounded = false;
        if first_cursor <= page_end {
            let start = captured
                .ranges
                .range((key.clone(), 0)..=(key.clone(), first_cursor))
                .next_back()
                .filter(|(_, (revision, index))| {
                    captured.entries[revision].commit.spans[*index].last >= first_cursor
                })
                .map_or(first_cursor, |((_, first), _)| *first);
            for (_, &(revision, index)) in captured
                .ranges
                .range((key.clone(), start)..=(key, page_end))
            {
                control.check()?;
                if revision > through {
                    continue;
                }
                let entry = &captured.entries[&revision];
                let span = &entry.commit.spans[index];
                let first = span.first.max(first_cursor);
                if first_cursor.checked_add(count as u64) != Some(first) {
                    return crate::Error::reject_path(
                        &self.root,
                        "the accepted evidence range has a missing record",
                    );
                }
                let available = max_records - count;
                let last = span
                    .last
                    .min(page_end)
                    .min(first.saturating_add(available as u64 - 1));
                count += (last - first + 1) as usize;
                frozen.push(self.freeze(entry, index, first, last)?);
                bounded = count == max_records;
                if bounded {
                    break;
                }
            }
        }
        let next_cursor = first_cursor.checked_add(count as u64);
        if next_cursor.is_some_and(|next| next <= page_end) && !bounded {
            return crate::Error::reject_path(
                &self.root,
                "the accepted evidence range has a missing record",
            );
        }
        Ok(RawPage {
            first_cursor,
            accepted: receipt.cursor(),
            revision: through,
            count,
            frozen,
        })
    }
}

impl RawPage {
    pub(in crate::analysis) fn read(
        self,
        root: &Path,
        control: &AnalysisReadControl,
        max_bytes: usize,
    ) -> Result<AnalysisReadPageV1> {
        let mut records = Vec::with_capacity(self.count);
        let mut encoded_bytes = 0_usize;
        'pages: for range in self.frozen {
            control.check()?;
            for record in range.read(root)?.0 {
                let next_bytes = encoded_bytes
                    .checked_add(record.framed_record.len())
                    .ok_or_else(|| {
                        crate::AnalysisStateSnafu {
                            path: root,
                            reason: "the evidence read page size overflowed",
                        }
                        .build()
                    })?;
                if !records.is_empty() && next_bytes > max_bytes {
                    break 'pages;
                }
                encoded_bytes = next_bytes;
                records.push(record);
            }
        }
        let next_cursor = self
            .first_cursor
            .checked_add(records.len() as u64)
            .filter(|next| *next <= self.accepted);
        control.check()?;
        Ok(AnalysisReadPageV1 {
            first_cursor: self.first_cursor,
            records,
            encoded_bytes,
            next_cursor,
            read_revision: self.revision,
        })
    }
}
