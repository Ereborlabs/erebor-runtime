use std::collections::BTreeMap;

use super::*;
use crate::{AnalysisSourceStatusV1, EvidenceIntakeIdentityV1, GraphInvalidSnafu};

pub(super) type WindowHead = (String, GraphSnapshotV1, u64);
pub(super) type WindowHeads = BTreeMap<u64, WindowHead>;

impl GraphAndFindingOwner {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit_window(
        &self,
        source: &EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
        consumed: u64,
        advance: bool,
        now: u64,
        force: bool,
    ) -> Result<bool> {
        let status = self.store.source_status(source)?.ok_or_else(|| {
            GraphInvalidSnafu {
                field: "source status",
            }
            .build()
        })?;
        let notice = self.provider.revision(source)?;
        let heads = self.window_heads(source, first, last)?;
        if let Some(changed) = self.expire_window_heads(
            &status, &heads, first, last, consumed, advance, now, force, notice,
        )? {
            return Ok(changed);
        }
        if !advance
            && !force
            && heads.get(&first).is_some_and(|(_, snapshot, _)| {
                snapshot.context_notice_revision == notice
                    && snapshot
                        .input_manifest
                        .coverage
                        .iter()
                        .map(|key| key.report_revision)
                        .max()
                        .unwrap_or(0)
                        == status.receipt.coverage_revision
            })
        {
            return Ok(false);
        }
        self.commit_retained_window(&status, &heads, first, last, consumed, advance, now, notice)
    }

    fn window_heads(
        &self,
        source: &EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
    ) -> Result<WindowHeads> {
        let mut heads = BTreeMap::new();
        let mut after = None;
        loop {
            let page = self.store.graph_snapshots(
                source.tenant_id,
                Some(source),
                after.as_deref(),
                true,
            )?;
            if page.is_empty() {
                break;
            }
            after = page.last().map(|row| row.0.clone());
            for row in page {
                if row.1.first_cursor <= last && row.1.last_cursor >= first {
                    heads.insert(row.1.first_cursor, row);
                }
            }
        }
        Ok(heads)
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_retained_window(
        &self,
        status: &AnalysisSourceStatusV1,
        heads: &WindowHeads,
        first: u64,
        last: u64,
        consumed: u64,
        advance: bool,
        now: u64,
        notice: u64,
    ) -> Result<bool> {
        let read_first = first.max(status.receipt.retained_floor.saturating_add(1));
        if read_first > first && heads.contains_key(&first) {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: first,
                last_cursor: last.min(status.receipt.retained_floor),
            }
            .fail();
        }
        let (records, positions): (Vec<_>, Vec<_>) = self
            .read_window(status, read_first, last)?
            .into_iter()
            .map(|(record, position)| {
                let id = record.id.clone();
                (record, (id, position))
            })
            .unzip();
        let by_record = self.window_context(&records, heads)?;
        self.commit_chunks(
            status, heads, first, read_first, consumed, advance, now, notice, records, positions,
            by_record,
        )
    }
}
