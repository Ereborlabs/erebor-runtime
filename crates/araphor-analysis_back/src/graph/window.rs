use std::collections::BTreeMap;

use super::*;
use crate::{AnalysisSourceStatusV1, EvidenceIntakeIdentityV1, GraphInvalidSnafu};

pub(super) type WindowHead = (String, GraphSnapshotV1, u64);
pub(super) type WindowHeads = BTreeMap<u64, WindowHead>;

pub(super) struct WindowRun<'a> {
    pub(super) advance: bool,
    pub(super) force: bool,
    pub(super) installed: &'a mut Option<crate::InstalledAnalysis>,
}

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
        installed: &mut Option<crate::InstalledAnalysis>,
    ) -> Result<bool> {
        let status = self.store.source_status(source)?.ok_or_else(|| {
            GraphInvalidSnafu {
                field: "source status",
            }
            .build()
        })?;
        let notice = self.provider.revision(source)?;
        let heads = self.window_heads(source, first, last)?;
        let mut run = WindowRun {
            advance,
            force,
            installed,
        };
        if let Some(changed) = self.expire_window_heads(
            &status, &heads, first, last, consumed, &mut run, now, notice,
        )? {
            return Ok(changed);
        }
        if !advance && !force {
            if let Some((id, snapshot, revision)) = heads.get(&first) {
                if self.store.graph_notice(&snapshot.scope, id, *revision)?
                    == Some((notice, status.receipt.coverage_revision))
                    && self.installed_current(id, snapshot, run.installed)?
                {
                    return Ok(false);
                }
            }
        }
        self.commit_retained_window(
            &status, &heads, first, last, consumed, &mut run, now, notice,
        )
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
            let (page, next) =
                self.store
                    .graph_window_page(source, first, last, after.as_deref())?;
            let Some(next) = next else {
                break;
            };
            after = Some(next);
            for row in page {
                heads.insert(row.1.first_cursor, row);
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
        run: &mut WindowRun<'_>,
        now: u64,
        notice: u64,
    ) -> Result<bool> {
        let read_first = first.max(status.receipt.retained_floor.saturating_add(1));
        if read_first > first && heads.contains_key(&first) {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: first,
                last_cursor: last.min(status.receipt.retained_floor),
            }
            .fail()
            .map_err(Into::into);
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
            status, heads, first, read_first, consumed, run, now, notice, records, positions,
            by_record,
        )
    }
}
