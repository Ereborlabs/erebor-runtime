use super::{Processor, Records};
use crate::analysis::native::{DataView, NativeStore};
use crate::{
    AnalysisGapV1, AnalysisReadControl, NativeStateSnafu, PackageErrorCodeV1 as Code,
    ProcessorClassV1, ProcessorHealthV1, ProcessorScopeV1, ProcessorStateV1, Result,
};
use snafu::ResultExt as _;

impl NativeStore {
    pub fn processor_health(&self, scope: &ProcessorScopeV1) -> Result<Option<ProcessorHealthV1>> {
        if !scope.valid() {
            return Err(Code::Invalid.error("processor health scope"));
        }
        let view = self.view()?;
        let Some((_, processor)) = Processor::read(
            scope,
            view.metadata_revision,
            |key| Records::read(key, &view.snapshot),
            &mut |_| Ok(()),
        )?
        else {
            return Ok(None);
        };
        let receipt = view.source_receipt(&scope.identity)?;
        let accepted = receipt
            .as_ref()
            .map_or(0, |receipt| receipt.contiguous_cursor);
        let effective = processor.consumed.max(processor.resumed);
        let lag = accepted.checked_sub(effective).ok_or_else(|| {
            NativeStateSnafu {
                field: "processor accepted bounds",
            }
            .build()
        })?;
        let recovery = view
            .recovery_gaps(&scope.identity, effective)?
            .into_iter()
            .next();
        let expired = view.expired_after(&scope.identity, effective)?;
        let gap = recovery.or(expired);
        let failed = scope.processor_id == crate::GRAPH_PROCESSOR
            && view.managed_graph_failed(&scope.identity)?;
        let recorded = !view
            .processor_gaps(scope, 0, &AnalysisReadControl::default(), &mut |_| Ok(()))?
            .is_empty()
            || !view.recovery_gaps(&scope.identity, 0)?.is_empty();
        let state = if processor.retirement.is_some() {
            ProcessorStateV1::Retired
        } else if failed {
            ProcessorStateV1::ProcessingFailed
        } else if let Some(gap) = recovery {
            ProcessorStateV1::RecoveryLoss(gap)
        } else if let Some(gap) = expired {
            ProcessorStateV1::ExpiredInput(gap)
        } else if receipt.is_none() {
            ProcessorStateV1::AwaitingSource
        } else if lag != 0 {
            ProcessorStateV1::Lagging
        } else {
            ProcessorStateV1::Current
        };
        Ok(Some(ProcessorHealthV1 {
            class: processor.class,
            state,
            accepted_cursor: accepted,
            consumed_cursor: processor.consumed,
            resume_floor: processor.resumed,
            cursor_lag: lag,
            incomplete: recorded || gap.is_some() || failed,
            read_revision: view.revision,
        }))
    }

    pub fn resume_optional(&self, scope: &ProcessorScopeV1) -> Result<Option<AnalysisGapV1>> {
        self.resume_optional_guarded(scope, || Ok(()))
    }

    pub fn resume_optional_guarded(
        &self,
        scope: &ProcessorScopeV1,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Option<AnalysisGapV1>> {
        if !scope.valid() {
            return Err(Code::Invalid.error("optional processor scope"));
        }
        let mut tx = self.maintenance_write()?;
        let (id, mut processor) = Processor::read(
            scope,
            tx.revision,
            |key| Records::staged(key, &tx.transaction),
            &mut |_| Ok(()),
        )?
        .filter(|(_, state)| {
            state.class == ProcessorClassV1::Optional && state.retirement.is_none()
        })
        .ok_or_else(|| crate::AnalysisConflictSnafu.build())?;
        let view = self.view()?;
        let effective = processor.consumed.max(processor.resumed);
        let first = effective.checked_add(1).ok_or_else(|| {
            NativeStateSnafu {
                field: "optional cursor exhausted",
            }
            .build()
        })?;
        let Some(expired) = view
            .expired_after(&scope.identity, effective)?
            .filter(|gap| gap.first_cursor <= first)
        else {
            check()?;
            return Ok(None);
        };
        let accepted = view
            .source_receipt(&scope.identity)?
            .ok_or_else(|| Code::Missing.error("optional source"))?
            .contiguous_cursor;
        if expired.last_cursor > accepted {
            return Err(Code::Invalid.error("optional expired gap bounds"));
        }
        let gap = AnalysisGapV1 {
            first_cursor: first,
            last_cursor: expired.last_cursor,
            commit_revision: tx.revision,
        };
        tx.stage_processor_gap(id, gap)?;
        processor.resumed = gap.last_cursor;
        processor.revision = tx.revision;
        tx.stage_processor(id, &processor)?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(crate::AnalysisCommitStage::BeforeResultCommit)?;
        check()?;
        tx.commit([])?;
        Ok(Some(gap))
    }
}

impl DataView {
    pub(in crate::analysis::native) fn expired_after(
        &self,
        source: &crate::EvidenceIntakeIdentityV1,
        after: u64,
    ) -> Result<Option<AnalysisGapV1>> {
        let events = super::super::events::Events::new(self);
        let mut gap: Option<AnalysisGapV1> = None;
        for row in events.spans(source, after.saturating_add(1), u64::MAX)? {
            let (key, value) = row.context(crate::NativeStorageSnafu {
                operation: "read expired processor spans",
            })?;
            let (first, index) = super::super::events::Events::decode_span(source, &key, &value)?;
            let entry = events.batch(index.revision)?;
            entry.check_span(source, first, &index)?;
            let span = &entry.meta.spans[index.slot];
            if span.last <= after {
                continue;
            }
            let expired = events.expiry(index.revision)?;
            if let Some(expired) = expired {
                if let Some(gap) = &mut gap {
                    if span.first > gap.last_cursor.saturating_add(1) {
                        break;
                    }
                    gap.last_cursor = gap.last_cursor.max(span.last);
                    gap.commit_revision = gap.commit_revision.max(expired.revision);
                } else {
                    gap = Some(AnalysisGapV1 {
                        first_cursor: span.first,
                        last_cursor: span.last,
                        commit_revision: expired.revision,
                    });
                }
            } else if gap.is_some() {
                break;
            }
        }
        Ok(gap)
    }
}
