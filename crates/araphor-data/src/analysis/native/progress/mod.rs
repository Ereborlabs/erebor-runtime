use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{records::Records, DataView, DataWrite, NativeStore};
use crate::analysis::PackageResultRefV1;
use crate::{
    AnalysisGapV1, AnalysisReadControl, PackageErrorCodeV1 as Code, ProcessorClassV1,
    ProcessorRetirementV1, ProcessorScopeV1, Result,
};

mod commit;
mod coverage;
mod health;
mod inputs;
mod notices;
pub(super) mod profile;
mod recovery;
mod result;
pub(super) use result::ResultRecord;

#[derive(Deserialize, PartialEq, Serialize)]
pub(super) struct Processor {
    pub scope: ProcessorScopeV1,
    pub class: ProcessorClassV1,
    pub start: u64,
    pub consumed: u64,
    pub resumed: u64,
    pub coverage: u64,
    pub context: u64,
    pub required: u64,
    pub head: Option<PackageResultRefV1>,
    pub retirement: Option<(ProcessorRetirementV1, u64)>,
    pub revision: u64,
}

impl Processor {
    pub(super) const PREFIX: &'static [u8] = b"\0data/@progress/state/";
    pub(super) const GAPS: &'static [u8] = b"\0data/@progress/gap/";

    pub(super) fn identity(scope: &ProcessorScopeV1) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(b"processor".as_slice(), scope)).context(crate::ManagedEncodingSnafu)
    }

    pub(super) fn key(prefix: &[u8], owner: u64) -> Vec<u8> {
        [prefix, &owner.to_be_bytes()].concat()
    }

    pub(super) fn read(
        scope: &ProcessorScopeV1,
        head: u64,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<(u64, Self)>> {
        let Some(id) = Records::find(&Self::identity(scope)?, &mut get)? else {
            return Ok(None);
        };
        let Some(bytes) = Records::charged_payload(&Self::key(Self::PREFIX, id), get, charge)?
        else {
            return Ok(None);
        };
        let state: Self = Records::decode(&bytes)?;
        if state.scope != *scope
            || !state.scope.valid()
            || state.start == 0
            || state.start - 1 > state.consumed
            || state.required != state.consumed
            || state.revision == 0
            || state.revision > head
            || state.context > state.revision
            || state.head.as_ref().is_some_and(|result| {
                result.result_id.is_empty()
                    || result.commit_revision == 0
                    || result.commit_revision > state.revision
            })
            || state
                .retirement
                .as_ref()
                .is_some_and(|(request, revision)| {
                    !request.valid()
                        || request.scope != state.scope
                        || request.expected_cursor != state.consumed
                        || state.class != ProcessorClassV1::Required
                        || *revision == 0
                        || *revision > state.revision
                })
        {
            return Err(Code::Invalid.error("processor state"));
        }
        Ok(Some((id, state)))
    }
}

impl NativeStore {
    pub fn discovery_enabled(&self) -> bool {
        self.discovery_owners
            .load(std::sync::atomic::Ordering::Acquire)
            > 0
    }

    pub fn register_discovery_owner(&self) {
        if self
            .discovery_owners
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            == 0
        {
            self.controls.send_replace(());
        }
    }

    pub fn release_discovery_owner(&self) {
        if self
            .discovery_owners
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.controls.send_replace(());
        }
    }

    pub fn register_processor(
        &self,
        scope: &ProcessorScopeV1,
        class: ProcessorClassV1,
        start: u64,
    ) -> Result<u64> {
        self.register_processor_guarded(scope, class, start, || Ok(()))
    }

    pub fn register_processor_guarded(
        &self,
        scope: &ProcessorScopeV1,
        class: ProcessorClassV1,
        start: u64,
        check: impl FnMut() -> Result<()>,
    ) -> Result<u64> {
        self.register_processor_with(scope, class, start, false, check)
    }

    pub fn ensure_optional_processor_guarded(
        &self,
        scope: &ProcessorScopeV1,
        check: impl FnMut() -> Result<()>,
    ) -> Result<u64> {
        self.register_processor_with(scope, ProcessorClassV1::Optional, 1, true, check)
    }

    fn register_processor_with(
        &self,
        scope: &ProcessorScopeV1,
        class: ProcessorClassV1,
        start: u64,
        keep: bool,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<u64> {
        if !scope.valid() || start == 0 {
            return crate::Error::reject_path(
                &self.root,
                "the processor scope or start cursor is invalid",
            );
        }
        let mut tx = self.write()?;
        if let Some((_, state)) = Processor::read(
            scope,
            tx.revision,
            |key| Records::staged(key, &tx.transaction),
            &mut |_| Ok(()),
        )? {
            if state.retirement.is_some() || !keep && (state.class != class || state.start != start)
            {
                return crate::AnalysisConflictSnafu.fail();
            }
            check()?;
            return Ok(self.view()?.revision);
        }
        let view = self.view()?;
        let receipt = view.source_receipt(&scope.identity)?;
        if receipt.as_ref().is_some_and(|receipt| {
            start <= receipt.retained_floor && !(class == ProcessorClassV1::Optional && start == 1)
                || start > receipt.contiguous_cursor.saturating_add(1)
        }) || receipt.is_none() && start != 1
        {
            return crate::Error::reject_path(
                &self.root,
                "the processor start is outside retained source input",
            );
        }
        let id = Records::intern(&mut tx.transaction, &Processor::identity(scope)?)?;
        let state = Processor {
            scope: scope.clone(),
            class,
            start,
            consumed: start - 1,
            resumed: start - 1,
            coverage: 0,
            context: 0,
            required: start - 1,
            head: None,
            retirement: None,
            revision: tx.revision,
        };
        tx.stage_processor(id, &state)?;
        let revision = tx.revision;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(crate::AnalysisCommitStage::BeforeResultCommit)?;
        check()?;
        tx.commit([])?;
        Ok(revision)
    }

    pub fn processor_gaps(
        &self,
        scope: &ProcessorScopeV1,
        after: u64,
    ) -> Result<Vec<AnalysisGapV1>> {
        self.view()?
            .processor_gaps(scope, after, &AnalysisReadControl::default(), &mut |_| {
                Ok(())
            })
    }

    pub fn processor_retirement(
        &self,
        scope: &ProcessorScopeV1,
    ) -> Result<Option<(ProcessorRetirementV1, u64)>> {
        if !scope.valid() {
            return Err(Code::Invalid.error("processor scope"));
        }
        let view = self.view()?;
        Ok(Processor::read(
            scope,
            view.revision,
            |key| Records::read(key, &view.snapshot),
            &mut |_| Ok(()),
        )?
        .and_then(|(_, state)| state.retirement))
    }

    pub fn retire_required(&self, request: &ProcessorRetirementV1) -> Result<u64> {
        if !request.valid() {
            return crate::Error::reject_path(
                &self.root,
                "the processor retirement request is invalid",
            );
        }
        let mut tx = self.maintenance_write()?;
        let (id, mut state) = Processor::read(
            &request.scope,
            tx.revision,
            |key| Records::staged(key, &tx.transaction),
            &mut |_| Ok(()),
        )?
        .ok_or_else(|| crate::AnalysisConflictSnafu.build())?;
        if state.class != ProcessorClassV1::Required || state.consumed != request.expected_cursor {
            return crate::AnalysisConflictSnafu.fail();
        }
        if let Some((prior, revision)) = state.retirement {
            return if prior == *request {
                Ok(revision)
            } else {
                crate::AnalysisConflictSnafu.fail()
            };
        }
        let accepted = self
            .view()?
            .source_receipt(&request.scope.identity)?
            .map_or(0, |receipt| receipt.contiguous_cursor);
        if accepted != request.cutoff_cursor {
            return crate::AnalysisConflictSnafu.fail();
        }
        if state.consumed < accepted {
            tx.stage_processor_gap(
                id,
                AnalysisGapV1 {
                    first_cursor: state.consumed + 1,
                    last_cursor: accepted,
                    commit_revision: tx.revision,
                },
            )?;
        }
        let revision = tx.revision;
        state.retirement = Some((request.clone(), revision));
        state.revision = revision;
        tx.stage_processor(id, &state)?;
        tx.commit([])?;
        Ok(revision)
    }
}

impl DataWrite<'_> {
    pub(super) fn stage_processor(&mut self, id: u64, state: &Processor) -> Result<()> {
        Records::stage(
            &mut self.transaction,
            Processor::key(Processor::PREFIX, id),
            Records::named(state)?,
        );
        if self.store.retention.raw_max_age_ns.is_some()
            || self.store.retention.raw_max_bytes.is_some()
        {
            self.processors.insert(
                id,
                (
                    state.scope.identity.clone(),
                    (state.class == ProcessorClassV1::Required && state.retirement.is_none())
                        .then_some(state.consumed),
                ),
            );
        }
        self.note_relation("processor_progress", self.revision)
    }

    pub(super) fn stage_processor_gap(&mut self, id: u64, gap: AnalysisGapV1) -> Result<()> {
        let key = [
            Processor::key(Processor::GAPS, id),
            gap.first_cursor.to_be_bytes().to_vec(),
            gap.last_cursor.to_be_bytes().to_vec(),
        ]
        .concat();
        Records::stage(&mut self.transaction, key, Records::named(&gap)?);
        self.note_relation("processor_gaps", self.revision)
    }
}

impl DataView {
    pub(super) fn processor_gaps(
        &self,
        scope: &ProcessorScopeV1,
        after: u64,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Vec<AnalysisGapV1>> {
        if !scope.valid() {
            return Err(Code::Invalid.error("processor scope"));
        }
        let Some(id) = Records::find(&Processor::identity(scope)?, |key| {
            Records::read(key, &self.snapshot)
        })?
        else {
            return Ok(Vec::new());
        };
        let prefix = Processor::key(Processor::GAPS, id);
        let mut gaps = Vec::new();
        for row in self.snapshot.prefix(&prefix) {
            control.check()?;
            let (key, value) = row.context(crate::NativeStorageSnafu {
                operation: "read processor gaps",
            })?;
            if key.len() != prefix.len() + 16 {
                return Err(Code::Invalid.error("processor gap key"));
            }
            if NativeStore::number(&key[key.len() - 8..])? <= after {
                continue;
            }
            charge(value.len().saturating_mul(2) + size_of::<AnalysisGapV1>())?;
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| Code::Missing.error("processor gap"))?;
            let gap: AnalysisGapV1 = Records::decode(&bytes)?;
            if gap.first_cursor == 0
                || gap.last_cursor < gap.first_cursor
                || gap.commit_revision == 0
                || gap.commit_revision > self.revision
                || NativeStore::number(&key[prefix.len()..prefix.len() + 8])? != gap.first_cursor
                || NativeStore::number(&key[prefix.len() + 8..])? != gap.last_cursor
            {
                return Err(Code::Invalid.error("processor gap"));
            }
            gaps.push(gap);
        }
        Ok(gaps)
    }
}
