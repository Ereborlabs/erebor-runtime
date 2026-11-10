use super::*;
use crate :: analysis :: { managed :: PreparedMemory , progress :: { PreparedProfile , ProfileHeader , ProgressWrite , ResultHead } } ;
use crate :: { AnalysisContextVersionV1 , AnalysisResultCommitV1 , AnalysisResultReceiptV1 , DiscoveryProfileV1 } ;

struct ProgressBudget;

impl crate::ManagedBudget for ProgressBudget {
    fn limit(&self) -> usize {
        usize::MAX
    }
    fn check(&self) -> Result<()> {
        Ok(())
    }
    fn reserve(&self, _: usize) -> Result<Box<dyn std::any::Any + Send + Sync>> {
        Ok(Box::new(()))
    }
}

impl NativeStore {
    pub fn commit_result(&self, input: &AnalysisResultCommitV1) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id == crate::GRAPH_PROCESSOR {
            return crate::Error::reject_path(
                &self.root,
                "the graph result requires a guarded graph commit",
            );
        }
        let control = AnalysisReadControl::default();
        let budget = ProgressBudget;
        let mut memory = PreparedMemory::new(&control, &budget)?;
        let mut tx = self.maintenance_write()?;
        let output = tx.progress_rows(
            input,
            ResultHead::Unchecked,
            true,
            None,
            &[],
            None,
            &mut memory,
        )?;
        if !output.commit { return Ok(output.receipt); }
        tx.check_witnesses(input.scope.identity.tenant_id, input.created_utc_ns)?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(crate::AnalysisCommitStage::BeforeResultCommit)?;
        tx.commit([])?;
        Ok(output.receipt)
    }
}

impl DataWrite<'_> {
    pub(super) fn progress_rows(
        &mut self,
        input: &AnalysisResultCommitV1,
        expected: ResultHead<'_>,
        advance: bool,
        mut profile: Option<&mut DiscoveryProfileV1>,
        contexts: &[AnalysisContextVersionV1],
        producer: Option<&PackageResultRefV1>,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<ProgressWrite> {
        input.check(profile.as_deref(), contexts, &self.store.root)?;
        memory.check()?;
        memory.charge(
            input
                .body
                .len()
                .saturating_mul(3)
                .saturating_add(input.result_id.len().saturating_mul(4))
                .saturating_add(input.scope.processor_id.len().saturating_mul(4))
                .saturating_add(input.scope.identity.node_id.len().saturating_mul(4))
                .saturating_add(size_of::<ResultRecord>().saturating_mul(3))
                .saturating_add(
                    crate::analysis::managed::source::SourceEvidence::metadata_bytes(
                        input.witnesses.iter(),
                        input.context_refs.iter(),
                    )?,
                ),
        )?;
        let existing = ResultRecord::read(
            &input.result_id,
            self.revision,
            |key| Records::staged(key, &self.transaction),
            &mut |bytes| memory.charge(bytes),
        )?;
        if existing.is_none()
            && Records::find(&ResultRecord::identity(&input.result_id)?, |key| {
                Records::staged(key, &self.transaction)
            })?
            .is_some()
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        if input.context_revision
            != input
                .context_refs
                .iter()
                .map(|reference| reference.commit_revision)
                .max()
                .unwrap_or(0)
        {
            if existing.is_some() {
                return crate::AnalysisConflictSnafu.fail();
            }
            return crate::Error::reject_path(
                &self.store.root,
                "the result context revision differs from its captured references",
            );
        }
        let mut references = input.context_refs.clone();
        let mut inserted = Vec::new();
        for context in contexts {
            memory.check()?;
            memory.charge(
                context
                    .body
                    .len()
                    .saturating_add(context.key.allocated_bytes())
                    .saturating_mul(4)
                    .saturating_add(size_of::<AnalysisContextVersionV1>()),
            )?;
            let reference = self.context(context, None)?;
            inserted.push(reference.clone());
            references.push(reference);
        }
        references.sort_by(|left, right| left.key.cmp(&right.key));
        if references
            .windows(2)
            .any(|pair| pair[0].key == pair[1].key && pair[0] != pair[1])
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        references.dedup();
        let context_revision = references
            .iter()
            .map(|reference| reference.commit_revision)
            .max()
            .unwrap_or(0);
        let mut request = input.clone();
        request.context_refs = references;
        request.context_revision = context_revision;
        if let Some(profile) = profile.as_deref_mut().filter(|_| !contexts.is_empty()) {
            profile.context_refs = request.context_refs.clone();
            profile.validate()?;
            request.body =
                PreparedProfile::encode_charged(profile, &mut |bytes| memory.charge(bytes))?;
        }
        if let Some((_, saved)) = existing {
            if saved.request == request {
                return Ok(ProgressWrite {
                    contexts: inserted,
                    relations: Vec::new(),
                    commit: false,
                    receipt: AnalysisResultReceiptV1 {
                        commit_revision: saved.revision,
                        consumed_cursor: input.consumed_cursor,
                    },
                });
            }
            return crate::AnalysisConflictSnafu.fail();
        }
        let (owner, mut state) = Processor::read(
            &input.scope,
            self.revision,
            |key| Records::staged(key, &self.transaction),
            &mut |bytes| memory.charge(bytes),
        )?
        .ok_or_else(|| crate::AnalysisConflictSnafu.build())?;
        if state.retirement.is_some()
            || state.consumed.max(state.resumed) != input.expected_cursor
            || match expected {
                ResultHead::Current(head) => state.head.as_ref() != head,
                ResultHead::Unchecked => false,
            }
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        let view = self.store.view()?;
        let receipt = view
            .source_receipt(&input.scope.identity)?
            .ok_or_else(|| Code::Missing.error("processor source"))?;
        if input.consumed_cursor > receipt.contiguous_cursor
            || input.coverage_revision > receipt.coverage_revision
        {
            return crate::Error::reject_path(
                &self.store.root,
                "the result claims unavailable source or coverage progress",
            );
        }
        let available = self
            .store
            .raw
            .lock()
            .map_err(|_| {
                crate::NativeStateSnafu {
                    field: "raw owner lock",
                }
                .build()
            })?
            .record_count(
                &input.scope.identity.key(),
                input.expected_cursor.saturating_add(1),
                input.consumed_cursor,
                view.revision,
            );
        if let Some(profile) = profile.as_deref().filter(|_| advance) {
            let gaps = &profile.gaps[profile
                .gaps
                .partition_point(|gap| gap.last_cursor <= input.expected_cursor)..];
            if !gaps.is_empty() {
                if input.scope.processor_id != crate::DISCOVERY_PROCESSOR
                    || state.class != ProcessorClassV1::Optional
                {
                    return crate::Error::reject_path(
                        &self.store.root,
                        "only optional Discovery can consume expired input",
                    );
                }
                return crate::Error::reject_path(
                    &self.store.root,
                    "the discovery gap differs from its captured expiry",
                );
            }
        }
        if available != input.consumed_cursor - input.expected_cursor {
            return crate::Error::reject_path(
                &self.store.root,
                "the processor result skips unavailable raw input",
            );
        }
        let segments = self
            .store
            .resolve_witnesses(&input.witnesses, view.revision)?;
        for reference in &request.context_refs {
            if !self.check_context_ref(reference)? {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        let id = Records::intern(
            &mut self.transaction,
            &ResultRecord::identity(&input.result_id)?,
        )?;
        let mut body = std::mem::take(&mut request.body);
        let record = ResultRecord {
            revision: self.revision,
            header: profile
                .as_deref()
                .map(ProfileHeader::from)
                .unwrap_or_default(),
            body_bytes: body.len() as u64,
            request,
            producer: producer.cloned(),
        };
        Records::stage(
            &mut self.transaction,
            Processor::key(ResultRecord::PREFIX, id),
            Records::named(&record)?,
        );
        body.insert(0, 0);
        Records::stage(
            &mut self.transaction,
            Processor::key(ResultRecord::BODY, id),
            body,
        );
        self.stage_result_references(
            input.scope.identity.tenant_id,
            id,
            &input.witnesses,
            &record.request.context_refs,
            &[],
            producer.map(std::slice::from_ref).unwrap_or_default(),
            &[],
            (&input.witnesses, &segments),
            memory,
        )?;
        if let Some(profile) = profile.as_deref() {
            self.stage_profile_head(
                owner,
                profile,
                &PackageResultRefV1 {
                    result_id: input.result_id.clone(),
                    commit_revision: self.revision,
                },
            )?;
        }
        if advance {
            state.consumed = input.consumed_cursor;
            state.required = state.consumed;
            state.coverage = input.coverage_revision;
            state.context = context_revision;
            state.head = Some(PackageResultRefV1 {
                result_id: input.result_id.clone(),
                commit_revision: self.revision,
            });
            state.revision = self.revision;
            self.stage_processor(owner, &state)?;
        }
        self.count_revision(input.scope.identity.tenant_id, 2)?;
        self.note_relation("analysis_results", self.revision)?;
        if !input.witnesses.is_empty() {
            self.note_relation("evidence_refs", self.revision)?;
        }
        if !record.request.context_refs.is_empty() {
            self.note_relation("context_refs", self.revision)?;
        }
        Ok(ProgressWrite {
            contexts: inserted,
            relations: vec!["analysis_results"],
            commit: true,
            receipt: AnalysisResultReceiptV1 {
                commit_revision: self.revision,
                consumed_cursor: input.consumed_cursor,
            },
        })
    }
}
