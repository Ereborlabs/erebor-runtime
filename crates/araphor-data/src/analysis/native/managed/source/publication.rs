use super::*;

impl NativeStore {
    pub(in crate::analysis::native::managed) fn prepare_source(
        &self,
        input: &ManagedCommit<'_>,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<Option<PreparedSource>> {
        let Some(selection) = input
            .attempt
            .source_frame()
            .map(|frame| frame.input_selection())
            .transpose()?
            .flatten()
        else {
            return Ok(None);
        };
        let spec = &input.attempt.instance().spec;
        let view = self.view()?;
        let prior = SourceRecord::head(
            spec.tenant,
            &spec.id,
            &selection.source,
            view.metadata_revision,
            |key| Records::read(key, &view.snapshot),
            &mut |bytes| memory.charge(bytes),
        )?;
        PreparedSource::prepare(
            input.attempt,
            &selection,
            prior,
            input
                .returns
                .iter()
                .map(|returned| (returned.call, returned.evaluation)),
            memory,
        )
        .map(Some)
    }

    pub fn commit_managed_graph(
        &self,
        prepared: super::super::PreparedManagedCommit<'_>,
        packet: Option<crate::GraphCommit>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<(ManagedReceipt, Option<crate::AnalysisResultReceiptV1>)> {
        if !matches!(
            &prepared.input.attempt.instance().spec.destination,
            ManagedDestination::Graph {
                operation: ManagedGraphOperation::Evaluate,
                ..
            }
        ) {
            return Err(Code::Invalid.error("managed source publication destination"));
        }
        if packet.is_some() != prepared.source.is_some() {
            return Err(Code::Incomplete.error("managed source selection receipt"));
        }
        let cursor = prepared.source.as_ref().map(|source| source.selection.last);
        self.commit_managed_projection(prepared, |_, _, _, _| Ok(()), check)
            .map(|(receipt, ())| {
                let progress = cursor.map(|consumed_cursor| crate::AnalysisResultReceiptV1 {
                    commit_revision: receipt.commit_revision,
                    consumed_cursor,
                });
                (receipt, progress)
            })
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native::managed) fn publish_source(
        &mut self,
        input: &ManagedCommit<'_>,
        receipt: &ManagedReceipt,
        selected: u64,
        step: &Step,
        prepared: PreparedSource,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<()> {
        let spec = &input.attempt.instance().spec;
        let selection = &prepared.selection;
        if SourceRecord::head(
            spec.tenant,
            &spec.id,
            &selection.source,
            self.revision,
            |key| Records::staged(key, &self.transaction),
            &mut |bytes| memory.charge(bytes),
        )? != prepared.prior
        {
            return Err(Code::Conflict.error("native source publication parent"));
        }
        let source = step
            .source
            .as_ref()
            .ok_or_else(|| Code::Missing.error("source publication step"))?;
        let owner = Records::find(&InstanceRecord::identity(spec.tenant, &spec.id)?, |key| {
            Records::staged(key, &self.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("source publication instance"))?;
        let source_id = Records::intern(
            &mut self.transaction,
            &SourceRecord::identity(&selection.source)?,
        )?;
        let prefix = SourceRecord::key(SourceRecord::MEMBER, &[owner, source_id]);
        if !selection.append && !selection.expired {
            let old = self.store.view()?;
            for entry in old.snapshot.prefix(&prefix) {
                memory.check()?;
                let (key, _) = entry.context(crate::NativeStorageSnafu {
                    operation: "replace source membership",
                })?;
                self.transaction.remove(key);
            }
        }
        for (record, position) in &source.records {
            memory.check()?;
            let key = SourceRecord::member_key(&prefix, record);
            if selection.append && Records::staged(&key, &self.transaction)?.is_some() {
                return Err(Code::Conflict.error("native source append overlap"));
            }
            memory.charge(key.len().saturating_mul(2) + 4 * size_of::<Member>())?;
            Records::stage(
                &mut self.transaction,
                key,
                Records::named(&Member {
                    position: *position,
                    origin: selected,
                    restricted: selection.restricted.get(record).copied().unwrap_or(0),
                })?,
            );
        }
        self.source_postings(selected, step, memory)?;
        let row = SourceRecord {
            captured: input
                .attempt
                .source_frame()
                .ok_or_else(|| Code::Missing.error("source publication frame"))?
                .position(),
            coverage: prepared.coverage,
            gaps: prepared.gaps,
            count: prepared.count,
            restricted: prepared.restricted,
            append: selection.append,
        };
        Records::stage(
            &mut self.transaction,
            SourceRecord::key(SourceRecord::PREFIX, &[selected]),
            Records::named(&row)?,
        );
        self.transaction.insert(
            SourceRecord::key(SourceRecord::HEAD, &[owner, source_id]),
            selected.to_be_bytes(),
        );
        self.transaction.insert(
            SourceRecord::key(SourceRecord::WINDOW, &[source_id, source.first]),
            selected.to_be_bytes(),
        );
        let scope = crate::ProcessorScopeV1 {
            processor_id: crate::GRAPH_PROCESSOR.into(),
            method_version: u64::from(crate::GRAPH_SCHEMA_VERSION),
            identity: selection.source.clone(),
        };
        let (processor, mut state) = Processor::read(
            &scope,
            self.revision,
            |key| Records::staged(key, &self.transaction),
            &mut |bytes| memory.charge(bytes),
        )?
        .ok_or_else(|| Code::Conflict.error("native source processor head"))?;
        if state.retirement.is_some() {
            return Err(Code::Conflict.error("native source processor retirement"));
        }
        state.consumed = state.consumed.max(source.last);
        state.required = state.required.max(source.last);
        state.coverage = prepared.coverage;
        state.context = input.attempt.captured_revision();
        state.head = Some(receipt.selected.clone());
        state.revision = self.revision;
        self.stage_processor(processor, &state)?;
        for relation in [
            "managed_source_publications",
            "managed_source_members",
            "managed_source_gaps",
        ] {
            self.note_relation(relation, self.revision)?;
        }
        Ok(())
    }

    fn source_postings(
        &mut self,
        selected: u64,
        step: &Step,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<()> {
        let postings = SourceRecord::postings(
            selected,
            step,
            |key| Records::staged(key, &self.transaction),
            &mut |bytes| memory.charge(bytes),
        )?;
        for (key, value) in postings {
            self.transaction.insert(key, value);
        }
        Ok(())
    }
}
