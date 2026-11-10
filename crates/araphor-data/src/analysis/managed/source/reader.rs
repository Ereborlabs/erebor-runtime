use super::*;

impl AnalysisStore {
    pub(in crate::analysis::managed) fn check_managed_progress(
        reader: &Connection,
        capture: &super::super::model::Capture,
    ) -> Result<()> {
        let progress: u64 = reader.query_row(
            "SELECT COALESCE(MAX(r.commit_revision), 0) FROM managed_attempts a
             JOIN analysis_results r ON r.tenant_id = a.tenant_id AND r.commit_revision = a.completed
             WHERE a.tenant_id = ? AND a.instance_id = ? AND a.generation = ?
                AND r.processor_id = 'managed-definition-v1' AND r.commit_revision <= ?",
            params![capture.tenant.as_slice(), capture.instance, capture.expected_generation, capture.revision],
            |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "validate captured success frontier" })?;
        if capture.progress != progress
            || capture.progress > capture.completed
            || capture.completed > capture.revision
        {
            return Err(Code::Invalid.error("managed captured progress"));
        }
        Ok(())
    }

    pub(in crate::analysis) fn managed_parent_from(
        reader: &Connection,
        reference: &super::super::model::ManagedAttempt,
    ) -> Result<Option<ManagedSourceRef>> {
        let capture = &reference.0.capture;
        Self::check_managed_progress(reader, capture)?;
        if capture.progress == 0
            || capture.rebuild
            || capture.generation != capture.expected_generation
        {
            return Ok(None);
        }
        let mut instance = reference.instance().clone();
        instance.generation = capture.expected_generation;
        instance.progress = capture.progress;
        let (source, parent) = Self::managed_source_at(reader, &instance)?
            .ok_or_else(|| Code::Missing.error("managed source parent"))?;
        if parent.capture.store != capture.store
            || parent.capture.schema != capture.schema
            || parent.capture.recovery == 0
            || parent.capture.recovery > capture.recovery
            || parent.capture.grant.selection != capture.grant.selection
            || source.result.commit_revision > capture.revision
        {
            return Err(Code::Conflict.error("managed source parent basis"));
        }
        Ok(Some(source))
    }

    pub fn managed_parent(
        &self,
        reference: &super::super::model::ManagedAttempt,
        control: &AnalysisReadControl,
    ) -> Result<Option<ManagedSourceRef>> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            Self::managed_parent_from(reader, reference)
        })
    }

    pub(in crate::analysis::managed) fn capture_source(
        reader: &Connection,
        request: &ManagedRead,
        read: &AnalysisTableRead<'_>,
        selection: &AnalysisSelectionV1,
        meta: &AnalysisStoreMetaV1,
        context_owners: Option<&BTreeSet<String>>,
    ) -> Result<Option<Arc<ManagedSourceFrame>>> {
        let Some(mode) = &request.source else {
            return Ok(None);
        };
        let head = Self::managed_source_head(reader, request.expected())?;
        match (mode, read.mode) {
            (ManagedSourceRead::Initial, AnalysisReadModeV1::Complete)
                if head.is_none()
                    || request.rebuild
                    || request.instance.generation != request.expected().generation => {}
            (ManagedSourceRead::Changes(parent), AnalysisReadModeV1::Changes(after))
                if head.as_ref() == Some(parent) && after == parent.position =>
            {
                let (step, _) = Self::managed_step_header(
                    reader,
                    request.instance.spec.tenant,
                    &parent.result.result_id,
                )?;
                let attempt = Self::managed_attempt_from(
                    reader,
                    request.instance.spec.tenant,
                    &step.instance,
                    &step.attempt,
                )?
                .ok_or_else(|| Code::Missing.error("managed source parent attempt"))?;
                if attempt.terminal.is_some()
                    || attempt.receipt.as_ref().is_none_or(|receipt| {
                        receipt.selected != parent.result
                            || receipt.commit_revision != parent.result.commit_revision
                            || receipt.instance != step.instance
                            || receipt.attempt != step.attempt
                    })
                {
                    return Err(Code::Conflict.error("managed source parent receipt"));
                }
                if attempt.capture.store != meta.store_uuid
                    || attempt.capture.schema != meta.schema_version
                    || attempt.capture.recovery == 0
                    || attempt.capture.recovery > meta.recovery_epoch
                    || attempt.capture.generation != request.instance.generation
                {
                    return Err(Code::Conflict.error("managed source store basis"));
                }
            }
            _ => return Err(Code::Conflict.error("managed source read mode")),
        }
        SourceScope::capture(
            &request.instance,
            meta,
            mode.clone(),
            read,
            selection,
            context_owners,
        )?
        .map(Some)
        .ok_or_else(|| Code::Unsupported.error("managed source projection"))
    }
}

impl SourceScope {
    pub(in crate::analysis) fn capture(
        instance: &ManagedInstance,
        meta: &AnalysisStoreMetaV1,
        mode: ManagedSourceRead,
        read: &AnalysisTableRead<'_>,
        selection: &AnalysisSelectionV1,
        context_owners: Option<&BTreeSet<String>>,
    ) -> Result<Option<Arc<ManagedSourceFrame>>> {
        for (name, columns) in read.requests {
            let Some(columns) = columns else {
                continue;
            };
            let schema = AnalysisStore::table_schemas()
                .get(name)
                .ok_or_else(|| Code::Invalid.error("managed source schema"))?;
            if AnalysisTableRead::source_header(name) {
                schema
                    .project(&columns.iter().copied().collect::<Vec<_>>())
                    .context(crate::PackageArrowSnafu)?;
                continue;
            }
            if !AnalysisTableRead::source_rows(name) {
                return Ok(None);
            }
            let field = schema
                .fields()
                .first()
                .ok_or_else(|| Code::Invalid.error("managed source fields"))?;
            let keys = field
                .metadata()
                .get("araphor.join_keys")
                .ok_or_else(|| Code::Invalid.error("managed source keys"))?;
            for key in keys.split(',') {
                if !columns.contains(&schema.index_of(key).context(crate::PackageArrowSnafu)?) {
                    return Ok(None);
                }
            }
            for name in ["commit_revision", "ordinal", "received_utc_ns"] {
                if let Ok(index) = schema.index_of(name) {
                    if !columns.contains(&index) {
                        return Ok(None);
                    }
                }
            }
        }
        let scope = Arc::new(Self {
            tenant: instance.spec.tenant,
            instance: instance.spec.id.clone(),
            generation: instance.generation,
            store: meta.store_uuid,
            schema: meta.schema_version,
            recovery: meta.recovery_epoch,
            read: mode,
            position: StorePositionV1 {
                commit_revision: meta.commit_revision,
                ordinal: u32::MAX,
            },
            selection: selection.clone(),
            tables: read.requests.clone(),
            event_ranges: read.event_ranges.map(<[_]>::to_vec),
            context_owners: context_owners.cloned(),
        });
        Ok(Some(Arc::new(ManagedSourceFrame::new(
            Vec::new(),
            BTreeMap::new(),
            scope,
        ))))
    }
}

impl ManagedSourceFrame {
    pub fn check_before(&self, reference: &super::super::model::ManagedAttempt) -> Result<()> {
        let ManagedSourceRead::Changes(parent) = self.read() else {
            return Err(Code::Conflict.error("managed before parent"));
        };
        self.check_point(reference, parent)
    }

    pub fn check_point(
        &self,
        reference: &super::super::model::ManagedAttempt,
        parent: &ManagedSourceRef,
    ) -> Result<()> {
        let capture = &reference.0.capture;
        if reference
            .receipt()
            .is_none_or(|receipt| receipt.selected != parent.result)
            || parent.position
                != (StorePositionV1 {
                    commit_revision: capture.revision,
                    ordinal: u32::MAX,
                })
            || self.scope.tenant != capture.tenant
            || self.scope.instance != capture.instance
            || self.scope.generation != capture.generation
            || self.scope.store != capture.store
            || self.scope.schema != capture.schema
            || capture.recovery == 0
            || capture.recovery > self.scope.recovery
        {
            return Err(Code::Conflict.error("managed before owner"));
        }
        Ok(())
    }
}

impl super::super::model::ManagedCapture {
    pub(in crate::analysis) fn seal_source(
        &mut self,
        page: &mut crate::AnalysisPositionPageV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let Some(source) = self.source.as_mut() else {
            return Ok(());
        };
        let frame =
            Arc::get_mut(source).ok_or_else(|| Code::Conflict.error("shared source capture"))?;
        let mut sources = std::mem::take(&mut page.extraction.sources);
        let coverage = (|| {
            page.extraction.charge(sources.len().checked_mul(std::mem::size_of::<super::coverage::SourceCoverage>())
                .ok_or_else(|| Code::Limit.error("source coverage collection memory"))?)?;
            let mut coverage = Vec::with_capacity(sources.len());
            for source in &mut sources {
                control.check()?;
                if source.commit_revision > frame.scope.position.commit_revision {
                    return Err(Code::Invalid.error("source coverage captured cut"));
                }
                let value = super::coverage::SourceCoverage::capture(source, &mut |bytes| {
                    control.check()?;
                    page.extraction.charge(bytes)
                })?;
                coverage.push(value);
            }
            Ok(coverage)
        })();
        page.extraction.sources = sources;
        frame.coverage = coverage?;
        frame.tables = frame
            .scope
            .tables
            .iter()
            .filter(|(_, columns)| columns.is_some())
            .map(|(name, _)| sdk::Dataset {
                name: name.clone(),
                batches: page.tables.get(name).cloned().unwrap_or_default(),
            })
            .collect();
        frame.removals = page.removals.clone();
        frame.check_tables()?;
        let buffers = frame
            .datasets()
            .iter()
            .flat_map(|data| &data.batches)
            .flat_map(sdk::RecordBatch::columns)
            .map(|array| array.get_buffer_memory_size())
            .sum::<usize>();
        let bytes = frame.allocated_bytes();
        let coverage = frame.coverage.iter().map(super::coverage::SourceCoverage::allocated_bytes)
            .fold(frame.coverage.capacity().saturating_mul(std::mem::size_of::<super::coverage::SourceCoverage>()), usize::saturating_add);
        page.extraction.charge(bytes.saturating_sub(buffers).saturating_sub(coverage))?;
        self.bytes = self.bytes.saturating_add(bytes);
        control.check()
    }
}

impl AnalysisStore {
    pub(in crate::analysis::managed) fn managed_source_head(
        reader: &Connection,
        instance: &ManagedInstance,
    ) -> Result<Option<ManagedSourceRef>> {
        Ok(Self::managed_source_at(reader, instance)?.map(|(source, _)| source))
    }

    fn managed_source_at(
        reader: &Connection,
        instance: &ManagedInstance,
    ) -> Result<Option<(ManagedSourceRef, Attempt)>> {
        if instance.progress == 0 {
            return Ok(None);
        }
        let bytes: Vec<u8> = reader
            .query_row(
                "SELECT contract FROM managed_attempts
                 WHERE tenant_id = ? AND instance_id = ? AND completed = ?",
                params![
                    instance.spec.tenant.as_slice(),
                    instance.spec.id,
                    instance.progress
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read committed source head",
            })?;
        let attempt: Attempt = ManagedCodec::decode(&bytes).context(crate::ManagedDecodingSnafu)?;
        let receipt = attempt
            .receipt
            .as_ref()
            .filter(|receipt| {
                receipt.instance == instance.spec.id
                    && receipt.attempt == attempt.request.id
                    && receipt.commit_revision == instance.progress
                    && receipt.selected.commit_revision == instance.progress
                    && attempt.capture.tenant == instance.spec.tenant
                    && attempt.capture.instance == instance.spec.id
                    && attempt.capture.generation == instance.generation
                    && attempt.terminal.is_none()
            })
            .ok_or_else(|| Code::Invalid.error("committed source receipt"))?;
        let (step, revision) =
            Self::managed_step_header(reader, instance.spec.tenant, &receipt.selected.result_id)?;
        if step.instance != instance.spec.id
            || step.attempt != receipt.attempt
            || revision != instance.progress
        {
            return Err(Code::Invalid.error("committed source step"));
        }
        if attempt.capture.revision >= attempt.registered || attempt.registered >= revision {
            return Err(Code::Invalid.error("committed source position"));
        }
        let source = ManagedSourceRef {
            result: receipt.selected.clone(),
            position: StorePositionV1 {
                commit_revision: attempt.capture.revision,
                ordinal: u32::MAX,
            },
        };
        Ok(Some((source, attempt)))
    }
}
