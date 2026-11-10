use super::*;



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
            let schema = crate::AnalysisStore::table_schemas()
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
            page.extraction.charge(
                sources
                    .len()
                    .checked_mul(std::mem::size_of::<super::coverage::SourceCoverage>())
                    .ok_or_else(|| Code::Limit.error("source coverage collection memory"))?,
            )?;
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
        
        {
            frame.complete = page.exhausted && page.scanned_through == frame.position();
        }
        frame.check_tables()?;
        let buffers = frame
            .datasets()
            .iter()
            .flat_map(|data| &data.batches)
            .flat_map(sdk::RecordBatch::columns)
            .map(|array| array.get_buffer_memory_size())
            .sum::<usize>();
        let bytes = frame.allocated_bytes();
        let coverage = frame
            .coverage
            .iter()
            .map(super::coverage::SourceCoverage::allocated_bytes)
            .fold(
                frame
                    .coverage
                    .capacity()
                    .saturating_mul(std::mem::size_of::<super::coverage::SourceCoverage>()),
                usize::saturating_add,
            );
        page.extraction
            .charge(bytes.saturating_sub(buffers).saturating_sub(coverage))?;
        self.bytes = self.bytes.saturating_add(bytes);
        control.check()
    }
}


