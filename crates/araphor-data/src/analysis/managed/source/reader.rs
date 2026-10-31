use super::*;

impl AnalysisStore {
    pub(in crate::analysis::managed) fn check_source_header(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        step: &Step,
        revision: u64,
    ) -> Result<()> {
        let mut statement = reader
            .prepare_cached(
                "SELECT dependency_id, commit_revision FROM managed_edges
             WHERE tenant_id = ? AND result_id = ? AND kind = 'source'",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare managed source parent",
            })?;
        let parents = statement
            .query_map(params![tenant.as_slice(), id], |row| {
                Ok(PackageResultRefV1 {
                    result_id: row.get(0)?,
                    commit_revision: row.get(1)?,
                })
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read managed source parent",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode managed source parent",
            })?;
        let expected = step
            .source
            .as_ref()
            .and_then(|source| match &source.contract.read {
                ManagedSourceRead::Initial => None,
                ManagedSourceRead::Changes(parent) => Some(&parent.result),
            });
        if !parents.iter().eq(expected) {
            return Err(Code::Invalid.error("managed source parent edge"));
        }
        let count: u64 = reader
            .query_row(
                "SELECT count(*) FROM managed_arrow WHERE result_id = ? AND role = 'source'",
                params![id],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read managed source payload count",
            })?;
        let Some(source) = &step.source else {
            if count != 0 {
                return Err(Code::Invalid.error("unexpected managed source payload"));
            }
            return Ok(());
        };
        if source
            .tables
            .iter()
            .any(|table| table.batches == 0 && table.rows != 0)
            || count
                != source
                    .tables
                    .iter()
                    .filter(|table| table.batches != 0)
                    .count() as u64
        {
            return Err(Code::Invalid.error("managed source payload count"));
        }
        let attempt = Self::managed_attempt_from(reader, tenant, &step.instance, &step.attempt)?
            .ok_or_else(|| Code::Missing.error("managed source attempt"))?;
        if attempt.capture.source.as_ref() != Some(&source.contract)
            || source.contract.position.commit_revision != attempt.capture.revision
            || source.contract.position.ordinal != u32::MAX
            || !source.contract.selection.valid()
            || source.contract.selection.tenant_id != tenant
            || attempt.capture.generation == 0
            || attempt.capture.revision >= revision
        {
            return Err(Code::Invalid.error("managed source capture contract"));
        }
        if let ManagedSourceRead::Changes(parent) = &source.contract.read {
            if parent.result.commit_revision != attempt.capture.progress
                || parent.result.commit_revision >= revision
                || parent.position.ordinal != u32::MAX
                || parent.position > source.contract.position
            {
                return Err(Code::Invalid.error("managed source captured parent"));
            }
            let (metadata, saved): (Vec<u8>, u64) = reader
                .query_row(
                    "SELECT request_meta, commit_revision FROM analysis_results
                 WHERE tenant_id = ? AND result_id = ? AND processor_id = 'managed-definition-v1'",
                    params![tenant.as_slice(), parent.result.result_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read source parent contract",
                })?;
            let prior: Step =
                ManagedCodec::decode(&metadata).context(crate::ManagedDecodingSnafu)?;
            let record = prior
                .source
                .as_ref()
                .ok_or_else(|| Code::Missing.error("managed source parent record"))?;
            let old = Self::managed_attempt_from(reader, tenant, &prior.instance, &prior.attempt)?
                .ok_or_else(|| Code::Missing.error("managed source parent attempt"))?;
            if saved != parent.result.commit_revision
                || prior.instance != step.instance
                || record.contract.position != parent.position
                || record.contract.selection != source.contract.selection
                || record.contract.tables != source.contract.tables
                || record.contract.event_ranges != source.contract.event_ranges
                || old.capture.source.as_ref() != Some(&record.contract)
                || old.capture.generation != attempt.capture.generation
                || old.capture.store != attempt.capture.store
                || old.capture.schema != attempt.capture.schema
                || old.capture.recovery != attempt.capture.recovery
                || old.terminal.is_some()
                || old.receipt.as_ref().is_none_or(|receipt| {
                    receipt.selected != parent.result
                        || receipt.commit_revision != saved
                        || receipt.attempt != prior.attempt
                })
            {
                return Err(Code::Invalid.error("managed source parent contract"));
            }
        }
        let names = source
            .contract
            .tables
            .iter()
            .filter(|(_, columns)| columns.is_some())
            .map(|(name, _)| name.as_str());
        if !names.eq(source.tables.iter().map(|table| table.name.as_str())) {
            return Err(Code::Invalid.error("managed source captured tables"));
        }
        for table in &source.tables {
            source.schema(&table.name)?;
        }
        Ok(())
    }

    pub(in crate::analysis::managed) fn capture_source(
        reader: &Connection,
        request: &ManagedRead,
        read: &AnalysisTableRead<'_>,
        selection: &AnalysisSelectionV1,
        meta: &AnalysisStoreMetaV1,
    ) -> Result<Option<SourceContract>> {
        let Some(mode) = &request.source else {
            return Ok(None);
        };
        let head = Self::managed_source_head(reader, request.expected())?;
        match (mode, read.mode) {
            (ManagedSourceRead::Initial, AnalysisReadModeV1::Complete)
                if head.is_none() || request.rebuild => {}
            (ManagedSourceRead::Changes(parent), AnalysisReadModeV1::Changes(after))
                if head.as_ref() == Some(parent) && after == parent.position =>
            {
                let (step, _, _) = Self::managed_step_header(
                    reader,
                    request.instance.spec.tenant,
                    &parent.result.result_id,
                )?;
                let (attempt, _) = Self::validate_selected_header(
                    reader,
                    request.instance.spec.tenant,
                    &parent.result.result_id,
                    &step,
                    parent.result.commit_revision,
                )?;
                if attempt.capture.store != meta.store_uuid
                    || attempt.capture.schema != meta.schema_version
                    || attempt.capture.recovery != meta.recovery_epoch
                    || attempt.capture.generation != request.instance.generation
                {
                    return Err(Code::Conflict.error("managed source store basis"));
                }
                let prior = step
                    .source
                    .ok_or_else(|| Code::Missing.error("managed source parent"))?;
                if prior.contract.tables != *read.requests
                    || prior.contract.selection != *selection
                    || prior.contract.event_ranges.as_deref() != read.event_ranges
                {
                    return Err(Code::Conflict.error("managed source capture scope"));
                }
            }
            _ => return Err(Code::Conflict.error("managed source read mode")),
        }
        if read.inputs.is_some() {
            return Err(Code::Unsupported.error("managed source model input"));
        }
        for (name, columns) in read.requests {
            let Some(columns) = columns else {
                continue;
            };
            let schema = Self::table_schemas()
                .get(name)
                .ok_or_else(|| Code::Invalid.error("managed source schema"))?;
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
                    return Err(Code::Invalid.error("managed source key projection"));
                }
            }
            for name in ["commit_revision", "ordinal", "received_utc_ns"] {
                if let Ok(index) = schema.index_of(name) {
                    if !columns.contains(&index) {
                        return Err(Code::Invalid.error("managed source position projection"));
                    }
                }
            }
        }
        Ok(Some(SourceContract {
            read: mode.clone(),
            position: StorePositionV1 {
                commit_revision: meta.commit_revision,
                ordinal: u32::MAX,
            },
            selection: selection.clone(),
            tables: read.requests.clone(),
            event_ranges: read.event_ranges.map(<[_]>::to_vec),
        }))
    }

    pub(in crate::analysis::managed) fn managed_source_head(
        reader: &Connection,
        instance: &ManagedInstance,
    ) -> Result<Option<ManagedSourceRef>> {
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
        let (step, _, revision) =
            Self::managed_step_header(reader, instance.spec.tenant, &receipt.selected.result_id)?;
        if step.instance != instance.spec.id
            || step.attempt != receipt.attempt
            || revision != instance.progress
        {
            return Err(Code::Invalid.error("committed source step"));
        }
        Ok(step.source.map(|source| ManagedSourceRef {
            result: receipt.selected,
            position: source.contract.position,
        }))
    }

    pub fn managed_source_history<E: From<crate::Error>>(
        &self,
        instance: &ManagedInstance,
        reference: &ManagedSourceRef,
        control: &AnalysisReadControl,
        mut reserve: impl FnMut(usize) -> std::result::Result<(), E>,
        mut apply: impl FnMut(ManagedSourceFrame) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E> {
        instance.validate()?;
        let mut reader = self.reader_until(control)?;
        control
            .run(&mut reader, |reader| {
                let current =
                    Self::managed_instance_from(reader, instance.spec.tenant, &instance.spec.id)?
                        .filter(|current| current == instance)
                        .ok_or_else(|| Code::Conflict.error("managed source owner"))?;
                if Self::managed_source_head(reader, &current)?.as_ref() != Some(reference) {
                    return Err(Code::Conflict.error("managed source head"));
                }
                let mut history = Vec::new();
                let meta = Self::read_meta_from(reader, &self.root.join("analysis.duckdb"))?;
                let mut next = reference.clone();
                loop {
                    control.check()?;
                    let (step, _, revision) = Self::managed_step_header(
                        reader,
                        instance.spec.tenant,
                        &next.result.result_id,
                    )?;
                    let (attempt, _) = Self::validate_selected_header(
                        reader,
                        instance.spec.tenant,
                        &next.result.result_id,
                        &step,
                        revision,
                    )?;
                    if attempt.capture.generation != instance.generation
                        || attempt.capture.store != meta.store_uuid
                        || attempt.capture.schema != meta.schema_version
                        || attempt.capture.recovery != meta.recovery_epoch
                    {
                        return Err(Code::Conflict.error("managed source store basis"));
                    }
                    let source = step
                        .source
                        .ok_or_else(|| Code::Missing.error("managed source basis"))?;
                    if step.instance != instance.spec.id
                        || revision != next.result.commit_revision
                        || source.contract.position != next.position
                    {
                        return Err(Code::Invalid.error("managed source history"));
                    }
                    let parent = match &source.contract.read {
                        ManagedSourceRead::Initial => None,
                        ManagedSourceRead::Changes(parent) => {
                            if parent.result.commit_revision >= revision
                                || parent.position > next.position
                            {
                                return Err(Code::Invalid.error("managed source parent"));
                            }
                            Some(parent.clone())
                        }
                    };
                    let scope =
                        Arc::new(SourceScope::new(&attempt.capture, source.contract.clone()));
                    history.push((
                        next.result.clone(),
                        source,
                        step.witnesses,
                        step.contexts,
                        scope,
                    ));
                    let Some(parent) = parent else {
                        break;
                    };
                    next = parent;
                }
                history.reverse();
                let mut members = BTreeSet::new();
                for (result, record, witnesses, contexts, scope) in history {
                    for metadata in &record.metadata {
                        let key = metadata.receipt.identity.key();
                        if matches!(metadata.state, ManagedSourceState::Initial { .. })
                            != !members.contains(&key)
                        {
                            return Err(Code::Invalid.error("managed source membership transition"));
                        }
                        members.insert(key);
                    }
                    let frame = match Self::managed_source_frame(
                        reader,
                        &result.result_id,
                        record,
                        scope,
                        control,
                        &mut reserve,
                    ) {
                        Ok(frame) => frame,
                        Err(error) => return Ok(Err(error)),
                    };
                    frame.commit_proof(Arc::new(ManagedSourceProof {
                        result,
                        witnesses,
                        contexts,
                    }));
                    if let Err(error) = apply(frame) {
                        return Ok(Err(error));
                    }
                    if let Err(error) = reserve(0) {
                        return Ok(Err(error));
                    }
                }
                Ok(Ok(()))
            })
            .map_err(E::from)?
    }

    fn managed_source_frame<E: From<crate::Error>>(
        reader: &Connection,
        id: &str,
        record: RecordSource,
        scope: Arc<SourceScope>,
        control: &AnalysisReadControl,
        reserve: &mut impl FnMut(usize) -> std::result::Result<(), E>,
    ) -> std::result::Result<ManagedSourceFrame, E> {
        let mut statement = reader
            .prepare_cached(
                "SELECT slot, ipc FROM managed_arrow
                 WHERE result_id = ? AND role = 'source' ORDER BY slot",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare managed source payloads",
            })?;
        let mut rows = statement
            .query(params![id])
            .context(AnalysisDatabaseSnafu {
                operation: "read managed source payloads",
            })?;
        let mut tables = Vec::with_capacity(record.tables.len());
        let mut count = 0;
        let mut held = 0usize;
        for header in &record.tables {
            control.check()?;
            if header.batches == 0 {
                if header.rows != 0 {
                    return Err(Code::Invalid.error("managed source empty table").into());
                }
                tables.push(sdk::Dataset {
                    name: header.name.clone(),
                    batches: Vec::new(),
                });
                continue;
            }
            let row = rows
                .next()
                .context(AnalysisDatabaseSnafu {
                    operation: "advance managed source payloads",
                })?
                .ok_or_else(|| Code::Missing.error("managed source payload"))?;
            let slot: usize = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode managed source slot",
            })?;
            let value = row.get_ref(1).context(AnalysisDatabaseSnafu {
                operation: "borrow managed source bytes",
            })?;
            let duckdb::types::ValueRef::Blob(bytes) = value else {
                return Err(Code::Invalid.error("managed source payload type").into());
            };
            if slot != count || bytes.is_empty() {
                return Err(Code::Invalid.error("managed source payload slot").into());
            }
            let schema = record.schema(&header.name)?;
            if sdk::wire::Dataset::batch_count_ipc(bytes).context(crate::AnalysisContractSnafu)?
                != header.batches
            {
                return Err(Code::Invalid.error("managed source IPC batch count").into());
            }
            let bound =
                sdk::wire::Dataset::decoding_bytes(bytes).context(crate::AnalysisContractSnafu)?;
            reserve(
                held.checked_add(bound)
                    .ok_or_else(|| Code::Limit.error("managed source decode bytes"))?,
            )?;
            let data = sdk::wire::Dataset::decode_ipc(&header.name, bytes, Some(&schema))
                .context(crate::AnalysisContractSnafu)?;
            held = held
                .checked_add(data.allocated_bytes())
                .ok_or_else(|| Code::Limit.error("managed source frame bytes"))?;
            reserve(held)?;
            tables.push(data);
            count += 1;
        }
        if rows
            .next()
            .context(AnalysisDatabaseSnafu {
                operation: "check managed source payload end",
            })?
            .is_some()
        {
            return Err(Code::Invalid.error("extra managed source payload").into());
        }
        record.check_tables(&tables)?;
        Ok(ManagedSourceFrame::new(record, tables, scope))
    }
}
