use super::*;

impl NativeStore {
    pub(super) fn frozen_source_input<T>(
        &self,
        capture: &ManagedCapture,
        reference: Option<&ManagedAttempt>,
        result: &PackageResultRefV1,
        records: Option<&BTreeSet<DiscoveryRecordIdV1>>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        map: impl FnOnce(FrozenInput, &mut dyn FnMut(usize, usize) -> Result<()>) -> Result<T>,
    ) -> Result<T> {
        let source = Self::source_identity(capture)?;
        if records.is_some_and(|records| {
            records
                .iter()
                .any(|record| &record.stream != source || record.durable_cursor == 0)
        }) {
            return Err(Code::Denied.error("frozen Graph source"));
        }
        if limits
            .keys
            .is_some_and(|limit| records.is_some_and(|records| records.len() > limit))
        {
            return crate::AnalysisInputTooLargeSnafu {
                resource: "frozen Graph keys",
            }
            .fail();
        }
        self.source_reader(
            capture,
            reference,
            result,
            limits,
            control,
            |view, header, stored, owner, charge| {
                let ResultBody::Selected(step) = &stored.body else {
                    return Err(Code::Invalid.error("source result kind"));
                };
                let source_step = step
                    .source
                    .as_ref()
                    .ok_or_else(|| Code::Missing.error("source result step"))?;
                let bytes = source_step
                    .coverage
                    .iter()
                    .try_fold(0usize, |bytes, key| {
                        bytes
                            .checked_add(size_of_val(key))?
                            .checked_add(key.source.node_id.len())?
                            .checked_add(
                                key.gap_reasons
                                    .iter()
                                    .map(|reason| reason.len() + size_of::<String>())
                                    .sum::<usize>(),
                            )
                    })
                    .and_then(|bytes| {
                        bytes.checked_add(
                            header.gaps.len().checked_mul(2 * size_of::<(u64, u64)>())?,
                        )
                    })
                    .ok_or_else(|| Code::Limit.error("source manifest memory"))?;
                charge(0, bytes)?;
                let summary = crate::analysis::graph::GraphSourceSummary {
                    manifest: header.manifest(stored, source)?,
                    restricted_count: Some(header.restricted),
                    expired: step.source.as_ref().is_some_and(|source| source.expired),
                };
                if records.is_some_and(BTreeSet::is_empty) {
                    return map((summary, Vec::new(), Vec::new()), charge);
                }
                let prefix = view.source_members(owner)?;
                let members = if let Some(records) = records {
                    let mut members = Vec::new();
                    for record in records {
                        control.check()?;
                        let key = SourceRecord::member_key(&prefix, record);
                        if let Some(bytes) = Records::charged_payload(
                            &key,
                            |key| Records::read(key, &view.snapshot),
                            &mut |bytes| charge(bytes, bytes),
                        )? {
                            charge(
                                0,
                                record
                                    .allocated_bytes()
                                    .saturating_add(4 * size_of::<Member>()),
                            )?;
                            members.push((record.clone(), Records::decode::<Member>(&bytes)?));
                        }
                    }
                    members
                } else {
                    let mut members = Vec::new();
                    for entry in view.snapshot.prefix(&prefix) {
                        control.check()?;
                        let (key, _) = entry.context(crate::NativeStorageSnafu {
                            operation: "read frozen source membership",
                        })?;
                        let record = view.source_record(&prefix, &key, source)?;
                        let bytes = Records::charged_payload(
                            &key,
                            |key| Records::read(key, &view.snapshot),
                            &mut |bytes| charge(bytes, bytes),
                        )?
                        .ok_or_else(|| Code::Missing.error("source member"))?;
                        charge(
                            0,
                            record
                                .allocated_bytes()
                                .saturating_add(4 * size_of::<Member>()),
                        )?;
                        members.push((record, Records::decode::<Member>(&bytes)?));
                    }
                    if members.len() as u64 != header.count {
                        return Err(Code::Invalid.error("source membership count"));
                    }
                    members
                };
                let mut verified = crate::analysis::context::VerifiedPackages::default();
                let mut origins = BTreeMap::new();
                let mut contexts = BTreeMap::new();
                let mut proofs = BTreeMap::new();
                for (record, member) in members {
                    control.check()?;
                    if !origins.contains_key(&member.origin) {
                        let (header, result) = SourceRecord::publication(
                            member.origin,
                            view.metadata_revision,
                            |key| Records::read(key, &view.snapshot),
                            &mut |bytes| charge(bytes, bytes),
                        )?;
                        let (instance, attempt) = result.owner();
                        let producer = view
                            .managed_attempt_charged(
                                source.tenant_id,
                                instance,
                                attempt,
                                control,
                                &mut |bytes| charge(bytes, bytes),
                            )?
                            .ok_or_else(|| Code::Missing.error("source member origin"))?;
                        result.check(&producer.0, &producer.instance().spec)?;
                        if Records::find(
                            &StoredResult::identity(result.tenant, &result.id)?,
                            |key| Records::read(key, &view.snapshot),
                        )? != Some(member.origin)
                        {
                            return Err(Code::Invalid.error("source origin dictionary"));
                        }
                        if result.tenant != source.tenant_id
                            || result.owner().0 != stored.owner().0
                            || header.captured.commit_revision != producer.captured_revision()
                            || NativeStore::source_identity_owner(&producer)? != source
                            || producer
                                .receipt()
                                .and_then(|receipt| receipt.graph.as_ref())
                                != Some(&header.summary(&result)?.reference)
                        {
                            return Err(Code::Denied.error("frozen source origin owner"));
                        }
                        origins.insert(member.origin, result);
                    }
                    let ResultBody::Selected(origin) = &origins[&member.origin].body else {
                        return Err(Code::Invalid.error("source origin kind"));
                    };
                    if origin.source.as_ref().and_then(|source| {
                        source
                            .records
                            .binary_search_by(|(wanted, _)| wanted.cmp(&record))
                            .ok()
                            .map(|index| source.records[index].1)
                    }) != Some(member.position)
                    {
                        return Err(Code::Invalid.error("source member origin position"));
                    }
                    for (kind, facts) in [(SourceRecord::FACT, true), (SourceRecord::PROOF, false)]
                    {
                        let prefix = SourceRecord::member_key(
                            &SourceRecord::key(kind, &[member.origin]),
                            &record,
                        );
                        for entry in view.snapshot.prefix(&prefix) {
                            control.check()?;
                            let (key, revision) = entry.context(crate::NativeStorageSnafu {
                                operation: "read source context postings",
                            })?;
                            if key.len() != prefix.len() + 8 {
                                return Err(Code::Invalid.error("source context posting key"));
                            }
                            charge(key.len() + revision.len(), key.len() + revision.len())?;
                            let id = NativeStore::number(&key[prefix.len()..])?;
                            let bytes = Records::charged_payload(
                                &Records::key(b'C', id),
                                |key| Records::read(key, &view.snapshot),
                                &mut |bytes| charge(bytes, bytes),
                            )?
                            .ok_or_else(|| Code::Missing.error("source context posting"))?;
                            let row: ContextRecord = Records::decode(&bytes)?;
                            let reference = AnalysisContextRefV1 {
                                key: row.version.key.clone(),
                                commit_revision: NativeStore::number(&revision)?,
                            };
                            ContextRecord::check(&row, &reference.key)?;
                            let allowed = &capture.instance().grant.selection.contexts;
                            if row.revision != reference.commit_revision
                                || reference.key.tenant_id != source.tenant_id
                                || !allowed.is_all() && !allowed.as_slice().contains(&reference.key)
                            {
                                return Err(Code::Denied.error("frozen source context scope"));
                            }
                            if Records::read(
                                &References::key(References::CONTEXT, &[member.origin, id]),
                                &view.snapshot,
                            )?
                            .map(|value| NativeStore::number(&value))
                            .transpose()?
                                != Some(reference.commit_revision)
                            {
                                return Err(Code::Denied.error("frozen source context pin"));
                            }
                            if !facts
                                && !origin
                                    .proofs
                                    .iter()
                                    .any(|(wanted, proof)| wanted == &record && proof == &reference)
                            {
                                return Err(Code::Denied.error("frozen source proof association"));
                            }
                            if facts {
                                let mut failed = false;
                                let checked = verified.check_context(
                                    &row.version,
                                    |tenant, package, revision| {
                                        let mut bound = |bytes: usize| {
                                            let checked = charge(bytes, bytes.saturating_mul(12));
                                            failed |= checked.is_err();
                                            checked
                                        };
                                        let value = view.package_revision_charged(
                                            tenant, package, revision, control, &mut bound,
                                        )?;
                                        if let Some(value) = &value {
                                            bound(
                                                value
                                                    .descriptor
                                                    .len()
                                                    .saturating_add(value.artifact.len()),
                                            )?;
                                        }
                                        Ok(value)
                                    },
                                );
                                if failed {
                                    checked?;
                                } else {
                                    checked.map_err(crate::Error::stored_artifact)?;
                                }
                                let fact = DataView::fact_record(
                                    id,
                                    &row.version,
                                    |key| Records::read(key, &view.snapshot),
                                    &mut |bytes| charge(bytes, bytes),
                                )?
                                .ok_or_else(|| Code::Invalid.error("source fact posting"))?;
                                if fact.cursor != record.durable_cursor
                                    || fact.stream != record.stream.key()
                                    || fact.record
                                        != araphor_analysis_types::DomainRelations::key(&record)
                                            .context(crate::AnalysisContractSnafu)?
                                {
                                    return Err(Code::Invalid.error("source fact record"));
                                }
                                contexts.insert(reference.key.clone(), (row.version, reference));
                            } else {
                                proofs.insert(
                                    (record.clone(), reference.key.clone()),
                                    (record.clone(), reference),
                                );
                            }
                        }
                    }
                }
                map(
                    (
                        summary,
                        contexts.into_values().collect(),
                        proofs.into_values().collect(),
                    ),
                    charge,
                )
            },
        )
    }
}
