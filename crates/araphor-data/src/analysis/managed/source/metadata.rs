use std::ops::Bound;

use super::*;
use crate::analysis::raw::RawIdentity;
use crate::AnalysisPositionPageV1;

impl AnalysisStore {
    pub(in crate::analysis) fn seal_source(
        &self,
        reader: &Connection,
        capture: &mut super::super::model::ManagedCapture,
        page: &mut AnalysisPositionPageV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let Some(contract) = &capture.contract.source else {
            return Ok(());
        };
        let mut members = match &contract.read {
            ManagedSourceRead::Initial => Arc::default(),
            ManagedSourceRead::Changes(parent) => capture
                .execution
                .as_ref()
                .and_then(|execution| {
                    execution.source_members(&capture.instance, &page.extraction.meta, parent)
                })
                .map_or_else(
                    || {
                        Self::source_members_from(
                            reader,
                            capture.instance.spec.tenant,
                            parent,
                            control,
                        )
                    },
                    Ok,
                )?,
        };
        let metadata = self.source_metadata(reader, contract, page, &members, control)?;
        for source in &metadata {
            let key = source.receipt.identity.key();
            if !members.contains(&key) {
                Arc::make_mut(&mut members).insert(key);
            }
        }
        let tables = contract
            .tables
            .iter()
            .filter(|(_, columns)| columns.is_some())
            .map(|(name, _)| sdk::Dataset {
                name: name.clone(),
                batches: page.tables.get(name).cloned().unwrap_or_default(),
            })
            .collect::<Vec<_>>();
        let record = RecordSource {
            contract: contract.clone(),
            tables: tables
                .iter()
                .map(|data| RecordInput {
                    name: data.name.clone(),
                    rows: data.rows(),
                    batches: data.batches.len(),
                })
                .collect(),
            removals: page.removals.clone(),
            metadata,
            support: Vec::new(),
        };
        record.check_tables(&tables)?;
        let source = SourceCapture {
            frame: Arc::new(ManagedSourceFrame::new(
                record,
                tables,
                Arc::new(SourceScope::new(&capture.contract, contract.clone())),
            )),
            members,
        };
        let buffers = source
            .frame
            .datasets()
            .iter()
            .flat_map(|data| &data.batches)
            .flat_map(sdk::RecordBatch::columns)
            .map(|array| array.get_buffer_memory_size())
            .sum::<usize>();
        let bytes = source.allocated_bytes();
        page.extraction.charge(bytes.saturating_sub(buffers))?;
        capture.bytes = capture.bytes.saturating_add(bytes);
        capture.source = Some(source);
        Ok(())
    }

    fn source_metadata(
        &self,
        reader: &Connection,
        contract: &SourceContract,
        page: &AnalysisPositionPageV1,
        members: &BTreeSet<Vec<u8>>,
        control: &AnalysisReadControl,
    ) -> Result<Vec<ManagedSourceMetadata>> {
        if matches!(contract.read, ManagedSourceRead::Initial) {
            let mut metadata = page
                .extraction
                .sources
                .iter()
                .map(|source| {
                    Ok(ManagedSourceMetadata {
                        receipt: source.receipt.clone(),
                        state: ManagedSourceState::Initial {
                            high: self.source_high(
                                &source.receipt,
                                contract.position.commit_revision,
                                control,
                            )?,
                            pending: source.pending.clone(),
                        },
                        expired: source.expired.clone(),
                        recovery: source.recovery.clone(),
                        coverage: (source.receipt.coverage_revision != 0)
                            .then(|| {
                                Self::source_report_ref(
                                    reader,
                                    &source.receipt,
                                    contract.position.commit_revision,
                                )
                            })
                            .transpose()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            metadata.sort_by_cached_key(|source| source.receipt.identity.key());
            return Ok(metadata);
        }
        let after = contract
            .read
            .after()
            .map_or(0, |position| position.commit_revision);
        let through = contract.position.commit_revision;
        let mut changed = BTreeMap::<Vec<u8>, Vec<AnalysisGapV1>>::new();
        {
            let raw = self.raw.until(control)?;
            for (_, entry) in raw
                .entries
                .range((Bound::Excluded(after), Bound::Included(through)))
            {
                control.check()?;
                let RawIdentity::Evidence(source) = &entry.identity else {
                    continue;
                };
                if !contract.selection.includes_source(source) {
                    continue;
                }
                let accepted = changed.entry(source.key()).or_default();
                accepted.extend(entry.commit.spans.iter().map(|span| AnalysisGapV1 {
                    first_cursor: span.first,
                    last_cursor: span.last,
                    commit_revision: entry.commit.revision,
                }));
            }
        }
        let mut reports = BTreeMap::new();
        for report in
            self.coverage_changes_from(reader, &contract.selection, after, through, control)?
        {
            let key = report.reference.source.key();
            changed.entry(key.clone()).or_default();
            reports.insert(key, report.reference);
        }
        let mut expired = self.source_gap_changes(reader, contract, false, control)?;
        let mut recovery = self.source_gap_changes(reader, contract, true, control)?;
        for key in expired.keys().chain(recovery.keys()) {
            changed.entry(key.clone()).or_default();
        }
        let mut metadata = Vec::new();
        for (key, accepted) in changed {
            control.check()?;
            let identity = self
                .raw
                .until(control)?
                .sources
                .get(&key)
                .and_then(|source| source.receipt.evidence())
                .map(|source| (source.identity.clone(), source.cpu_id));
            let Some((identity, cpu)) = identity else {
                if accepted.is_empty() && !reports.contains_key(&key) {
                    continue;
                }
                return Err(Code::Missing.error("managed source identity"));
            };
            if !contract.selection.includes_source(&identity) {
                continue;
            }
            let receipt = Self::source_receipt_from(reader, identity, cpu)?;
            let Some(receipt) = receipt else {
                if accepted.is_empty() && !reports.contains_key(&key) {
                    continue;
                }
                return Err(Code::Missing.error("managed source receipt"));
            };
            let initial = !members.contains(&key);
            let mut output = ManagedSourceMetadata {
                receipt,
                state: ManagedSourceState::Changes { accepted },
                expired: expired.remove(&key).unwrap_or_default(),
                recovery: recovery.remove(&key).unwrap_or_default(),
                coverage: reports.remove(&key),
            };
            if initial {
                output.expired =
                    self.source_gaps_for(reader, &output.receipt, false, through, control)?;
                output.recovery =
                    self.source_gaps_for(reader, &output.receipt, true, through, control)?;
                output.state = ManagedSourceState::Initial {
                    high: self.source_high(&output.receipt, through, control)?,
                    pending: self.raw.until(control)?.pending_gaps(
                        &output.receipt,
                        through,
                        control,
                    )?,
                };
                if output.coverage.is_none() && output.receipt.coverage_revision != 0 {
                    output.coverage =
                        Some(Self::source_report_ref(reader, &output.receipt, through)?);
                }
            }
            if output
                .expired
                .iter()
                .any(|range| range.last_cursor > output.receipt.contiguous_cursor)
            {
                return Err(Code::Invalid.error("managed source retirement frontier"));
            }
            metadata.push(output);
        }
        Ok(metadata)
    }

    fn source_high(
        &self,
        receipt: &AnalysisSourceReceiptV1,
        through: u64,
        control: &AnalysisReadControl,
    ) -> Result<u64> {
        let key = receipt.identity.key();
        let raw = self.raw.until(control)?;
        for (_, (revision, index)) in raw.ranges.range((key.clone(), 0)..=(key, u64::MAX)).rev() {
            control.check()?;
            if *revision <= through {
                return Ok(receipt
                    .contiguous_cursor
                    .max(raw.entries[revision].commit.spans[*index].last));
            }
        }
        Ok(receipt.contiguous_cursor)
    }

    fn source_gap_changes(
        &self,
        reader: &Connection,
        contract: &SourceContract,
        recovery: bool,
        control: &AnalysisReadControl,
    ) -> Result<BTreeMap<Vec<u8>, Vec<AnalysisGapV1>>> {
        let sql = if recovery {
            "SELECT stream_key, tenant_id, first_cursor, last_cursor, commit_revision
             FROM recovery_gaps WHERE commit_revision > ? ORDER BY commit_revision, first_cursor"
        } else {
            "SELECT stream_key, tenant_id, first_cursor, last_cursor, commit_revision
             FROM expired_ranges WHERE commit_revision > ? ORDER BY commit_revision, first_cursor"
        };
        let mut statement = reader.prepare_cached(sql).context(AnalysisDatabaseSnafu {
            operation: "prepare managed source gap changes",
        })?;
        let after = contract
            .read
            .after()
            .map_or(0, |position| position.commit_revision);
        let mut rows = statement
            .query(params![after])
            .context(AnalysisDatabaseSnafu {
                operation: "read managed source gap changes",
            })?;
        let mut gaps = BTreeMap::<Vec<u8>, Vec<AnalysisGapV1>>::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance managed source gap changes",
        })? {
            control.check()?;
            let tenant: Vec<u8> = row.get(1).context(AnalysisDatabaseSnafu {
                operation: "decode managed source gap tenant",
            })?;
            if tenant != contract.selection.tenant_id {
                continue;
            }
            let key: Vec<u8> = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode managed source gap key",
            })?;
            let source = self
                .raw
                .until(control)?
                .sources
                .get(&key)
                .and_then(|source| source.receipt.evidence())
                .map(|source| source.identity.clone());
            if source
                .as_ref()
                .is_none_or(|source| !contract.selection.includes_source(source))
            {
                continue;
            }
            let gap = AnalysisGapV1 {
                first_cursor: row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "decode managed source gap start",
                })?,
                last_cursor: row.get(3).context(AnalysisDatabaseSnafu {
                    operation: "decode managed source gap end",
                })?,
                commit_revision: row.get(4).context(AnalysisDatabaseSnafu {
                    operation: "decode managed source gap revision",
                })?,
            };
            if gap.first_cursor == 0
                || gap.last_cursor < gap.first_cursor
                || gap.commit_revision <= after
                || gap.commit_revision > contract.position.commit_revision
            {
                return Err(Code::Invalid.error("managed source gap interval"));
            }
            gaps.entry(key).or_default().push(gap);
        }
        Ok(gaps)
    }

    fn source_gaps_for(
        &self,
        reader: &Connection,
        receipt: &AnalysisSourceReceiptV1,
        recovery: bool,
        through: u64,
        control: &AnalysisReadControl,
    ) -> Result<Vec<AnalysisGapV1>> {
        let sql = if recovery {
            "SELECT first_cursor, last_cursor, commit_revision, tenant_id
             FROM recovery_gaps WHERE stream_key = ? ORDER BY first_cursor"
        } else {
            "SELECT first_cursor, last_cursor, commit_revision, tenant_id
             FROM expired_ranges WHERE stream_key = ? ORDER BY first_cursor"
        };
        let mut statement = reader.prepare_cached(sql).context(AnalysisDatabaseSnafu {
            operation: "prepare initial source gaps",
        })?;
        let rows = statement
            .query_map(params![receipt.identity.key()], |row| {
                Ok((
                    AnalysisGapV1 {
                        first_cursor: row.get(0)?,
                        last_cursor: row.get(1)?,
                        commit_revision: row.get(2)?,
                    },
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read initial source gaps",
            })?;
        let mut gaps = Vec::new();
        for row in rows {
            control.check()?;
            let (gap, tenant) = row.context(AnalysisDatabaseSnafu {
                operation: "decode initial source gap",
            })?;
            if tenant != receipt.identity.tenant_id
                || gap.first_cursor == 0
                || gap.last_cursor < gap.first_cursor
                || gap.commit_revision == 0
                || gap.commit_revision > through
            {
                return Err(Code::Invalid.error("initial source gap"));
            }
            gaps.push(gap);
        }
        Ok(gaps)
    }

    fn source_report_ref(
        reader: &Connection,
        receipt: &AnalysisSourceReceiptV1,
        through: u64,
    ) -> Result<CoverageReportRef> {
        let (revision, commit_revision, ordinal, tenant): (u64, u64, u32, Vec<u8>) = reader
            .query_row(
                "SELECT revision, commit_revision, ordinal, tenant_id FROM coverage
             WHERE stream_key = ? ORDER BY revision DESC LIMIT 1",
                params![receipt.identity.key()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read initial source coverage reference",
            })?;
        if tenant != receipt.identity.tenant_id
            || revision != receipt.coverage_revision
            || commit_revision == 0
            || commit_revision > through
            || ordinal != 0
        {
            return Err(Code::Invalid.error("initial source coverage reference"));
        }
        Ok(CoverageReportRef {
            source: receipt.identity.clone(),
            revision,
            position: StorePositionV1 {
                commit_revision,
                ordinal,
            },
        })
    }

    fn source_receipt_from(
        reader: &Connection,
        identity: crate::EvidenceIntakeIdentityV1,
        cpu: u32,
    ) -> Result<Option<AnalysisSourceReceiptV1>> {
        use duckdb::OptionalExt as _;
        let row = reader
            .query_row(
                "SELECT tenant_id, cpu_id, contiguous_cursor, coverage_revision, retained_floor
             FROM source_receipts WHERE stream_key = ?",
                params![identity.key()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, u64>(4)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read managed source receipt scalars",
            })?;
        row.map(|(tenant, recorded, contiguous, coverage, floor)| {
            if tenant != identity.tenant_id || recorded != cpu || floor > contiguous {
                return Err(Code::Invalid.error("managed source receipt scalars"));
            }
            Ok(AnalysisSourceReceiptV1 {
                identity,
                cpu_id: recorded,
                contiguous_cursor: contiguous,
                coverage_revision: coverage,
                retained_floor: floor,
            })
        })
        .transpose()
    }

    fn source_members_from(
        reader: &Connection,
        tenant: [u8; 16],
        reference: &ManagedSourceRef,
        control: &AnalysisReadControl,
    ) -> Result<Arc<BTreeSet<Vec<u8>>>> {
        let mut members = BTreeSet::new();
        let mut next = reference.clone();
        loop {
            control.check()?;
            let (step, _, revision) =
                Self::managed_step_header(reader, tenant, &next.result.result_id)?;
            let source = step
                .source
                .ok_or_else(|| Code::Missing.error("source member basis"))?;
            if revision != next.result.commit_revision || source.contract.position != next.position
            {
                return Err(Code::Invalid.error("source member revision"));
            }
            for metadata in source.metadata {
                members.insert(metadata.receipt.identity.key());
            }
            match source.contract.read {
                ManagedSourceRead::Initial => break,
                ManagedSourceRead::Changes(parent) => {
                    if parent.result.commit_revision >= revision {
                        return Err(Code::Invalid.error("source member parent"));
                    }
                    next = parent;
                }
            }
        }
        Ok(Arc::new(members))
    }
}
