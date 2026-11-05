use super::*;
use std::time::{Duration, Instant};

pub(in crate::analysis::extraction) struct SourceHeader {
    pub receipt: AnalysisSourceReceiptV1,
    pub revision: u64,
    pub expired: Vec<AnalysisGapV1>,
    pub recovery: Vec<AnalysisGapV1>,
    pub retired: Vec<AnalysisGapV1>,
    pub coverage: Option<Vec<u8>>,
}

pub(in crate::analysis::extraction) struct SourceHeaders {
    pub values: Vec<SourceHeader>,
    pub receipt_s: Duration,
    pub gaps_s: Duration,
}

impl SourceHeaders {
    pub(in crate::analysis::extraction) fn read(
        store: &AnalysisStore,
        reader: &Connection,
        sources: &[EvidenceIntakeIdentityV1],
        physical: u64,
        journal: Option<(&AnalysisSelectionV1, &AnalysisTableRead<'_>)>,
        control: &AnalysisReadControl,
        output: &mut AnalysisExtractionV1,
    ) -> Result<Self> {
        let started = Instant::now();
        if sources.is_empty() {
            return Ok(Self {
                values: Vec::new(),
                receipt_s: Duration::ZERO,
                gaps_s: Duration::ZERO,
            });
        }
        let bytes = sources
            .len()
            .checked_mul(
                12 * (size_of::<SourceHeader>() + size_of::<(Vec<u8>, usize)>())
                    + 4 * EvidenceIntakeIdentityV1::MAX_KEY_BYTES,
            )
            .ok_or_else(|| crate::PackageErrorCodeV1::Limit.error("source header set memory"))?;
        output.charge(bytes)?;
        let keys = sources
            .iter()
            .enumerate()
            .map(|(index, source)| (source.key(), index))
            .collect::<BTreeMap<_, _>>();
        let placeholders = std::iter::repeat_n("?", sources.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut values = std::iter::repeat_with(|| None)
            .take(sources.len())
            .collect::<Vec<Option<SourceHeader>>>();
        let mut query = reader
            .prepare(&format!(
                "SELECT receipt.stream_key,receipt.identity_json,receipt.tenant_id,receipt.cpu_id,
                receipt.contiguous_cursor,receipt.coverage_revision,receipt.retained_floor,
                receipt.commit_revision,coverage.report,
                coalesce(octet_length(coverage.report),0)
             FROM source_receipts receipt LEFT JOIN coverage
                ON coverage.stream_key=receipt.stream_key AND coverage.tenant_id=receipt.tenant_id
                AND coverage.revision=receipt.coverage_revision AND receipt.coverage_revision<>0
             WHERE receipt.stream_key IN ({placeholders})"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare selected source headers",
            })?;
        let mut rows =
            query
                .query(duckdb::params_from_iter(keys.keys()))
                .context(AnalysisDatabaseSnafu {
                    operation: "read selected source headers",
                })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance selected source headers",
        })? {
            control.check()?;
            let key: Vec<u8> = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "read selected source key",
            })?;
            let index = keys[&key];
            output.charge(sources[index].node_id.len())?;
            let stored = (|| -> duckdb::Result<_> {
                Ok((
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode selected source receipt",
            })?;
            let (receipt, revision) =
                AnalysisStore::decode_receipt(&store.root, &sources[index], stored)?;
            output.charge(
                receipt
                    .identity
                    .node_id
                    .capacity()
                    .saturating_sub(sources[index].node_id.len()),
            )?;
            let report_bytes: usize = row.get(9).context(AnalysisDatabaseSnafu {
                operation: "bound selected source coverage",
            })?;
            output.charge(report_bytes)?;
            let coverage: Option<Vec<u8>> = row.get(8).context(AnalysisDatabaseSnafu {
                operation: "read retained coverage",
            })?;
            if receipt.coverage_revision != 0 {
                let Some(report) = &coverage else {
                    return store.reject("the source coverage receipt has no retained report");
                };
                if report.is_empty() {
                    return store.reject("the retained coverage report size is invalid");
                }
            }
            values[index] = Some(SourceHeader {
                receipt,
                revision,
                expired: Vec::new(),
                recovery: Vec::new(),
                retired: Vec::new(),
                coverage,
            });
        }
        drop(rows);
        drop(query);
        let through = output.meta.commit_revision;
        let mut values = values
            .into_iter()
            .map(|value| {
                let value =
                    value.ok_or_else(|| store.state_error("the selected source is absent"))?;
                if let Some((selection, read)) = journal {
                    store.check_journal_source(
                        reader,
                        &value.receipt.identity.key(),
                        selection,
                        read,
                        through,
                        control,
                    )?;
                }
                Ok(value)
            })
            .collect::<Result<Vec<_>>>()?;
        let receipts_at = Instant::now();
        let retired = if through < physical {
            let catalog: String = reader
                .query_row("SELECT current_database()", [], |row| row.get(0))
                .context(AnalysisDatabaseSnafu {
                    operation: "read source history catalog",
                })?;
            format!(
                " UNION ALL SELECT stream_key,2 AS kind,first_cursor,last_cursor,commit_revision,
                source_revision,received_utc_ns FROM \"{}\".main.expired_ranges
                WHERE tenant_id=? AND stream_key IN ({placeholders})
                    AND source_revision<=? AND commit_revision>?",
                catalog.replace('"', "\"\"")
            )
        } else {
            String::new()
        };
        let mut query = reader.prepare(&format!(
            "SELECT stream_key,0 AS kind,first_cursor,last_cursor,commit_revision,source_revision,received_utc_ns
             FROM expired_ranges WHERE tenant_id=? AND stream_key IN ({placeholders})
             UNION ALL SELECT stream_key,1 AS kind,first_cursor,last_cursor,commit_revision,
                NULL::UBIGINT,NULL::UBIGINT FROM recovery_gaps
             WHERE tenant_id=? AND stream_key IN ({placeholders}){retired}
             ORDER BY stream_key,kind,first_cursor"
        )).context(AnalysisDatabaseSnafu { operation: "prepare selected source gaps" })?;
        let tenant = sources[0].tenant_id.as_slice();
        let mut parameters = Vec::<&dyn duckdb::ToSql>::new();
        for _ in 0..(if retired.is_empty() { 2 } else { 3 }) {
            parameters.push(&tenant);
            parameters.extend(keys.keys().map(|key| key as &dyn duckdb::ToSql));
        }
        if !retired.is_empty() {
            parameters.extend([&through as &dyn duckdb::ToSql, &through]);
        }
        let mut rows =
            query
                .query(duckdb::params_from_iter(parameters))
                .context(AnalysisDatabaseSnafu {
                    operation: "read selected source gaps",
                })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance selected source gaps",
        })? {
            control.check()?;
            let (key, kind, first, last, revision, accepted, intake) = (|| -> duckdb::Result<_> {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u8>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, Option<u64>>(5)?,
                    row.get::<_, Option<u64>>(6)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode selected source gap",
            })?;
            let header = &mut values[keys[&key]];
            let gap = if kind == 2 {
                output.scan(size_of::<[u64; 5]>())?;
                let Some(accepted) = accepted else {
                    return store.reject("the retired source header is invalid");
                };
                if first == 0
                    || last < first
                    || accepted == 0
                    || accepted > through
                    || intake.is_none_or(|value| value == 0)
                    || revision <= through
                    || revision <= accepted
                {
                    return store.reject("the retired source header is invalid");
                }
                AnalysisGapV1 {
                    first_cursor: first,
                    last_cursor: last,
                    commit_revision: accepted,
                }
            } else {
                if first == 0
                    || last < first
                    || revision == 0
                    || revision > through
                    || (kind == 0
                        && (accepted.is_none_or(|value| value == 0 || value >= revision)
                            || intake.is_none_or(|value| value == 0)))
                {
                    return store.reject("the selected source gap header is invalid");
                }
                AnalysisGapV1 {
                    first_cursor: first,
                    last_cursor: last,
                    commit_revision: revision,
                }
            };
            let gaps = match kind {
                0 => &mut header.expired,
                1 => &mut header.recovery,
                _ => &mut header.retired,
            };
            let added =
                AnalysisExtractionV1::grow(gaps, output.input_bytes, output.limits.input_bytes)?;
            output.charge(added)?;
            gaps.push(gap);
        }
        let complete = Instant::now();
        Ok(Self {
            values,
            receipt_s: receipts_at.duration_since(started),
            gaps_s: complete.duration_since(receipts_at),
        })
    }
}
