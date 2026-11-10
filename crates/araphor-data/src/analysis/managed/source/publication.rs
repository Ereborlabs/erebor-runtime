use duckdb::{OptionalExt as _, Transaction};

use super::*;
use crate::{ManagedCommit, ManagedReceipt};

mod check;
mod frozen;
mod read;
mod revision;

#[derive(Debug, Eq, PartialEq)]
pub(in crate::analysis) struct SourcePublication {
    pub reference: PackageResultRefV1,
    pub captured: StorePositionV1,
    pub first: u64,
    pub last: u64,
    pub deadline: u64,
    pub count: u64,
    pub restricted: u64,
}

pub(in crate::analysis) struct PreparedSource {
    pub(in crate::analysis) selection: Arc<ManagedInputSelection>,
    pub(in crate::analysis) prior: Option<SourcePublication>,
    pub(in crate::analysis) stream: Vec<u8>,
    pub(in crate::analysis) rows: Vec<(Vec<u8>, u32, u64, StorePositionV1, u64)>,
    pub(in crate::analysis) coverage: u64,
    pub(in crate::analysis) gaps: Vec<(u64, u64)>,
    pub(in crate::analysis) count: u64,
    pub(in crate::analysis) restricted: u64,
    pub(in crate::analysis) roots: BTreeMap<u64, (u64, u64)>,
}

impl SourcePublication {
    pub(in crate::analysis) fn head(
        reader: &Connection,
        tenant: [u8; 16],
        instance: &str,
        stream: &[u8],
    ) -> Result<Option<Self>> {
        reader
            .query_row(
                "SELECT result_id,revision,captured_revision,captured_ordinal,
                first_cursor,last_cursor,witness_deadline,record_count,restricted_count
             FROM managed_source_publications WHERE tenant_id=? AND instance_id=? AND stream_key=?
             ORDER BY revision DESC LIMIT 1",
                params![tenant.as_slice(), instance, stream],
                |row| {
                    Ok(Self {
                        reference: PackageResultRefV1 {
                            result_id: row.get(0)?,
                            commit_revision: row.get(1)?,
                        },
                        captured: StorePositionV1 {
                            commit_revision: row.get(2)?,
                            ordinal: row.get(3)?,
                        },
                        first: row.get(4)?,
                        last: row.get(5)?,
                        deadline: row.get(6)?,
                        count: row.get(7)?,
                        restricted: row.get(8)?,
                    })
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read native source publication head",
            })
    }

    pub(in crate::analysis::managed) fn prepare(
        connection: &Connection,
        input: &ManagedCommit<'_>,
        selection: &Arc<ManagedInputSelection>,
        memory: &mut super::super::budget::PreparedMemory<'_>,
    ) -> Result<PreparedSource> {
        let spec = &input.attempt.instance().spec;
        let prior = Self::head(connection, spec.tenant, &spec.id, &selection.source.key())?;
        PreparedSource::prepare(
            input.attempt,
            selection,
            prior,
            input
                .returns
                .iter()
                .map(|returned| (returned.call, returned.evaluation)),
            memory,
        )
    }

    pub(in crate::analysis) fn check_parent(
        connection: &Connection,
        input: &ManagedCommit<'_>,
        prepared: &PreparedSource,
    ) -> Result<()> {
        let spec = &input.attempt.instance().spec;
        if Self::head(connection, spec.tenant, &spec.id, &prepared.stream)? != prepared.prior {
            return Err(Code::Conflict.error("native source publication parent"));
        }
        Ok(())
    }

    pub(in crate::analysis) fn publish(
        connection: &Transaction<'_>,
        input: &ManagedCommit<'_>,
        receipt: &ManagedReceipt,
        revision: u64,
        prepared: PreparedSource,
    ) -> Result<(Self, (u64, u64))> {
        Self::check_parent(connection, input, &prepared)?;
        let PreparedSource {
            selection,
            prior,
            stream,
            rows,
            coverage,
            gaps,
            count,
            restricted,
            roots: _,
        } = prepared;
        let attempt = input.attempt;
        let spec = &attempt.instance().spec;
        if receipt.selected.commit_revision != revision {
            return Err(Code::Denied.error("native source publication revision"));
        }
        if selection.expired {
            AnalysisStore::check_source_retention(
                connection,
                &receipt.selected.result_id,
                &selection.source,
                selection.first,
                selection.last,
            )?;
        }
        connection.execute_batch(
            "CREATE TEMP TABLE native_source_records(record_key BLOB PRIMARY KEY,cpu_id UINTEGER,
                source_cursor UBIGINT,position_revision UBIGINT,position_ordinal UINTEGER,restricted UBIGINT)",
        ).context(AnalysisDatabaseSnafu { operation:"create native source publication input" })?;
        let result = (|| {
            {
                let mut append = connection.appender("native_source_records").context(
                    AnalysisDatabaseSnafu {
                        operation: "open native source records",
                    },
                )?;
                for (key, cpu, cursor, position, restricted) in &rows {
                    append
                        .append_row(params![
                            key,
                            cpu,
                            cursor,
                            position.commit_revision,
                            position.ordinal,
                            restricted
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append native source record",
                        })?;
                }
                append.flush().context(AnalysisDatabaseSnafu {
                    operation: "flush native source records",
                })?;
            }
            if selection.append {
                let duplicate: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM native_source_records wanted JOIN managed_source_members member
                     USING(record_key) WHERE member.tenant_id=? AND member.instance_id=? AND member.stream_key=?
                        AND member.valid_to IS NULL)",
                    params![spec.tenant.as_slice(),spec.id,stream], |row| row.get(0),
                ).context(AnalysisDatabaseSnafu { operation:"check native source append identities" })?;
                if duplicate {
                    return Err(Code::Conflict.error("native source append identity"));
                }
            }
            let closed = if selection.append || selection.expired {
                0
            } else {
                connection.execute(
                    "UPDATE managed_source_members SET valid_to=? WHERE tenant_id=? AND instance_id=?
                     AND stream_key=? AND valid_to IS NULL",
                    params![revision,spec.tenant.as_slice(),spec.id,stream],
                ).context(AnalysisDatabaseSnafu { operation:"close native source selection" })? as u64
            };
            let inserted = connection.execute(
                "INSERT INTO managed_source_members SELECT ?,?,?,record_key,cpu_id,source_cursor,
                    position_revision,position_ordinal,?,restricted,?,NULL FROM native_source_records",
                params![spec.tenant.as_slice(),spec.id,stream,receipt.selected.result_id,revision],
            ).context(AnalysisDatabaseSnafu { operation:"publish native source membership" })? as u64;
            if inserted != rows.len() as u64 {
                return Err(Code::Invalid.error("native source member cardinality"));
            }
            let publication = Self {
                reference: receipt.selected.clone(),
                captured: selection.scope.position,
                first: selection.first,
                last: selection.last,
                deadline: selection.deadline,
                count,
                restricted,
            };
            let counts_at = std::time::Instant::now();
            let counts =
                AnalysisStore::native_domain_counts(connection, &receipt.selected.result_id)?;
            erebor_telemetry::debug!(
                stage = "source_counts_timing", instance_id = %spec.id,
                cut_revision = attempt.captured_revision(), publication_revision = revision,
                first_cursor = publication.first, last_cursor = publication.last,
                record_count = count, selected_rows = selection.records.len(), append = selection.append,
                expired = selection.expired, base_revision = selection.base.as_ref().map_or(0, |base| base.commit_revision),
                elapsed_s = counts_at.elapsed().as_secs_f64(),
                "Source publication counts completed"
            );
            connection.execute(
                "INSERT INTO managed_source_publications VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                params![receipt.selected.result_id,spec.tenant.as_slice(),spec.id,stream,revision,
                    attempt.request().id,attempt.0.capture.generation,
                    prior.as_ref().map(|prior| prior.reference.result_id.as_str()),
                    publication.captured.commit_revision,publication.captured.ordinal,publication.first,
                    publication.last,publication.deadline,coverage,attempt.captured_revision(),count,restricted,
                    counts.0,counts.1,counts.2,selection.expired],
            ).context(AnalysisDatabaseSnafu { operation:"publish native source cut" })?;
            {
                let mut append = connection.appender("managed_source_coverage").context(
                    AnalysisDatabaseSnafu {
                        operation: "open native source coverage",
                    },
                )?;
                let mut reasons = connection.appender("managed_source_reasons").context(
                    AnalysisDatabaseSnafu {
                        operation: "open native source coverage reasons",
                    },
                )?;
                for (ordinal, key) in selection.coverage.iter().enumerate() {
                    let ordinal = u64::try_from(ordinal)
                        .map_err(|_| Code::Limit.error("native source coverage ordinal"))?;
                    let state = match key.state {
                        crate::DiscoveryCoverageStateV1::Healthy => 0u8,
                        crate::DiscoveryCoverageStateV1::Gapped => 1,
                        crate::DiscoveryCoverageStateV1::Unknown => 2,
                        crate::DiscoveryCoverageStateV1::Closed => 3,
                    };
                    append
                        .append_row(params![
                            receipt.selected.result_id,
                            ordinal,
                            key.cpu_id,
                            key.report_revision,
                            key.interval_id.as_slice(),
                            key.interval_revision,
                            state
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append native source coverage",
                        })?;
                    for reason in &key.gap_reasons {
                        reasons
                            .append_row(params![receipt.selected.result_id, ordinal, reason])
                            .context(AnalysisDatabaseSnafu {
                                operation: "append native source coverage reason",
                            })?;
                    }
                }
                append.flush().context(AnalysisDatabaseSnafu {
                    operation: "flush native source coverage",
                })?;
                reasons.flush().context(AnalysisDatabaseSnafu {
                    operation: "flush native source coverage reasons",
                })?;
            }
            {
                let mut append =
                    connection
                        .appender("managed_source_gaps")
                        .context(AnalysisDatabaseSnafu {
                            operation: "open native source gaps",
                        })?;
                for (first, last) in gaps {
                    append
                        .append_row(params![receipt.selected.result_id, first, last])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append native source gap",
                        })?;
                }
                append.flush().context(AnalysisDatabaseSnafu {
                    operation: "flush native source gaps",
                })?;
            }
            Ok((publication, (inserted, closed)))
        })();
        let cleanup = connection
            .execute_batch("DROP TABLE native_source_records")
            .context(AnalysisDatabaseSnafu {
                operation: "release native source publication input",
            });
        let value = result?;
        cleanup?;
        Ok(value)
    }
}

impl PreparedSource {
    pub(in crate::analysis) fn prepare<'a>(
        attempt: &crate::ManagedAttempt,
        selection: &Arc<ManagedInputSelection>,
        prior: Option<SourcePublication>,
        returns: impl ExactSizeIterator<Item = (u64, &'a araphor_analysis_sdk::Evaluation)>,
        memory: &mut super::super::budget::PreparedMemory<'_>,
    ) -> Result<Self> {
        let spec = &attempt.instance().spec;
        let frame = attempt
            .5
            .as_ref()
            .ok_or_else(|| Code::Denied.error("native source publication frame"))?;
        let registered = frame
            .input_selection()?
            .ok_or_else(|| Code::Incomplete.error("native source selection"))?;
        if !Arc::ptr_eq(&registered, selection)
            || !Arc::ptr_eq(&selection.scope, &frame.scope)
            || !Arc::ptr_eq(&selection.proof, &frame.proof)
            || selection.scope.position.commit_revision != attempt.captured_revision()
            || !matches!(&spec.destination, super::super::model::ManagedDestination::Graph { source,
                operation: super::super::model::ManagedGraphOperation::Evaluate, .. } if source == &selection.source)
        {
            return Err(Code::Denied.error("native source publication owner"));
        }
        memory.charge(
            selection
                .source
                .node_id
                .capacity()
                .checked_add(std::mem::size_of_val(&selection.source))
                .and_then(|bytes| bytes.checked_mul(8))
                .and_then(|bytes| {
                    bytes.checked_add(
                        selection
                            .base
                            .as_ref()
                            .map_or(0, |base| base.result_id.capacity())
                            .checked_mul(4)?,
                    )
                })
                .ok_or_else(|| Code::Limit.error("source preparation metadata"))?,
        )?;
        let stream = selection.source.key();
        if prior.as_ref().map(|prior| &prior.reference) != selection.base.as_ref()
            || selection.expired
                && prior.as_ref().is_none_or(|prior| {
                    prior.first != selection.first
                        || prior.last != selection.last
                        || prior.deadline != selection.deadline
                })
            || selection.append
                && prior.as_ref().is_none_or(|prior| {
                    selection.parent.as_ref().is_none_or(|parent| {
                        parent.result != prior.reference || parent.position != prior.captured
                    }) || prior.first != selection.first
                        || prior.last > selection.last
                        || prior.deadline != selection.deadline
                })
        {
            return Err(Code::Conflict.error("native source publication parent"));
        }
        let (coverage, gaps) = frame.source_metadata(&selection.source)?;
        memory.charge(
            gaps.len()
                .checked_add(usize::from(selection.expired))
                .and_then(|count| count.checked_mul(4 * std::mem::size_of::<(u64, u64)>()))
                .ok_or_else(|| Code::Limit.error("source preparation gap memory"))?,
        )?;
        let mut gaps = gaps.to_vec();
        if selection.expired {
            gaps.push((selection.first, selection.last));
            gaps.sort_unstable();
            gaps.dedup();
        }
        memory.charge(
            selection
                .records
                .len()
                .checked_mul(4 * std::mem::size_of::<(Vec<u8>, u32, u64, StorePositionV1, u64)>())
                .and_then(|bytes| {
                    bytes.checked_add(
                        gaps.capacity()
                            .checked_mul(std::mem::size_of::<(u64, u64)>())?,
                    )
                })
                .ok_or_else(|| Code::Limit.error("source preparation memory"))?,
        )?;
        let mut rows = Vec::with_capacity(selection.records.len());
        let mut added = 0u64;
        for (id, position) in &selection.records {
            memory.check()?;
            memory.charge(
                id.allocated_bytes()
                    .checked_add(std::mem::size_of_val(id))
                    .and_then(|bytes| bytes.checked_mul(4))
                    .ok_or_else(|| Code::Limit.error("source record key memory"))?,
            )?;
            let key = araphor_analysis_types::DomainRelations::key(id)
                .context(crate::AnalysisContractSnafu)?;
            let restricted = selection.restricted.get(id).copied().unwrap_or(0);
            added = added
                .checked_add(restricted)
                .ok_or_else(|| Code::Limit.error("native source disclosure count"))?;
            rows.push((key, id.cpu_id, id.durable_cursor, *position, restricted));
        }
        let count = (rows.len() as u64)
            .checked_add(if selection.append || selection.expired {
                prior.as_ref().map_or(0, |prior| prior.count)
            } else {
                0
            })
            .ok_or_else(|| Code::Limit.error("native source membership count"))?;
        let restricted = added
            .checked_add(if selection.append || selection.expired {
                prior.as_ref().map_or(0, |prior| prior.restricted)
            } else {
                0
            })
            .ok_or_else(|| Code::Limit.error("native source disclosure count"))?;
        if selection
            .prefix
            .as_ref()
            .is_some_and(|proof| !usize::try_from(count).is_ok_and(|count| proof.has_count(count)))
        {
            return Err(Code::Conflict.error("native source prefix count"));
        }
        memory.charge(
            returns
                .len()
                .checked_mul(12 * std::mem::size_of::<(u64, (u64, u64))>())
                .ok_or_else(|| Code::Limit.error("source root metadata memory"))?,
        )?;
        let mut roots = BTreeMap::new();
        for (call, evaluation) in returns {
            use araphor_analysis_sdk::arrow_array::{Array as _, StructArray, UInt64Array};
            let mut bounds = None::<(u64, u64)>;
            for batch in evaluation
                .inputs
                .iter()
                .filter(|input| input.data.name == "units")
                .flat_map(|input| &input.data.batches)
            {
                let Some(records) = batch
                    .column_by_name("record")
                    .and_then(|column| column.as_any().downcast_ref::<StructArray>())
                else {
                    continue;
                };
                let Some(cursors) = records
                    .column_by_name("durable_cursor")
                    .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
                else {
                    continue;
                };
                for cursor in cursors.iter().flatten() {
                    bounds = Some(bounds.map_or((cursor, cursor), |(first, last)| {
                        (first.min(cursor), last.max(cursor))
                    }));
                }
            }
            if let Some(bounds) = bounds {
                roots.insert(call, bounds);
            }
        }
        Ok(PreparedSource {
            selection: Arc::clone(selection),
            prior,
            stream,
            rows,
            coverage,
            gaps,
            count,
            restricted,
            roots,
        })
    }
}
