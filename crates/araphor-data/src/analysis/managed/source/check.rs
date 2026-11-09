use super::*;
use crate::{AnalysisContextRefV1, AnalysisContextVersionV1};

impl AnalysisStore {
    pub(in crate::analysis::managed) fn check_source_proofs(
        connection: &Connection,
        result: &str,
        evidence: (
            &[crate::AnalysisWitnessV1],
            &[AnalysisContextRefV1],
            &[(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)],
        ),
        cut: u64,
    ) -> Result<()> {
        let mut expected = BTreeMap::new();
        let (witnesses, derived, proofs) = evidence;
        for (id, reference) in proofs {
            if id.durable_cursor == 0
                || id.stream.tenant_id != reference.key.tenant_id
                || witnesses
                    .binary_search_by(|witness| match &witness.identity {
                        crate::AnalysisStreamIdentityV1::Evidence(source) => {
                            (source, witness.cursor).cmp(&(&id.stream, id.durable_cursor))
                        }
                        crate::AnalysisStreamIdentityV1::Diagnostic(_) => {
                            std::cmp::Ordering::Greater
                        }
                    })
                    .is_err()
                || derived
                    .binary_search_by(|value| value.key.cmp(&reference.key))
                    .ok()
                    .is_none_or(|index| derived[index] != *reference)
            {
                return Err(Code::Invalid.error("source record proof authority"));
            }
            let key = (
                araphor_analysis_types::DomainRelations::key(id)
                    .context(crate::AnalysisContractSnafu)?,
                crate::analysis::context::version_key(&reference.key)?,
            );
            if expected
                .insert(
                    key,
                    (
                        reference.commit_revision,
                        id.stream.key(),
                        id.cpu_id,
                        id.durable_cursor,
                    ),
                )
                .is_some()
            {
                return Err(Code::Invalid.error("duplicate source record proof"));
            }
        }
        let mut query = connection.prepare(
            "SELECT pin.record_key,pin.version_key,pin.revision,pin.stream_key,pin.cpu_id,pin.source_cursor,
                (SELECT source.cpu_id=pin.cpu_id AND source.contiguous_cursor>=pin.source_cursor
                 FROM source_versions source WHERE source.stream_key=pin.stream_key AND source.commit_revision<=?
                 ORDER BY source.commit_revision DESC LIMIT 1) IS TRUE
             FROM managed_source_proofs pin WHERE pin.result_id=?",
        ).context(AnalysisDatabaseSnafu { operation: "prepare source record proof pins" })?;
        let mut rows = query
            .query(params![cut, result])
            .context(AnalysisDatabaseSnafu {
                operation: "read source record proof pins",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance source record proof pins",
        })? {
            let (record, context, value, valid) = (|| -> duckdb::Result<_> {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    (
                        row.get::<_, u64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, u32>(4)?,
                        row.get::<_, u64>(5)?,
                    ),
                    row.get::<_, bool>(6)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode source record proof pin",
            })?;
            if !valid || expected.remove(&(record, context)) != Some(value) {
                return Err(Code::Invalid.error("source record proof pin"));
            }
        }
        if !expected.is_empty() {
            return Err(Code::Missing.error("source record proof pin"));
        }
        Ok(())
    }

    pub(in crate::analysis::managed) fn check_source_pins(
        connection: &Connection,
        result: &str,
        witnesses: &[crate::AnalysisWitnessV1],
        contexts: &[AnalysisContextRefV1],
    ) -> Result<()> {
        if witnesses
            .windows(2)
            .any(|pair| (&pair[0].identity, pair[0].cursor) >= (&pair[1].identity, pair[1].cursor))
            || contexts.windows(2).any(|pair| pair[0].key >= pair[1].key)
        {
            return Err(Code::Invalid.error("managed evidence pin order"));
        }
        Self::check_witness_pins(connection, result, witnesses)?;
        let mut expected = contexts
            .iter()
            .map(|value| (&value.key, value.commit_revision))
            .collect::<BTreeMap<_, _>>();
        let mut query = connection
            .prepare(
                "SELECT pin.tenant_id,pin.owner_id,pin.entity_key,pin.lifetime_key,pin.owner_revision,
                    pin.commit_revision,canonical.owner_revision IS NOT NULL
                 FROM context_refs pin LEFT JOIN context_versions canonical
                    ON canonical.tenant_id=pin.tenant_id AND canonical.owner_id=pin.owner_id
                    AND canonical.entity_key=pin.entity_key AND canonical.lifetime_key=pin.lifetime_key
                    AND canonical.owner_revision=pin.owner_revision
                    AND canonical.commit_revision=pin.commit_revision
                 WHERE pin.ref_id=?",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare managed context pins",
            })?;
        let mut rows = query
            .query(params![result])
            .context(AnalysisDatabaseSnafu {
                operation: "read managed context pins",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance managed context pins",
        })? {
            let native = (|| -> duckdb::Result<_> {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode managed context pin",
            })?;
            let key = crate::AnalysisContextKeyV1 {
                tenant_id: native
                    .0
                    .try_into()
                    .map_err(|_| Code::Invalid.error("managed context pin tenant"))?,
                owner_id: native.1,
                entity_key: native.2,
                lifetime_key: native.3,
                owner_revision: native.4,
            };
            if expected.remove(&key) != Some(native.5) || !native.6 {
                return Err(Code::Invalid.error("managed context pin value"));
            }
        }
        if !expected.is_empty() {
            return Err(Code::Missing.error("managed context pin"));
        }
        Ok(())
    }

    pub(in crate::analysis::managed) fn check_witness_pins(
        connection: &Connection,
        result: &str,
        witnesses: &[crate::AnalysisWitnessV1],
    ) -> Result<()> {
        let mut expected = witnesses
            .iter()
            .map(|value| ((value.identity.key(), value.cursor), value))
            .collect::<BTreeMap<_, _>>();
        let mut query = connection
            .prepare(
                "SELECT e.tenant_id,e.stream_key,e.durable_cursor,e.expires_utc_ns,
                    s.segment_id IS NOT NULL FROM evidence_refs e LEFT JOIN segments s
                    ON s.segment_id=e.segment_id AND s.state='Live' AND s.tenant_id=e.tenant_id
                        AND s.stream_key=e.stream_key
                        AND e.durable_cursor BETWEEN s.first_cursor AND s.last_cursor
                    WHERE e.ref_id=?",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare managed witness pins",
            })?;
        let mut rows = query
            .query(params![result])
            .context(AnalysisDatabaseSnafu {
                operation: "read managed witness pins",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance managed witness pins",
        })? {
            let native = (|| -> duckdb::Result<_> {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, bool>(4)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode managed witness pin",
            })?;
            let witness = expected
                .remove(&(native.1, native.2))
                .ok_or_else(|| Code::Invalid.error("extra managed witness pin"))?;
            if witness.identity.tenant().as_slice() != native.0
                || witness.expires_utc_ns != native.3
                || !native.4
            {
                return Err(Code::Invalid.error("managed witness pin value"));
            }
        }
        if !expected.is_empty() {
            let now: u64 = connection
                .query_row("SELECT epoch_ns(current_timestamp)::UBIGINT", [], |row| {
                    row.get(0)
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read source witness expiry clock",
                })?;
            if expected
                .values()
                .any(|witness| witness.expires_utc_ns > now)
            {
                return Err(Code::Missing.error("managed source witness binding"));
            }
        }
        Ok(())
    }

    pub(in crate::analysis::managed) fn check_derived_refs(
        connection: &Connection,
        attempt: &Attempt,
        references: &[AnalysisContextRefV1],
        origins: &[PackageResultRefV1],
        captured: &[AnalysisContextRefV1],
        witnesses: &[crate::AnalysisWitnessV1],
        publication: u64,
        result: &str,
    ) -> Result<()> {
        if references.windows(2).any(|pair| pair[0].key >= pair[1].key)
            || origins
                .windows(2)
                .any(|pair| pair[0].result_id >= pair[1].result_id)
        {
            return Err(Code::Invalid.error("derived evidence order"));
        }
        if Self::source_origins(connection, result)? != origins {
            return Err(Code::Conflict.error("derived origin pins"));
        }
        if !origins.is_empty() {
            let spec = Self::managed_version_from(
                connection,
                attempt.capture.tenant,
                &attempt.capture.instance,
                attempt.capture.generation,
            )?;
            let super::super::model::ManagedDestination::Graph { source, .. } = &spec.destination
            else {
                return Err(Code::Denied.error("derived historical source scope"));
            };
            if !attempt.capture.grant.selection.includes_source(source) {
                return Err(Code::Denied.error("derived historical source grant"));
            }
            let invalid: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM managed_source_reads p
                LEFT JOIN analysis_results r ON r.result_id=p.producer_id LEFT JOIN graph_versions g ON g.result_id=p.producer_id
                LEFT JOIN managed_source_publications native ON native.result_id=p.producer_id
                WHERE p.result_id=? AND (r.result_id IS NULL OR coalesce(native.revision,g.commit_revision) IS NULL OR r.tenant_id<>?
                    OR coalesce(native.stream_key,r.stream_key) IS DISTINCT FROM ? OR r.commit_revision<>p.revision
                    OR coalesce(native.revision,g.commit_revision)<>p.revision OR p.revision=0 OR p.revision>?))",
                params![result,attempt.capture.tenant.as_slice(),source.key(),attempt.capture.revision],|row| row.get(0))
                .context(AnalysisDatabaseSnafu { operation:"validate derived origin batch" })?;
            if invalid {
                return Err(Code::Invalid.error("derived historical origin"));
            }
        }
        if references.is_empty() {
            let extra: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM managed_context_imports WHERE result_id=?)",
                    params![result],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "check empty derived import pins",
                })?;
            if extra {
                return Err(Code::Invalid.error("extra derived import pin"));
            }
            return Ok(());
        }
        connection.execute_batch("CREATE TEMP TABLE managed_check_refs(ordinal UBIGINT PRIMARY KEY,version_key BLOB UNIQUE,revision UBIGINT,captured BOOLEAN);
            CREATE TEMP TABLE managed_check_witnesses(stream_key BLOB,source_cursor UBIGINT,PRIMARY KEY(stream_key,source_cursor))")
            .context(AnalysisDatabaseSnafu { operation:"create derived reference inputs" })?;
        let checked = Self::check_derived_batch(
            connection,
            attempt,
            references,
            captured,
            witnesses,
            publication,
            result,
        );
        let cleanup = connection
            .execute_batch("DROP TABLE managed_check_witnesses; DROP TABLE managed_check_refs")
            .context(AnalysisDatabaseSnafu {
                operation: "release derived reference inputs",
            });
        checked?;
        cleanup?;
        Ok(())
    }

    fn check_derived_batch(
        connection: &Connection,
        attempt: &Attempt,
        references: &[AnalysisContextRefV1],
        captured: &[AnalysisContextRefV1],
        witnesses: &[crate::AnalysisWitnessV1],
        publication: u64,
        result: &str,
    ) -> Result<()> {
        let captured = captured
            .iter()
            .map(|value| (&value.key, value.commit_revision))
            .collect::<BTreeSet<_>>();
        {
            let mut appender =
                connection
                    .appender("managed_check_refs")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open derived reference inputs",
                    })?;
            for (ordinal, reference) in references.iter().enumerate() {
                if !reference.key.valid()
                    || reference.key.tenant_id != attempt.capture.tenant
                    || reference.commit_revision == 0
                    || reference.commit_revision > publication
                {
                    return Err(Code::Invalid.error("derived context bounds"));
                }
                appender
                    .append_row(params![
                        ordinal as u64,
                        crate::analysis::context::version_key(&reference.key)?,
                        reference.commit_revision,
                        captured.contains(&(&reference.key, reference.commit_revision))
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append derived reference input",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush derived reference inputs",
            })?;
        }
        {
            let mut appender =
                connection
                    .appender("managed_check_witnesses")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open derived witness inputs",
                    })?;
            for witness in witnesses {
                if let AnalysisStreamIdentityV1::Evidence(source) = &witness.identity {
                    appender
                        .append_row(params![source.key(), witness.cursor])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append derived witness input",
                        })?;
                }
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush derived witness inputs",
            })?;
        }
        let extra: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM managed_context_imports i WHERE i.result_id=?
            AND NOT EXISTS(SELECT 1 FROM managed_check_refs q WHERE q.version_key=i.version_key AND q.revision=i.revision))",params![result],|row| row.get(0))
            .context(AnalysisDatabaseSnafu { operation:"check exact derived import pins" })?;
        if extra {
            return Err(Code::Invalid.error("extra derived import pin"));
        }
        let mut query = connection.prepare("SELECT q.ordinal,q.captured,c.tenant_id,c.owner_id,c.entity_key,c.lifetime_key,c.owner_revision,
            c.valid_from_utc_ns,c.valid_until_utc_ns,c.sensitivity,c.body,c.commit_revision,f.record_key,f.stream_key,f.source_cursor,
            i.result_id IS NOT NULL,w.stream_key IS NOT NULL,
            (EXISTS(SELECT 1 FROM managed_source_reads origin
                JOIN managed_source_publications publication ON publication.result_id=origin.producer_id
                    AND publication.revision=origin.revision
                JOIN context_versions historical ON historical.version_key=q.version_key AND historical.commit_revision=q.revision
                JOIN context_refs pin ON pin.ref_id=origin.producer_id AND pin.tenant_id=historical.tenant_id
                    AND pin.owner_id=historical.owner_id AND pin.entity_key=historical.entity_key
                    AND pin.lifetime_key=historical.lifetime_key AND pin.owner_revision=historical.owner_revision
                    AND pin.commit_revision=historical.commit_revision
                WHERE origin.result_id=? AND (
                    EXISTS(SELECT 1 FROM managed_source_members member
                        WHERE member.tenant_id=publication.tenant_id AND member.instance_id=publication.instance_id
                            AND member.stream_key=publication.stream_key AND member.record_key=f.record_key
                            AND member.valid_from<=publication.revision AND (member.valid_to IS NULL OR member.valid_to>publication.revision))
                    OR EXISTS(SELECT 1 FROM managed_source_proofs proof
                        JOIN managed_check_witnesses witness ON witness.stream_key=proof.stream_key AND witness.source_cursor=proof.source_cursor
                        JOIN managed_source_members member ON member.record_key=proof.record_key AND member.tenant_id=publication.tenant_id
                            AND member.instance_id=publication.instance_id AND member.stream_key=publication.stream_key
                            AND member.valid_from<=publication.revision AND (member.valid_to IS NULL OR member.valid_to>publication.revision)
                        WHERE proof.result_id=origin.producer_id AND proof.version_key=q.version_key AND proof.revision=q.revision)))
             OR EXISTS(SELECT 1 FROM managed_source_reads origin JOIN graph_versions g ON g.result_id=origin.producer_id AND g.commit_revision=origin.revision
                JOIN graph_producer_versions v ON v.result_id=g.metadata_result_id JOIN graph_producer_members m ON m.scope_id=v.scope_id
                    AND m.valid_from<=v.commit_revision AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision)
                WHERE origin.result_id=? AND m.member_key=q.version_key AND m.member_kind IN(7,10) AND (m.member_kind=7 OR m.value_ref=q.revision)))
            FROM managed_check_refs q LEFT JOIN context_versions c ON c.version_key=q.version_key
            LEFT JOIN graph_fact_records f ON f.version_key=q.version_key
            LEFT JOIN managed_context_imports i ON i.result_id=? AND i.version_key=q.version_key AND i.revision=q.revision
            LEFT JOIN managed_check_witnesses w ON w.stream_key=f.stream_key AND w.source_cursor=f.source_cursor ORDER BY q.ordinal")
            .context(AnalysisDatabaseSnafu { operation:"prepare derived reference batch" })?;
        let mut rows =
            query
                .query(params![result, result, result])
                .context(AnalysisDatabaseSnafu {
                    operation: "read derived reference batch",
                })?;
        let mut count = 0usize;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance derived reference batch",
        })? {
            let column = |index| {
                row.get::<_, Option<Vec<u8>>>(index)
                    .context(AnalysisDatabaseSnafu {
                        operation: "decode derived binary field",
                    })
            };
            let ordinal: usize = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode derived ordinal",
            })?;
            let expected = references
                .get(ordinal)
                .filter(|_| ordinal == count)
                .ok_or_else(|| Code::Invalid.error("derived reference cardinality"))?;
            let tenant = column(2)?
                .ok_or_else(|| Code::Missing.error("derived context"))?
                .try_into()
                .map_err(|_| Code::Invalid.error("derived context tenant"))?;
            let value = AnalysisContextVersionV1 {
                key: crate::AnalysisContextKeyV1 {
                    tenant_id: tenant,
                    owner_id: row.get(3).context(AnalysisDatabaseSnafu {
                        operation: "decode derived owner",
                    })?,
                    entity_key: row.get(4).context(AnalysisDatabaseSnafu {
                        operation: "decode derived entity",
                    })?,
                    lifetime_key: row.get(5).context(AnalysisDatabaseSnafu {
                        operation: "decode derived lifetime",
                    })?,
                    owner_revision: row.get(6).context(AnalysisDatabaseSnafu {
                        operation: "decode derived owner revision",
                    })?,
                },
                valid_from_utc_ns: row.get(7).context(AnalysisDatabaseSnafu {
                    operation: "decode derived lower bound",
                })?,
                valid_until_utc_ns: row.get(8).context(AnalysisDatabaseSnafu {
                    operation: "decode derived upper bound",
                })?,
                sensitivity: crate::ContextSensitivityV1::try_from(
                    row.get::<_, String>(9)
                        .context(AnalysisDatabaseSnafu {
                            operation: "decode derived sensitivity",
                        })?
                        .as_str(),
                )
                .map_err(|_| Code::Invalid.error("derived context sensitivity"))?,
                body: column(10)?.ok_or_else(|| Code::Missing.error("derived body"))?,
            };
            let revision: u64 = row.get(11).context(AnalysisDatabaseSnafu {
                operation: "decode derived revision",
            })?;
            if !value.valid() || value.key != expected.key || revision != expected.commit_revision {
                return Err(Code::Conflict.error("derived immutable reference"));
            }
            Self::validate_context_packages(connection, &value)
                .map_err(crate::Error::stored_artifact)?;
            let fact = crate::analysis::context::FactRecord::from_context(&value)?;
            let cursor: Option<u64> = row.get(14).context(AnalysisDatabaseSnafu {
                operation: "decode derived cursor",
            })?;
            let indexed = (column(12)?, column(13)?, cursor);
            if fact
                .as_ref()
                .map(|fact| {
                    (
                        Some(fact.record.as_slice()),
                        Some(fact.stream.as_slice()),
                        Some(fact.cursor),
                    )
                })
                .unwrap_or((None, None, None))
                != (indexed.0.as_deref(), indexed.1.as_deref(), indexed.2)
            {
                return Err(Code::Invalid.error("canonical fact index"));
            }
            let captured: bool = row.get(1).context(AnalysisDatabaseSnafu {
                operation: "decode captured reference",
            })?;
            let imported: bool = row.get(15).context(AnalysisDatabaseSnafu {
                operation: "decode import receipt",
            })?;
            let witnessed: bool = row.get(16).context(AnalysisDatabaseSnafu {
                operation: "decode derived witness",
            })?;
            let historical: bool = row.get(17).context(AnalysisDatabaseSnafu {
                operation: "decode historical reference",
            })?;
            if fact.is_some() && !witnessed {
                return Err(Code::Denied.error("derived fact source witness"));
            }
            if !captured
                && !(fact.is_some() && imported)
                && historical
                && !attempt.capture.grant.selection.contexts.is_all()
                && !attempt
                    .capture
                    .grant
                    .selection
                    .contexts
                    .as_slice()
                    .contains(&expected.key)
            {
                return Err(Code::Denied.error("derived historical context grant"));
            }
            if !captured && !(fact.is_some() && imported) && !historical {
                return Err(Code::Denied.error("unbound derived parent"));
            }
            count += 1;
        }
        if count != references.len() {
            return Err(Code::Invalid.error("derived reference cardinality"));
        }
        Ok(())
    }
}
