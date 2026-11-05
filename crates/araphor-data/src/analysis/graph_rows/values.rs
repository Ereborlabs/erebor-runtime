use crate::{DiscoveryRecordIdV1, DiscoveryValidate as _, EvidenceIntakeIdentityV1};

use super::*;

impl GraphRows {
    pub(super) fn intern_records(
        writer: &Connection,
        source: &EvidenceIntakeIdentityV1,
        records: &[DiscoveryRecordIdV1],
    ) -> Result<BTreeMap<DiscoveryRecordIdV1, u64>> {
        let reference = Self::source_id(writer, source)?;
        Self::check_record_cpus(writer, source, records)?;
        writer.execute_batch("CREATE TEMP TABLE graph_value_records(cpu_id UINTEGER,durable_cursor UBIGINT,PRIMARY KEY(cpu_id,durable_cursor))").context(AnalysisDatabaseSnafu {operation:"create Graph record candidates"})?;
        {
            let mut appender =
                writer
                    .appender("graph_value_records")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph record candidates",
                    })?;
            for record in records {
                record.validate()?;
                appender
                    .append_row(params![record.cpu_id, record.durable_cursor])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph record candidate",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph record candidates",
            })?;
        }
        writer.execute("INSERT INTO graph_evidence SELECT nextval('graph_evidence_seq'),?,c.cpu_id,c.durable_cursor FROM graph_value_records c WHERE NOT EXISTS(SELECT 1 FROM graph_evidence e WHERE e.source_ref=? AND e.cpu_id=c.cpu_id AND e.durable_cursor=c.durable_cursor)",params![reference,reference]).context(AnalysisDatabaseSnafu {operation:"intern Graph record candidates"})?;
        let mut statement=writer.prepare("SELECT e.evidence_id,c.cpu_id,c.durable_cursor FROM graph_value_records c JOIN graph_evidence e ON e.source_ref=? AND e.cpu_id=c.cpu_id AND e.durable_cursor=c.durable_cursor").context(AnalysisDatabaseSnafu {operation:"prepare Graph record references"})?;
        let mut rows = statement
            .query(params![reference])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph record references",
            })?;
        let mut values = BTreeMap::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph record references",
        })? {
            let record = DiscoveryRecordIdV1 {
                stream: source.clone(),
                cpu_id: Self::column(row, 1)?,
                durable_cursor: Self::column(row, 2)?,
            };
            if values.insert(record, Self::column(row, 0)?).is_some() {
                return Err(Self::invalid("graph duplicate record reference"));
            }
        }
        drop(rows);
        drop(statement);
        writer
            .execute_batch("DROP TABLE graph_value_records")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph record candidates",
            })?;
        if values.len() != records.len() {
            return Err(Self::invalid("graph record candidate count"));
        }
        Ok(values)
    }

    pub(super) fn check_record_cpus(
        writer: &Connection,
        source: &EvidenceIntakeIdentityV1,
        records: &[DiscoveryRecordIdV1],
    ) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let cpu: u32 = writer
            .query_row(
                "SELECT cpu_id FROM source_receipts WHERE stream_key=? AND tenant_id=?",
                params![source.key(), source.tenant_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph source CPU",
            })?
            .ok_or_else(|| Self::invalid("graph evidence source"))?;
        if records
            .iter()
            .any(|record| record.stream != *source || record.cpu_id != cpu)
        {
            return Err(Self::invalid("graph evidence source"));
        }
        Ok(())
    }

    pub(super) fn source_id(writer: &Connection, source: &EvidenceIntakeIdentityV1) -> Result<u64> {
        let present: bool = writer
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM source_receipts WHERE stream_key=? AND tenant_id=?)",
                params![source.key(), source.tenant_id.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check Graph evidence source",
            })?;
        if !source.valid() || !present {
            return Err(Self::invalid("graph evidence source"));
        }
        if let Some((id, tenant, identity)) = writer
            .query_row(
                "SELECT source_ref,tenant_id,identity FROM graph_sources WHERE stream_key=?",
                params![source.key()],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph source",
            })?
        {
            if tenant != source.tenant_id
                || Self::decode_value::<EvidenceIntakeIdentityV1>(&identity)? != *source
            {
                return Err(Self::invalid("graph evidence source"));
            }
            return Ok(id);
        }
        let id = Self::next_id(writer, "graph_sources")?;
        writer
            .execute(
                "INSERT INTO graph_sources VALUES(?,?,?,?)",
                params![
                    id,
                    source.key(),
                    source.tenant_id.as_slice(),
                    Self::encode_value(source)?
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert Graph source",
            })?;
        Ok(id)
    }

    pub(in crate::analysis) fn decode_subject(row: &Row<'_>) -> Result<GraphSubjectKeyV1> {
        crate::analysis::graph_rows::store::SubjectRows::decode(row).map_err(Into::into)
    }

    #[cfg(test)]
    pub(super) fn label(value: &impl Serialize) -> Result<String> {
        serde_plain::to_string(value).map_err(|_| Self::invalid("graph scalar label"))
    }
    pub(super) fn label_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> Result<T> {
        Self::parse(&Self::column::<String>(row, index)?)
    }
    pub(super) fn parse<T: DeserializeOwned>(label: &str) -> Result<T> {
        serde_plain::from_str(label).map_err(|_| Self::invalid("graph scalar label"))
    }
    pub(super) fn read_ids(row: &Row<'_>, index: usize) -> Result<Vec<u64>> {
        crate::analysis::graph_rows::store::FindingRows::evidence_references(row, index)
            .map_err(Into::into)
    }
}
