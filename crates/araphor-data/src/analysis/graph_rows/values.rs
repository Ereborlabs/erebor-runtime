use crate::{
    DiscoveryRecordIdV1, DiscoveryValidate as _, EvidenceIntakeIdentityV1, GraphValidate as _,
};
use duckdb::types::Value;

use super::*;

impl GraphRows {
    pub(super) fn intern_progress(
        writer: &Connection,
        records: &BTreeMap<DiscoveryRecordIdV1, u64>,
        progress: &[Progress],
    ) -> Result<BTreeMap<DiscoveryRecordIdV1, u64>> {
        if progress.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut requested = BTreeMap::new();
        for value in progress {
            if value.digest.len() != 32 {
                return Err(Self::invalid("graph progress digest"));
            }
            let id = *records
                .get(&value.record)
                .ok_or_else(|| Self::invalid("graph progress evidence"))?;
            if requested.insert(id, value).is_some() {
                return Err(Self::invalid("graph duplicate progress"));
            }
        }
        writer.execute_batch("CREATE TEMP TABLE graph_value_progress(evidence_id UBIGINT PRIMARY KEY,digest BLOB NOT NULL,state VARCHAR)").context(AnalysisDatabaseSnafu {operation:"create Graph progress candidates"})?;
        {
            let mut appender =
                writer
                    .appender("graph_value_progress")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph progress candidates",
                    })?;
            for (id, value) in &requested {
                appender
                    .append_row(params![id, value.digest.as_ref(), value.state])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph progress candidate",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph progress candidates",
            })?;
        }
        writer.execute_batch("INSERT INTO graph_progress_values SELECT nextval('graph_progress_values_seq'),c.evidence_id,c.digest,c.state FROM graph_value_progress c WHERE NOT EXISTS(SELECT 1 FROM graph_progress_values v WHERE v.evidence_id=c.evidence_id AND v.digest=c.digest AND v.state IS NOT DISTINCT FROM c.state)").context(AnalysisDatabaseSnafu {operation:"intern Graph progress candidates"})?;
        let mut statement=writer.prepare("SELECT c.evidence_id,v.value_ref FROM graph_value_progress c JOIN graph_progress_values v ON v.evidence_id=c.evidence_id AND v.digest=c.digest AND v.state IS NOT DISTINCT FROM c.state").context(AnalysisDatabaseSnafu {operation:"prepare Graph progress references"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph progress references",
        })?;
        let mut values = BTreeMap::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph progress references",
        })? {
            let id: u64 = Self::column(row, 0)?;
            let record = requested
                .get(&id)
                .ok_or_else(|| Self::invalid("graph progress candidate"))?
                .record
                .clone();
            if values.insert(record, Self::column(row, 1)?).is_some() {
                return Err(Self::invalid("graph duplicate progress value"));
            }
        }
        drop(rows);
        drop(statement);
        writer
            .execute_batch("DROP TABLE graph_value_progress")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph progress candidates",
            })?;
        if values.len() != progress.len() {
            return Err(Self::invalid("graph progress candidate count"));
        }
        Ok(values)
    }

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

    pub(super) fn authority(authority: &GraphSubjectAuthorityV1) -> (u8, &str, &[u8], u64) {
        match authority {
            GraphSubjectAuthorityV1::Native {
                node_id,
                node_boot_id,
                label_epoch,
            } => (0, node_id, node_boot_id, *label_epoch),
            GraphSubjectAuthorityV1::Provider { authority_id } => (1, authority_id, &[], 0),
            GraphSubjectAuthorityV1::Kubernetes { cluster_id } => (2, cluster_id, &[], 0),
            GraphSubjectAuthorityV1::External { authority_id } => (3, authority_id, &[], 0),
        }
    }

    pub(in crate::analysis) fn decode_subject(row: &Row<'_>) -> Result<GraphSubjectKeyV1> {
        let tenant: Vec<u8> = Self::column(row, 1)?;
        let rank: u8 = Self::column(row, 2)?;
        let text = Self::column(row, 3)?;
        let boot: Vec<u8> = Self::column(row, 4)?;
        let epoch: u64 = Self::column(row, 5)?;
        let kind: u8 = Self::column(row, 6)?;
        if rank != 0 && (!boot.is_empty() || epoch != 0) {
            return Err(Self::invalid("graph subject authority"));
        }
        let authority = match rank {
            0 => GraphSubjectAuthorityV1::Native {
                node_id: text,
                node_boot_id: boot
                    .try_into()
                    .map_err(|_| Self::invalid("graph subject authority"))?,
                label_epoch: epoch,
            },
            1 => GraphSubjectAuthorityV1::Provider { authority_id: text },
            2 => GraphSubjectAuthorityV1::Kubernetes { cluster_id: text },
            3 => GraphSubjectAuthorityV1::External { authority_id: text },
            _ => return Err(Self::invalid("graph subject authority")),
        };
        let kinds = [
            GraphSubjectKindV1::Task,
            GraphSubjectKindV1::Process,
            GraphSubjectKindV1::ExecutionSet,
            GraphSubjectKindV1::Socket,
            GraphSubjectKindV1::Artifact,
            GraphSubjectKindV1::Request,
            GraphSubjectKindV1::CredentialLease,
            GraphSubjectKindV1::KubernetesObject,
            GraphSubjectKindV1::ProviderObject,
            GraphSubjectKindV1::External,
        ];
        let subject = GraphSubjectKeyV1 {
            tenant_id: tenant
                .try_into()
                .map_err(|_| Self::invalid("graph subject tenant"))?,
            authority,
            kind: *kinds
                .get(kind as usize)
                .ok_or_else(|| Self::invalid("graph subject kind"))?,
            identity: Self::column(row, 7)?,
        };
        subject.validate()?;
        Ok(subject)
    }

    pub(super) fn label(value: &impl Serialize) -> Result<String> {
        serde_plain::to_string(value).map_err(|_| Self::invalid("graph scalar label"))
    }
    pub(super) fn property_hash(
        edge_type: GraphEdgeTypeV1,
        package: &str,
        cause: GraphCauseV1,
        proof: ProofQualityV1,
        coverage: &[[u8; 16]],
    ) -> Result<Vec<u8>> {
        Ok(Self::hash(&Self::encode_value(&(
            edge_type, package, cause, proof, coverage,
        ))?))
    }
    pub(super) fn read_proof(row: &Row<'_>, index: usize) -> Result<ProofQualityV1> {
        let Value::Struct(fields) = Self::column(row, index)? else {
            return Err(Self::invalid("graph native proof"));
        };
        if fields.iter().count() != 6 {
            return Err(Self::invalid("graph native proof"));
        }
        let rank = |name: &str| match fields.get(&name.to_owned()) {
            Some(Value::UTinyInt(value)) => Ok(*value),
            _ => Err(Self::invalid("graph native proof")),
        };
        fn decode<T: DeserializeOwned>(value: u8) -> Result<T> {
            T::deserialize(
                serde::de::value::U32Deserializer::<serde::de::value::Error>::new(value as u32),
            )
            .map_err(|_| GraphRows::invalid("graph native proof"))
        }
        Ok(ProofQualityV1 {
            source_authority: decode(rank("source_authority")?)?,
            local_subject_binding: decode(rank("local_subject_binding")?)?,
            remote_subject_binding: decode(rank("remote_subject_binding")?)?,
            operation_result_authority: decode(rank("operation_result_authority")?)?,
            temporal_coverage: decode(rank("temporal_coverage")?)?,
            integrity: decode(rank("integrity")?)?,
        })
    }
    pub(super) fn label_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> Result<T> {
        Self::parse(&Self::column::<String>(row, index)?)
    }
    pub(super) fn parse<T: DeserializeOwned>(label: &str) -> Result<T> {
        serde_plain::from_str(label).map_err(|_| Self::invalid("graph scalar label"))
    }
    pub(super) fn read_ids(row: &Row<'_>, index: usize) -> Result<Vec<u64>> {
        araphor_graph::FindingRows::evidence_references(row, index).map_err(Into::into)
    }
    pub(super) fn read_bytes(row: &Row<'_>, index: usize) -> Result<Vec<[u8; 16]>> {
        match Self::column(row, index)? {
            Value::List(values) => values
                .into_iter()
                .map(|value| match value {
                    Value::Blob(bytes) => bytes
                        .try_into()
                        .map_err(|_| Self::invalid("graph byte array")),
                    _ => Err(Self::invalid("graph byte array")),
                })
                .collect(),
            _ => Err(Self::invalid("graph list column")),
        }
    }
}
