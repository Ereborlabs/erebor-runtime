use super::*;
use crate::{
    DiscoveryRecordIdV1, DiscoveryValidate as _, EvidenceIntakeIdentityV1, GraphValidate as _,
};

impl GraphRows {
    pub(super) fn registry_keys(reader: &Connection) -> Result<BTreeMap<(u8, u64), Vec<u8>>> {
        let mut keys = BTreeMap::new();
        let mut sources = BTreeMap::new();
        let mut statement = reader
            .prepare("SELECT source_ref,stream_key,tenant_id,identity FROM graph_sources")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph source registry",
            })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph source registry",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph source registry",
        })? {
            let key: Vec<u8> = Self::column(row, 1)?;
            let tenant: Vec<u8> = Self::column(row, 2)?;
            let source: EvidenceIntakeIdentityV1 =
                Self::decode_value(&Self::column::<Vec<u8>>(row, 3)?)?;
            if !source.valid() || source.key() != key || source.tenant_id.as_slice() != tenant {
                return Err(Self::invalid("graph source registry identity"));
            }
            sources.insert(Self::column::<u64>(row, 0)?, source);
        }
        drop(rows);
        drop(statement);
        let mut evidence = BTreeMap::new();
        let mut statement = reader
            .prepare("SELECT evidence_id,source_ref,cpu_id,durable_cursor FROM graph_evidence")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph evidence registry",
            })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph evidence registry",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph evidence registry",
        })? {
            let id = Self::column::<u64>(row, 0)?;
            let source = Self::column::<u64>(row, 1)?;
            let record = DiscoveryRecordIdV1 {
                stream: sources
                    .get(&source)
                    .cloned()
                    .ok_or_else(|| Self::invalid("graph evidence source"))?,
                cpu_id: Self::column(row, 2)?,
                durable_cursor: Self::column(row, 3)?,
            };
            record.validate()?;
            keys.insert((0, id), Self::member_key(&record)?);
            evidence.insert(id, record);
        }
        drop(rows);
        drop(statement);
        let subjects = araphor_graph::SubjectRows::registry(reader)?;
        for (id, subject) in &subjects {
            keys.insert((2, *id), Self::member_key(subject)?);
        }
        for (id, key) in araphor_graph::RelationshipRows::registry(reader, &subjects, &evidence)? {
            keys.insert((3, id), Self::member_key(&key)?);
        }
        let columns = araphor_graph::FindingRows::COLUMNS
            .split_once(',')
            .ok_or_else(|| Self::invalid("graph finding columns"))?
            .1;
        let mut statement = reader
            .prepare(&format!(
                "SELECT value_id AS ordinal,{columns} FROM graph_finding_values"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph finding registry",
            })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph finding registry",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph finding registry",
        })? {
            let (subject, records) = araphor_graph::FindingRows::references(row)?;
            let finding = araphor_graph::FindingRows::decode(
                row,
                subjects
                    .get(&subject)
                    .cloned()
                    .ok_or_else(|| Self::invalid("graph finding subject reference"))?,
                records
                    .into_iter()
                    .map(|id| {
                        evidence
                            .get(&id)
                            .cloned()
                            .ok_or_else(|| Self::invalid("graph finding evidence reference"))
                    })
                    .collect::<Result<_>>()?,
            )?;
            finding.validate()?;
            keys.insert(
                (4, Self::column::<u64>(row, 0)?),
                Self::member_key(&finding.finding_id)?,
            );
        }
        drop(rows);
        drop(statement);
        Ok(keys)
    }
}
