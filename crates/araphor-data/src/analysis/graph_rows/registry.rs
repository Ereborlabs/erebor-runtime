use super::*;
use crate::{
    DiscoveryRecordIdV1, DiscoveryValidate as _, EvidenceIntakeIdentityV1, GraphValidate as _,
};

impl GraphRows {
    pub(super) fn registry_keys(reader: &Connection) -> Result<BTreeMap<(u8, u64), Vec<u8>>> {
        Self::validate_properties(reader)?;
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
        let mut subjects = BTreeMap::new();
        let mut statement=reader.prepare("SELECT subject_id,tenant_id,authority_rank,authority_text,authority_boot,authority_epoch,subject_kind,identity FROM graph_subject_values").context(AnalysisDatabaseSnafu {operation:"prepare Graph subject registry"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph subject registry",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph subject registry",
        })? {
            let id = Self::column::<u64>(row, 0)?;
            let subject = Self::decode_subject(row)?;
            keys.insert((2, id), Self::member_key(&subject)?);
            subjects.insert(id, subject);
        }
        drop(rows);
        drop(statement);
        let mut values = BTreeSet::new();
        let mut statement=reader.prepare("SELECT e.edge_id,e.value_hash,e.from_ref,e.to_ref,p.edge_type,p.edge_rank,p.package_id,p.cause,p.cause_rank,e.evidence_refs,p.proof_quality,p.required_coverage_interval_ids,e.first_boottime_ns,e.last_boottime_ns FROM graph_edge_values e LEFT JOIN graph_edge_properties p USING(property_ref)").context(AnalysisDatabaseSnafu {operation:"prepare Graph edge registry"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph edge registry",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph edge registry",
        })? {
            let id = Self::column::<u64>(row, 0)?;
            let hash: Vec<u8> = Self::column(row, 1)?;
            let from = subjects
                .get(&Self::column::<u64>(row, 2)?)
                .cloned()
                .ok_or_else(|| Self::invalid("graph edge source subject"))?;
            let to = subjects
                .get(&Self::column::<u64>(row, 3)?)
                .cloned()
                .ok_or_else(|| Self::invalid("graph edge target subject"))?;
            let key = RelationshipIdentity {
                from,
                to,
                edge_type: Self::label_column(row, 4)?,
                package_id: Self::column(row, 6)?,
                cause: Self::label_column(row, 7)?,
                evidence: Self::read_ids(row, 9)?
                    .into_iter()
                    .map(|id| {
                        evidence
                            .get(&id)
                            .cloned()
                            .ok_or_else(|| Self::invalid("graph edge evidence reference"))
                    })
                    .collect::<Result<_>>()?,
            };
            let proof = Self::read_proof(row, 10)?;
            let coverage = Self::read_bytes(row, 11)?;
            let first: u64 = Self::column(row, 12)?;
            let last: u64 = Self::column(row, 13)?;
            let body = Self::encode_value(&(&key, proof, coverage, first, last))?;
            if key.edge_type as u8 != Self::column::<u8>(row, 5)?
                || key.cause as u8 != Self::column::<u8>(row, 8)?
                || first > last
                || key.from.tenant_id != key.to.tenant_id
                || key.evidence.windows(2).any(|pair| pair[0] >= pair[1])
                || Self::hash(&body) != hash
                || !values.insert(body)
            {
                return Err(Self::invalid("graph edge registry value"));
            }
            keys.insert((3, id), Self::member_key(&key)?);
        }
        drop(rows);
        drop(statement);
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
        let mut statement = reader
            .prepare("SELECT value_ref,evidence_id,digest,state FROM graph_progress_values")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph progress registry",
            })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph progress registry",
        })?;
        let mut progress = BTreeSet::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph progress registry",
        })? {
            let record = Self::column::<u64>(row, 1)?;
            let digest: Vec<u8> = Self::column(row, 2)?;
            let state: Option<String> = Self::column(row, 3)?;
            if digest.len() != 32 || !progress.insert((record, digest, state)) {
                return Err(Self::invalid("graph progress registry value"));
            }
            keys.insert(
                (5, Self::column::<u64>(row, 0)?),
                Self::member_key(
                    evidence
                        .get(&record)
                        .ok_or_else(|| Self::invalid("graph progress evidence reference"))?,
                )?,
            );
        }
        Ok(keys)
    }

    pub(super) fn validate_properties(reader: &Connection) -> Result<()> {
        let missing:bool=reader.query_row("SELECT EXISTS(SELECT 1 FROM graph_edge_values e LEFT JOIN graph_edge_properties p USING(property_ref) WHERE p.property_ref IS NULL)",[],|row|row.get(0)).context(AnalysisDatabaseSnafu {operation:"validate Graph property references"})?;
        if missing {
            return Err(Self::invalid("graph edge property reference"));
        }
        let mut statement=reader.prepare("SELECT property_ref,property_hash,edge_type,edge_rank,package_id,cause,cause_rank,proof_quality,required_coverage_interval_ids FROM graph_edge_properties").context(AnalysisDatabaseSnafu {operation:"prepare Graph property registry"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph property registry",
        })?;
        let mut values = BTreeSet::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph property registry",
        })? {
            let edge: GraphEdgeTypeV1 = Self::label_column(row, 2)?;
            let package: String = Self::column(row, 4)?;
            let cause: GraphCauseV1 = Self::label_column(row, 5)?;
            let proof = Self::read_proof(row, 7)?;
            let coverage = Self::read_bytes(row, 8)?;
            let body = Self::encode_value(&(edge, &package, cause, proof, &coverage))?;
            if edge as u8 != Self::column::<u8>(row, 3)?
                || cause as u8 != Self::column::<u8>(row, 6)?
                || Self::hash(&body) != Self::column::<Vec<u8>>(row, 1)?
                || !values.insert(body)
            {
                return Err(Self::invalid("graph edge property value"));
            }
        }
        Ok(())
    }
}
