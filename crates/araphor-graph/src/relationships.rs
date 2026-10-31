use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_builtins::{discovery::DiscoveryRecordIdV1, graph::*};
use araphor_analysis_sdk as sdk;
use duckdb::{Connection, Row};
use snafu::ResultExt as _;

use crate::{error::DatabaseSnafu, native::NativeRows, FindingRows, Result, SubjectRows};

pub struct RelationshipRows;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationshipValue {
    pub key: RelationshipIdentity,
    pub proof_quality: ProofQualityV1,
    pub required_coverage_interval_ids: Vec<[u8; 16]>,
    pub first_boottime_ns: u64,
    pub last_boottime_ns: u64,
}

impl From<&RelationshipChange> for RelationshipValue {
    fn from(value: &RelationshipChange) -> Self {
        Self {
            key: value.key.clone(),
            proof_quality: value.proof_quality,
            required_coverage_interval_ids: value.required_coverage_interval_ids.clone(),
            first_boottime_ns: value.first_boottime_ns,
            last_boottime_ns: value.last_boottime_ns,
        }
    }
}

impl RelationshipRows {
    pub const SCHEMA: &str = include_str!("relationships.sql");
    pub const COLUMNS: &str = "ordinal,from_subject_id,to_subject_id,edge_type,package_id,cause,evidence,proof_quality,required_coverage_interval_ids,first_boottime_ns,last_boottime_ns";

    pub fn intern(
        writer: &Connection,
        subjects: &BTreeMap<GraphSubjectKeyV1, u64>,
        records: &BTreeMap<DiscoveryRecordIdV1, u64>,
        edges: &[RelationshipValue],
    ) -> Result<Vec<u64>> {
        for edge in edges {
            Self::validate(edge)?;
        }
        if edges.is_empty() {
            return Ok(Vec::new());
        }
        writer.execute_batch("CREATE TEMP TABLE graph_value_edges AS SELECT e.edge_id,e.value_hash,e.from_ref,e.to_ref,p.edge_type,p.edge_rank,p.package_id,p.cause,p.cause_rank,e.evidence_refs,p.proof_quality,p.required_coverage_interval_ids,e.first_boottime_ns,e.last_boottime_ns,p.property_hash FROM graph_edge_values e JOIN graph_edge_properties p USING(property_ref) WHERE false").context(DatabaseSnafu {operation:"create Graph edge candidates"})?;
        Self::append(writer, "graph_value_edges", subjects, records, edges)?;
        let property="p.property_hash=c.property_hash AND p.edge_type=c.edge_type AND p.edge_rank=c.edge_rank AND p.package_id=c.package_id AND p.cause=c.cause AND p.cause_rank=c.cause_rank AND p.proof_quality=c.proof_quality AND p.required_coverage_interval_ids=c.required_coverage_interval_ids";
        let invalid:bool=writer.query_row(&format!("SELECT EXISTS(SELECT 1 FROM graph_value_edges c JOIN graph_edge_properties p ON p.property_hash=c.property_hash WHERE NOT ({property}))"),[],|row|row.get(0)).context(DatabaseSnafu {operation:"check Graph edge properties"})?;
        if invalid {
            return Err(NativeRows::invalid("graph edge property value"));
        }
        writer.execute_batch(&format!("INSERT INTO graph_edge_properties SELECT nextval('graph_edge_properties_seq'),c.property_hash,c.edge_type,c.edge_rank,c.package_id,c.cause,c.cause_rank,c.proof_quality,c.required_coverage_interval_ids FROM (SELECT DISTINCT property_hash,edge_type,edge_rank,package_id,cause,cause_rank,proof_quality,required_coverage_interval_ids FROM graph_value_edges) c WHERE NOT EXISTS(SELECT 1 FROM graph_edge_properties p WHERE {property})")).context(DatabaseSnafu {operation:"intern Graph edge properties"})?;
        let expanded="SELECT e.edge_id,e.value_hash,e.from_ref,e.to_ref,p.edge_type,p.edge_rank,p.package_id,p.cause,p.cause_rank,e.evidence_refs,p.proof_quality,p.required_coverage_interval_ids,e.first_boottime_ns,e.last_boottime_ns,p.property_hash FROM graph_edge_values e LEFT JOIN graph_edge_properties p USING(property_ref)";
        let equal="v.property_hash=c.property_hash AND v.value_hash=c.value_hash AND v.from_ref=c.from_ref AND v.to_ref=c.to_ref AND v.edge_type=c.edge_type AND v.edge_rank=c.edge_rank AND v.package_id=c.package_id AND v.cause=c.cause AND v.cause_rank=c.cause_rank AND v.evidence_refs=c.evidence_refs AND v.proof_quality=c.proof_quality AND v.required_coverage_interval_ids=c.required_coverage_interval_ids AND v.first_boottime_ns=c.first_boottime_ns AND v.last_boottime_ns=c.last_boottime_ns";
        let identity="v.from_ref=c.from_ref AND v.to_ref=c.to_ref AND v.edge_type=c.edge_type AND v.package_id=c.package_id AND v.cause=c.cause AND v.evidence_refs=c.evidence_refs";
        let corrupt:bool=writer.query_row(&format!("SELECT EXISTS(SELECT 1 FROM graph_value_edges c JOIN ({expanded}) v ON v.value_hash=c.value_hash WHERE v.property_hash IS NULL OR ({identity} AND NOT ({equal})))"),[],|row|row.get(0)).context(DatabaseSnafu {operation:"check Graph edge candidates"})?;
        if corrupt {
            return Err(NativeRows::invalid("duplicate graph edge value"));
        }
        writer.execute_batch(&format!("INSERT INTO graph_edge_values SELECT nextval('graph_edge_values_seq'),c.value_hash,c.from_ref,c.to_ref,p.property_ref,c.evidence_refs,c.first_boottime_ns,c.last_boottime_ns FROM (SELECT DISTINCT * EXCLUDE(edge_id) FROM graph_value_edges) c JOIN graph_edge_properties p ON {property} WHERE NOT EXISTS(SELECT 1 FROM ({expanded}) v WHERE {equal})")).context(DatabaseSnafu {operation:"intern Graph edge candidates"})?;
        let mut statement=writer.prepare(&format!("SELECT c.edge_id,v.edge_id FROM graph_value_edges c JOIN ({expanded}) v ON {equal} ORDER BY c.edge_id")).context(DatabaseSnafu {operation:"prepare Graph edge references"})?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read Graph edge references",
        })?;
        let mut values = Vec::with_capacity(edges.len());
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph edge references",
        })? {
            if NativeRows::column::<u64>(row, 0)? != values.len() as u64 {
                return Err(NativeRows::invalid("graph duplicate edge value"));
            }
            values.push(NativeRows::column(row, 1)?);
        }
        drop(rows);
        drop(statement);
        writer
            .execute_batch("DROP TABLE graph_value_edges")
            .context(DatabaseSnafu {
                operation: "release Graph edge candidates",
            })?;
        if values.len() != edges.len() {
            return Err(NativeRows::invalid("graph edge candidate count"));
        }
        Ok(values)
    }

    fn append(
        writer: &Connection,
        table: &str,
        subjects: &BTreeMap<GraphSubjectKeyV1, u64>,
        records: &BTreeMap<DiscoveryRecordIdV1, u64>,
        edges: &[RelationshipValue],
    ) -> Result<()> {
        use sdk::{
            arrow_array::{
                builder::{LargeBinaryBuilder, LargeListBuilder, UInt64Builder},
                ArrayRef, LargeBinaryArray, LargeStringArray, RecordBatch, UInt64Array, UInt8Array,
            },
            arrow_schema::{Field, Schema},
        };
        use std::sync::Arc;
        let mut evidence = LargeListBuilder::new(UInt64Builder::new());
        let mut coverage = LargeListBuilder::new(LargeBinaryBuilder::new());
        let mut hashes = Vec::with_capacity(edges.len());
        let mut property_hashes = Vec::with_capacity(edges.len());
        let mut from = Vec::with_capacity(edges.len());
        let mut to = Vec::with_capacity(edges.len());
        let mut types = Vec::with_capacity(edges.len());
        let mut causes = Vec::with_capacity(edges.len());
        for edge in edges {
            from.push(
                *subjects
                    .get(&edge.key.from)
                    .ok_or_else(|| NativeRows::invalid("graph edge subject"))?,
            );
            to.push(
                *subjects
                    .get(&edge.key.to)
                    .ok_or_else(|| NativeRows::invalid("graph edge subject"))?,
            );
            for record in &edge.key.evidence {
                evidence.values().append_value(
                    *records
                        .get(record)
                        .ok_or_else(|| NativeRows::invalid("graph edge evidence"))?,
                );
            }
            evidence.append(true);
            for id in &edge.required_coverage_interval_ids {
                coverage.values().append_value(id);
            }
            coverage.append(true);
            hashes.push(NativeRows::hash(&NativeRows::encode(&(
                &edge.key,
                edge.proof_quality,
                &edge.required_coverage_interval_ids,
                edge.first_boottime_ns,
                edge.last_boottime_ns,
            ))?));
            property_hashes.push(Self::property_hash(
                edge.key.edge_type,
                &edge.key.package_id,
                edge.key.cause,
                edge.proof_quality,
                &edge.required_coverage_interval_ids,
            )?);
            types.push(NativeRows::label(&edge.key.edge_type)?);
            causes.push(NativeRows::label(&edge.key.cause)?);
        }
        let proof = NativeRows::proofs(edges.iter().map(|edge| edge.proof_quality));
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(UInt64Array::from_iter_values(0..edges.len() as u64)),
            Arc::new(LargeBinaryArray::from_iter_values(&hashes)),
            Arc::new(UInt64Array::from(from)),
            Arc::new(UInt64Array::from(to)),
            Arc::new(LargeStringArray::from_iter_values(&types)),
            Arc::new(UInt8Array::from_iter_values(
                edges.iter().map(|edge| edge.key.edge_type as u8),
            )),
            Arc::new(LargeStringArray::from_iter_values(
                edges.iter().map(|edge| edge.key.package_id.as_str()),
            )),
            Arc::new(LargeStringArray::from_iter_values(&causes)),
            Arc::new(UInt8Array::from_iter_values(
                edges.iter().map(|edge| edge.key.cause as u8),
            )),
            Arc::new(evidence.finish()),
            Arc::new(proof),
            Arc::new(coverage.finish()),
            Arc::new(UInt64Array::from_iter_values(
                edges.iter().map(|edge| edge.first_boottime_ns),
            )),
            Arc::new(UInt64Array::from_iter_values(
                edges.iter().map(|edge| edge.last_boottime_ns),
            )),
            Arc::new(LargeBinaryArray::from_iter_values(&property_hashes)),
        ];
        let names = [
            "edge_id",
            "value_hash",
            "from_ref",
            "to_ref",
            "edge_type",
            "edge_rank",
            "package_id",
            "cause",
            "cause_rank",
            "evidence_refs",
            "proof_quality",
            "required_coverage_interval_ids",
            "first_boottime_ns",
            "last_boottime_ns",
            "property_hash",
        ];
        let fields = names
            .into_iter()
            .zip(&arrays)
            .map(|(name, array)| Field::new(name, array.data_type().clone(), false))
            .collect::<Vec<_>>();
        let batch = RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays)
            .map_err(|_| NativeRows::invalid("graph edge native batch"))?;
        let mut appender = writer.appender(table).context(DatabaseSnafu {
            operation: "open Graph edge candidates",
        })?;
        appender.append_record_batch(batch).context(DatabaseSnafu {
            operation: "append Graph edge candidates",
        })?;
        appender.flush().context(DatabaseSnafu {
            operation: "flush Graph edge candidates",
        })?;
        Ok(())
    }

    pub fn decode(row: &Row<'_>) -> Result<GraphEdgeV1> {
        let evidence = match NativeRows::column(row, 6)? {
            duckdb::types::Value::List(values) => values
                .into_iter()
                .map(|value| match value {
                    duckdb::types::Value::UInt(id) => Ok(id),
                    _ => Err(NativeRows::invalid("graph relationship evidence")),
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(NativeRows::invalid("graph relationship evidence")),
        };
        Ok(GraphEdgeV1 {
            key: GraphEdgeKeyV1 {
                from: NativeRows::column(row, 1)?,
                to: NativeRows::column(row, 2)?,
                edge_type: NativeRows::label_column(row, 3)?,
                package_id: NativeRows::column(row, 4)?,
                cause: NativeRows::label_column(row, 5)?,
                evidence,
            },
            proof_quality: NativeRows::proof(row, 7)?,
            required_coverage_interval_ids: NativeRows::coverage(row, 8)?,
            first_boottime_ns: NativeRows::column(row, 9)?,
            last_boottime_ns: NativeRows::column(row, 10)?,
        })
    }

    pub fn registry(
        reader: &Connection,
        subjects: &BTreeMap<u64, GraphSubjectKeyV1>,
        evidence: &BTreeMap<u64, DiscoveryRecordIdV1>,
    ) -> Result<BTreeMap<u64, RelationshipIdentity>> {
        Self::validate_properties(reader)?;
        let mut relationships = BTreeMap::new();
        let mut values = BTreeSet::new();
        let mut statement=reader.prepare("SELECT e.edge_id,e.value_hash,e.from_ref,e.to_ref,p.edge_type,p.edge_rank,p.package_id,p.cause,p.cause_rank,e.evidence_refs,p.proof_quality,p.required_coverage_interval_ids,e.first_boottime_ns,e.last_boottime_ns FROM graph_edge_values e LEFT JOIN graph_edge_properties p USING(property_ref)").context(DatabaseSnafu {operation:"prepare Graph edge registry"})?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read Graph edge registry",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph edge registry",
        })? {
            let id = NativeRows::column::<u64>(row, 0)?;
            let hash: Vec<u8> = NativeRows::column(row, 1)?;
            let from = subjects
                .get(&NativeRows::column::<u64>(row, 2)?)
                .cloned()
                .ok_or_else(|| NativeRows::invalid("graph edge source subject"))?;
            let to = subjects
                .get(&NativeRows::column::<u64>(row, 3)?)
                .cloned()
                .ok_or_else(|| NativeRows::invalid("graph edge target subject"))?;
            let key = RelationshipIdentity {
                from,
                to,
                edge_type: NativeRows::label_column(row, 4)?,
                package_id: NativeRows::column(row, 6)?,
                cause: NativeRows::label_column(row, 7)?,
                evidence: FindingRows::evidence_references(row, 9)?
                    .into_iter()
                    .map(|id| {
                        evidence
                            .get(&id)
                            .cloned()
                            .ok_or_else(|| NativeRows::invalid("graph edge evidence reference"))
                    })
                    .collect::<Result<_>>()?,
            };
            let proof = NativeRows::proof(row, 10)?;
            let coverage = NativeRows::coverage(row, 11)?;
            let first: u64 = NativeRows::column(row, 12)?;
            let last: u64 = NativeRows::column(row, 13)?;
            let body = NativeRows::encode(&(&key, proof, coverage, first, last))?;
            if key.edge_type as u8 != NativeRows::column::<u8>(row, 5)?
                || key.cause as u8 != NativeRows::column::<u8>(row, 8)?
                || first > last
                || key.from.tenant_id != key.to.tenant_id
                || key.evidence.windows(2).any(|pair| pair[0] >= pair[1])
                || NativeRows::hash(&body) != hash
                || !values.insert(body)
            {
                return Err(NativeRows::invalid("graph edge registry value"));
            }
            if id == 0 || relationships.insert(id, key).is_some() {
                return Err(NativeRows::invalid("graph duplicate edge value"));
            }
        }
        drop(rows);
        drop(statement);
        Ok(relationships)
    }

    fn validate(edge: &RelationshipValue) -> Result<()> {
        SubjectRows::validate(&edge.key.from)?;
        SubjectRows::validate(&edge.key.to)?;
        if edge.key.from.tenant_id != edge.key.to.tenant_id
            || edge.first_boottime_ns > edge.last_boottime_ns
            || edge.key.evidence.windows(2).any(|pair| pair[0] >= pair[1])
            || (edge.key.edge_type == GraphEdgeTypeV1::NativeParent
                && (edge.key.from.authority != edge.key.to.authority
                    || !matches!(
                        edge.key.from.authority,
                        GraphSubjectAuthorityV1::Native { .. }
                    )))
        {
            return Err(NativeRows::invalid("graph edge proof"));
        }
        Ok(())
    }
    fn property_hash(
        edge_type: GraphEdgeTypeV1,
        package: &str,
        cause: GraphCauseV1,
        proof: ProofQualityV1,
        coverage: &[[u8; 16]],
    ) -> Result<Vec<u8>> {
        Ok(NativeRows::hash(&NativeRows::encode(&(
            edge_type, package, cause, proof, coverage,
        ))?))
    }
    fn validate_properties(reader: &Connection) -> Result<()> {
        let missing:bool=reader.query_row("SELECT EXISTS(SELECT 1 FROM graph_edge_values e LEFT JOIN graph_edge_properties p USING(property_ref) WHERE p.property_ref IS NULL)",[],|row|row.get(0)).context(DatabaseSnafu {operation:"validate Graph property references"})?;
        if missing {
            return Err(NativeRows::invalid("graph edge property reference"));
        }
        let mut statement=reader.prepare("SELECT property_ref,property_hash,edge_type,edge_rank,package_id,cause,cause_rank,proof_quality,required_coverage_interval_ids FROM graph_edge_properties").context(DatabaseSnafu {operation:"prepare Graph property registry"})?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read Graph property registry",
        })?;
        let mut values = BTreeSet::new();
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph property registry",
        })? {
            let edge: GraphEdgeTypeV1 = NativeRows::label_column(row, 2)?;
            let package: String = NativeRows::column(row, 4)?;
            let cause: GraphCauseV1 = NativeRows::label_column(row, 5)?;
            let proof = NativeRows::proof(row, 7)?;
            let coverage = NativeRows::coverage(row, 8)?;
            let body = NativeRows::encode(&(edge, &package, cause, proof, &coverage))?;
            if edge as u8 != NativeRows::column::<u8>(row, 3)?
                || cause as u8 != NativeRows::column::<u8>(row, 6)?
                || NativeRows::hash(&body) != NativeRows::column::<Vec<u8>>(row, 1)?
                || !values.insert(body)
            {
                return Err(NativeRows::invalid("graph edge property value"));
            }
        }
        Ok(())
    }
}
