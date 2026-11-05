use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::analysis::graph_rows::store::{source::DiscoveryRecordIdV1, values::*};
use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, Row};
use sdk::{
    arrow_array::{
        builder::{LargeBinaryBuilder, LargeListBuilder, UInt64Builder},
        ArrayRef, LargeBinaryArray, LargeStringArray, RecordBatch, UInt64Array, UInt8Array,
    },
    arrow_schema::{Field, Schema},
};
use snafu::ResultExt as _;

use crate::analysis::graph_rows::store::{
    error::DatabaseSnafu, native::NativeRows, FindingRows, Result, SubjectRows,
};

pub struct RelationshipRows;

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
            Self::validate(&edge.key, edge.first_boottime_ns, edge.last_boottime_ns)?;
        }
        if edges.is_empty() {
            return Ok(Vec::new());
        }
        let properties = Self::intern_properties(writer, edges)?;
        let mut keys = BTreeMap::<Vec<u8>, Vec<usize>>::new();
        for (ordinal, edge) in edges.iter().enumerate() {
            let from = subjects
                .get(&edge.key.from)
                .copied()
                .ok_or_else(|| NativeRows::invalid("graph edge subject"))?;
            let to = subjects
                .get(&edge.key.to)
                .copied()
                .ok_or_else(|| NativeRows::invalid("graph edge subject"))?;
            let evidence = edge
                .key
                .evidence
                .iter()
                .map(|record| {
                    records
                        .get(record)
                        .copied()
                        .ok_or_else(|| NativeRows::invalid("graph edge evidence"))
                })
                .collect::<Result<Vec<_>>>()?;
            let key = Self::value_key(
                from,
                to,
                properties[ordinal],
                &evidence,
                edge.first_boottime_ns,
                edge.last_boottime_ns,
            )?;
            keys.entry(key).or_default().push(ordinal);
        }
        let mut values = vec![0; edges.len()];
        writer
            .execute_batch("CREATE TEMP TABLE graph_value_edges(value_key BLOB PRIMARY KEY)")
            .context(DatabaseSnafu {
                operation: "stage Graph edge candidates",
            })?;
        let result = (|| -> Result<()> {
            {
                let mut appender = writer
                    .appender("graph_value_edges")
                    .context(DatabaseSnafu {
                        operation: "open Graph edge candidates",
                    })?;
                for key in keys.keys() {
                    appender.append_row(params![key]).context(DatabaseSnafu {
                        operation: "append Graph edge candidate",
                    })?;
                }
                appender.flush().context(DatabaseSnafu {
                    operation: "flush Graph edge candidates",
                })?;
            }
            let mut statement = writer.prepare("SELECT e.edge_id,e.value_key,e.from_ref,e.to_ref,e.property_ref,e.evidence_refs,e.first_boottime_ns,e.last_boottime_ns FROM graph_value_edges c JOIN graph_edge_values e USING(value_key)").context(DatabaseSnafu { operation: "prepare Graph edge candidates" })?;
            let mut rows = statement.query([]).context(DatabaseSnafu {
                operation: "read Graph edge candidates",
            })?;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance Graph edge candidates",
            })? {
                let key = Self::check_value(row)?;
                let value = NativeRows::column::<u64>(row, 0)?;
                let ordinals = keys
                    .get(&key)
                    .ok_or_else(|| NativeRows::invalid("graph edge candidate"))?;
                if value == 0 || values[ordinals[0]] != 0 {
                    return Err(NativeRows::invalid("graph duplicate edge value"));
                }
                for ordinal in ordinals {
                    values[*ordinal] = value;
                }
            }
            Ok(())
        })();
        let cleanup = writer
            .execute_batch("DROP TABLE graph_value_edges")
            .context(DatabaseSnafu {
                operation: "release Graph edge candidates",
            });
        result?;
        cleanup?;
        let missing = keys
            .iter()
            .filter(|(_, ordinals)| values[ordinals[0]] == 0)
            .map(|(key, ordinals)| (key.as_slice(), ordinals.as_slice()))
            .collect::<Vec<_>>();
        let allocated = NativeRows::allocate(writer, "graph_edge_values_seq", missing.len())?;
        let mut inserts = Vec::with_capacity(missing.len());
        for ((key, ordinals), value) in missing.into_iter().zip(allocated) {
            for ordinal in ordinals {
                values[*ordinal] = value;
            }
            inserts.push((value, ordinals[0], key));
        }
        if !inserts.is_empty() {
            Self::append_edges(writer, subjects, records, edges, &properties, &inserts)?;
        }
        Ok(values)
    }

    fn intern_properties(writer: &Connection, edges: &[RelationshipValue]) -> Result<Vec<u64>> {
        let mut keys = BTreeMap::<Vec<u8>, Vec<usize>>::new();
        for (ordinal, edge) in edges.iter().enumerate() {
            let key = Self::property_key(
                edge.key.edge_type,
                &edge.key.package_id,
                edge.key.cause,
                edge.proof_quality,
                &edge.required_coverage_interval_ids,
            )?;
            keys.entry(key).or_default().push(ordinal);
        }
        let mut values = vec![0; edges.len()];
        let mut missing = Vec::new();
        let mut statement = writer.prepare("WITH candidates AS MATERIALIZED (SELECT * FROM graph_edge_properties WHERE property_key=?) SELECT property_ref,property_key,edge_type,edge_rank,package_id,cause,cause_rank,proof_quality,required_coverage_interval_ids FROM candidates").context(DatabaseSnafu { operation: "prepare Graph property candidate" })?;
        for (key, ordinals) in &keys {
            let mut rows = statement.query(params![key]).context(DatabaseSnafu {
                operation: "read Graph property candidate",
            })?;
            let value = rows
                .next()
                .context(DatabaseSnafu {
                    operation: "advance Graph property candidate",
                })?
                .map(|row| {
                    Self::check_property(row)?;
                    NativeRows::column::<u64>(row, 0)
                })
                .transpose()?;
            if value == Some(0)
                || rows
                    .next()
                    .context(DatabaseSnafu {
                        operation: "check unique Graph property value",
                    })?
                    .is_some()
            {
                return Err(NativeRows::invalid("graph duplicate property value"));
            }
            if let Some(value) = value {
                for ordinal in ordinals {
                    values[*ordinal] = value;
                }
            } else {
                missing.push((key.as_slice(), ordinals.as_slice()));
            }
        }
        drop(statement);
        let allocated = NativeRows::allocate(writer, "graph_edge_properties_seq", missing.len())?;
        let mut inserts = Vec::with_capacity(missing.len());
        for ((key, ordinals), value) in missing.into_iter().zip(allocated) {
            for ordinal in ordinals {
                values[*ordinal] = value;
            }
            inserts.push((value, ordinals[0], key));
        }
        if !inserts.is_empty() {
            Self::append_properties(writer, edges, &inserts)?;
        }
        Ok(values)
    }

    fn append_properties(
        writer: &Connection,
        edges: &[RelationshipValue],
        inserts: &[(u64, usize, &[u8])],
    ) -> Result<()> {
        let mut coverage = LargeListBuilder::new(LargeBinaryBuilder::new());
        let mut types = Vec::with_capacity(inserts.len());
        let mut causes = Vec::with_capacity(inserts.len());
        for (_, ordinal, _) in inserts {
            let edge = &edges[*ordinal];
            types.push(NativeRows::label(&edge.key.edge_type)?);
            causes.push(NativeRows::label(&edge.key.cause)?);
            for id in &edge.required_coverage_interval_ids {
                coverage.values().append_value(id);
            }
            coverage.append(true);
        }
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(UInt64Array::from_iter_values(
                inserts.iter().map(|(id, _, _)| *id),
            )),
            Arc::new(LargeBinaryArray::from_iter_values(
                inserts.iter().map(|(_, _, key)| *key),
            )),
            Arc::new(LargeStringArray::from_iter_values(&types)),
            Arc::new(UInt8Array::from_iter_values(
                inserts
                    .iter()
                    .map(|(_, row, _)| edges[*row].key.edge_type as u8),
            )),
            Arc::new(LargeStringArray::from_iter_values(
                inserts
                    .iter()
                    .map(|(_, row, _)| edges[*row].key.package_id.as_str()),
            )),
            Arc::new(LargeStringArray::from_iter_values(&causes)),
            Arc::new(UInt8Array::from_iter_values(
                inserts
                    .iter()
                    .map(|(_, row, _)| edges[*row].key.cause as u8),
            )),
            Arc::new(NativeRows::proofs(
                inserts.iter().map(|(_, row, _)| edges[*row].proof_quality),
            )),
            Arc::new(coverage.finish()),
        ];
        Self::append(
            writer,
            "graph_edge_properties",
            &[
                "property_ref",
                "property_key",
                "edge_type",
                "edge_rank",
                "package_id",
                "cause",
                "cause_rank",
                "proof_quality",
                "required_coverage_interval_ids",
            ],
            arrays,
        )
    }

    fn append_edges(
        writer: &Connection,
        subjects: &BTreeMap<GraphSubjectKeyV1, u64>,
        records: &BTreeMap<DiscoveryRecordIdV1, u64>,
        edges: &[RelationshipValue],
        properties: &[u64],
        inserts: &[(u64, usize, &[u8])],
    ) -> Result<()> {
        let mut evidence = LargeListBuilder::new(UInt64Builder::new());
        let mut from = Vec::with_capacity(inserts.len());
        let mut to = Vec::with_capacity(inserts.len());
        for (_, ordinal, _) in inserts {
            let edge = &edges[*ordinal];
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
        }
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(UInt64Array::from_iter_values(
                inserts.iter().map(|(id, _, _)| *id),
            )),
            Arc::new(LargeBinaryArray::from_iter_values(
                inserts.iter().map(|(_, _, key)| *key),
            )),
            Arc::new(UInt64Array::from(from)),
            Arc::new(UInt64Array::from(to)),
            Arc::new(UInt64Array::from_iter_values(
                inserts.iter().map(|(_, row, _)| properties[*row]),
            )),
            Arc::new(evidence.finish()),
            Arc::new(UInt64Array::from_iter_values(
                inserts
                    .iter()
                    .map(|(_, row, _)| edges[*row].first_boottime_ns),
            )),
            Arc::new(UInt64Array::from_iter_values(
                inserts
                    .iter()
                    .map(|(_, row, _)| edges[*row].last_boottime_ns),
            )),
        ];
        Self::append(
            writer,
            "graph_edge_values",
            &[
                "edge_id",
                "value_key",
                "from_ref",
                "to_ref",
                "property_ref",
                "evidence_refs",
                "first_boottime_ns",
                "last_boottime_ns",
            ],
            arrays,
        )
    }

    fn append(
        writer: &Connection,
        table: &str,
        names: &[&str],
        arrays: Vec<ArrayRef>,
    ) -> Result<()> {
        let fields = names
            .iter()
            .zip(&arrays)
            .map(|(name, array)| Field::new(*name, array.data_type().clone(), false))
            .collect::<Vec<_>>();
        let batch = RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays)
            .map_err(|_| NativeRows::invalid("graph edge native batch"))?;
        let mut appender = writer.appender(table).context(DatabaseSnafu {
            operation: "open Graph edge values",
        })?;
        appender.append_record_batch(batch).context(DatabaseSnafu {
            operation: "append Graph edge values",
        })?;
        appender.flush().context(DatabaseSnafu {
            operation: "flush Graph edge values",
        })?;
        Ok(())
    }

    fn value_key(
        from: u64,
        to: u64,
        property: u64,
        evidence: &[u64],
        first: u64,
        last: u64,
    ) -> Result<Vec<u8>> {
        NativeRows::encode(&(from, to, property, evidence, first, last))
    }

    fn check_value(row: &Row<'_>) -> Result<Vec<u8>> {
        let from = NativeRows::column(row, 2)?;
        let to = NativeRows::column(row, 3)?;
        let property = NativeRows::column(row, 4)?;
        let evidence = FindingRows::evidence_references(row, 5)?;
        let first = NativeRows::column(row, 6)?;
        let last = NativeRows::column(row, 7)?;
        if first > last {
            return Err(NativeRows::invalid("graph edge native value"));
        }
        let key = Self::value_key(from, to, property, &evidence, first, last)?;
        if key != NativeRows::column::<Vec<u8>>(row, 1)? {
            return Err(NativeRows::invalid("graph edge native value"));
        }
        Ok(key)
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
        let mut statement=reader.prepare("SELECT e.edge_id,e.value_key,e.from_ref,e.to_ref,e.property_ref,e.evidence_refs,e.first_boottime_ns,e.last_boottime_ns,p.edge_type,p.edge_rank,p.package_id,p.cause,p.cause_rank,p.proof_quality,p.required_coverage_interval_ids FROM graph_edge_values e LEFT JOIN graph_edge_properties p USING(property_ref)").context(DatabaseSnafu {operation:"prepare Graph edge registry"})?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read Graph edge registry",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph edge registry",
        })? {
            let id = NativeRows::column::<u64>(row, 0)?;
            Self::check_value(row)?;
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
                edge_type: NativeRows::label_column(row, 8)?,
                package_id: NativeRows::column(row, 10)?,
                cause: NativeRows::label_column(row, 11)?,
                evidence: FindingRows::evidence_references(row, 5)?
                    .into_iter()
                    .map(|id| {
                        evidence
                            .get(&id)
                            .cloned()
                            .ok_or_else(|| NativeRows::invalid("graph edge evidence reference"))
                    })
                    .collect::<Result<_>>()?,
            };
            let proof = NativeRows::proof(row, 13)?;
            let coverage = NativeRows::coverage(row, 14)?;
            let first: u64 = NativeRows::column(row, 6)?;
            let last: u64 = NativeRows::column(row, 7)?;
            Self::validate(&key, first, last)?;
            let body = NativeRows::encode(&(&key, proof, coverage, first, last))?;
            if key.edge_type as u8 != NativeRows::column::<u8>(row, 9)?
                || key.cause as u8 != NativeRows::column::<u8>(row, 12)?
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

    fn validate(key: &RelationshipIdentity, first: u64, last: u64) -> Result<()> {
        SubjectRows::validate(&key.from)?;
        SubjectRows::validate(&key.to)?;
        if key.from.tenant_id != key.to.tenant_id
            || first > last
            || key.evidence.windows(2).any(|pair| pair[0] >= pair[1])
            || (key.edge_type == GraphEdgeTypeV1::NativeParent
                && (key.from.authority != key.to.authority
                    || !matches!(key.from.authority, GraphSubjectAuthorityV1::Native { .. })))
        {
            return Err(NativeRows::invalid("graph edge proof"));
        }
        Ok(())
    }
    fn property_key(
        edge_type: GraphEdgeTypeV1,
        package: &str,
        cause: GraphCauseV1,
        proof: ProofQualityV1,
        coverage: &[[u8; 16]],
    ) -> Result<Vec<u8>> {
        NativeRows::encode(&(edge_type, package, cause, proof, coverage))
    }
    fn check_property(row: &Row<'_>) -> Result<Vec<u8>> {
        let edge: GraphEdgeTypeV1 = NativeRows::label_column(row, 2)?;
        let package: String = NativeRows::column(row, 4)?;
        let cause: GraphCauseV1 = NativeRows::label_column(row, 5)?;
        let proof = NativeRows::proof(row, 7)?;
        let coverage = NativeRows::coverage(row, 8)?;
        let body = Self::property_key(edge, &package, cause, proof, &coverage)?;
        if edge as u8 != NativeRows::column::<u8>(row, 3)?
            || cause as u8 != NativeRows::column::<u8>(row, 6)?
            || body != NativeRows::column::<Vec<u8>>(row, 1)?
        {
            return Err(NativeRows::invalid("graph edge property value"));
        }
        Ok(body)
    }

    fn validate_properties(reader: &Connection) -> Result<()> {
        let missing:bool=reader.query_row("SELECT EXISTS(SELECT 1 FROM graph_edge_values e LEFT JOIN graph_edge_properties p USING(property_ref) WHERE p.property_ref IS NULL)",[],|row|row.get(0)).context(DatabaseSnafu {operation:"validate Graph property references"})?;
        if missing {
            return Err(NativeRows::invalid("graph edge property reference"));
        }
        let mut statement=reader.prepare("SELECT property_ref,property_key,edge_type,edge_rank,package_id,cause,cause_rank,proof_quality,required_coverage_interval_ids FROM graph_edge_properties").context(DatabaseSnafu {operation:"prepare Graph property registry"})?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read Graph property registry",
        })?;
        let mut values = BTreeSet::new();
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph property registry",
        })? {
            if !values.insert(Self::check_property(row)?) {
                return Err(NativeRows::invalid("graph duplicate property value"));
            }
        }
        Ok(())
    }
}
