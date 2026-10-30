use super::*;
use crate::GraphValidate as _;

pub(super) struct EdgeValue {
    pub key: RelationshipIdentity,
    pub proof_quality: ProofQualityV1,
    pub required_coverage_interval_ids: Vec<[u8; 16]>,
    pub first_boottime_ns: u64,
    pub last_boottime_ns: u64,
}

impl From<&RelationshipChange> for EdgeValue {
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

impl GraphRows {
    pub(super) fn intern_subjects(
        writer: &Connection,
        subjects: &[GraphSubjectKeyV1],
    ) -> Result<BTreeMap<GraphSubjectKeyV1, u64>> {
        let subjects = subjects.iter().collect::<BTreeSet<_>>();
        if subjects.is_empty() {
            return Ok(BTreeMap::new());
        }
        writer.execute_batch("CREATE TEMP TABLE graph_value_subjects AS SELECT * EXCLUDE(subject_id) FROM graph_subject_values WHERE false").context(AnalysisDatabaseSnafu {operation:"create Graph subject candidates"})?;
        {
            let mut appender =
                writer
                    .appender("graph_value_subjects")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph subject candidates",
                    })?;
            for subject in &subjects {
                subject.validate()?;
                let (rank, text, boot, epoch) = Self::authority(&subject.authority);
                appender
                    .append_row(params![
                        subject.tenant_id.as_slice(),
                        rank,
                        text,
                        boot,
                        epoch,
                        subject.kind as u8,
                        subject.identity
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph subject candidate",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph subject candidates",
            })?;
        }
        let equal="v.tenant_id=c.tenant_id AND v.authority_rank=c.authority_rank AND v.authority_text=c.authority_text AND v.authority_boot=c.authority_boot AND v.authority_epoch=c.authority_epoch AND v.subject_kind=c.subject_kind AND v.identity=c.identity";
        writer.execute_batch(&format!("INSERT INTO graph_subject_values SELECT nextval('graph_subject_values_seq'),c.* FROM graph_value_subjects c WHERE NOT EXISTS(SELECT 1 FROM graph_subject_values v WHERE {equal})")).context(AnalysisDatabaseSnafu {operation:"intern Graph subject candidates"})?;
        let mut statement = writer
            .prepare(&format!(
                "SELECT v.* FROM graph_value_subjects c JOIN graph_subject_values v ON {equal}"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph subject references",
            })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph subject references",
        })?;
        let mut values = BTreeMap::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph subject references",
        })? {
            if values
                .insert(Self::decode_subject(row)?, Self::column(row, 0)?)
                .is_some()
            {
                return Err(Self::invalid("graph duplicate subject value"));
            }
        }
        drop(rows);
        drop(statement);
        writer
            .execute_batch("DROP TABLE graph_value_subjects")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph subject candidates",
            })?;
        if values.len() != subjects.len() {
            return Err(Self::invalid("graph subject candidate count"));
        }
        Ok(values)
    }

    pub(super) fn intern_edges(
        writer: &Connection,
        subjects: &BTreeMap<GraphSubjectKeyV1, u64>,
        records: &BTreeMap<crate::DiscoveryRecordIdV1, u64>,
        edges: &[EdgeValue],
    ) -> Result<Vec<u64>> {
        if edges.is_empty() {
            return Ok(Vec::new());
        }
        writer.execute_batch("CREATE TEMP TABLE graph_value_edges AS SELECT e.edge_id,e.value_hash,e.from_ref,e.to_ref,p.edge_type,p.edge_rank,p.package_id,p.cause,p.cause_rank,e.evidence_refs,p.proof_quality,p.required_coverage_interval_ids,e.first_boottime_ns,e.last_boottime_ns,p.property_hash FROM graph_edge_values e JOIN graph_edge_properties p USING(property_ref) WHERE false").context(AnalysisDatabaseSnafu {operation:"create Graph edge candidates"})?;
        Self::append_edges(writer, "graph_value_edges", subjects, records, edges)?;
        let property="p.property_hash=c.property_hash AND p.edge_type=c.edge_type AND p.edge_rank=c.edge_rank AND p.package_id=c.package_id AND p.cause=c.cause AND p.cause_rank=c.cause_rank AND p.proof_quality=c.proof_quality AND p.required_coverage_interval_ids=c.required_coverage_interval_ids";
        let invalid:bool=writer.query_row(&format!("SELECT EXISTS(SELECT 1 FROM graph_value_edges c JOIN graph_edge_properties p ON p.property_hash=c.property_hash WHERE NOT ({property}))"),[],|row|row.get(0)).context(AnalysisDatabaseSnafu {operation:"check Graph edge properties"})?;
        if invalid {
            return Err(Self::invalid("graph edge property value"));
        }
        writer.execute_batch(&format!("INSERT INTO graph_edge_properties SELECT nextval('graph_edge_properties_seq'),c.property_hash,c.edge_type,c.edge_rank,c.package_id,c.cause,c.cause_rank,c.proof_quality,c.required_coverage_interval_ids FROM (SELECT DISTINCT property_hash,edge_type,edge_rank,package_id,cause,cause_rank,proof_quality,required_coverage_interval_ids FROM graph_value_edges) c WHERE NOT EXISTS(SELECT 1 FROM graph_edge_properties p WHERE {property})")).context(AnalysisDatabaseSnafu {operation:"intern Graph edge properties"})?;
        let expanded="SELECT e.edge_id,e.value_hash,e.from_ref,e.to_ref,p.edge_type,p.edge_rank,p.package_id,p.cause,p.cause_rank,e.evidence_refs,p.proof_quality,p.required_coverage_interval_ids,e.first_boottime_ns,e.last_boottime_ns,p.property_hash FROM graph_edge_values e LEFT JOIN graph_edge_properties p USING(property_ref)";
        let equal="v.property_hash=c.property_hash AND v.value_hash=c.value_hash AND v.from_ref=c.from_ref AND v.to_ref=c.to_ref AND v.edge_type=c.edge_type AND v.edge_rank=c.edge_rank AND v.package_id=c.package_id AND v.cause=c.cause AND v.cause_rank=c.cause_rank AND v.evidence_refs=c.evidence_refs AND v.proof_quality=c.proof_quality AND v.required_coverage_interval_ids=c.required_coverage_interval_ids AND v.first_boottime_ns=c.first_boottime_ns AND v.last_boottime_ns=c.last_boottime_ns";
        let identity="v.from_ref=c.from_ref AND v.to_ref=c.to_ref AND v.edge_type=c.edge_type AND v.package_id=c.package_id AND v.cause=c.cause AND v.evidence_refs=c.evidence_refs";
        let corrupt:bool=writer.query_row(&format!("SELECT EXISTS(SELECT 1 FROM graph_value_edges c JOIN ({expanded}) v ON v.value_hash=c.value_hash WHERE v.property_hash IS NULL OR ({identity} AND NOT ({equal})))"),[],|row|row.get(0)).context(AnalysisDatabaseSnafu {operation:"check Graph edge candidates"})?;
        if corrupt {
            return Err(Self::invalid("duplicate graph edge value"));
        }
        writer.execute_batch(&format!("INSERT INTO graph_edge_values SELECT nextval('graph_edge_values_seq'),c.value_hash,c.from_ref,c.to_ref,p.property_ref,c.evidence_refs,c.first_boottime_ns,c.last_boottime_ns FROM (SELECT DISTINCT * EXCLUDE(edge_id) FROM graph_value_edges) c JOIN graph_edge_properties p ON {property} WHERE NOT EXISTS(SELECT 1 FROM ({expanded}) v WHERE {equal})")).context(AnalysisDatabaseSnafu {operation:"intern Graph edge candidates"})?;
        let mut statement=writer.prepare(&format!("SELECT c.edge_id,v.edge_id FROM graph_value_edges c JOIN ({expanded}) v ON {equal} ORDER BY c.edge_id")).context(AnalysisDatabaseSnafu {operation:"prepare Graph edge references"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph edge references",
        })?;
        let mut values = Vec::with_capacity(edges.len());
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph edge references",
        })? {
            if Self::column::<u64>(row, 0)? != values.len() as u64 {
                return Err(Self::invalid("graph duplicate edge value"));
            }
            values.push(Self::column(row, 1)?);
        }
        drop(rows);
        drop(statement);
        writer
            .execute_batch("DROP TABLE graph_value_edges")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph edge candidates",
            })?;
        if values.len() != edges.len() {
            return Err(Self::invalid("graph edge candidate count"));
        }
        Ok(values)
    }

    fn append_edges(
        writer: &Connection,
        table: &str,
        subjects: &BTreeMap<GraphSubjectKeyV1, u64>,
        records: &BTreeMap<crate::DiscoveryRecordIdV1, u64>,
        edges: &[EdgeValue],
    ) -> Result<()> {
        use sdk::{
            arrow_array::{
                builder::{LargeBinaryBuilder, LargeListBuilder, UInt64Builder},
                ArrayRef, LargeBinaryArray, LargeStringArray, RecordBatch, StructArray,
                UInt64Array, UInt8Array,
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
                    .ok_or_else(|| Self::invalid("graph edge subject"))?,
            );
            to.push(
                *subjects
                    .get(&edge.key.to)
                    .ok_or_else(|| Self::invalid("graph edge subject"))?,
            );
            for record in &edge.key.evidence {
                evidence.values().append_value(
                    *records
                        .get(record)
                        .ok_or_else(|| Self::invalid("graph edge evidence"))?,
                );
            }
            evidence.append(true);
            for id in &edge.required_coverage_interval_ids {
                coverage.values().append_value(id);
            }
            coverage.append(true);
            hashes.push(Self::hash(&Self::encode_value(&(
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
            types.push(Self::label(&edge.key.edge_type)?);
            causes.push(Self::label(&edge.key.cause)?);
        }
        let ranks = edges
            .iter()
            .map(|edge| {
                let proof = edge.proof_quality;
                [
                    proof.source_authority as u8,
                    proof.local_subject_binding as u8,
                    proof.remote_subject_binding as u8,
                    proof.operation_result_authority as u8,
                    proof.temporal_coverage as u8,
                    proof.integrity as u8,
                ]
            })
            .collect::<Vec<_>>();
        let names = [
            "source_authority",
            "local_subject_binding",
            "remote_subject_binding",
            "operation_result_authority",
            "temporal_coverage",
            "integrity",
        ];
        let proof = StructArray::from(
            names
                .into_iter()
                .enumerate()
                .map(|(index, name)| {
                    (
                        Arc::new(Field::new(name, sdk::arrow_schema::DataType::UInt8, false)),
                        Arc::new(UInt8Array::from_iter_values(
                            ranks.iter().map(|ranks| ranks[index]),
                        )) as ArrayRef,
                    )
                })
                .collect::<Vec<_>>(),
        );
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
            .map_err(|_| Self::invalid("graph edge native batch"))?;
        let mut appender = writer.appender(table).context(AnalysisDatabaseSnafu {
            operation: "open Graph edge candidates",
        })?;
        appender
            .append_record_batch(batch)
            .context(AnalysisDatabaseSnafu {
                operation: "append Graph edge candidates",
            })?;
        appender.flush().context(AnalysisDatabaseSnafu {
            operation: "flush Graph edge candidates",
        })?;
        Ok(())
    }

    pub(super) fn intern_findings(
        writer: &Connection,
        subjects: &BTreeMap<GraphSubjectKeyV1, u64>,
        records: &BTreeMap<crate::DiscoveryRecordIdV1, u64>,
        findings: &[FindingV1],
    ) -> Result<BTreeMap<String, u64>> {
        let references = findings
            .iter()
            .map(|finding| {
                finding.validate()?;
                Ok(araphor_graph::FindingRefs {
                    finding,
                    subject: *subjects
                        .get(&finding.subject_id)
                        .ok_or_else(|| Self::invalid("graph finding subject"))?,
                    evidence: finding
                        .evidence
                        .iter()
                        .map(|record| {
                            records
                                .get(record)
                                .copied()
                                .ok_or_else(|| Self::invalid("graph finding evidence"))
                        })
                        .collect::<Result<Vec<_>>>()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        araphor_graph::FindingRows::intern(writer, &references).map_err(Into::into)
    }

    pub(super) fn intern_branches(
        writer: &Connection,
        tenant: [u8; 16],
        branches: &[GraphBranchV1],
    ) -> Result<Vec<u64>> {
        if branches.is_empty() {
            return Ok(Vec::new());
        }
        writer.execute_batch("CREATE TEMP TABLE graph_value_branches(ordinal UBIGINT,tenant_id BLOB,value_hash BLOB,body BLOB)").context(AnalysisDatabaseSnafu {operation:"create Graph branch candidates"})?;
        {
            let mut appender =
                writer
                    .appender("graph_value_branches")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph branch candidates",
                    })?;
            for (ordinal, branch) in branches.iter().enumerate() {
                Self::check_branch(branch, tenant)?;
                let body = Self::encode_value(branch)?;
                appender
                    .append_row(params![
                        ordinal as u64,
                        tenant.as_slice(),
                        Self::hash(&body),
                        body
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph branch candidate",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph branch candidates",
            })?;
        }
        writer.execute_batch("INSERT INTO graph_branch_values SELECT nextval('graph_branch_values_seq'),c.* FROM (SELECT DISTINCT tenant_id,value_hash,body FROM graph_value_branches) c WHERE NOT EXISTS(SELECT 1 FROM graph_branch_values v WHERE v.tenant_id=c.tenant_id AND v.value_hash=c.value_hash AND v.body=c.body)").context(AnalysisDatabaseSnafu {operation:"intern Graph branch candidates"})?;
        let mut statement=writer.prepare("SELECT c.ordinal,v.branch_id FROM graph_value_branches c JOIN graph_branch_values v ON v.tenant_id=c.tenant_id AND v.value_hash=c.value_hash AND v.body=c.body ORDER BY c.ordinal").context(AnalysisDatabaseSnafu {operation:"prepare Graph branch references"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph branch references",
        })?;
        let mut values = Vec::with_capacity(branches.len());
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph branch references",
        })? {
            if Self::column::<u64>(row, 0)? != values.len() as u64 {
                return Err(Self::invalid("graph duplicate branch value"));
            }
            values.push(Self::column(row, 1)?);
        }
        drop(rows);
        drop(statement);
        writer
            .execute_batch("DROP TABLE graph_value_branches")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph branch candidates",
            })?;
        if values.len() != branches.len() {
            return Err(Self::invalid("graph branch candidate count"));
        }
        Ok(values)
    }
}
