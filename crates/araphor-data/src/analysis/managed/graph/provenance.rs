use super::*;
use crate::{AnalysisContextRefV1, AnalysisWitnessV1, DiscoveryRecordIdV1};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct FindingOrigin {
    result: String,
    revision: u64,
    relation: u64,
    writer: u64,
    owner: Vec<u8>,
    key: Vec<u8>,
}

impl AnalysisStore {
    fn finding_read_parents(
        reader: &duckdb::Connection,
        tenant: [u8; 16],
        owner: &FindingOrigin,
        wanted: &BTreeSet<DiscoveryRecordIdV1>,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Vec<(FindingOrigin, BTreeSet<DiscoveryRecordIdV1>)>> {
        use sdk::arrow_array::{Array as _, BinaryArray, StringArray, StructArray, UInt64Array};
        let relation = owner.relation;
        let mut query = reader.prepare(&format!(
            "SELECT origin.producer_id,pin.revision,pin.writer_id,pin.owner_key,pin.entity_key,properties.properties
             FROM managed_graph_row_reads pin JOIN managed_graph_reads origin ON origin.result_id=pin.result_id
                AND origin.writer_id=pin.writer_id AND origin.revision=pin.revision
             JOIN managed_graph_results consumer ON consumer.result_id=pin.result_id
                AND consumer.writer_id=? AND consumer.revision=?
             JOIN managed_graph_writers writer ON writer.writer_id=consumer.writer_id
             JOIN managed_graphs graph ON graph.graph_id=writer.graph_id AND graph.tenant_id=?
             JOIN graph_relations relation ON relation.graph_id=graph.graph_id AND relation.relation_id=pin.relation_id
             JOIN graph_writer_owners scope ON scope.writer_id=pin.writer_id AND scope.owner_key=pin.owner_key
             JOIN graph_members member ON member.writer_id=pin.writer_id AND member.owner_ref=scope.owner_ref
                AND member.relation_id=pin.relation_id AND member.entity_key=pin.entity_key AND member.valid_from=pin.revision
             JOIN managed_graph_results producer ON producer.result_id=origin.producer_id
                AND producer.writer_id=pin.writer_id AND producer.revision=pin.revision
             JOIN graph_properties_{relation} properties ON properties.property_ref=member.properties_ref
             WHERE pin.result_id=? AND pin.relation_id=? AND pin.owner_key=? AND pin.entity_key=?
             ORDER BY pin.revision,pin.writer_id"))
            .context(AnalysisDatabaseSnafu { operation:"prepare native finding read parents" })?;
        let batches = query
            .query_arrow(params![
                owner.writer,
                owner.revision,
                tenant.as_slice(),
                owner.result,
                owner.relation,
                owner.owner,
                owner.key
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "read native finding read parents",
            })?;
        let mut parents = Vec::new();
        for batch in batches {
            control.check()?;
            let bytes = batch
                .get_array_memory_size()
                .checked_mul(20)
                .ok_or_else(|| Code::Limit.error("native finding parent memory"))?;
            charge(bytes, bytes)?;
            let ids = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| Code::Invalid.error("native finding parent result"))?;
            let revisions = batch
                .column(1)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| Code::Invalid.error("native finding parent revision"))?;
            let writers = batch
                .column(2)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| Code::Invalid.error("native finding parent writer"))?;
            let owners = batch
                .column(3)
                .as_any()
                .downcast_ref::<BinaryArray>()
                .ok_or_else(|| Code::Invalid.error("native finding parent owner"))?;
            let keys = batch
                .column(4)
                .as_any()
                .downcast_ref::<BinaryArray>()
                .ok_or_else(|| Code::Invalid.error("native finding parent key"))?;
            let properties = batch
                .column(5)
                .as_any()
                .downcast_ref::<StructArray>()
                .ok_or_else(|| Code::Invalid.error("native finding parent properties"))?;
            if batch
                .columns()
                .iter()
                .any(|column| column.null_count() != 0)
            {
                return Err(Code::Invalid.error("native finding parent null"));
            }
            let port = araphor_analysis_types::FindingMember::port();
            let native = sdk::RecordBatch::try_new(
                Arc::new(sdk::Schema::new(properties.fields().clone())),
                properties.columns().to_vec(),
            )
            .context(crate::PackageArrowSnafu)?;
            let data = sdk::Dataset {
                name: port.name,
                batches: vec![sdk::Dataset::normalize_batch(native, Arc::new(port.schema))
                    .context(crate::AnalysisContractSnafu)?],
            };
            for (row, member) in araphor_analysis_types::FindingMember::decode(&data)
                .context(crate::AnalysisContractSnafu)?
                .into_iter()
                .enumerate()
            {
                if revisions.value(row) == 0
                    || revisions.value(row) >= owner.revision
                    || writers.value(row) == 0
                    || member.value.tenant_id != tenant
                    || araphor_analysis_types::DomainRelations::key(&member.value.finding_id)
                        .context(crate::AnalysisContractSnafu)?
                        .as_slice()
                        != keys.value(row)
                {
                    return Err(Code::Denied.error("native finding parent authority"));
                }
                let mut records = member.value.evidence.into_iter().collect::<BTreeSet<_>>();
                records.insert(member.anchor.record);
                if let Some(fact) = member.anchor.fact {
                    records.insert(fact.record);
                }
                records.retain(|record| wanted.contains(record));
                if !records.is_empty() {
                    parents.push((
                        FindingOrigin {
                            result: ids.value(row).into(),
                            revision: revisions.value(row),
                            relation,
                            writer: writers.value(row),
                            owner: owners.value(row).to_vec(),
                            key: keys.value(row).to_vec(),
                        },
                        records,
                    ));
                }
            }
        }
        Ok(parents)
    }

    pub(in crate::analysis) fn native_finding_basis(
        reader: &duckdb::Connection,
        tenant: [u8; 16],
        result: &str,
        findings: &BTreeSet<String>,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<(
        Vec<AnalysisWitnessV1>,
        Vec<AnalysisContextRefV1>,
        crate::GraphRevisionV1,
    )> {
        Self::finding_basis(reader, tenant, result, findings, control, charge, true)
    }

    fn finding_basis(
        reader: &duckdb::Connection,
        tenant: [u8; 16],
        result: &str,
        findings: &BTreeSet<String>,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
        require_proof: bool,
    ) -> Result<(
        Vec<AnalysisWitnessV1>,
        Vec<AnalysisContextRefV1>,
        crate::GraphRevisionV1,
    )> {
        let mut owners = super::super::OwnerRead::new(reader, tenant, control);
        Self::finding_basis_on(
            reader,
            tenant,
            result,
            findings,
            control,
            charge,
            require_proof,
            &mut owners,
        )
    }

    pub(in crate::analysis) fn finding_basis_on(
        reader: &duckdb::Connection,
        tenant: [u8; 16],
        result: &str,
        findings: &BTreeSet<String>,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
        require_proof: bool,
        validated: &mut super::super::OwnerRead<'_>,
    ) -> Result<(
        Vec<AnalysisWitnessV1>,
        Vec<AnalysisContextRefV1>,
        crate::GraphRevisionV1,
    )> {
        validated.check_reader(reader, tenant)?;
        let sql = validated
            .finding_sql(reader, tenant, charge)?
            .ok_or_else(|| Code::Missing.error("native finding relations"))?;
        let mut owners = BTreeMap::<FindingOrigin, BTreeSet<DiscoveryRecordIdV1>>::new();
        for id in findings {
            control.check()?;
            let mut query = reader.prepare(&format!("SELECT origin_result_id,origin_revision,properties,relation_id,writer_id,owner_key,entity_key FROM ({sql}) member
                WHERE tenant_id=? AND result_id=? AND properties.value.finding_id=?"))
                .context(AnalysisDatabaseSnafu { operation:"prepare native finding provenance owners" })?;
            let batches = query
                .query_arrow(params![tenant.as_slice(), result, id])
                .context(AnalysisDatabaseSnafu {
                    operation: "read native finding provenance owners",
                })?;
            let mut present = false;
            for batch in batches {
                use sdk::arrow_array::{
                    Array as _, BinaryArray, StringArray, StructArray, UInt64Array,
                };
                control.check()?;
                let bytes = batch.get_array_memory_size();
                charge(
                    bytes,
                    bytes
                        .checked_mul(12)
                        .ok_or_else(|| Code::Limit.error("native finding provenance memory"))?,
                )?;
                let ids = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .ok_or_else(|| Code::Invalid.error("native finding origin identity"))?;
                let revisions = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .ok_or_else(|| Code::Invalid.error("native finding origin revision"))?;
                let properties = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<StructArray>()
                    .ok_or_else(|| Code::Invalid.error("native finding origin properties"))?;
                if ids.null_count() != 0
                    || revisions.null_count() != 0
                    || properties.null_count() != 0
                {
                    return Err(Code::Invalid.error("native finding origin null"));
                }
                let native = sdk::RecordBatch::try_new(
                    Arc::new(sdk::Schema::new(properties.fields().clone())),
                    properties.columns().to_vec(),
                )
                .context(crate::PackageArrowSnafu)?;
                let data = sdk::Dataset {
                    name: araphor_analysis_types::FindingMember::port().name,
                    batches: vec![sdk::Dataset::normalize_batch(
                        native,
                        Arc::new(araphor_analysis_types::FindingMember::port().schema),
                    )
                    .context(crate::AnalysisContractSnafu)?],
                };
                let relation = batch
                    .column(3)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .ok_or_else(|| Code::Invalid.error("native finding origin relation"))?;
                let writer = batch
                    .column(4)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .ok_or_else(|| Code::Invalid.error("native finding origin writer"))?;
                let owner = batch
                    .column(5)
                    .as_any()
                    .downcast_ref::<BinaryArray>()
                    .ok_or_else(|| Code::Invalid.error("native finding origin owner"))?;
                let key = batch
                    .column(6)
                    .as_any()
                    .downcast_ref::<BinaryArray>()
                    .ok_or_else(|| Code::Invalid.error("native finding origin key"))?;
                if relation.null_count() != 0
                    || writer.null_count() != 0
                    || owner.null_count() != 0
                    || key.null_count() != 0
                {
                    return Err(Code::Invalid.error("native finding origin row null"));
                }
                let values = araphor_analysis_types::FindingMember::decode(&data)
                    .context(crate::AnalysisContractSnafu)?;
                for (row, member) in values.into_iter().enumerate() {
                    if member.value.tenant_id != tenant
                        || member.value.finding_id != *id
                        || revisions.value(row) == 0
                        || ids.value(row).is_empty()
                    {
                        return Err(Code::Denied.error("native finding origin authority"));
                    }
                    let origin = FindingOrigin {
                        result: ids.value(row).into(),
                        revision: revisions.value(row),
                        relation: relation.value(row),
                        writer: writer.value(row),
                        owner: owner.value(row).to_vec(),
                        key: key.value(row).to_vec(),
                    };
                    let records = owners.entry(origin).or_default();
                    records.extend(member.value.evidence);
                    records.insert(member.anchor.record);
                    if let Some(fact) = member.anchor.fact {
                        records.insert(fact.record);
                    }
                    present = true;
                }
            }
            if !present {
                return Err(Code::Missing.error("native finding provenance membership"));
            }
        }
        let evidence = owners
            .values()
            .flat_map(|records| records.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        reader
            .execute_batch("CREATE TEMP TABLE native_finding_records(record_key BLOB PRIMARY KEY)")
            .context(AnalysisDatabaseSnafu {
                operation: "create native finding provenance selection",
            })?;
        let selected = (|| {
            let mut witnesses = BTreeMap::new();
            let mut coverage = BTreeSet::new();
            let mut qualified = BTreeSet::new();
            let mut gaps = BTreeSet::new();
            let mut contexts = BTreeMap::new();
            let mut visited = BTreeMap::<FindingOrigin, BTreeSet<DiscoveryRecordIdV1>>::new();
            while let Some((owner, mut records)) = owners.pop_first() {
                control.check()?;
                let known = visited.entry(owner.clone()).or_default();
                records.retain(|record| known.insert(record.clone()));
                if records.is_empty() {
                    continue;
                }
                let origin = &owner.result;
                let revision = owner.revision;
                let producer = validated.producer(origin, revision, charge)?;
                let record = &producer.record;
                if let Some(proof) = &record.graph_proof {
                    for key in &proof.coverage {
                        if records.iter().any(|record| {
                            record.stream == key.source && record.cpu_id == key.cpu_id
                        }) {
                            coverage.insert(key.clone());
                        }
                    }
                    for source in &proof.sources {
                        if records.iter().any(|record| {
                            record.stream == source.source && record.cpu_id == source.cpu
                        }) {
                            gaps.extend(source.missing.iter().copied());
                            qualified.extend(
                                records
                                    .iter()
                                    .filter(|record| {
                                        record.stream == source.source
                                            && record.cpu_id == source.cpu
                                    })
                                    .cloned(),
                            );
                        }
                    }
                }
                let saved = &record.witnesses;
                let mut missing = records
                    .iter()
                    .map(|record| {
                        (
                            crate::AnalysisStreamIdentityV1::Evidence(record.stream.clone()),
                            record.durable_cursor,
                        )
                    })
                    .collect::<BTreeSet<_>>();
                for witness in saved {
                    let key = (witness.identity.clone(), witness.cursor);
                    if !missing.remove(&key) {
                        continue;
                    }
                    let value: &mut AnalysisWitnessV1 =
                        witnesses.entry(key).or_insert_with(|| witness.clone());
                    value.expires_utc_ns = value.expires_utc_ns.min(witness.expires_utc_ns);
                }
                let mut uncovered = records
                    .iter()
                    .filter(|record| {
                        missing.contains(&(
                            crate::AnalysisStreamIdentityV1::Evidence(record.stream.clone()),
                            record.durable_cursor,
                        ))
                    })
                    .cloned()
                    .collect::<BTreeSet<_>>();
                for (parent, records) in
                    Self::finding_read_parents(reader, tenant, &owner, &records, control, charge)?
                {
                    for record in &records {
                        uncovered.remove(record);
                    }
                    owners.entry(parent).or_default().extend(records);
                }
                if !uncovered.is_empty() {
                    return Err(Code::Denied.error("native finding origin witness"));
                }
                reader
                    .execute("DELETE FROM native_finding_records", [])
                    .context(AnalysisDatabaseSnafu {
                        operation: "reset native finding provenance selection",
                    })?;
                {
                    let mut append = reader.appender("native_finding_records").context(
                        AnalysisDatabaseSnafu {
                            operation: "open native finding provenance selection",
                        },
                    )?;
                    for record in records {
                        let key = araphor_analysis_types::DomainRelations::key(&record)
                            .context(crate::AnalysisContractSnafu)?;
                        charge(0, key.len() + std::mem::size_of::<DiscoveryRecordIdV1>())?;
                        append
                            .append_row(params![key])
                            .context(AnalysisDatabaseSnafu {
                                operation: "append native finding provenance selection",
                            })?;
                    }
                    append.flush().context(AnalysisDatabaseSnafu {
                        operation: "flush native finding provenance selection",
                    })?;
                }
                let mut query = reader.prepare(
                    "SELECT pin.owner_id,pin.entity_key,pin.lifetime_key,pin.owner_revision,pin.commit_revision,
                        octet_length(encode(pin.owner_id))+octet_length(pin.entity_key)+octet_length(pin.lifetime_key)
                     FROM context_refs pin JOIN context_versions context ON context.tenant_id=pin.tenant_id
                        AND context.owner_id=pin.owner_id AND context.entity_key=pin.entity_key
                        AND context.lifetime_key=pin.lifetime_key AND context.owner_revision=pin.owner_revision
                        AND context.commit_revision=pin.commit_revision
                     LEFT JOIN graph_fact_records fact ON fact.version_key=context.version_key
                     WHERE pin.tenant_id=? AND pin.ref_id=? AND (
                        fact.record_key IN (SELECT record_key FROM native_finding_records)
                        OR EXISTS(SELECT 1 FROM managed_source_proofs proof JOIN native_finding_records wanted USING(record_key)
                            WHERE proof.result_id=pin.ref_id AND proof.version_key=context.version_key AND proof.revision=context.commit_revision)
                        OR (fact.version_key IS NULL AND NOT EXISTS(SELECT 1 FROM managed_source_proofs proof
                            WHERE proof.result_id=pin.ref_id AND proof.version_key=context.version_key AND proof.revision=context.commit_revision)))",
                ).context(AnalysisDatabaseSnafu { operation:"prepare native finding provenance contexts" })?;
                let mut rows = query.query(params![tenant.as_slice(), origin]).context(
                    AnalysisDatabaseSnafu {
                        operation: "read native finding provenance contexts",
                    },
                )?;
                while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                    operation: "advance native finding provenance contexts",
                })? {
                    control.check()?;
                    let bytes: u64 = row.get(5).context(AnalysisDatabaseSnafu {
                        operation: "bound native finding provenance context",
                    })?;
                    let bytes = usize::try_from(bytes)
                        .ok()
                        .and_then(|bytes| bytes.checked_mul(4))
                        .and_then(|bytes| {
                            bytes.checked_add(4 * std::mem::size_of::<AnalysisContextRefV1>())
                        })
                        .ok_or_else(|| Code::Limit.error("native finding context memory"))?;
                    charge(bytes, bytes)?;
                    let value = (|| -> duckdb::Result<_> {
                        Ok(AnalysisContextRefV1 {
                            key: crate::AnalysisContextKeyV1 {
                                tenant_id: tenant,
                                owner_id: row.get(0)?,
                                entity_key: row.get(1)?,
                                lifetime_key: row.get(2)?,
                                owner_revision: row.get(3)?,
                            },
                            commit_revision: row.get(4)?,
                        })
                    })()
                    .context(AnalysisDatabaseSnafu {
                        operation: "decode native finding provenance context",
                    })?;
                    if contexts
                        .insert(value.key.clone(), value.clone())
                        .is_some_and(|prior| prior != value)
                    {
                        return Err(Code::Conflict.error("native finding context revision"));
                    }
                }
            }
            if require_proof && evidence.iter().any(|record| !qualified.contains(record)) {
                return Err(Code::Missing.error("native finding coverage proof"));
            }
            let contexts = contexts.into_values().collect::<Vec<_>>();
            let revision = crate::GraphRevisionV1 {
                evidence,
                coverage: coverage.into_iter().collect(),
                context: contexts
                    .iter()
                    .map(|reference| reference.key.clone())
                    .collect(),
                missing_ranges: gaps.into_iter().collect(),
            };
            revision.validate(tenant)?;
            Ok((witnesses.into_values().collect(), contexts, revision))
        })();
        let cleanup = reader
            .execute_batch("DROP TABLE native_finding_records")
            .context(AnalysisDatabaseSnafu {
                operation: "release native finding provenance selection",
            });
        let value = selected?;
        cleanup?;
        Ok(value)
    }
}
