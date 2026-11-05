use super::*;
use std::collections::BTreeMap;

type Identity = (u64, Vec<u8>, Vec<u8>);

#[derive(Default)]
pub(super) struct Basis {
    subjects: BTreeMap<Identity, Vec<algorithm::SubjectChange>>,
    edges: BTreeMap<Identity, Vec<algorithm::RelationshipChange>>,
    findings: BTreeMap<Identity, Vec<FindingMember>>,
}

impl Basis {
    pub(super) fn read(
        connection: &Connection,
        journal: &ManagedGraphJournal,
        scratch: &mut DomainScratch<'_>,
    ) -> Result<Self> {
        if journal.work.reads.is_empty() {
            return Ok(Self::default());
        }
        connection
            .execute_batch(
                "CREATE TEMP TABLE graph_domain_reads(relation_id UBIGINT,writer_id UBIGINT,
            owner_key BLOB,entity_key BLOB,revision UBIGINT)",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "create domain Graph read basis",
            })?;
        let result = (|| {
            {
                let mut append =
                    connection
                        .appender("graph_domain_reads")
                        .context(AnalysisDatabaseSnafu {
                            operation: "open domain Graph read basis",
                        })?;
                for row in &journal.work.reads {
                    scratch.charge(0)?;
                    if !journal
                        .work
                        .origins
                        .contains_key(&araphor_graph::ReadOrigin {
                            writer: row.writer,
                            revision: row.revision,
                        })
                    {
                        return Err(Code::Denied.error("domain Graph read origin"));
                    }
                    append
                        .append_row(params![
                            row.relation,
                            row.writer,
                            row.owner,
                            row.key,
                            row.revision
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append domain Graph read basis",
                        })?;
                }
                append.flush().context(AnalysisDatabaseSnafu {
                    operation: "flush domain Graph read basis",
                })?;
            }
            let mut basis = Self::default();
            for declaration in &journal.call.spec.relations {
                let subjects = DomainRelations::subjects(declaration);
                let edges = DomainRelations::relationships(declaration, &journal.call.spec);
                let findings = DomainRelations::findings(declaration);
                if !subjects && !edges && !findings {
                    continue;
                }
                let relation = journal.call.relations[&declaration.name];
                let mut query = connection.prepare(&format!(
                    "SELECT wanted.owner_key,wanted.entity_key,properties.properties
                     FROM graph_domain_reads wanted JOIN graph_members member ON member.relation_id=wanted.relation_id
                        AND member.writer_id=wanted.writer_id AND member.entity_key=wanted.entity_key
                        AND member.valid_from=wanted.revision AND member.valid_from<=?
                        AND (member.valid_to IS NULL OR member.valid_to>?)
                     JOIN graph_writer_owners owner ON owner.writer_id=member.writer_id AND owner.owner_ref=member.owner_ref
                        AND owner.owner_key=wanted.owner_key
                     JOIN graph_properties_{relation} properties ON properties.property_ref=member.properties_ref
                     WHERE wanted.relation_id=?"))
                    .context(AnalysisDatabaseSnafu { operation:"prepare domain Graph retained properties" })?;
                let batches = query
                    .query_arrow(params![
                        journal.call.attempt.captured_revision(),
                        journal.call.attempt.captured_revision(),
                        relation
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "read domain Graph retained properties",
                    })?;
                for batch in batches {
                    scratch.charge(
                        batch
                            .get_array_memory_size()
                            .checked_mul(16)
                            .ok_or_else(|| Code::Limit.error("domain Graph retained memory"))?,
                    )?;
                    let owners = batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<BinaryArray>()
                        .ok_or_else(|| Code::Invalid.error("domain Graph retained owner"))?;
                    let keys = batch
                        .column(1)
                        .as_any()
                        .downcast_ref::<BinaryArray>()
                        .ok_or_else(|| Code::Invalid.error("domain Graph retained key"))?;
                    let properties = batch
                        .column(2)
                        .as_any()
                        .downcast_ref::<StructArray>()
                        .ok_or_else(|| Code::Invalid.error("domain Graph retained properties"))?;
                    if owners.null_count() != 0
                        || keys.null_count() != 0
                        || properties.null_count() != 0
                    {
                        return Err(Code::Invalid.error("domain Graph retained null"));
                    }
                    let native = sdk::RecordBatch::try_new(
                        Arc::new(sdk::Schema::new(properties.fields().clone())),
                        properties.columns().to_vec(),
                    )
                    .context(crate::PackageArrowSnafu)?;
                    let port = if subjects {
                        algorithm::SubjectChange::port()
                    } else if edges {
                        algorithm::RelationshipChange::port()
                    } else {
                        FindingMember::port()
                    };
                    let data = sdk::Dataset {
                        name: port.name,
                        batches: vec![sdk::Dataset::normalize_batch(native, Arc::new(port.schema))
                            .context(crate::AnalysisContractSnafu)?],
                    };
                    if subjects {
                        for (row, value) in algorithm::SubjectChange::decode(&data)
                            .context(crate::AnalysisContractSnafu)?
                            .into_iter()
                            .enumerate()
                        {
                            basis
                                .subjects
                                .entry((
                                    relation,
                                    owners.value(row).to_vec(),
                                    keys.value(row).to_vec(),
                                ))
                                .or_default()
                                .push(value);
                        }
                    } else if edges {
                        for (row, value) in algorithm::RelationshipChange::decode(&data)
                            .context(crate::AnalysisContractSnafu)?
                            .into_iter()
                            .enumerate()
                        {
                            let owner = owners.value(row).to_vec();
                            let expired = value.retained_expiry();
                            basis
                                .edges
                                .entry((relation, owner.clone(), keys.value(row).to_vec()))
                                .or_default()
                                .push(value);
                            let key = DomainRelations::key(&expired.key)
                                .context(crate::AnalysisContractSnafu)?;
                            basis
                                .edges
                                .entry((relation, owner, key))
                                .or_default()
                                .push(expired);
                        }
                    } else {
                        for (row, value) in FindingMember::decode(&data)
                            .context(crate::AnalysisContractSnafu)?
                            .into_iter()
                            .enumerate()
                        {
                            let values = basis
                                .findings
                                .entry((
                                    relation,
                                    owners.value(row).to_vec(),
                                    keys.value(row).to_vec(),
                                ))
                                .or_default();
                            values.push(value.retained_expiry());
                            values.push(value);
                        }
                    }
                }
            }
            Ok(basis)
        })();
        let cleanup = connection
            .execute_batch("DROP TABLE graph_domain_reads")
            .context(AnalysisDatabaseSnafu {
                operation: "release domain Graph read basis",
            });
        let basis = result?;
        cleanup?;
        Ok(basis)
    }

    fn identity(relation: u64, batch: &sdk::RecordBatch, row: usize) -> Result<Identity> {
        let column = |name| {
            batch
                .column_by_name(name)
                .and_then(|array| array.as_any().downcast_ref::<BinaryArray>())
                .filter(|array| !array.is_null(row))
                .ok_or_else(|| Code::Invalid.error("domain Graph command identity"))
        };
        Ok((
            relation,
            column("owner")?.value(row).to_vec(),
            column("key")?.value(row).to_vec(),
        ))
    }

    pub(super) fn subject(
        &self,
        relation: u64,
        batch: &sdk::RecordBatch,
        row: usize,
        value: &algorithm::SubjectChange,
    ) -> Result<bool> {
        Ok(self
            .subjects
            .get(&Self::identity(relation, batch, row)?)
            .is_some_and(|values| values.contains(value)))
    }

    pub(super) fn edge(
        &self,
        relation: u64,
        batch: &sdk::RecordBatch,
        row: usize,
        value: &algorithm::RelationshipChange,
    ) -> Result<bool> {
        Ok(self
            .edges
            .get(&Self::identity(relation, batch, row)?)
            .is_some_and(|values| values.contains(value)))
    }

    pub(super) fn finding(
        &self,
        relation: u64,
        batch: &sdk::RecordBatch,
        row: usize,
        value: &FindingMember,
    ) -> Result<bool> {
        Ok(self
            .findings
            .get(&Self::identity(relation, batch, row)?)
            .is_some_and(|values| {
                values
                    .iter()
                    .any(|prior| prior.anchor == value.anchor && prior.value == value.value)
            }))
    }
}
