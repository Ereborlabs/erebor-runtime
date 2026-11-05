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
        journal: &ManagedGraphJournal,
        scratch: &mut DomainScratch<'_>,
    ) -> Result<Self> {
        if journal.work.reads.is_empty() {
            return Ok(Self::default());
        }
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
            let wanted = journal
                .work
                .reads
                .iter()
                .filter(|row| row.relation == relation)
                .map(|row| {
                    (
                        row.writer,
                        row.owner.as_slice(),
                        row.key.as_slice(),
                        row.revision,
                    )
                })
                .collect::<std::collections::BTreeSet<_>>();
            let keys = wanted
                .iter()
                .map(|(_, _, key, _)| key.to_vec())
                .collect::<Vec<_>>();
            for row in journal.prepared.view.members(relation, Some(&keys), || {
                scratch.charge(0).map_err(araphor_graph::Error::backend)
            })? {
                if !wanted.contains(&(
                    row.writer,
                    row.owner_key.as_ref(),
                    row.key.as_ref(),
                    row.revision,
                )) {
                    continue;
                }
                let native = row.property_batch()?;
                scratch.charge(
                    native
                        .get_array_memory_size()
                        .checked_mul(16)
                        .ok_or_else(|| Code::Limit.error("domain Graph retained memory"))?,
                )?;
                let port = if subjects {
                    algorithm::SubjectChange::port()
                } else if edges {
                    algorithm::RelationshipChange::port()
                } else {
                    FindingMember::port()
                };
                let data = sdk::Dataset {
                    name: port.name,
                    batches: vec![
                        sdk::Dataset::normalize_batch(native, Arc::new(port.schema))
                            .context(crate::AnalysisContractSnafu)?,
                    ],
                };
                let identity = (relation, row.owner_key.to_vec(), row.key.to_vec());
                if subjects {
                    basis.subjects.entry(identity).or_default().extend(
                        algorithm::SubjectChange::decode(&data)
                            .context(crate::AnalysisContractSnafu)?,
                    );
                } else if edges {
                    for value in algorithm::RelationshipChange::decode(&data)
                        .context(crate::AnalysisContractSnafu)?
                    {
                        let expired = value.retained_expiry();
                        basis.edges.entry(identity.clone()).or_default().push(value);
                        let key = DomainRelations::key(&expired.key)
                            .context(crate::AnalysisContractSnafu)?;
                        basis
                            .edges
                            .entry((relation, row.owner_key.to_vec(), key))
                            .or_default()
                            .push(expired);
                    }
                } else {
                    for value in
                        FindingMember::decode(&data).context(crate::AnalysisContractSnafu)?
                    {
                        let values = basis.findings.entry(identity.clone()).or_default();
                        values.push(value.retained_expiry());
                        values.push(value);
                    }
                }
            }
        }
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
