use super::*;
use std::collections::BTreeMap;

type Identity = (u64, Vec<u8>, Vec<u8>);

#[derive(Default)]
pub(in crate::analysis) struct Basis {
    subjects: BTreeMap<Identity, Vec<algorithm::SubjectChange>>,
    edges: BTreeMap<Identity, Vec<algorithm::RelationshipChange>>,
    findings: BTreeMap<Identity, Vec<FindingMember>>,
    states: BTreeMap<Identity, Vec<GraphStateMember>>,
}

impl Basis {
    pub(in crate::analysis) fn append(
        &mut self,
        identity: (u64, &[u8], &[u8]),
        declaration: &sdk::GraphRelation,
        spec: &sdk::GraphSpec,
        native: sdk::RecordBatch,
        scratch: &mut DomainScratch<'_>,
    ) -> Result<()> {
        let subjects = DomainRelations::subjects(declaration);
        let edges = DomainRelations::relationships(declaration, spec);
        let findings = DomainRelations::findings(declaration);
        let states = DomainRelations::states(declaration);
        if !subjects && !edges && !findings && !states {
            return Ok(());
        }
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
        } else if states {
            GraphStateMember::port()
        } else {
            FindingMember::port()
        };
        let data = sdk::Dataset {
            name: port.name,
            batches: vec![sdk::Dataset::normalize_batch(native, Arc::new(port.schema))
                .context(crate::AnalysisContractSnafu)?],
        };
        let identity = (identity.0, identity.1.to_vec(), identity.2.to_vec());
        if subjects {
            self.subjects.entry(identity).or_default().extend(
                algorithm::SubjectChange::decode(&data).context(crate::AnalysisContractSnafu)?,
            );
        } else if edges {
            for value in algorithm::RelationshipChange::decode(&data)
                .context(crate::AnalysisContractSnafu)?
            {
                let expired = value.retained_expiry();
                self.edges.entry(identity.clone()).or_default().push(value);
                let key =
                    DomainRelations::key(&expired.key).context(crate::AnalysisContractSnafu)?;
                self.edges
                    .entry((identity.0, identity.1.clone(), key))
                    .or_default()
                    .push(expired);
            }
        } else if states {
            for value in GraphStateMember::decode(&data).context(crate::AnalysisContractSnafu)? {
                let values = self.states.entry(identity.clone()).or_default();
                values.push(value.clone().retained_expiry());
                values.push(value);
            }
        } else {
            for value in FindingMember::decode(&data).context(crate::AnalysisContractSnafu)? {
                let values = self.findings.entry(identity.clone()).or_default();
                values.push(value.retained_expiry());
                values.push(value);
            }
        }
        Ok(())
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
    pub(super) fn state(
        &self,
        relation: u64,
        batch: &sdk::RecordBatch,
        row: usize,
        value: &GraphStateMember,
    ) -> Result<bool> {
        Ok(self
            .states
            .get(&Self::identity(relation, batch, row)?)
            .is_some_and(|values| values.contains(value)))
    }
}
