use super::*;
use sdk::arrow_array::{Array, StringArray, StructArray};
use std::sync::Arc;

pub(in crate::analysis) struct FindingRow {
    pub member: Arc<araphor_graph::Member>,
    pub revision: u64,
    pub origin: String,
    pub origin_revision: u64,
    pub restricted: bool,
    pub value: u64,
}

impl FindingRow {
    pub(in crate::analysis) fn id(&self) -> Result<&str> {
        let value = self
            .member
            .properties()
            .column_by_name("value")
            .and_then(|array| array.as_any().downcast_ref::<StructArray>())
            .and_then(|array| array.column_by_name("finding_id"))
            .and_then(|array| array.as_any().downcast_ref::<StringArray>())
            .filter(|array| !array.is_null(self.member.row))
            .ok_or_else(|| Code::Invalid.error("native finding identity"))?;
        Ok(value.value(self.member.row))
    }

    pub(in crate::analysis) fn decode(
        &self,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<FindingMember> {
        let batch = self.member.property_batch()?;
        let bytes = batch.get_array_memory_size();
        charge(
            bytes,
            bytes
                .checked_mul(12)
                .ok_or_else(|| Code::Limit.error("native finding memory"))?,
        )?;
        let port = FindingMember::port();
        let batch = sdk::Dataset::normalize_batch(batch, Arc::new(port.schema))
            .context(crate::AnalysisContractSnafu)?;
        let mut values = FindingMember::decode(&sdk::Dataset {
            name: port.name,
            batches: vec![batch],
        })
        .context(crate::AnalysisContractSnafu)?;
        values
            .pop()
            .ok_or_else(|| Code::Invalid.error("native finding value"))
    }

    pub(in crate::analysis) fn order(&self) -> (u64, u64, u64, u64) {
        (
            self.member.relation,
            self.member.property,
            self.member.writer,
            self.member.owner,
        )
    }
}

impl DomainProjection {
    pub(in crate::analysis) fn read_findings(
        &self,
        store: &AnalysisStore,
        connection: &Connection,
        tenant: [u8; 16],
        result: &str,
        wanted: Option<&[Vec<u8>]>,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Vec<FindingRow>> {
        let Some(publication) = store
            .managed_results
            .graph_publication(connection, tenant, result)?
        else {
            return Ok(Vec::new());
        };
        let graph = publication.graph;
        let revision = publication.revision;
        charge(
            0,
            wanted.map_or(0, |keys| {
                keys.len().saturating_mul(12 * std::mem::size_of::<usize>())
            }),
        )?;
        let mut selected = Vec::new();
        for (_, relation) in self.findings.iter().filter(|(id, _)| *id == graph) {
            let budget = std::cell::RefCell::new(&mut *charge);
            store.graph_engine.visit_members(
                *relation,
                &publication.heads,
                wanted,
                || budget.borrow_mut()(0, 0).map_err(araphor_graph::Error::backend),
                |member| {
                    budget.borrow_mut()(0, 12 * std::mem::size_of::<FindingRow>())
                        .map_err(araphor_graph::Error::backend)?;
                    selected.push(Arc::clone(member));
                    Ok(())
                },
            )?;
        }
        if selected.is_empty() {
            return Ok(Vec::new());
        }
        let mut findings = Vec::with_capacity(selected.len());
        for member in selected {
            let Some(origin) =
                store
                    .managed_results
                    .graph_origin(tenant, member.writer, member.revision)?
            else {
                continue;
            };
            let Some((_, value)) = store
                .managed_results
                .graph_canonical(member.relation, member.property)?
            else {
                continue;
            };
            charge(0, origin.result.len().saturating_mul(4))?;
            findings.push(FindingRow {
                member,
                revision,
                origin: origin.result.clone(),
                origin_revision: origin.revision,
                restricted: origin.restricted,
                value,
            });
        }
        findings.sort_unstable_by_key(FindingRow::order);
        Ok(findings)
    }
}
