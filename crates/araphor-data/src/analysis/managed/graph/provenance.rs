use super::*;
use crate::{AnalysisContextRefV1, AnalysisWitnessV1, DiscoveryRecordIdV1};
use std::collections::{BTreeMap, BTreeSet};

mod basis;
pub(in crate::analysis) use basis::{FindingBasis, FindingOrigin};

impl AnalysisStore {
    fn finding_read_parents(
        engine: &araphor_graph::GraphStore,
        tenant: [u8; 16],
        owner: &FindingOrigin,
        wanted: &BTreeSet<DiscoveryRecordIdV1>,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
        validated: &super::super::OwnerRead<'_>,
    ) -> Result<Vec<(FindingOrigin, BTreeSet<DiscoveryRecordIdV1>)>> {
        let mut parents = Vec::new();
        let Some(consumer) = validated.graph_origin(owner.writer, owner.revision)? else {
            return Ok(parents);
        };
        if consumer.result != owner.result {
            return Ok(parents);
        }
        for pin in consumer.reads.iter().filter(|pin| {
            pin.relation == owner.relation && pin.owner == owner.owner && pin.key == owner.key
        }) {
            let Some(producer) = validated.graph_origin(pin.writer, pin.revision)? else {
                continue;
            };
            if producer.result != pin.producer || producer.graph != consumer.graph {
                continue;
            }
            let (id, revision, writer, scope, key) = (
                &pin.producer,
                pin.revision,
                pin.writer,
                &pin.owner,
                &pin.key,
            );
            let bytes = id.len() + scope.len() + key.len();
            charge(
                bytes,
                bytes
                    .checked_mul(4)
                    .and_then(|bytes| bytes.checked_add(12 * std::mem::size_of::<FindingOrigin>()))
                    .ok_or_else(|| Code::Limit.error("native finding parent memory"))?,
            )?;
            control.check()?;
            let heads = BTreeMap::from([(writer, revision)]);
            let rows = engine.members(
                owner.relation,
                &heads,
                Some(std::slice::from_ref(key)),
                || control.check().map_err(araphor_graph::Error::backend),
            )?;
            for row in rows.into_iter().filter(|row| {
                row.writer == writer
                    && row.revision == revision
                    && row.owner_key.as_ref() == scope.as_slice()
            }) {
                let native = row.property_batch()?;
                let bytes = native
                    .get_array_memory_size()
                    .checked_mul(20)
                    .ok_or_else(|| Code::Limit.error("native finding parent memory"))?;
                charge(bytes, bytes)?;
                let port = araphor_analysis_types::FindingMember::port();
                let data = sdk::Dataset {
                    name: port.name,
                    batches: vec![sdk::Dataset::normalize_batch(native, Arc::new(port.schema))
                        .context(crate::AnalysisContractSnafu)?],
                };
                for member in araphor_analysis_types::FindingMember::decode(&data)
                    .context(crate::AnalysisContractSnafu)?
                {
                    if revision == 0
                        || revision >= owner.revision
                        || writer == 0
                        || member.value.tenant_id != tenant
                        || araphor_analysis_types::DomainRelations::key(&member.value.finding_id)
                            .context(crate::AnalysisContractSnafu)?
                            != *key
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
                                result: id.clone(),
                                revision,
                                relation: owner.relation,
                                writer,
                                owner: scope.clone(),
                                key: key.clone(),
                            },
                            records,
                        ));
                    }
                }
            }
        }
        Ok(parents)
    }

    pub(in crate::analysis) fn finding_basis_on(
        engine: &araphor_graph::GraphStore,
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
        let mut owners = BTreeMap::<FindingOrigin, BTreeSet<DiscoveryRecordIdV1>>::new();
        for id in findings {
            control.check()?;
            let key = araphor_analysis_types::DomainRelations::key(id)
                .context(crate::AnalysisContractSnafu)?;
            let rows =
                validated.finding_rows(engine, reader, tenant, result, Some(&[key]), charge)?;
            let mut present = false;
            for row in rows {
                control.check()?;
                let member = row.decode(charge)?;
                if member.value.tenant_id != tenant
                    || member.value.finding_id != *id
                    || row.origin_revision == 0
                    || row.origin.is_empty()
                {
                    return Err(Code::Denied.error("native finding origin authority"));
                }
                let origin = FindingOrigin {
                    result: row.origin,
                    revision: row.origin_revision,
                    relation: row.member.relation,
                    writer: row.member.writer,
                    owner: row.member.owner_key.to_vec(),
                    key: row.member.key.to_vec(),
                };
                let records = owners.entry(origin).or_default();
                records.extend(member.value.evidence);
                records.insert(member.anchor.record);
                if let Some(fact) = member.anchor.fact {
                    records.insert(fact.record);
                }
                present = true;
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
        let mut basis = FindingBasis::default();
        while let Some((owner, mut records)) = owners.pop_first() {
            control.check()?;
            basis.visit(&owner, &mut records);
            if records.is_empty() {
                continue;
            }
            let origin = &owner.result;
            let revision = owner.revision;
            let producer = validated.producer(origin, revision, charge)?;
            let record = &producer.record;
            let uncovered = basis.observe(&records, record);
            let parents = Self::finding_read_parents(
                engine, tenant, &owner, &records, control, charge, validated,
            )?;
            basis.parents(&mut owners, uncovered, parents)?;
            let graph = validated
                .graph_origin(owner.writer, revision)?
                .ok_or_else(|| Code::Missing.error("native finding origin"))?;
            let mut keys = BTreeSet::new();
            for record in &records {
                let key = araphor_analysis_types::DomainRelations::key(record)
                    .context(crate::AnalysisContractSnafu)?;
                charge(0, key.len() + std::mem::size_of::<DiscoveryRecordIdV1>())?;
                keys.insert(key);
            }
            let visible = validated.producer_contexts(origin, charge)?;
            for value in visible.iter() {
                control.check()?;
                let fact = graph.facts.get(&value.key);
                basis.context(
                    value,
                    &records,
                    &record.proofs,
                    fact.is_some(),
                    fact.is_some_and(|key| keys.contains(key)),
                )?;
            }
        }
        basis.finish(tenant, evidence, require_proof)
    }
}
