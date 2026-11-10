use std::cell::RefCell;

use super::super::super::{references::References, results::ResultBody};
use super::super::origin::GraphOrigin;
use super::*;
use crate::analysis::managed::{
    graph::{FindingBasis, FindingOrigin},
    Record,
};
use crate::analysis::native::context::ContextRecord;
use crate::{
    AnalysisContextRefV1, AnalysisReadControl, AnalysisWitnessV1, DiscoveryRecordIdV1, FindingV1,
    GraphRevisionV1, NotificationErrorCodeV1 as Notice, NotificationFindingRefV1,
    NotificationGrantV1,
};

mod notification;
mod provenance;

struct Producer {
    id: u64,
    origin: GraphOrigin,
    record: Record,
    selected: crate::analysis::PackageResultRefV1,
}

struct FindingRow {
    member: Member,
    origin: FindingOrigin,
    finding: araphor_analysis_types::FindingMember,
}

pub(in crate::analysis) struct FindingRead<'a> {
    store: &'a NativeStore,
    view: &'a DataView,
    tenant: [u8; 16],
    control: &'a AnalysisReadControl,
    charge: RefCell<&'a mut dyn FnMut(usize) -> Result<()>>,
    producers: BTreeMap<(u64, u64), Arc<Producer>>,
    selected: BTreeMap<String, (u64, String, String)>,
    findings: BTreeMap<(String, String), Arc<Vec<FindingRow>>>,
    qualified: BTreeSet<u64>,
    verified: RefCell<crate::analysis::context::VerifiedPackages>,
}

impl<'a> FindingRead<'a> {
    pub(in crate::analysis) fn new(
        store: &'a NativeStore,
        view: &'a DataView,
        tenant: [u8; 16],
        control: &'a AnalysisReadControl,
        charge: &'a mut dyn FnMut(usize) -> Result<()>,
    ) -> Self {
        Self {
            store,
            view,
            tenant,
            control,
            charge: RefCell::new(charge),
            producers: BTreeMap::new(),
            selected: BTreeMap::new(),
            findings: BTreeMap::new(),
            qualified: BTreeSet::new(),
            verified: RefCell::new(crate::analysis::context::VerifiedPackages::default()),
        }
    }

    fn charge(&self, bytes: usize) -> Result<()> {
        self.control.check()?;
        (self.charge.borrow_mut())(bytes)
    }

    fn reserve(
        &self,
        _: u64,
        bytes: usize,
        _: usize,
    ) -> araphor_graph::Result<Option<araphor_graph::native::Lease>> {
        self.charge(bytes).map_err(araphor_graph::Error::backend)?;
        Ok(None)
    }

    fn producer(&mut self, writer: u64, revision: u64) -> Result<Arc<Producer>> {
        self.control.check()?;
        if let Some(producer) = self.producers.get(&(writer, revision)) {
            return Ok(Arc::clone(producer));
        }
        let origin = self
            .view
            .graph_origin_charged(writer, revision, &mut |bytes| self.charge(bytes))?;
        let (id, result, owner) = self.view.result_owner(
            self.tenant,
            &origin.reference.result_id,
            self.control,
            &mut |bytes| self.charge(bytes),
        )?;
        let ResultBody::Call(record) = result.body else {
            return Err(Code::Invalid.error("native finding producer kind"));
        };
        if result.revision != revision
            || record.call != origin.call
            || record.instance != origin.instance
            || owner.instance().grant != origin.grant
            || origin.grant.selection.tenant_id != self.tenant
        {
            return Err(Code::Denied.error("native finding producer authority"));
        }
        let selected = &owner
            .receipt()
            .ok_or_else(|| Code::Missing.error("native finding selected receipt"))?
            .selected;
        self.charge(selected.result_id.len().saturating_mul(4))?;
        let selected = selected.clone();
        self.charge(12 * size_of::<Producer>())?;
        let producer = Arc::new(Producer {
            id,
            origin,
            record,
            selected,
        });
        self.producers
            .insert((writer, revision), Arc::clone(&producer));
        Ok(producer)
    }

    fn decode(&self, member: &Member) -> Result<araphor_analysis_types::FindingMember> {
        let batch = member.properties().slice(member.row, 1);
        self.charge(batch.get_array_memory_size().saturating_mul(12))?;
        let port = araphor_analysis_types::FindingMember::port();
        let batch = sdk::Dataset::normalize_batch(batch, Arc::new(port.schema))
            .context(crate::AnalysisContractSnafu)?;
        let mut values = araphor_analysis_types::FindingMember::decode(&sdk::Dataset {
            name: port.name,
            batches: vec![batch],
        })
        .context(crate::AnalysisContractSnafu)?;
        values
            .pop()
            .ok_or_else(|| Code::Invalid.error("native finding value"))
    }

    fn rows(&mut self, result: &str, ids: &BTreeSet<String>) -> Result<Vec<FindingRow>> {
        let (publication, owner) =
            self.view
                .managed_graph_owner(self.tenant, result, self.control, &mut |bytes| {
                    self.charge(bytes)
                })?;
        if matches!(
            &owner.instance().spec.destination,
            crate::ManagedDestination::Graph { .. }
        ) {
            return Err(Code::Unsupported.error("native source finding owner"));
        }
        let publication =
            publication.ok_or_else(|| Code::Missing.error("native finding publication"))?;
        let at = self.store.read_at(publication.reference.commit_revision)?;
        let mut snapshots = BTreeMap::new();
        for (&writer, &(_, revision)) in &publication.heads {
            self.charge(12 * size_of::<(u64, fjall::BranchSnapshot)>())?;
            snapshots.insert(writer, self.store.read_at(revision)?.snapshot.clone());
        }
        let graph = Graph::new(publication.graph)?.view(
            at.snapshot.clone(),
            snapshots,
            &|writer, bytes, total| self.reserve(writer, bytes, total),
        )?;
        for (&writer, &(layer, _)) in &publication.heads {
            if graph.head(writer)? != Some(layer) {
                return Err(Code::Invalid.error("native finding writer cut"));
            }
        }
        let mut rows = Vec::new();
        for id in ids {
            self.charge(id.len().saturating_mul(4))?;
            let identity =
                rmp_serde::to_vec(&("graph-finding", publication.graph, self.tenant, id))
                    .context(crate::ManagedEncodingSnafu)?;
            let Some(group) = Records::find(&identity, |key| Records::read(key, &at.snapshot))?
            else {
                continue;
            };
            let prefix = Index::key(Index::GROUP, &[group]);
            for entry in at.snapshot.prefix(&prefix) {
                self.charge(0)?;
                let (key, value) = entry.context(NativeStorageSnafu {
                    operation: "read selected finding membership",
                })?;
                if key.len() != prefix.len() + 8 {
                    return Err(Code::Invalid.error("native finding group key"));
                }
                let property_id = NativeStore::number(&value)?;
                let bytes = Records::charged_payload(
                    &Index::key(Index::PROPERTY, &[property_id]),
                    |key| Records::read(key, &at.snapshot),
                    &mut |bytes| self.charge(bytes),
                )?
                .ok_or_else(|| Code::Missing.error("native finding property"))?;
                let property: Property = Records::decode(&bytes)?;
                property.check(at.metadata_revision)?;
                if property.kind != Kind::Finding
                    || property.graph != publication.graph
                    || property.group != group
                    || NativeStore::number(&key[prefix.len()..])? != property.member
                {
                    return Err(Code::Invalid.error("native finding property identity"));
                }
                let member = graph
                    .member(
                        property.writer,
                        property.relation,
                        &property.owner,
                        &property.key,
                        &|writer, bytes, total| self.reserve(writer, bytes, total),
                    )?
                    .ok_or_else(|| Code::Missing.error("native finding selected member"))?;
                if member.revision != property.revision {
                    return Err(Code::Invalid.error("native finding opening revision"));
                }
                let producer = self.producer(member.writer, member.revision)?;
                if producer.origin.graph != publication.graph
                    || producer.origin.layer != property.layer
                {
                    return Err(Code::Denied.error("native finding opening authority"));
                }
                let finding = self.decode(&member)?;
                if finding.value.tenant_id != self.tenant
                    || finding.value.finding_id != *id
                    || DomainRelations::key(id).context(crate::AnalysisContractSnafu)? != member.key
                {
                    return Err(Code::Denied.error("native finding identity"));
                }
                self.charge(
                    (producer.origin.reference.result_id.len()
                        + member.owner.len()
                        + member.key.len())
                    .saturating_mul(4)
                    .saturating_add(12 * size_of::<FindingRow>()),
                )?;
                rows.push(FindingRow {
                    origin: FindingOrigin {
                        result: producer.origin.reference.result_id.clone(),
                        revision: member.revision,
                        relation: member.relation,
                        writer: member.writer,
                        owner: member.owner.clone(),
                        key: member.key.clone(),
                    },
                    member,
                    finding,
                });
            }
        }
        rows.sort_unstable_by(|left, right| {
            (
                left.member.relation,
                left.member.property,
                left.member.writer,
                &left.member.owner,
            )
                .cmp(&(
                    right.member.relation,
                    right.member.property,
                    right.member.writer,
                    &right.member.owner,
                ))
        });
        Ok(rows)
    }
}

impl NativeStore {
    pub fn graph_finding_batch(
        &self,
        tenant: [u8; 16],
        references: &[NotificationFindingRefV1],
    ) -> Result<BTreeMap<String, (GraphRevisionV1, BTreeMap<String, FindingV1>)>> {
        Notice::Invalid.require(
            tenant != [0; 16]
                && references.iter().all(|reference| {
                    NotificationGrantV1::identifier(&reference.finding_id, usize::MAX)
                        && NotificationGrantV1::identifier(&reference.result_id, usize::MAX)
                }),
            "finding reference",
        )?;
        if references.is_empty() {
            return Ok(BTreeMap::new());
        }
        let view = self.view()?;
        let control = AnalysisReadControl::default();
        let mut charge = |_| Ok(());
        let mut reader = FindingRead::new(self, &view, tenant, &control, &mut charge);
        let mut requested = BTreeMap::<&str, BTreeSet<String>>::new();
        for reference in references {
            requested
                .entry(&reference.result_id)
                .or_default()
                .insert(reference.finding_id.clone());
        }
        let mut results = BTreeMap::new();
        for (result, ids) in requested {
            let rows = reader.rows(result, &ids)?;
            let (_, _, revision) = reader.basis(&rows, true)?;
            let mut findings = BTreeMap::new();
            for row in rows {
                revision.validate_finding(&row.finding.value)?;
                findings
                    .entry(row.finding.value.finding_id.clone())
                    .or_insert(row.finding.value);
            }
            results.insert(result.to_owned(), (revision, findings));
        }
        Ok(results)
    }
}
