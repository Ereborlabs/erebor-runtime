use std :: { collections :: { BTreeMap , BTreeSet } , sync :: Arc } ;

use araphor_analysis_sdk as sdk;
use araphor_analysis_types::DomainRelations;
use araphor_graph::native::{Graph, Member, View};
use sdk::arrow_array::{Array, BinaryArray, StringArray, StructArray};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::ManagedGraphJournal;
use crate :: analysis :: { managed :: PreparedMemory , native :: { DataView , DataWrite , ManagedCommit , NativeStore } } ;
use crate::{ManagedReceipt, NativeStorageSnafu, PackageErrorCodeV1 as Code, Result};

mod expiry;
mod findings;
pub(in crate::analysis) use findings::FindingRead;
mod recovery;

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
enum Kind {
    Relationship,
    Finding,
}

impl Kind {
    fn group(
        self,
        graph: u64,
        expected_tenant: [u8; 16],
        key: &[u8],
        value: &sdk::RecordBatch,
    ) -> Result<Vec<u8>> {
        let group_key = match self {
            Kind::Relationship => rmp_serde::to_vec(&("graph-relationship", graph, key))
                .context(crate::ManagedEncodingSnafu)?,
            Kind::Finding => {
                let finding = value
                    .column_by_name("value")
                    .and_then(|array| array.as_any().downcast_ref::<StructArray>())
                    .ok_or_else(|| Code::Invalid.error("projected Graph finding value"))?;
                let tenant = finding
                    .column_by_name("tenant_id")
                    .and_then(|array| array.as_any().downcast_ref::<BinaryArray>())
                    .filter(|array| !array.is_null(0))
                    .ok_or_else(|| Code::Invalid.error("projected Graph finding tenant"))?;
                let finding_id = finding
                    .column_by_name("finding_id")
                    .and_then(|array| array.as_any().downcast_ref::<StringArray>())
                    .filter(|array| !array.is_null(0))
                    .ok_or_else(|| Code::Invalid.error("projected Graph finding identity"))?;
                if tenant.value(0) != expected_tenant {
                    return Err(Code::Denied.error("projected Graph finding scope"));
                }
                rmp_serde::to_vec(&("graph-finding", graph, tenant.value(0), finding_id.value(0)))
                    .context(crate::ManagedEncodingSnafu)?
            }
        };
        Ok(group_key)
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct Property {
    graph: u64,
    writer: u64,
    relation: u64,
    owner: Vec<u8>,
    key: Vec<u8>,
    revision: u64,
    layer: u64,
    member: u64,
    owner_id: u64,
    group: u64,
    kind: Kind,
}

impl Property {
    fn check(&self, head: u64) -> Result<()> {
        if [
            self.graph,
            self.writer,
            self.relation,
            self.revision,
            self.layer,
            self.member,
            self.owner_id,
            self.group,
        ]
        .contains(&0)
            || self.revision > head
        {
            return Err(Code::Invalid.error("projected Graph reference identity"));
        }
        Ok(())
    }
}

struct Index;
impl Index {
    const PROPERTY: &'static [u8] = b"\0data/graph/property/";
    const LIVE: &'static [u8] = b"\0data/graph/live/";
    const OWNED: &'static [u8] = b"\0data/graph/owned/";
    const GROUP: &'static [u8] = b"\0data/graph/group/";
    const CANONICAL: &'static [u8] = b"\0data/graph/canonical/";
    const CANDIDATE: &'static [u8] = b"\0data/graph/candidate/";
    const FINDING: &'static [u8] = b"\0data/graph/finding/";

    fn key(prefix: &[u8], parts: &[u64]) -> Vec<u8> {
        prefix
            .iter()
            .copied()
            .chain(parts.iter().flat_map(|id| id.to_be_bytes()))
            .collect()
    }

    fn member(graph: u64, writer: u64, relation: u64, owner: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&("graph-member", graph, writer, relation, owner, key))
            .context(crate::ManagedEncodingSnafu)
    }

    fn owner(graph: u64, writer: u64, owner: &[u8]) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&("graph-owner", graph, writer, owner))
            .context(crate::ManagedEncodingSnafu)
    }

    fn finding(tenant: [u8; 16], graph: u64, group: u64) -> Vec<u8> {
        [
            Self::FINDING,
            &tenant,
            &graph.to_be_bytes(),
            &group.to_be_bytes(),
        ]
        .concat()
    }
}

use super::super::Records;

impl DataView {
    pub(in crate::analysis::native) fn graph_finding_value(
        &self,
        graph: u64,
        member: &Member,
    ) -> Result<u64> {
        let id = Records::find(
            &Index::member(
                graph,
                member.writer,
                member.relation,
                &member.owner,
                &member.key,
            )?,
            |key| Records::read(key, &self.snapshot),
        )?
        .ok_or_else(|| Code::Missing.error("Graph finding member identity"))?;
        let property = Records::find(
            &rmp_serde::to_vec(&("graph-property", id, member.revision))
                .context(crate::ManagedEncodingSnafu)?,
            |key| Records::read(key, &self.snapshot),
        )?
        .ok_or_else(|| Code::Missing.error("Graph finding property identity"))?;
        Records::read(&Index::key(Index::CANONICAL, &[property]), &self.snapshot)?
            .map(|bytes| NativeStore::number(&bytes))
            .transpose()?
            .ok_or_else(|| Code::Missing.error("Graph finding canonical value"))
    }
}

struct Value {
    batch: sdk::RecordBatch,
    _member: Option<Member>,
}

struct Values<'a> {
    store: &'a NativeStore,
    reserve: &'a dyn Fn(usize) -> Result<Option<araphor_graph::native::Lease>>,
    views: BTreeMap<(u64, u64), View>,
    values: BTreeMap<u64, Value>,
    leases: Vec<araphor_graph::native::Lease>,
}

impl Values<'_> {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        if let Some(lease) = (self.reserve)(bytes)? {
            self.leases.push(lease);
        }
        Ok(())
    }

    fn graph_reserve(
        &self,
        _: u64,
        bytes: usize,
        _: usize,
    ) -> araphor_graph::Result<Option<araphor_graph::native::Lease>> {
        (self.reserve)(bytes).map_err(araphor_graph::Error::backend)
    }

    fn load(&mut self, id: u64, property: &Property) -> Result<()> {
        if self.values.contains_key(&id) {
            return Ok(());
        }
        self.charge(12 * size_of::<Value>())?;
        let cut = (property.graph, property.revision);
        if !self.views.contains_key(&cut) {
            let snapshot = self.store.read_at(property.revision)?;
            let view = Graph::new(property.graph)?.view(
                snapshot.snapshot().clone(),
                BTreeMap::new(),
                &|writer, bytes, total| self.graph_reserve(writer, bytes, total),
            )?;
            self.views.insert(cut, view);
        }
        if self.views[&cut].head(property.writer)? != Some(property.layer) {
            return Err(Code::Invalid.error("native projected Graph layer"));
        }
        let member = self.views[&cut]
            .member(
                property.writer,
                property.relation,
                &property.owner,
                &property.key,
                &|writer, bytes, total| self.graph_reserve(writer, bytes, total),
            )?
            .ok_or_else(|| Code::Invalid.error("native projected Graph property"))?;
        if member.writer != property.writer
            || member.relation != property.relation
            || member.owner != property.owner
            || member.key != property.key
            || member.revision != property.revision
        {
            return Err(Code::Invalid.error("native projected Graph property identity"));
        }
        let batch = member.properties().slice(member.row, 1);
        self.values.insert(
            id,
            Value {
                batch,
                _member: Some(member),
            },
        );
        Ok(())
    }

    fn equal(&self, left: u64, right: u64, kind: Kind) -> Result<bool> {
        let fields: &[&str] = match kind {
            Kind::Relationship => &[
                "proof_quality",
                "required_coverage_interval_ids",
                "first_boottime_ns",
                "last_boottime_ns",
            ],
            Kind::Finding => &["value"],
        };
        for name in fields {
            let left = self.values[&left]
                .batch
                .column_by_name(name)
                .ok_or_else(|| Code::Invalid.error("projected Graph value field"))?;
            let right = self.values[&right]
                .batch
                .column_by_name(name)
                .ok_or_else(|| Code::Invalid.error("projected Graph value field"))?;
            if left.to_data() != right.to_data() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl DataWrite<'_> {
    fn projected_property(
        &self,
        id: u64,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Property> {
        let bytes = Records::charged_payload(
            &Index::key(Index::PROPERTY, &[id]),
            |key| Records::staged(key, &self.transaction),
            charge,
        )?
        .ok_or_else(|| Code::Invalid.error("projected Graph reference"))?;
        let property: Property = Records::decode(&bytes)?;
        property.check(self.revision)?;
        Ok(property)
    }

    fn projection_refs(
        &self,
        prefix: &[u8],
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Vec<u64>> {
        let mut values = Vec::new();
        for entry in self.transaction.prefix(prefix) {
            charge(0)?;
            let (_, value) = entry.context(NativeStorageSnafu {
                operation: "read affected Graph references",
            })?;
            charge(12 * size_of::<u64>())?;
            values.push(NativeStore::number(&value)?);
        }
        Ok(values)
    }

    pub(super) fn project_graph(
        &mut self,
        input: &ManagedCommit<'_>,
        receipt: &ManagedReceipt,
        results: &BTreeMap<u64, u64>,
        journals: &[Arc<ManagedGraphJournal>],
        memory: &mut PreparedMemory<'_>,
    ) -> Result<()> {
        let mut removed = BTreeSet::new();
        let mut affected = BTreeMap::new();
        for journal in journals {
            for owner in journal.work.journal.clear_owners() {
                let mut parts = vec![journal.call.graph, journal.call.writer];
                if let Some(owner) = owner {
                    let Some(id) = Records::find(
                        &Index::owner(journal.call.graph, journal.call.writer, owner)?,
                        |key| Records::staged(key, &self.transaction),
                    )?
                    else {
                        continue;
                    };
                    parts.push(id);
                }
                removed.extend(
                    self.projection_refs(&Index::key(Index::OWNED, &parts), &mut |bytes| {
                        memory.charge(bytes)
                    })?,
                );
            }
            for (relation, owner, key, _) in journal.work.journal.touched_keys() {
                let Some(member) = Records::find(
                    &Index::member(
                        journal.call.graph,
                        journal.call.writer,
                        relation,
                        owner,
                        key,
                    )?,
                    |key| Records::staged(key, &self.transaction),
                )?
                else {
                    continue;
                };
                if let Some(value) =
                    Records::staged(&Index::key(Index::LIVE, &[member]), &self.transaction)?
                {
                    memory.charge(12 * size_of::<u64>())?;
                    removed.insert(NativeStore::number(&value)?);
                }
            }
        }
        for id in removed {
            let property = self.projected_property(id, &mut |bytes| memory.charge(bytes))?;
            affected.insert(property.group, property.kind);
            self.transaction
                .remove(Index::key(Index::LIVE, &[property.member]));
            self.transaction.remove(Index::key(
                Index::OWNED,
                &[
                    property.graph,
                    property.writer,
                    property.owner_id,
                    property.member,
                ],
            ));
            self.transaction
                .remove(Index::key(Index::GROUP, &[property.group, property.member]));
        }
        let store = self.store;
        let mut new_values = BTreeMap::new();
        for journal in journals {
            for (relation, batch, row) in journal.work.journal.final_rows() {
                memory.check()?;
                let declaration = journal
                    .call
                    .spec
                    .relations
                    .iter()
                    .find(|declaration| journal.call.relations[&declaration.name] == relation)
                    .ok_or_else(|| Code::Invalid.error("projected Graph declaration"))?;
                let kind = if DomainRelations::findings(declaration) {
                    Kind::Finding
                } else if DomainRelations::relationships(declaration, &journal.call.spec) {
                    Kind::Relationship
                } else {
                    continue;
                };
                let column = |name| {
                    batch
                        .column_by_name(name)
                        .and_then(|array| array.as_any().downcast_ref::<BinaryArray>())
                        .filter(|array| !array.is_null(row))
                        .ok_or_else(|| Code::Invalid.error("projected Graph member key"))
                };
                let owner = column("owner")?.value(row);
                let key = column("key")?.value(row);
                memory.charge(
                    (owner.len() + key.len())
                        .saturating_mul(8)
                        .saturating_add(16 * size_of::<Property>()),
                )?;
                let properties = batch
                    .column_by_name("properties")
                    .and_then(|array| array.as_any().downcast_ref::<StructArray>())
                    .filter(|array| !array.is_null(row))
                    .ok_or_else(|| Code::Invalid.error("projected Graph member properties"))?;
                let properties = properties.slice(row, 1);
                let value = sdk::RecordBatch::try_new(
                    Arc::new(declaration.properties.clone()),
                    properties.columns().to_vec(),
                )
                .context(crate::PackageArrowSnafu)?;
                let graph = journal.call.graph;
                let group_key = kind.group(graph, input.attempt.1.spec.tenant, key, &value)?;
                let group = Records::intern(&mut self.transaction, &group_key)?;
                let owner_id = Records::intern(
                    &mut self.transaction,
                    &Index::owner(graph, journal.call.writer, owner)?,
                )?;
                let member = Records::intern(
                    &mut self.transaction,
                    &Index::member(graph, journal.call.writer, relation, owner, key)?,
                )?;
                let id = Records::intern(
                    &mut self.transaction,
                    &rmp_serde::to_vec(&("graph-property", member, self.revision))
                        .context(crate::ManagedEncodingSnafu)?,
                )?;
                let property = Property {
                    graph,
                    writer: journal.call.writer,
                    relation,
                    owner: owner.to_vec(),
                    key: key.to_vec(),
                    revision: self.revision,
                    layer: results[&journal.call.call],
                    member,
                    owner_id,
                    group,
                    kind,
                };
                Records::stage(
                    &mut self.transaction,
                    Index::key(Index::PROPERTY, &[id]),
                    Records::named(&property)?,
                );
                self.transaction
                    .insert(Index::key(Index::LIVE, &[member]), id.to_be_bytes());
                self.transaction.insert(
                    Index::key(Index::OWNED, &[graph, property.writer, owner_id, member]),
                    id.to_be_bytes(),
                );
                self.transaction
                    .insert(Index::key(Index::GROUP, &[group, member]), id.to_be_bytes());
                affected.insert(group, kind);
                new_values.insert(
                    id,
                    Value {
                        batch: value,
                        _member: None,
                    },
                );
            }
        }
        let reserve = |bytes| {
            if bytes == 0 {
                memory.check()?;
                Ok(None)
            } else {
                memory.reserve(bytes).map(Some)
            }
        };
        let mut values = Values {
            store,
            reserve: &reserve,
            views: BTreeMap::new(),
            values: new_values,
            leases: Vec::new(),
        };
        for (group, kind) in affected {
            let references = self
                .projection_refs(&Index::key(Index::GROUP, &[group]), &mut |bytes| {
                    values.charge(bytes)
                })?;
            if let Some(first) = references.first() {
                for id in &references {
                    let property =
                        self.projected_property(*id, &mut |bytes| values.charge(bytes))?;
                    if property.group != group || property.kind != kind {
                        return Err(Code::Invalid.error("projected Graph group identity"));
                    }
                    values.load(*id, &property)?;
                    if !values.equal(*first, *id, kind)? {
                        return Err(Code::Conflict.error(match kind {
                            Kind::Relationship => "public Graph relationship value",
                            Kind::Finding => "public Graph finding value",
                        }));
                    }
                }
            }
            if kind == Kind::Finding {
                self.canonical_findings(
                    input.attempt.1.spec.tenant,
                    journals[0].call.graph,
                    group,
                    &references,
                    &mut values,
                )?;
            }
        }
        self.check_expired_source(input, &mut values)?;
        drop(values);
        let _ = receipt;
        self.dirty = true;
        Ok(())
    }

    fn canonical_findings(
        &mut self,
        tenant: [u8; 16],
        graph: u64,
        group: u64,
        references: &[u64],
        values: &mut Values<'_>,
    ) -> Result<()> {
        let head = Index::finding(tenant, graph, group);
        if references.is_empty() {
            if Records::staged(&head, &self.transaction)?.is_some() {
                self.transaction.remove(head);
            }
            return Ok(());
        }
        let first = references[0];
        let mut winner = None;
        for entry in self
            .transaction
            .prefix(Index::key(Index::CANDIDATE, &[group]))
        {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "read historical finding candidates",
            })?;
            let id = NativeStore::number(&key[key.len() - 8..])?;
            let property = self.projected_property(id, &mut |bytes| values.charge(bytes))?;
            if property.group != group || property.kind != Kind::Finding {
                return Err(Code::Invalid.error("historical finding candidate identity"));
            }
            values.load(id, &property)?;
            if values.equal(first, id, Kind::Finding)? {
                winner = Some(winner.map_or(id, |prior: u64| prior.min(id)));
            }
        }
        let winner = winner.unwrap_or_else(|| *references.iter().min().unwrap_or(&first));
        self.transaction
            .insert(Index::key(Index::CANDIDATE, &[group, winner]), []);
        for id in references {
            let key = Index::key(Index::CANONICAL, &[*id]);
            if let Some(prior) = Records::staged(&key, &self.transaction)? {
                if NativeStore::number(&prior)? != winner {
                    return Err(Code::Invalid.error("canonical finding reference"));
                }
            } else {
                self.transaction.insert(key, winner.to_be_bytes());
            }
        }
        if Records::staged(&head, &self.transaction)?
            .map(|value| NativeStore::number(&value))
            .transpose()?
            != Some(winner)
        {
            self.transaction.insert(head, winner.to_be_bytes());
        }
        Ok(())
    }
}
