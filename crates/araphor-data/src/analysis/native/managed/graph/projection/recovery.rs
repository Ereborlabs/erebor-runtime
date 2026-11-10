use araphor_analysis_types::{values::RelationshipChange, FindingMember};

use super::*;
use crate::analysis::native::{DataView, ManagedGraph};

type Owners = BTreeMap<u64, ([u8; 16], String, ManagedGraph)>;

fn insert(index: &mut BTreeMap<Vec<u8>, Vec<u8>>, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
    if index
        .insert(key, value.clone())
        .is_some_and(|prior| prior != value)
    {
        return Err(Code::Invalid.error("projected Graph index alias"));
    }
    Ok(())
}

fn find(view: &DataView, identity: &[u8]) -> Result<u64> {
    Records::find(identity, |key| Records::read(key, &view.snapshot))?
        .ok_or_else(|| Code::Missing.error("projected Graph dictionary identity"))
}

fn domain_key(value: &impl Serialize) -> Result<Vec<u8>> {
    DomainRelations::key(value).context(crate::AnalysisContractSnafu)
}

impl Values<'_> {
    fn check_property(
        &mut self,
        current: &DataView,
        id: u64,
        property: &Property,
        tenant: [u8; 16],
    ) -> Result<()> {
        self.load(id, property)?;
        let value = &self.values[&id];
        let member = value
            ._member
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("projected Graph historical member"))?;
        let port = match property.kind {
            Kind::Relationship => RelationshipChange::port(),
            Kind::Finding => FindingMember::port(),
        };
        let data = sdk::Dataset {
            name: port.name,
            batches: vec![sdk::Dataset::normalize_batch(
                value.batch.clone(),
                Arc::new(port.schema),
            )
            .context(crate::AnalysisContractSnafu)?],
        };
        let valid = match property.kind {
            Kind::Relationship => {
                let decoded =
                    RelationshipChange::decode(&data).context(crate::AnalysisContractSnafu)?;
                decoded.first().is_some_and(|_| decoded.len() == 1)
                    && decoded
                        .first()
                        .map(|row| -> Result<bool> {
                            Ok(domain_key(&row.key)? == property.key
                                && member.endpoints.as_ref()
                                    == Some(&[
                                        domain_key(&row.key.from)?,
                                        domain_key(&row.key.to)?,
                                        domain_key(&row.key.edge_type)?,
                                    ]))
                        })
                        .transpose()?
                        .unwrap_or(false)
            }
            Kind::Finding => {
                let decoded = FindingMember::decode(&data).context(crate::AnalysisContractSnafu)?;
                decoded.len() == 1 && domain_key(&decoded[0].value.finding_id)? == property.key
            }
        };
        if !valid
            || find(
                current,
                &Index::member(
                    property.graph,
                    property.writer,
                    property.relation,
                    &property.owner,
                    &property.key,
                )?,
            )? != property.member
            || find(
                current,
                &Index::owner(property.graph, property.writer, &property.owner)?,
            )? != property.owner_id
            || find(
                current,
                &property
                    .kind
                    .group(property.graph, tenant, &property.key, &value.batch)?,
            )? != property.group
            || find(
                current,
                &rmp_serde::to_vec(&("graph-property", property.member, property.revision))
                    .context(crate::ManagedEncodingSnafu)?,
            )? != id
        {
            return Err(Code::Invalid.error("projected Graph property identity"));
        }
        Ok(())
    }
}

impl NativeStore {
    pub(in crate::analysis::native::managed::graph) fn validate_graph_projection(
        &self,
        owners: &Owners,
        models: &BTreeMap<(u64, u64), sdk::GraphSpec>,
    ) -> Result<()> {
        let current = self.view()?;
        let mut groups = BTreeMap::<u64, BTreeMap<u64, Property>>::new();
        let mut members = BTreeMap::new();
        for entry in current.snapshot.prefix(Index::PROPERTY) {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "read projected Graph properties",
            })?;
            if key.len() == Index::PROPERTY.len() + 16 {
                continue;
            }
            if key.len() != Index::PROPERTY.len() + 8 {
                return Err(Code::Invalid.error("projected Graph property key"));
            }
            let id = Self::number(&key[Index::PROPERTY.len()..])?;
            let bytes = Records::payload(&key, |key| Records::read(key, &current.snapshot))?
                .ok_or_else(|| Code::Missing.error("projected Graph property"))?;
            let property: Property = Records::decode(&bytes)?;
            property.check(current.metadata_revision)?;
            let (_, _, mapping) = owners
                .get(&property.graph)
                .ok_or_else(|| Code::Missing.error("projected Graph managed owner"))?;
            let model = models
                .get(&(property.writer, property.revision))
                .ok_or_else(|| Code::Missing.error("projected Graph retained model"))?;
            let declaration = model
                .relations
                .iter()
                .find(|relation| {
                    mapping
                        .relations
                        .get(&relation.name)
                        .is_some_and(|row| row.0 == property.relation)
                })
                .ok_or_else(|| Code::Invalid.error("projected Graph retained relation"))?;
            let kind = if DomainRelations::findings(declaration) {
                Kind::Finding
            } else if DomainRelations::relationships(declaration, model) {
                Kind::Relationship
            } else {
                return Err(Code::Invalid.error("projected Graph retained kind"));
            };
            let origin = current.graph_origin(property.writer, property.revision)?;
            if kind != property.kind
                || origin.graph != property.graph
                || origin.layer != property.layer
            {
                return Err(Code::Invalid.error("projected Graph opening layer"));
            }
            if members
                .insert((property.member, property.revision), id)
                .is_some()
            {
                return Err(Code::Invalid.error("projected Graph member alias"));
            }
            groups
                .entry(property.group)
                .or_default()
                .insert(id, property);
        }
        let mut live = BTreeMap::new();
        for (graph, (_, _, mapping)) in owners {
            let view = Graph::new(*graph)?.view(
                current.snapshot.clone(),
                BTreeMap::new(),
                &|_, _, _| Ok(None),
            )?;
            for writer in mapping.writers.values() {
                let relations = models
                    .range((*writer, 0)..=(*writer, u64::MAX))
                    .flat_map(|(_, model)| {
                        model
                            .relations
                            .iter()
                            .filter(|declaration| {
                                DomainRelations::findings(declaration)
                                    || DomainRelations::relationships(declaration, model)
                            })
                            .map(|declaration| mapping.relations[&declaration.name].0)
                    })
                    .collect::<BTreeSet<_>>();
                for relation in relations {
                    view.visit(
                        relation,
                        araphor_graph::Read::Owned(*writer),
                        &sdk::RecordBatch::new_empty(Arc::new(sdk::arrow_schema::Schema::empty())),
                        &|_, _, _| Ok(None),
                        |member| {
                            let identity = find(
                                &current,
                                &Index::member(
                                    *graph,
                                    *writer,
                                    relation,
                                    &member.owner,
                                    &member.key,
                                )
                                .map_err(araphor_graph::Error::backend)?,
                            )
                            .map_err(araphor_graph::Error::backend)?;
                            let id =
                                *members.get(&(identity, member.revision)).ok_or_else(|| {
                                    araphor_graph::Error::backend(
                                        Code::Missing.error("live projected Graph property"),
                                    )
                                })?;
                            if live.insert(id, member.property).is_some() {
                                return Err(araphor_graph::Error::backend(
                                    Code::Invalid.error("live projected Graph alias"),
                                ));
                            }
                            Ok(())
                        },
                    )?;
                }
            }
        }
        let mut expected = BTreeMap::new();
        for (group, properties) in groups {
            let first = properties
                .values()
                .next()
                .ok_or_else(|| Code::Missing.error("projected Graph group"))?;
            let (tenant, _, _) = owners[&first.graph];
            let mut values = Values {
                store: self,
                reserve: &|_| Ok(None),
                views: BTreeMap::new(),
                values: BTreeMap::new(),
                leases: Vec::new(),
            };
            let mut visible = Vec::new();
            let mut canonical = BTreeMap::new();
            for (id, property) in &properties {
                if property.graph != first.graph || property.kind != first.kind {
                    return Err(Code::Invalid.error("projected Graph group scope"));
                }
                values.check_property(&current, *id, property, tenant)?;
                if let Some(native_property) = live.remove(id) {
                    if values.values[id]
                        ._member
                        .as_ref()
                        .is_none_or(|member| member.property != native_property)
                    {
                        return Err(Code::Invalid.error("live projected Graph property reference"));
                    }
                    for key in [
                        Index::key(Index::LIVE, &[property.member]),
                        Index::key(
                            Index::OWNED,
                            &[
                                property.graph,
                                property.writer,
                                property.owner_id,
                                property.member,
                            ],
                        ),
                        Index::key(Index::GROUP, &[group, property.member]),
                    ] {
                        insert(&mut expected, key, id.to_be_bytes().to_vec())?;
                    }
                    visible.push(*id);
                }
                if property.kind == Kind::Finding {
                    let key = Index::key(Index::CANONICAL, &[*id]);
                    let bytes = Records::read(&key, &current.snapshot)?
                        .ok_or_else(|| Code::Missing.error("canonical finding reference"))?;
                    let target = Self::number(&bytes)?;
                    if !properties.contains_key(&target) || target > *id {
                        return Err(Code::Invalid.error("canonical finding identity"));
                    }
                    canonical.insert(*id, target);
                    insert(&mut expected, key, target.to_be_bytes().to_vec())?;
                }
            }
            if let Some(first) = visible.first() {
                for id in &visible {
                    if !values.equal(*first, *id, properties[id].kind)? {
                        return Err(Code::Conflict.error("public Graph value"));
                    }
                }
            }
            if first.kind == Kind::Finding {
                let candidates = canonical.values().copied().collect::<BTreeSet<_>>();
                for (id, target) in &canonical {
                    if canonical.get(target) != Some(target)
                        || !values.equal(*id, *target, Kind::Finding)?
                    {
                        return Err(Code::Invalid.error("canonical finding value"));
                    }
                }
                for candidate in &candidates {
                    insert(
                        &mut expected,
                        Index::key(Index::CANDIDATE, &[group, *candidate]),
                        Vec::new(),
                    )?;
                    for prior in candidates.range(..candidate) {
                        if values.equal(*prior, *candidate, Kind::Finding)? {
                            return Err(Code::Invalid.error("duplicate finding candidate"));
                        }
                    }
                }
                if let Some(id) = visible.first() {
                    let winner = canonical[id];
                    if visible.iter().any(|id| canonical[id] != winner) {
                        return Err(Code::Invalid.error("live canonical finding value"));
                    }
                    insert(
                        &mut expected,
                        Index::finding(tenant, first.graph, group),
                        winner.to_be_bytes().to_vec(),
                    )?;
                }
            }
        }
        if !live.is_empty() {
            return Err(Code::Invalid.error("live projected Graph set"));
        }
        for prefix in [
            Index::LIVE,
            Index::OWNED,
            Index::GROUP,
            Index::CANONICAL,
            Index::CANDIDATE,
            Index::FINDING,
        ] {
            for entry in current.snapshot.prefix(prefix) {
                let (key, value) = entry.context(NativeStorageSnafu {
                    operation: "validate projected Graph indexes",
                })?;
                if expected.remove(key.as_ref()).as_deref() != Some(value.as_ref()) {
                    return Err(Code::Invalid.error("projected Graph index set"));
                }
            }
        }
        if !expected.is_empty() {
            return Err(Code::Missing.error("projected Graph index set"));
        }
        Ok(())
    }
}
