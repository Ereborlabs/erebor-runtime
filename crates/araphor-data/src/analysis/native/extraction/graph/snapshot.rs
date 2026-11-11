use super::*;
use crate::{GraphPackageCheckpointV1, GraphPackageStateV1, GraphSnapshotV1};
use araphor_analysis_builtins::graph::{BranchExt, CheckpointExt};
use araphor_analysis_types::{GraphStateMember, RelationshipChange, SubjectChange};

pub(super) struct SnapshotRead {
    pub(super) snapshot: GraphSnapshotV1,
    pub(super) values: BTreeMap<String, u64>,
    pub(super) contexts: Vec<crate::AnalysisContextRefV1>,
    pub(super) restricted: bool,
}

struct PackageState {
    contract: Arc<(sdk::Package, sdk::Model)>,
    fallback: Option<GraphPackageStateV1>,
    selected: Option<GraphStateMember>,
}

impl PackageState {
    fn add(&mut self, value: GraphStateMember) -> Result<()> {
        if value.record.is_none() {
            if self
                .fallback
                .as_ref()
                .is_some_and(|prior| prior != &value.state)
            {
                return Err(Code::Conflict.error("Graph package default state"));
            }
            self.fallback = Some(value.state);
            return Ok(());
        }
        if let Some(prior) = &self.selected {
            let order = match (&value.fact, &prior.fact) {
                (Some(left), Some(right)) => (left, &value.record).cmp(&(right, &prior.record)),
                (None, None) => value.record.cmp(&prior.record),
                _ => return Err(Code::Invalid.error("Graph state ordering mode")),
            };
            if !order.is_gt() {
                return Ok(());
            }
        }
        self.selected = Some(value);
        Ok(())
    }

    fn checkpoint(self, accepted: u64, observed: u64) -> Result<GraphPackageCheckpointV1> {
        let state = self
            .selected
            .map(|row| row.state)
            .or(self.fallback)
            .ok_or_else(|| Code::Missing.error("Graph package state"))?;
        Ok(GraphPackageCheckpointV1::from_package(
            &self.contract.0,
            &self.contract.1,
            state,
            accepted,
            observed,
        ))
    }
}

impl NativeStore {
    pub fn graph_snapshot(
        &self,
        source: &crate::EvidenceIntakeIdentityV1,
    ) -> Result<Option<GraphSnapshotV1>> {
        if !source.valid() {
            return Err(Code::Invalid.error("Graph source"));
        }
        let _lease = self
            .maintenance
            .read_until(&AnalysisReadControl::default())?;
        self.check()?;
        let view = self.view()?;
        let scope = crate::ProcessorScopeV1 {
            processor_id: crate::GRAPH_PROCESSOR.into(),
            method_version: u64::from(crate::GRAPH_SCHEMA_VERSION),
            identity: source.clone(),
        };
        let processor = crate::analysis::native::progress::Processor::read(
            &scope,
            view.metadata_revision,
            |key| Records::read(key, &view.snapshot),
            &mut |_| Ok(()),
        )?;
        let Some(head) = processor.and_then(|(_, processor)| processor.head) else {
            return Ok(None);
        };
        let control = AnalysisReadControl::default();
        let source = SourceRead::load(
            &view,
            source.tenant_id,
            &head.result_id,
            &control,
            &mut |_| Ok(()),
        )?
        .ok_or_else(|| Code::Missing.error("Graph source head"))?;
        if source.reference() != head {
            return Err(Code::Invalid.error("Graph processor head reference"));
        }
        self.read_source_snapshot(&view, &source, true, &control, &mut |_| Ok(()))
            .map(|read| Some(read.snapshot))
    }

    pub fn graph_result(
        &self,
        tenant: [u8; 16],
        result_id: &str,
    ) -> Result<Option<GraphSnapshotV1>> {
        if tenant == [0; 16] || !crate::NotificationGrantV1::identifier(result_id, usize::MAX) {
            return Err(Code::Invalid.error("Graph result reference"));
        }
        let _lease = self
            .maintenance
            .read_until(&AnalysisReadControl::default())?;
        self.check()?;
        let view = self.view()?;
        let control = AnalysisReadControl::default();
        let Some(source) = SourceRead::load(&view, tenant, result_id, &control, &mut |_| Ok(()))?
        else {
            return Ok(None);
        };
        self.read_source_snapshot(&view, &source, true, &control, &mut |_| Ok(()))
            .map(|read| Some(read.snapshot))
    }

    pub(super) fn read_source_snapshot(
        &self,
        view: &DataView,
        source: &SourceRead,
        complete: bool,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<SnapshotRead> {
        let publication = source
            .publication(view, charge)?
            .ok_or_else(|| Code::Missing.error("Source Graph publication"))?;
        let reader = PublicationRead::open(self, &publication, control, charge)?;
        let memory = RefCell::new(&mut *charge);
        let reserve = |_: u64, bytes: usize, _: usize| {
            control.check().map_err(araphor_graph::Error::backend)?;
            memory.borrow_mut()(bytes).map_err(araphor_graph::Error::backend)?;
            Ok(None)
        };
        let keys = sdk::RecordBatch::new_empty(Arc::new(sdk::Schema::empty()));
        let mut rows = Vec::new();
        let spec = sdk::GraphSpec {
            access: sdk::GraphAccess::ReadWrite,
            relations: reader
                .mapping
                .relations
                .values()
                .map(|(_, value)| value.clone())
                .collect(),
        };
        for (relation, declaration) in reader.mapping.relations.values() {
            if !DomainRelations::subjects(declaration)
                && !DomainRelations::relationships(declaration, &spec)
                && !DomainRelations::findings(declaration)
                && !DomainRelations::states(declaration)
            {
                continue;
            }
            for &writer in publication.heads.keys() {
                reader.graph.visit(
                    *relation,
                    araphor_graph::Read::Owned(writer),
                    &keys,
                    &reserve,
                    |member| {
                        memory.borrow_mut()(size_of::<(Member, Option<FindingMember>)>() * 12)
                            .map_err(araphor_graph::Error::backend)?;
                        rows.push((member, None));
                        Ok(())
                    },
                )?;
            }
        }
        drop(memory);
        let contents = source.contents(self, control, charge, complete)?;
        self.source_snapshot(
            source,
            &publication,
            &reader,
            rows,
            contents,
            control,
            charge,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn source_snapshot(
        &self,
        source: &SourceRead,
        publication: &GraphPublication,
        reader: &PublicationRead,
        mut rows: Vec<(Member, Option<FindingMember>)>,
        contents: crate::analysis::native::managed::source::SourceContents,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<SnapshotRead> {
        let crate::analysis::native::managed::source::SourceContents {
            complete,
            manifest,
            contexts,
            observed,
            facts,
        } = contents;
        let mut snapshot = manifest.snapshot();
        let mut restricted = reader.restricted || source.restricted() != 0;
        let mut subjects = BTreeSet::new();
        let mut relationships = BTreeMap::new();
        let mut findings = BTreeMap::new();
        let mut values = BTreeMap::new();
        let mut packages = BTreeMap::<String, PackageState>::new();
        let mut producers = BTreeMap::<(u64, u64), u64>::new();
        let mut contracts =
            BTreeMap::<u64, (crate::ManagedCall, Arc<(sdk::Package, sdk::Model)>)>::new();
        let memory = RefCell::new(charge);
        rows.sort_unstable_by(|(left, _), (right, _)| {
            (left.relation, left.property, left.writer, &left.owner).cmp(&(
                right.relation,
                right.property,
                right.writer,
                &right.owner,
            ))
        });
        for (member, finding) in rows {
            control.check()?;
            let declaration = &reader
                .mapping
                .relations
                .values()
                .find(|(id, _)| *id == member.relation)
                .ok_or_else(|| Code::Missing.error("Source Graph relation"))?
                .1;
            let opening = (member.writer, member.revision);
            if !producers.contains_key(&opening) {
                let origin =
                    reader
                        .at
                        .graph_origin_charged(opening.0, opening.1, &mut |bytes| {
                            memory.borrow_mut()(bytes)
                        })?;
                if origin.graph != publication.graph
                    || origin.instance != publication.instance
                    || reader.mapping.writers.get(&origin.call) != Some(&opening.0)
                {
                    return Err(Code::Denied.error("Source Graph member authority"));
                }
                restricted |= origin.restricted;
                let (id, stored, owner) = reader.at.result_owner(
                    publication.tenant,
                    &origin.reference.result_id,
                    control,
                    &mut |bytes| memory.borrow_mut()(bytes),
                )?;
                let crate::analysis::native::managed::results::ResultBody::Call(record) =
                    stored.body
                else {
                    return Err(Code::Invalid.error("Source Graph producer kind"));
                };
                if id != origin.layer
                    || stored.revision != member.revision
                    || record.call != origin.call
                    || record.instance != origin.instance
                    || owner.instance().grant != origin.grant
                    || origin.grant.selection.tenant_id != publication.tenant
                {
                    return Err(Code::Denied.error("Source Graph producer authority"));
                }
                let call = owner
                    .instance()
                    .spec
                    .manifest
                    .calls
                    .get(&origin.call)
                    .ok_or_else(|| Code::Missing.error("Source Graph producer call"))?;
                if let Some((saved, _)) = contracts.get(&origin.call) {
                    if saved.package != call.package
                        || saved.target != call.target
                        || saved.artifact != call.artifact
                        || saved.export != call.export
                    {
                        return Err(Code::Conflict.error("Source Graph retained contract"));
                    }
                } else {
                    let package = reader.at.managed_contract_charged(
                        &owner.instance().spec,
                        call,
                        &mut |bytes| memory.borrow_mut()(bytes),
                    )?;
                    let model = package
                        .exports
                        .iter()
                        .find(|model| model.name == call.export)
                        .ok_or_else(|| Code::Missing.error("Source Graph export"))?
                        .clone();
                    memory.borrow_mut()(
                        12 * size_of::<(crate::ManagedCall, sdk::Package, sdk::Model)>(),
                    )?;
                    contracts.insert(origin.call, (call.clone(), Arc::new((package, model))));
                }
                producers.insert(opening, origin.call);
            }
            let contract = &contracts[&producers[&opening]].1;
            let package = &contract.0;
            if DomainRelations::subjects(declaration) {
                let row = PublicationRead::decode(
                    &member,
                    SubjectChange::port(),
                    SubjectChange::decode,
                    &mut |bytes| memory.borrow_mut()(bytes),
                )?;
                subjects.insert(row.key);
            } else if DomainRelations::findings(declaration) {
                let row = match finding {
                    Some(value) => value,
                    None => PublicationRead::decode(
                        &member,
                        FindingMember::port(),
                        FindingMember::decode,
                        &mut |bytes| memory.borrow_mut()(bytes),
                    )?,
                };
                if row.value.package_id != package.id || row.value.package_version != 1 {
                    return Err(Code::Denied.error("Source Graph finding package"));
                }
                let id = row.value.finding_id.clone();
                if !findings.contains_key(&id) {
                    values.insert(
                        id.clone(),
                        reader.at.graph_finding_value(publication.graph, &member)?,
                    );
                    findings.insert(id, row.value);
                }
            } else if DomainRelations::states(declaration) {
                let row = PublicationRead::decode(
                    &member,
                    GraphStateMember::port(),
                    GraphStateMember::decode,
                    &mut |bytes| memory.borrow_mut()(bytes),
                )?;
                if let Some(record) = &row.record {
                    let position = snapshot
                        .input_positions
                        .binary_search_by(|(id, _)| id.cmp(record))
                        .ok()
                        .map(|index| snapshot.input_positions[index].1);
                    if position.is_none()
                        || position.map(|value| araphor_analysis_types::Position {
                            commit_revision: value.commit_revision,
                            ordinal: value.ordinal,
                        }) != row.position
                        || row
                            .fact
                            .as_ref()
                            .is_some_and(|key| facts.get(key) != Some(record))
                    {
                        return Err(Code::Denied.error("Source Graph state provenance"));
                    }
                }
                let state = packages
                    .entry(package.id.clone())
                    .or_insert_with(|| PackageState {
                        contract: Arc::clone(contract),
                        fallback: None,
                        selected: None,
                    });
                if state.contract.as_ref() != contract.as_ref() {
                    return Err(Code::Conflict.error("Source Graph package contract"));
                }
                state.add(row)?;
            } else {
                let row = PublicationRead::decode(
                    &member,
                    RelationshipChange::port(),
                    RelationshipChange::decode,
                    &mut |bytes| memory.borrow_mut()(bytes),
                )?;
                relationships.entry(row.key.clone()).or_insert(row);
            }
        }
        snapshot.graph.subjects = subjects.into_iter().collect();
        for row in relationships.into_values() {
            let subject = |key| {
                snapshot
                    .graph
                    .subjects
                    .binary_search(key)
                    .ok()
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or_else(|| Code::Missing.error("Source Graph edge subject"))
            };
            let evidence = row
                .key
                .evidence
                .iter()
                .map(|record| {
                    snapshot
                        .input_manifest
                        .evidence
                        .binary_search(record)
                        .ok()
                        .and_then(|index| u32::try_from(index).ok())
                        .ok_or_else(|| Code::Missing.error("Source Graph edge evidence"))
                })
                .collect::<Result<Vec<_>>>()?;
            snapshot.graph.edges.push(crate::GraphEdgeV1 {
                key: crate::GraphEdgeKeyV1 {
                    from: subject(&row.key.from)?,
                    to: subject(&row.key.to)?,
                    edge_type: row.key.edge_type,
                    package_id: row.key.package_id,
                    evidence,
                    cause: row.key.cause,
                },
                proof_quality: row.proof_quality,
                required_coverage_interval_ids: row.required_coverage_interval_ids,
                first_boottime_ns: row.first_boottime_ns,
                last_boottime_ns: row.last_boottime_ns,
            });
        }
        snapshot
            .graph
            .edges
            .sort_unstable_by(|left, right| left.key.cmp(&right.key));
        snapshot.findings = findings.into_values().collect();
        snapshot.graph.branches = snapshot
            .findings
            .iter()
            .map(crate::GraphBranchV1::from_value)
            .collect();
        snapshot.graph.branches.sort_unstable_by(|left, right| {
            (
                &left.package_id,
                &left.seed,
                &left.evidence,
                &left.missing_fields,
            )
                .cmp(&(
                    &right.package_id,
                    &right.seed,
                    &right.evidence,
                    &right.missing_fields,
                ))
        });
        snapshot.graph.branches.dedup();
        let accepted = snapshot
            .input_manifest
            .evidence
            .iter()
            .map(|record| record.durable_cursor)
            .max()
            .unwrap_or(0);
        snapshot.packages = packages
            .into_values()
            .map(|state| state.checkpoint(accepted, observed))
            .collect::<Result<_>>()?;
        if complete {
            snapshot.validate()?;
        } else {
            snapshot.validate_projection()?;
        }
        Ok(SnapshotRead {
            snapshot,
            values,
            contexts,
            restricted,
        })
    }
}
