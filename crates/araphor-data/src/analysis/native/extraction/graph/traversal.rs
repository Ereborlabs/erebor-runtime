use super::*;
use crate::analysis::native::managed::source::SourceContents;
use crate::{
    GraphSubjectKeyV1, GraphTraversalDirectionV1, GraphTraversalReceiptV1, GraphTraversalV1,
};
use araphor_analysis_types::RelationshipIdentity;
use araphor_graph::native::Identity;

struct Version {
    source: SourceRead,
    publication: GraphPublication,
    reader: PublicationRead,
    contents: SourceContents,
    rows: Vec<(Member, Option<FindingMember>)>,
    finding_subjects: BTreeSet<GraphSubjectKeyV1>,
    incidence: RefCell<BTreeMap<GraphSubjectKeyV1, bool>>,
    edges: BTreeMap<RelationshipIdentity, Identity>,
}

impl Version {
    fn key_batch(keys: impl IntoIterator<Item = Vec<u8>>) -> Result<sdk::RecordBatch> {
        sdk::RecordBatch::try_new(
            Arc::new(araphor_graph::Relation::key_schema()),
            vec![Arc::new(sdk::arrow_array::BinaryArray::from_iter_values(
                keys,
            ))],
        )
        .map_err(|source| crate::Error::AnalysisContract {
            source: source.into(),
            location: snafu::location!(),
        })
    }

    fn visit_identities(
        reader: &PublicationRead,
        relation: u64,
        read: araphor_graph::Read,
        keys: &sdk::RecordBatch,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
        mut visit: impl FnMut(Identity, &mut AnalysisExtractionV1) -> Result<()>,
    ) -> Result<()> {
        let memory = RefCell::new(output);
        reader.graph.visit_identities(
            relation,
            read,
            keys,
            &|_, bytes, _| {
                control.check().map_err(araphor_graph::Error::backend)?;
                memory
                    .borrow_mut()
                    .charge(bytes)
                    .map_err(araphor_graph::Error::backend)?;
                Ok(None)
            },
            |value| visit(value, &mut memory.borrow_mut()).map_err(araphor_graph::Error::backend),
        )?;
        Ok(())
    }

    fn identities(
        reader: &PublicationRead,
        relation: u64,
        read: araphor_graph::Read,
        keys: &sdk::RecordBatch,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<Vec<Identity>> {
        let mut values = Vec::new();
        Version::visit_identities(
            reader,
            relation,
            read,
            keys,
            output,
            control,
            |value, output| {
                output.charge(12 * size_of::<Identity>())?;
                values.push(value);
                Ok(())
            },
        )?;
        Ok(values)
    }

    fn subject(
        identity: &Identity,
        output: &mut AnalysisExtractionV1,
    ) -> Result<GraphSubjectKeyV1> {
        output.charge(identity.key.len().saturating_mul(12) + size_of::<GraphSubjectKeyV1>())?;
        rmp_serde::from_slice(&identity.key)
            .map_err(|_| Code::Invalid.error("traversal subject identity"))
    }

    fn relationship(reader: &PublicationRead, relation: &sdk::GraphRelation) -> bool {
        let sdk::GraphKind::Edge { from, to } = &relation.kind else {
            return false;
        };
        relation.properties == araphor_analysis_types::RelationshipChange::port().schema
            && [from, to].iter().all(|name| {
                reader
                    .mapping
                    .relations
                    .get(*name)
                    .is_some_and(|(_, declaration)| DomainRelations::subjects(declaration))
            })
    }
}

impl Version {
    fn eligible(
        &self,
        key: &GraphSubjectKeyV1,
        binding: bool,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<bool> {
        if !binding || self.finding_subjects.contains(key) {
            return Ok(true);
        }
        if let Some(found) = self.incidence.borrow().get(key) {
            return Ok(*found);
        }
        output.charge(
            key.allocated_bytes().saturating_mul(4) + 12 * size_of::<GraphSubjectKeyV1>(),
        )?;
        let keys =
            Version::key_batch([DomainRelations::key(key).context(crate::AnalysisContractSnafu)?])?;
        let mut found = false;
        for (relation, declaration) in self.reader.mapping.relations.values() {
            if !Version::relationship(&self.reader, declaration) {
                continue;
            }
            Version::visit_identities(
                &self.reader,
                *relation,
                araphor_graph::Read::Neighbors,
                &keys,
                output,
                control,
                |_, _| {
                    found = true;
                    Ok(())
                },
            )?;
            if found {
                break;
            }
        }
        self.incidence.borrow_mut().insert(key.clone(), found);
        Ok(found)
    }

    fn selected(
        &self,
        keys: &[GraphSubjectKeyV1],
        binding: bool,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<BTreeSet<GraphSubjectKeyV1>> {
        output.charge(
            keys.iter()
                .map(|key| {
                    key.allocated_bytes().saturating_mul(4) + 12 * size_of::<GraphSubjectKeyV1>()
                })
                .sum(),
        )?;
        let batch = Version::key_batch(
            keys.iter()
                .map(DomainRelations::key)
                .collect::<sdk::Result<Vec<_>>>()
                .context(crate::AnalysisContractSnafu)?,
        )?;
        let mut selected = BTreeSet::new();
        for (relation, declaration) in self.reader.mapping.relations.values() {
            if !DomainRelations::subjects(declaration) {
                continue;
            }
            for identity in Version::identities(
                &self.reader,
                *relation,
                araphor_graph::Read::Nodes,
                &batch,
                output,
                control,
            )? {
                let key = Version::subject(&identity, output)?;
                if self.eligible(&key, binding, output, control)? {
                    output.charge(identity.key.len() + 12 * size_of::<GraphSubjectKeyV1>())?;
                    selected.insert(key);
                }
            }
        }
        Ok(selected)
    }

    fn member(
        &self,
        identity: Identity,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<Member> {
        let memory = RefCell::new(output);
        self.reader
            .graph
            .member(
                identity.writer,
                identity.relation,
                &identity.owner,
                &identity.key,
                &|_, bytes, _| {
                    control.check().map_err(araphor_graph::Error::backend)?;
                    memory
                        .borrow_mut()
                        .charge(bytes)
                        .map_err(araphor_graph::Error::backend)?;
                    Ok(None)
                },
            )?
            .ok_or_else(|| Code::Missing.error("traversal member"))
    }
}

impl NativeStore {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn traverse_graphs(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        request: &GraphTraversalV1,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let binding = !selection.binding_ids.is_empty();
        let full = ["snapshot", "metadata"]
            .iter()
            .any(|field| read.projects_field("graph_manifest", field));
        let findings = binding
            || full
            || ["findings", "graph_branches", "policy_observations"]
                .iter()
                .any(|table| read.projected(table).is_some());
        let mut versions = Vec::new();
        let mut ids = Vec::new();
        for id in selection.graphs() {
            let source = SourceRead::load(view, selection.tenant_id, id, control, &mut |bytes| {
                output.charge(bytes)
            })?
            .ok_or_else(|| crate::AnalysisReadDeniedSnafu.build())?;
            if !selection.sources.as_slice().contains(source.identity()?) {
                return crate::AnalysisReadDeniedSnafu.fail();
            }
            let contents =
                source.contents(self, control, &mut |bytes| output.charge(bytes), full)?;
            let publication = source.publication(view, &mut |bytes| output.charge(bytes))?;
            let Some(publication) = publication else {
                if binding && !contents.manifest.input_manifest.evidence.is_empty() {
                    continue;
                }
                if full {
                    return Err(Code::Missing.error("Source Graph snapshot"));
                }
                let reference = source.reference();
                if read.projected("graph_manifest").is_some() {
                    self.extract_source_manifest(
                        &source,
                        read,
                        (0, 0),
                        false,
                        output,
                        capture,
                        control,
                    )?;
                } else {
                    output.capture_graph(
                        &reference.result_id,
                        &contents.manifest.snapshot(),
                        control,
                    )?;
                    output.reference_result(
                        &reference.result_id,
                        reference.commit_revision,
                        AnalysisReferenceOriginV1::Graph,
                    )?;
                }
                output.charge(reference.result_id.len() + 12 * size_of::<String>())?;
                ids.push(reference.result_id);
                continue;
            };
            let reader = PublicationRead::open(self, &publication, control, &mut |bytes| {
                output.charge(bytes)
            })?;
            let mut rows = Vec::new();
            let mut finding_subjects = BTreeSet::new();
            let keys = sdk::RecordBatch::new_empty(Arc::new(sdk::Schema::empty()));
            for (relation, declaration) in reader.mapping.relations.values() {
                if !DomainRelations::states(declaration)
                    && !(findings && DomainRelations::findings(declaration))
                {
                    continue;
                }
                for writer in publication.heads.keys() {
                    for identity in Version::identities(
                        &reader,
                        *relation,
                        araphor_graph::Read::Owned(*writer),
                        &keys,
                        output,
                        control,
                    )? {
                        let memory = RefCell::new(&mut *output);
                        let member = reader
                            .graph
                            .member(
                                identity.writer,
                                identity.relation,
                                &identity.owner,
                                &identity.key,
                                &|_, bytes, _| {
                                    control.check().map_err(araphor_graph::Error::backend)?;
                                    memory
                                        .borrow_mut()
                                        .charge(bytes)
                                        .map_err(araphor_graph::Error::backend)?;
                                    Ok(None)
                                },
                            )?
                            .ok_or_else(|| Code::Missing.error("traversal header member"))?;
                        let finding = if DomainRelations::findings(declaration) {
                            Some(PublicationRead::decode(
                                &member,
                                FindingMember::port(),
                                FindingMember::decode,
                                &mut |bytes| memory.borrow_mut().charge(bytes),
                            )?)
                        } else {
                            None
                        };
                        memory
                            .borrow_mut()
                            .charge(12 * size_of::<(Member, Option<FindingMember>)>())?;
                        rows.push((member, finding));
                    }
                }
            }
            rows.sort_unstable_by(|(left, _), (right, _)| {
                (left.relation, left.property, left.writer, &left.owner).cmp(&(
                    right.relation,
                    right.property,
                    right.writer,
                    &right.owner,
                ))
            });
            let mut seen = BTreeSet::new();
            let mut covered = BTreeSet::new();
            let mut allowed = true;
            for (_, finding) in &rows {
                let Some(finding) = finding else {
                    continue;
                };
                if !seen.insert(&finding.value.finding_id) {
                    continue;
                }
                contents
                    .manifest
                    .input_manifest
                    .validate_finding(&finding.value)?;
                output.charge(
                    12 * size_of::<GraphSubjectKeyV1>()
                        + finding.value.subject_id.allocated_bytes(),
                )?;
                finding_subjects.insert(finding.value.subject_id.clone());
                if !binding {
                    continue;
                }
                allowed &= !finding.value.effects.is_empty();
                for effect in &finding.value.effects {
                    let bound = effect
                        .binding_id
                        .is_some_and(|id| selection.binding_ids.contains(&id));
                    allowed &= bound;
                    if bound {
                        output.charge(effect.evidence.allocated_bytes() + 128)?;
                        covered.insert(&effect.evidence);
                    }
                }
            }
            if binding
                && (!allowed
                    || contents
                        .manifest
                        .input_manifest
                        .evidence
                        .iter()
                        .any(|record| !covered.contains(record)))
            {
                continue;
            }
            let reference = source.reference();
            output.capture_graph(&reference.result_id, &contents.manifest.snapshot(), control)?;
            output.reference_result(
                &reference.result_id,
                reference.commit_revision,
                AnalysisReferenceOriginV1::Graph,
            )?;
            output.charge(reference.result_id.len() + 12 * size_of::<String>())?;
            ids.push(reference.result_id);
            output.charge(12 * size_of::<Version>())?;
            versions.push(Version {
                source,
                publication,
                reader,
                contents,
                rows,
                finding_subjects,
                incidence: RefCell::new(BTreeMap::new()),
                edges: BTreeMap::new(),
            });
        }
        let mut subjects = BTreeMap::new();
        for version in &versions {
            for key in version.selected(&request.seeds, binding, output, control)? {
                output
                    .charge(key.allocated_bytes() + 12 * size_of::<(GraphSubjectKeyV1, u32)>())?;
                subjects.entry(key).or_insert(0);
            }
        }
        let mut boundary = false;
        let mut relationships = 0;
        for depth in 0..=request.max_hops {
            control.check()?;
            output.charge(
                subjects
                    .iter()
                    .filter(|(_, found)| **found == depth)
                    .map(|(key, _)| key.allocated_bytes() + size_of::<GraphSubjectKeyV1>())
                    .sum(),
            )?;
            let frontier = subjects
                .iter()
                .filter(|(_, found)| **found == depth)
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            if frontier.is_empty() {
                break;
            }
            for version in &mut versions {
                let selected = version.selected(&frontier, binding, output, control)?;
                if selected.is_empty() {
                    continue;
                }
                let keys = Version::key_batch(
                    selected
                        .iter()
                        .map(DomainRelations::key)
                        .collect::<sdk::Result<Vec<_>>>()
                        .context(crate::AnalysisContractSnafu)?,
                )?;
                let direction = match request.direction {
                    GraphTraversalDirectionV1::Outgoing => araphor_graph::Read::Outgoing,
                    GraphTraversalDirectionV1::Incoming => araphor_graph::Read::Incoming,
                    GraphTraversalDirectionV1::Both => araphor_graph::Read::Neighbors,
                };
                for (relation, declaration) in version.reader.mapping.relations.values() {
                    if !Version::relationship(&version.reader, declaration) {
                        continue;
                    }
                    Version::visit_identities(
                        &version.reader,
                        *relation,
                        direction,
                        &keys,
                        output,
                        control,
                        |identity, output| {
                            output.charge(identity.key.len().saturating_mul(12))?;
                            let edge: RelationshipIdentity = rmp_serde::from_slice(&identity.key)
                                .map_err(|_| {
                                Code::Invalid.error("traversal relationship identity")
                            })?;
                            let endpoints = [
                                DomainRelations::key(&edge.from),
                                DomainRelations::key(&edge.to),
                                DomainRelations::key(&edge.edge_type),
                            ]
                            .into_iter()
                            .collect::<sdk::Result<Vec<_>>>()
                            .context(crate::AnalysisContractSnafu)?;
                            if identity
                                .endpoints
                                .as_ref()
                                .is_none_or(|stored| stored.as_slice() != endpoints)
                            {
                                return Err(Code::Invalid.error("traversal relationship endpoints"));
                            }
                            if !request.edge_types.is_empty()
                                && !request.edge_types.contains(&edge.edge_type)
                            {
                                return Ok(());
                            }
                            for (source, target, follows) in [
                                (
                                    &edge.from,
                                    &edge.to,
                                    !matches!(direction, araphor_graph::Read::Incoming),
                                ),
                                (
                                    &edge.to,
                                    &edge.from,
                                    !matches!(direction, araphor_graph::Read::Outgoing),
                                ),
                            ] {
                                if !follows || !selected.contains(source) {
                                    continue;
                                }
                                if depth == request.max_hops {
                                    boundary |= !subjects.contains_key(target);
                                } else if !subjects.contains_key(target) {
                                    output.charge(
                                        identity.key.len() + 12 * size_of::<GraphSubjectKeyV1>(),
                                    )?;
                                    subjects.insert(target.clone(), depth + 1);
                                }
                            }
                            if depth == request.max_hops {
                                return Ok(());
                            }
                            match version.edges.entry(edge) {
                                std::collections::btree_map::Entry::Vacant(entry) => {
                                    entry.insert(identity);
                                    relationships += 1;
                                }
                                std::collections::btree_map::Entry::Occupied(mut entry) => {
                                    let prior = entry.get();
                                    if (
                                        identity.relation,
                                        identity.property,
                                        identity.writer,
                                        &identity.owner,
                                    ) < (
                                        prior.relation,
                                        prior.property,
                                        prior.writer,
                                        &prior.owner,
                                    ) {
                                        entry.insert(identity);
                                    }
                                }
                            }
                            if subjects.len() > request.max_subjects {
                                return crate::AnalysisInputTooLargeSnafu {
                                    resource: "graph traversal subjects",
                                }
                                .fail();
                            }
                            if relationships > request.max_relationships {
                                return crate::AnalysisInputTooLargeSnafu {
                                    resource: "graph traversal relationships",
                                }
                                .fail();
                            }
                            Ok(())
                        },
                    )?;
                }
            }
        }
        output.charge(
            subjects
                .len()
                .saturating_mul(size_of::<(GraphSubjectKeyV1, u32)>()),
        )?;
        let depths = subjects.into_iter().collect::<Vec<_>>();
        let mut versioned = 0usize;
        for mut version in versions {
            let reference = version.source.reference();
            let mut all = BTreeMap::new();
            let keys = sdk::RecordBatch::new_empty(Arc::new(sdk::Schema::empty()));
            for (relation, declaration) in version.reader.mapping.relations.values() {
                if !DomainRelations::subjects(declaration) {
                    continue;
                }
                for writer in version.publication.heads.keys() {
                    for identity in Version::identities(
                        &version.reader,
                        *relation,
                        araphor_graph::Read::Owned(*writer),
                        &keys,
                        output,
                        control,
                    )? {
                        let key = Version::subject(&identity, output)?;
                        output.charge(identity.key.len() + 12 * size_of::<GraphSubjectKeyV1>())?;
                        all.entry(key).or_insert(identity);
                    }
                }
            }
            let mut subject_ids = Vec::new();
            for (ordinal, (key, identity)) in all.into_iter().enumerate() {
                if depths
                    .binary_search_by(|(found, _)| found.cmp(&key))
                    .is_err()
                    || !version.eligible(&key, binding, output, control)?
                {
                    continue;
                }
                output
                    .charge(size_of::<u32>() + 12 * size_of::<(Member, Option<FindingMember>)>())?;
                subject_ids.push(
                    u32::try_from(ordinal)
                        .map_err(|_| Code::Limit.error("traversal subject ordinal"))?,
                );
                let member = version.member(identity, output, control)?;
                version.rows.push((member, None));
                versioned = versioned
                    .checked_add(1)
                    .ok_or_else(|| Code::Limit.error("traversal subject rows"))?;
                if versioned > request.max_subjects {
                    return crate::AnalysisInputTooLargeSnafu {
                        resource: "graph subject rows",
                    }
                    .fail();
                }
            }
            for (_, identity) in std::mem::take(&mut version.edges) {
                let member = version.member(identity, output, control)?;
                output.charge(12 * size_of::<(Member, Option<FindingMember>)>())?;
                version.rows.push((member, None));
            }
            let data = self.source_snapshot(
                &version.source,
                &version.publication,
                &version.reader,
                version.rows,
                version.contents,
                control,
                &mut |bytes| output.charge(bytes),
            )?;
            if subject_ids.is_empty()
                && data.snapshot.graph.edges.is_empty()
                && read.projected("graph_manifest").is_none()
            {
                continue;
            }
            capture.graph(
                &reference.result_id,
                &data.snapshot,
                &data.values,
                data.snapshot.graph.subjects.len(),
                data.snapshot.graph.edges.len(),
                reference.commit_revision,
                if data.restricted {
                    crate::ContextSensitivityV1::HostRestricted
                } else {
                    crate::ContextSensitivityV1::Tenant
                },
                Some(&depths),
                Some(&subject_ids),
                &data.contexts,
                (
                    version.source.header.captured.commit_revision,
                    version.source.header.coverage,
                ),
                version.source.expired(),
                Some(version.source.restricted()),
                &mut output.sink(control),
            )?;
        }
        output.graph_traversal = Some(GraphTraversalReceiptV1 {
            result_ids: ids,
            unique_subject_count: depths.len(),
            versioned_subject_count: versioned,
            relationship_count: relationships,
            max_hops: request.max_hops,
            hop_boundary: boundary,
        });
        Ok(())
    }
}
