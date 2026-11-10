use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use araphor_analysis_sdk as sdk;
use araphor_analysis_types::{DomainRelations, FindingMember};
use araphor_graph::native::{Graph, Member};
use sdk::arrow_array::{Array, StringArray, StructArray};
use snafu::ResultExt as _;

use super::{Capture, DataView, NativeStore};
use crate::analysis::native::{records::Records, GraphPublication};
use crate::{
    AnalysisExtractionV1, AnalysisReadControl, AnalysisReferenceOriginV1, AnalysisSelectionV1,
    AnalysisTableRead, PackageErrorCodeV1 as Code, Result, Selection,
};

fn finding_id(member: &Member) -> Result<&str> {
    let values = member
        .properties()
        .column_by_name("value")
        .and_then(|array| array.as_any().downcast_ref::<StructArray>())
        .and_then(|array| array.column_by_name("finding_id"))
        .and_then(|array| array.as_any().downcast_ref::<StringArray>())
        .filter(|array| !array.is_null(member.row))
        .ok_or_else(|| Code::Invalid.error("native finding identity"))?;
    Ok(values.value(member.row))
}

impl NativeStore {
    pub(super) fn select_graphs(
        &self,
        view: &DataView,
        selection: &mut AnalysisSelectionV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if !selection.graphs.is_all() {
            return Ok(());
        }
        let mut selected = Vec::new();
        for ((_, graph), ()) in view
            .graphs
            .range((selection.tenant_id, 0)..=(selection.tenant_id, u64::MAX))
        {
            control.check()?;
            let key = [GraphPublication::HEAD, &graph.to_be_bytes()].concat();
            let Some(value) = Records::read(&key, &view.snapshot)? else {
                continue;
            };
            output.scan(key.len() + value.len())?;
            let id = NativeStore::number(&value)?;
            let publication = GraphPublication::read(
                id,
                view.metadata_revision,
                |key| Records::read(key, &view.snapshot),
                &mut |bytes| output.charge(bytes),
            )?
            .ok_or_else(|| Code::Missing.error("Graph publication head"))?;
            if publication.graph != *graph {
                return Err(Code::Invalid.error("Graph publication head identity"));
            }
            if publication.tenant != selection.tenant_id {
                continue;
            }
            if output
                .limits
                .keys
                .is_some_and(|limit| selection.key_count() + selected.len() >= limit)
            {
                return crate::AnalysisInputTooLargeSnafu {
                    resource: "selected input keys",
                }
                .fail();
            }
            output.charge(AnalysisExtractionV1::grow(
                &mut selected,
                output.input_bytes,
                output.limits.input_bytes,
            )?)?;
            output.charge(publication.reference.result_id.capacity())?;
            selected.push(publication.reference.result_id);
        }
        selected.sort();
        selection.graphs = Selection::Exact(selected);
        Ok(())
    }

    pub(super) fn extract_graphs(
        &self,
        view: &DataView,
        selected: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if read.projected("findings").is_none() && read.projected("graph_manifest").is_none() {
            return Ok(());
        }
        for name in selected.graphs() {
            let (publication, owner) =
                view.managed_graph_owner(selected.tenant_id, name, control, &mut |bytes| {
                    output.charge(bytes)
                })?;
            if matches!(
                &owner.instance().spec.destination,
                crate::ManagedDestination::Graph { .. }
            ) {
                return Err(Code::Unsupported.error("native source Graph provider"));
            }
            let publication = publication
                .ok_or_else(|| Code::Unsupported.error("native Graph publication owner"))?;
            if owner.instance().grant.permitted_by(scope).is_err() {
                continue;
            }
            self.extract_publication(view, &publication, scope, read, output, capture, control)?;
        }
        Ok(())
    }

    fn extract_publication(
        &self,
        view: &DataView,
        publication: &GraphPublication,
        scope: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let at = self.read_at(publication.reference.commit_revision)?;
        let mapping = at
            .managed_graph_charged(
                publication.tenant,
                &publication.instance,
                control,
                &mut |bytes| output.charge(bytes),
            )?
            .ok_or_else(|| Code::Missing.error("Graph publication mapping"))?;
        let memory = RefCell::new(output);
        let reserve = |_: u64, bytes: usize, _: usize| {
            control.check().map_err(araphor_graph::Error::backend)?;
            memory
                .borrow_mut()
                .charge(bytes)
                .map_err(araphor_graph::Error::backend)?;
            Ok(None)
        };
        let mut snapshots = BTreeMap::new();
        let mut restricted = false;
        for (writer, (_, revision)) in &publication.heads {
            memory
                .borrow_mut()
                .charge(12 * size_of::<(u64, fjall::BranchSnapshot)>())?;
            let selected = self.read_at(*revision)?;
            snapshots.insert(*writer, selected.snapshot().clone());
            restricted |= view
                .graph_origin_charged(*writer, *revision, &mut |bytes| {
                    memory.borrow_mut().charge(bytes)
                })?
                .restricted;
        }
        let graph =
            Graph::new(publication.graph)?.view(at.snapshot().clone(), snapshots, &reserve)?;
        for (writer, (layer, _)) in &publication.heads {
            if graph.head(*writer)? != Some(*layer) {
                return Err(Code::Invalid.error("Graph publication writer cut"));
            }
        }
        let manifest = read.projected("graph_manifest").is_some();
        let findings = read.projected("findings").is_some();
        let mut nodes = BTreeSet::new();
        let mut edges = BTreeSet::new();
        let mut origins = BTreeMap::new();
        let mut rows = Vec::new();
        let mut permitted = true;
        let keys = sdk::RecordBatch::new_empty(Arc::new(sdk::Schema::empty()));
        for (relation, declaration) in mapping.relations.values() {
            let finding = DomainRelations::findings(declaration);
            if !manifest && !(findings && finding) {
                continue;
            }
            for writer in publication.heads.keys() {
                graph.visit(
                    *relation,
                    araphor_graph::Read::Owned(*writer),
                    &keys,
                    &reserve,
                    |member| {
                        let result = (|| -> Result<()> {
                            control.check()?;
                            let opening = (member.writer, member.revision);
                            if !origins.contains_key(&opening) {
                                let origin = view.graph_origin_charged(
                                    opening.0,
                                    opening.1,
                                    &mut |bytes| memory.borrow_mut().charge(bytes),
                                )?;
                                origins.insert(
                                    opening,
                                    (origin.grant.permitted_by(scope).is_ok(), origin.restricted),
                                );
                            }
                            let (allowed, restricted) = origins[&opening];
                            if manifest {
                                permitted &= allowed;
                                memory
                                    .borrow_mut()
                                    .charge(member.key.len() + 12 * size_of::<(u64, Vec<u8>)>())?;
                                let set = if matches!(declaration.kind, sdk::GraphKind::Node) {
                                    &mut nodes
                                } else {
                                    &mut edges
                                };
                                set.insert((*relation, member.key.clone()));
                            }
                            if findings && finding {
                                let mut output = memory.borrow_mut();
                                let added = AnalysisExtractionV1::grow(
                                    &mut rows,
                                    output.input_bytes,
                                    output.limits.input_bytes,
                                )?;
                                output.charge(added)?;
                                rows.push((member, allowed, restricted));
                            }
                            Ok(())
                        })();
                        result.map_err(araphor_graph::Error::backend)
                    },
                )?;
            }
        }
        rows.sort_unstable_by(|(a, _, _), (b, _, _)| {
            (a.relation, a.property, a.writer, &a.owner)
                .cmp(&(b.relation, b.property, b.writer, &b.owner))
        });
        let mut seen = BTreeSet::new();
        for (member, allowed, restricted) in rows {
            control.check()?;
            let id = finding_id(&member)?;
            if seen.contains(id) {
                continue;
            }
            memory
                .borrow_mut()
                .charge(id.len() + 12 * size_of::<String>())?;
            seen.insert(id.to_owned());
            if !allowed {
                continue;
            }
            let value = at.graph_finding_value(publication.graph, &member)?;
            let batch = member.properties().slice(member.row, 1);
            let bytes = batch.get_array_memory_size();
            memory.borrow_mut().scan(bytes)?;
            memory.borrow_mut().charge(
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
            let finding = values
                .pop()
                .ok_or_else(|| Code::Invalid.error("native finding value"))?;
            if !capture.native_finding(
                &publication.reference.result_id,
                publication.reference.commit_revision,
                restricted,
                None,
                &finding.value,
                value,
                &mut memory.borrow_mut().sink(control),
            )? {
                return Ok(());
            }
        }
        if manifest && permitted {
            let mut output = memory.borrow_mut();
            output.reference_result(
                &publication.reference.result_id,
                publication.reference.commit_revision,
                AnalysisReferenceOriginV1::Graph,
            )?;
            capture.definition_manifest(
                publication.tenant,
                &publication.reference.result_id,
                publication.reference.commit_revision,
                (nodes.len() as u64, edges.len() as u64),
                publication
                    .previous
                    .as_ref()
                    .map(|prior| prior.result_id.as_str()),
                restricted,
                &mut output.sink(control),
            )?;
        }
        Ok(())
    }
}
