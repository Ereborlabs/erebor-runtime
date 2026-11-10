use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::super::{results::ResultBody, InstanceRecord};
use super::{ManagedGraph, Records};
use crate::analysis::managed::PreparedMemory;
use crate::analysis::native::{DataView, DataWrite, ManagedCommit};
use crate::analysis::PackageResultRefV1;
use crate::{AnalysisReadControl, ManagedReceipt, PackageErrorCodeV1 as Code, Result};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct GraphPublication {
    pub tenant: [u8; 16],
    pub instance: String,
    pub graph: u64,
    pub reference: PackageResultRefV1,
    pub previous: Option<PackageResultRefV1>,
    pub heads: BTreeMap<u64, (u64, u64)>,
}

impl GraphPublication {
    pub(super) const PREFIX: &'static [u8] = b"\0data/graph/publication/";
    pub(in crate::analysis::native) const HEAD: &'static [u8] = b"\0data/graph/head/";

    pub(super) fn key(prefix: &[u8], id: u64) -> Vec<u8> {
        [prefix, &id.to_be_bytes()].concat()
    }

    pub(in crate::analysis::native) fn read(
        id: u64,
        head: u64,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<Self>> {
        let Some(bytes) = Records::charged_payload(&Self::key(Self::PREFIX, id), &mut get, charge)?
        else {
            return Ok(None);
        };
        let row: Self = Records::decode(&bytes)?;
        if row.tenant == [0; 16]
            || row.instance.is_empty()
            || row.graph == 0
            || row.reference.result_id.is_empty()
            || row.reference.commit_revision == 0
            || row.reference.commit_revision > head
            || row.previous.as_ref().is_some_and(|prior| {
                prior.result_id.is_empty()
                    || prior.commit_revision == 0
                    || prior.commit_revision >= row.reference.commit_revision
            })
            || row.heads.iter().any(|(writer, (layer, revision))| {
                *writer == 0
                    || *layer == 0
                    || *revision == 0
                    || *revision > row.reference.commit_revision
            })
        {
            return Err(Code::Invalid.error("managed Graph publication"));
        }
        Ok(Some(row))
    }
}

impl DataView {
    pub(in crate::analysis::native) fn input_graph_key(key: &[u8]) -> bool {
        Self::input_source_key(key)
            || key.starts_with(GraphPublication::PREFIX)
                && key.len() == GraphPublication::PREFIX.len() + 8
    }

    pub(in crate::analysis::native) fn input_graph(
        &self,
        key: &[u8],
        inputs: &crate::analysis::inputs::InputChanges,
        position: crate::StorePositionV1,
    ) -> Result<()> {
        if Self::input_source_key(key) {
            return self.input_source(key, inputs, position);
        }
        if !Self::input_graph_key(key) {
            return Ok(());
        }
        let id =
            crate::analysis::native::NativeStore::number(&key[GraphPublication::PREFIX.len()..])?;
        let publication = GraphPublication::read(
            id,
            self.metadata_revision,
            |key| Records::read(key, &self.snapshot),
            &mut |_| Ok(()),
        )?
        .ok_or_else(|| Code::Missing.error("input Graph publication"))?;
        if publication.reference.commit_revision != position.commit_revision {
            return Err(Code::Invalid.error("input Graph publication revision"));
        }
        let (_, _, owner) = self.result_owner(
            publication.tenant,
            &publication.reference.result_id,
            &AnalysisReadControl::default(),
            &mut |_| Ok(()),
        )?;
        let source = match &owner.instance().spec.destination {
            crate::ManagedDestination::Graph { source, .. } => Some(source),
            _ => None,
        };
        if !inputs.interested(crate::analysis::inputs::InputChange::Graph {
            tenant: publication.tenant,
            result: &publication.reference.result_id,
            source,
            witnesses: &[],
        }) {
            return Ok(());
        }
        let mut has_witnesses = false;
        for (&writer, &(layer, revision)) in &publication.heads {
            let origin = self.graph_origin(writer, revision)?;
            let (_, result) = super::super::results::StoredResult::read(
                publication.tenant,
                &origin.reference.result_id,
                self.metadata_revision,
                |key| Records::read(key, &self.snapshot),
                &mut |_| Ok(()),
            )?
            .ok_or_else(|| Code::Missing.error("input Graph producer"))?;
            let ResultBody::Call(record) = result.body else {
                return Err(Code::Invalid.error("input Graph producer kind"));
            };
            if origin.graph != publication.graph
                || origin.layer != layer
                || result.revision != revision
                || record.call != origin.call
            {
                return Err(Code::Invalid.error("input Graph producer identity"));
            }
            if !record.witnesses.is_empty() {
                has_witnesses = true;
                inputs.publish(
                    position,
                    crate::analysis::inputs::InputChange::Graph {
                        tenant: publication.tenant,
                        result: &publication.reference.result_id,
                        source,
                        witnesses: &record.witnesses,
                    },
                );
            }
        }
        if !has_witnesses {
            inputs.publish(
                position,
                crate::analysis::inputs::InputChange::Graph {
                    tenant: publication.tenant,
                    result: &publication.reference.result_id,
                    source,
                    witnesses: &[],
                },
            );
        }
        Ok(())
    }

    pub fn managed_graph_publication(
        &self,
        tenant: [u8; 16],
        reference: &PackageResultRefV1,
        control: &AnalysisReadControl,
    ) -> Result<Option<GraphPublication>> {
        self.managed_graph_publication_charged(tenant, reference, control, &mut |_| Ok(()))
    }

    pub(in crate::analysis::native) fn managed_graph_publication_charged(
        &self,
        tenant: [u8; 16],
        reference: &PackageResultRefV1,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<GraphPublication>> {
        let (publication, owner) =
            self.managed_graph_owner(tenant, &reference.result_id, control, charge)?;
        if owner
            .receipt()
            .is_none_or(|receipt| receipt.selected != *reference)
        {
            return Err(Code::Invalid.error("managed Graph selected reference"));
        }
        Ok(publication)
    }

    pub(in crate::analysis::native) fn managed_graph_owner(
        &self,
        tenant: [u8; 16],
        name: &str,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<(Option<GraphPublication>, crate::ManagedAttempt)> {
        let (id, result, owner) = self.result_owner(tenant, name, control, charge)?;
        if !matches!(result.body, ResultBody::Selected(_)) {
            return Err(Code::Invalid.error("managed Graph selected reference"));
        }
        let publication = GraphPublication::read(
            id,
            self.metadata_revision,
            |key| Records::read(key, &self.snapshot),
            charge,
        )?;
        if publication.as_ref().is_some_and(|publication| {
            publication.tenant != tenant
                || publication.reference.result_id != name
                || publication.reference.commit_revision != result.revision
                || publication.instance != owner.instance().spec.id
        }) {
            return Err(Code::Invalid.error("managed Graph publication owner"));
        }
        Ok((publication, owner))
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native::managed) fn publish_managed_graph(
        &mut self,
        input: &ManagedCommit<'_>,
        receipt: &ManagedReceipt,
        selected: u64,
        results: &BTreeMap<u64, u64>,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<()> {
        let has_selection = input
            .attempt
            .source_frame()
            .map(|frame| frame.input_selection())
            .transpose()?
            .flatten()
            .is_some();
        if !has_selection
            && !input
                .returns
                .iter()
                .any(|returned| returned.graph.is_some())
        {
            return Ok(());
        }
        let spec = &input.attempt.1.spec;
        let graph = Records::find(&InstanceRecord::identity(spec.tenant, &spec.id)?, |key| {
            Records::staged(key, &self.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("managed Graph publication owner"))?;
        let Some(mapping) =
            ManagedGraph::read(graph, |key| Records::staged(key, &self.transaction))?
        else {
            return Ok(());
        };
        let previous = Records::staged(
            &GraphPublication::key(GraphPublication::HEAD, graph),
            &self.transaction,
        )?
        .map(|bytes| crate::analysis::native::NativeStore::number(&bytes))
        .transpose()?
        .map(|id| {
            GraphPublication::read(
                id,
                self.revision,
                |key| Records::staged(key, &self.transaction),
                &mut |bytes| memory.charge(bytes),
            )?
            .ok_or_else(|| Code::Missing.error("managed Graph publication predecessor"))
        })
        .transpose()?;
        if previous.as_ref().is_some_and(|prior| {
            prior.tenant != spec.tenant
                || prior.instance != spec.id
                || prior.graph != graph
                || prior.reference.commit_revision >= self.revision
        }) {
            return Err(Code::Invalid.error("managed Graph publication predecessor"));
        }
        memory.charge(
            previous
                .as_ref()
                .map_or(0, |prior| prior.heads.len())
                .saturating_add(results.len())
                .saturating_mul(12 * size_of::<(u64, (u64, u64))>())
                .saturating_add(spec.id.len().saturating_mul(4)),
        )?;
        let mut heads = previous
            .as_ref()
            .map(|prior| prior.heads.clone())
            .unwrap_or_default();
        for returned in input.returns {
            let Some(journal) = returned.graph else {
                continue;
            };
            memory.check()?;
            let writer = journal.call.writer;
            if mapping.writers.get(&returned.call) != Some(&writer)
                || heads.get(&writer).map(|(layer, _)| *layer) != journal.call.head
            {
                return Err(Code::Conflict.error("managed Graph publication writer cut"));
            }
            heads.insert(writer, (results[&returned.call], self.revision));
        }
        let row = GraphPublication {
            tenant: spec.tenant,
            instance: spec.id.clone(),
            graph,
            reference: receipt.selected.clone(),
            previous: previous.map(|prior| prior.reference),
            heads,
        };
        Records::stage(
            &mut self.transaction,
            GraphPublication::key(GraphPublication::PREFIX, selected),
            Records::named(&row)?,
        );
        self.transaction.insert(
            GraphPublication::key(GraphPublication::HEAD, graph),
            selected.to_be_bytes(),
        );
        self.note_relation("managed_graph_publications", self.revision)?;
        self.note_relation("graph_manifest", self.revision)?;
        self.note_relation("findings", self.revision)?;
        self.dirty = true;
        Ok(())
    }
}
