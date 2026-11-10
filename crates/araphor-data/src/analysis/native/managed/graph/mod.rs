use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use araphor_analysis_sdk as sdk;
use araphor_graph::native::{Declaration, Graph};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{InstanceRecord, Records};

mod authority;
mod cuts;
mod domain;
mod origin;
mod projection;
pub(in crate::analysis) use projection::FindingRead;
mod publication;
mod read;
pub(in crate::analysis::native) use read::PublicationRead;
mod recovery;
mod transaction;
pub use cuts::GraphPublication;
pub(super) use publication::PreparedGraph;
pub use transaction::{ManagedGraphJournal, ManagedGraphTransaction};

#[derive(Clone)]
pub(super) struct GraphCall {
    pub attempt: std::sync::Arc<crate::ManagedAttempt>,
    pub call: u64,
    pub graph: u64,
    pub writer: u64,
    pub head: Option<u64>,
    pub spec: sdk::GraphSpec,
    pub relations: BTreeMap<String, u64>,
}

use crate::{
    analysis::native::{DataView, DataWrite},
    AnalysisReadControl, ManagedSpec, NativeStateSnafu, PackageErrorCodeV1 as Code, Result,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ManagedGraph {
    pub graph: u64,
    pub writers: BTreeMap<u64, u64>,
    pub relations: BTreeMap<String, (u64, sdk::GraphRelation)>,
}

impl ManagedGraph {
    pub(super) fn read(
        id: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Option<Self>> {
        Self::read_charged(id, get, &mut |_| Ok(()))
    }

    fn read_charged(
        id: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<Self>> {
        let Some(bytes) = Records::charged_payload(&Records::key(b'G', id), get, charge)? else {
            return Ok(None);
        };
        let row: Self = Records::decode(&bytes)?;
        if row.graph != id
            || row.writers.is_empty()
            || row.relations.is_empty()
            || row.writers.values().copied().collect::<BTreeSet<_>>().len() != row.writers.len()
            || row
                .relations
                .values()
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>()
                .len()
                != row.relations.len()
            || row.writers.values().any(|writer| *writer == 0)
            || row
                .relations
                .iter()
                .any(|(name, (id, relation))| *id == 0 || name != &relation.name)
        {
            return NativeStateSnafu {
                field: "managed Graph mapping",
            }
            .fail();
        }
        Ok(Some(row))
    }

    pub(super) fn extend(
        &mut self,
        relations: BTreeMap<String, sdk::GraphRelation>,
        calls: Vec<u64>,
        mut resolve: impl FnMut(&[u8]) -> Result<u64>,
    ) -> Result<()> {
        for (name, relation) in relations {
            if let Some((_, saved)) = self.relations.get(&name) {
                if saved != &relation {
                    return Err(Code::Conflict.error("Graph relation declaration changed"));
                }
            } else {
                let identity = rmp_serde::to_vec(&(b'R', self.graph, &name))
                    .context(crate::ManagedEncodingSnafu)?;
                let relation_id = resolve(&identity)?;
                self.relations.insert(name, (relation_id, relation));
            }
        }
        for call in calls {
            if let Entry::Vacant(entry) = self.writers.entry(call) {
                let identity = rmp_serde::to_vec(&(b'W', self.graph, call))
                    .context(crate::ManagedEncodingSnafu)?;
                let writer = resolve(&identity)?;
                entry.insert(writer);
            }
        }
        Ok(())
    }

    pub(super) fn declarations(&self) -> Result<Vec<Declaration>> {
        self.relations
            .values()
            .map(|(id, relation)| {
                let endpoints = match &relation.kind {
                    sdk::GraphKind::Node => None,
                    sdk::GraphKind::Edge { from, to } => Some((
                        self.relations
                            .get(from)
                            .ok_or_else(|| Code::Invalid.error("Graph source relation"))?
                            .0,
                        self.relations
                            .get(to)
                            .ok_or_else(|| Code::Invalid.error("Graph target relation"))?
                            .0,
                    )),
                };
                Ok(Declaration {
                    relation: *id,
                    shape: relation.engine(),
                    endpoints,
                })
            })
            .collect()
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn managed_contract(
        &self,
        spec: &ManagedSpec,
        call: &crate::ManagedCall,
    ) -> Result<sdk::Package> {
        let row = self
            .package_revision(
                spec.tenant,
                &call.package.package_id,
                &call.package.revision,
            )?
            .ok_or_else(|| Code::Missing.error("managed SDK descriptor"))?;
        call.contract(&row.descriptor)
    }

    pub(super) fn admit_managed_graph(&mut self, spec: &ManagedSpec, create: bool) -> Result<()> {
        let admission = spec.graph_declarations(|call| self.managed_contract(spec, call))?;
        if admission.calls.is_empty() {
            return Ok(());
        }
        let identity = InstanceRecord::identity(spec.tenant, &spec.id)?;
        let id = if create {
            Records::intern(&mut self.transaction, &identity)?
        } else {
            Records::find(&identity, |key| Records::staged(key, &self.transaction))?.ok_or_else(
                || {
                    NativeStateSnafu {
                        field: "managed Graph identity",
                    }
                    .build()
                },
            )?
        };
        let prior = ManagedGraph::read(id, |key| Records::staged(key, &self.transaction))?;
        if !create && prior.is_none() {
            return NativeStateSnafu {
                field: "managed Graph mapping",
            }
            .fail();
        }
        let mut graph = prior.clone().unwrap_or_else(|| ManagedGraph {
            graph: id,
            writers: BTreeMap::new(),
            relations: BTreeMap::new(),
        });
        graph.extend(admission.relations, admission.calls, |identity| {
            if create {
                Records::intern(&mut self.transaction, identity)
            } else {
                Records::find(identity, |key| Records::staged(key, &self.transaction))?
                    .ok_or_else(|| Code::Conflict.error("managed Graph declaration"))
            }
        })?;
        if prior.as_ref() == Some(&graph) {
            return Ok(());
        }
        if !create {
            return Err(Code::Conflict.error("managed Graph mapping"));
        }
        let writers = graph.writers.values().copied().collect::<Vec<_>>();
        Graph::new(id)?.install(&mut self.transaction, &writers, &graph.declarations()?)?;
        Records::stage(
            &mut self.transaction,
            Records::key(b'G', id),
            Records::encode(&graph)?,
        );
        self.graphs.insert_mut((spec.tenant, id), ());
        self.dirty = true;
        Ok(())
    }
}

impl DataView {
    pub(in crate::analysis::native) fn managed_contract(
        &self,
        spec: &ManagedSpec,
        call: &crate::ManagedCall,
    ) -> Result<sdk::Package> {
        self.managed_contract_charged(spec, call, &mut |_| Ok(()))
    }

    pub(in crate::analysis::native) fn managed_contract_charged(
        &self,
        spec: &ManagedSpec,
        call: &crate::ManagedCall,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<sdk::Package> {
        let descriptor = self
            .package_descriptor_charged(
                spec.tenant,
                &call.package.package_id,
                &call.package.revision,
                charge,
            )?
            .ok_or_else(|| Code::Missing.error("managed SDK descriptor"))?;
        charge(
            descriptor
                .len()
                .saturating_mul(12)
                .saturating_add(12 * size_of::<sdk::Package>()),
        )?;
        call.contract(&descriptor)
    }

    pub fn managed_graph(
        &self,
        tenant: [u8; 16],
        name: &str,
        control: &AnalysisReadControl,
    ) -> Result<Option<ManagedGraph>> {
        self.managed_graph_charged(tenant, name, control, &mut |_| Ok(()))
    }

    pub(in crate::analysis::native) fn managed_graph_charged(
        &self,
        tenant: [u8; 16],
        name: &str,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<ManagedGraph>> {
        control.check()?;
        let Some(id) = Records::find(&InstanceRecord::identity(tenant, name)?, |key| {
            Records::read(key, &self.snapshot)
        })?
        else {
            return Ok(None);
        };
        let graph =
            ManagedGraph::read_charged(id, |key| Records::read(key, &self.snapshot), charge)?;
        control.check()?;
        Ok(graph)
    }
}
