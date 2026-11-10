use crate::analysis::native::{DataView, GraphPublication, ManagedGraph, NativeStore};
use crate::{AnalysisReadControl, PackageErrorCodeV1 as Code, Result};
use araphor_analysis_sdk as sdk;
use araphor_graph::native::{Graph, Member};
use snafu::ResultExt as _;
use std::{cell::RefCell, collections::BTreeMap, mem::size_of, sync::Arc};

pub(in crate::analysis::native) struct PublicationRead {
    pub(in crate::analysis::native) at: DataView,
    pub(in crate::analysis::native) mapping: ManagedGraph,
    pub(in crate::analysis::native) graph: araphor_graph::native::View,
    pub(in crate::analysis::native) restricted: bool,
}

impl PublicationRead {
    pub(in crate::analysis::native) fn open(
        store: &NativeStore,
        publication: &GraphPublication,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Self> {
        let at = store.read_at(publication.reference.commit_revision)?;
        let mapping = at
            .managed_graph_charged(publication.tenant, &publication.instance, control, charge)?
            .ok_or_else(|| Code::Missing.error("Graph publication mapping"))?;
        if mapping.graph != publication.graph {
            return Err(Code::Invalid.error("Graph publication mapping identity"));
        }
        let mut snapshots = BTreeMap::new();
        let mut restricted = false;
        for (&writer, &(layer, revision)) in &publication.heads {
            control.check()?;
            charge(12 * size_of::<(u64, fjall::BranchSnapshot)>())?;
            let selected = store.read_at(revision)?;
            snapshots.insert(writer, selected.snapshot().clone());
            let origin = at.graph_origin_charged(writer, revision, charge)?;
            if origin.graph != publication.graph
                || origin.layer != layer
                || origin.instance != publication.instance
                || mapping.writers.get(&origin.call) != Some(&writer)
            {
                return Err(Code::Denied.error("Graph publication writer authority"));
            }
            restricted |= origin.restricted;
        }
        let memory = RefCell::new(charge);
        let graph = Graph::new(publication.graph)?.view(
            at.snapshot().clone(),
            snapshots,
            &|_, bytes, _| {
                control.check().map_err(araphor_graph::Error::backend)?;
                memory.borrow_mut()(bytes).map_err(araphor_graph::Error::backend)?;
                Ok(None)
            },
        )?;
        for &writer in mapping.writers.values() {
            if graph.head(writer)? != publication.heads.get(&writer).map(|(layer, _)| *layer) {
                return Err(Code::Invalid.error("Graph publication writer cut"));
            }
        }
        Ok(Self {
            at,
            mapping,
            graph,
            restricted,
        })
    }

    pub(in crate::analysis::native) fn decode<T>(
        member: &Member,
        port: sdk::Port,
        decode: impl FnOnce(&sdk::Dataset) -> sdk::Result<Vec<T>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<T> {
        let batch = member.properties().slice(member.row, 1);
        charge(batch.get_array_memory_size().saturating_mul(12) + size_of::<T>())?;
        let batch = sdk::Dataset::normalize_batch(batch, Arc::new(port.schema))
            .context(crate::AnalysisContractSnafu)?;
        let mut values = decode(&sdk::Dataset {
            name: port.name,
            batches: vec![batch],
        })
        .context(crate::AnalysisContractSnafu)?;
        values
            .pop()
            .ok_or_else(|| Code::Invalid.error("Graph member value"))
    }
}
