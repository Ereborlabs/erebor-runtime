use std::{any::Any, collections::BTreeMap, sync::Arc};

use araphor_analysis_sdk as sdk;
use araphor_graph::{
    native::{Graph, View},
    ReadOrigin,
};

use super::{GraphCall, ManagedGraphTransaction};
use crate::analysis::{
    native::{DataView, NativeStore},
    PackageResultRefV1,
};
use crate::{
    AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisReadControl, ManagedAttempt,
    ManagedBudget, PackageErrorCodeV1 as Code, Result,
};

pub(super) struct GraphAuthority {
    attempt: Arc<ManagedAttempt>,
    call: u64,
    pub(super) prepared: GraphPreparation,
    origins: BTreeMap<ReadOrigin, PackageResultRefV1>,
    leases: Vec<Arc<dyn Any + Send + Sync>>,
}

pub(super) struct GraphPreparation {
    pub(super) view: View,
    pub(super) package: sdk::Package,
    pub(super) contexts: Vec<(AnalysisContextVersionV1, AnalysisContextRefV1)>,
    pub(super) snapshot: DataView,
    _leases: Vec<Box<dyn Any + Send + Sync>>,
}

impl GraphAuthority {
    pub(super) fn bind(
        store: &NativeStore,
        attempt: Arc<ManagedAttempt>,
        call: u64,
        model: &sdk::Model,
        budget: &dyn ManagedBudget,
        control: &AnalysisReadControl,
    ) -> Result<(GraphCall, Self)> {
        let current = store.live_attempt(&attempt, control)?;
        let specification = &attempt.1.spec;
        let declaration = specification
            .manifest
            .calls
            .get(&call)
            .ok_or_else(|| Code::Denied.error("Graph actual call"))?;
        let mut leases = Vec::new();
        let package =
            current.managed_contract_charged(specification, declaration, &mut |bytes| {
                leases.push(budget.reserve(bytes)?);
                Ok(())
            })?;
        let canonical = package
            .exports
            .iter()
            .find(|export| export.name == declaration.export)
            .ok_or_else(|| Code::Invalid.error("Graph actual export"))?;
        if canonical.name != model.name || canonical.graph != model.graph {
            return Err(Code::Denied.error("Graph actual relation contract"));
        }
        let capability = model
            .graph
            .clone()
            .ok_or_else(|| Code::Denied.error("Graph invocation capability"))?;
        let snapshot = store.read_at(attempt.captured_revision())?;
        let mapping = snapshot
            .managed_graph(specification.tenant, &specification.id, control)?
            .ok_or_else(|| Code::Missing.error("managed Graph mapping"))?;
        let writer = *mapping
            .writers
            .get(&call)
            .ok_or_else(|| Code::Denied.error("Graph admitted writer"))?;
        let mut relations = BTreeMap::new();
        for relation in &capability.relations {
            let (id, saved) = mapping
                .relations
                .get(&relation.name)
                .ok_or_else(|| Code::Missing.error("Graph admitted relation"))?;
            if saved != relation {
                return Err(Code::Denied.error("Graph admitted relation contract"));
            }
            relations.insert(relation.name.clone(), *id);
        }
        let view = Graph::new(mapping.graph)?.view(
            snapshot.snapshot().clone(),
            BTreeMap::new(),
            &|_, bytes, total| ManagedGraphTransaction::reserve(budget, control, bytes, total),
        )?;
        let mut contexts = Vec::new();
        if attempt.5.is_none() {
            for reference in &attempt.0.capture.contexts {
                control.check()?;
                let (value, revision) = snapshot
                    .context_charged(&reference.key, &mut |bytes| {
                        leases.push(budget.reserve(bytes)?);
                        Ok(())
                    })?
                    .ok_or_else(|| Code::Missing.error("captured Graph context"))?;
                if revision != reference.commit_revision {
                    return Err(Code::Conflict.error("captured Graph context revision"));
                }
                snapshot.verify_context(&value)?;
                contexts.push((value, reference.clone()));
            }
        }
        let bound = GraphCall {
            head: view.head(writer)?,
            attempt: Arc::clone(&attempt),
            call,
            graph: mapping.graph,
            writer,
            spec: capability,
            relations,
        };
        Ok((
            bound,
            Self {
                attempt,
                call,
                origins: BTreeMap::new(),
                leases: Vec::new(),
                prepared: GraphPreparation {
                    view,
                    package,
                    contexts,
                    snapshot,
                    _leases: leases,
                },
            },
        ))
    }

    pub(super) fn check(
        &self,
        call: &GraphCall,
        store: &NativeStore,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        self.check_snapshot(call, store, control)?;
        store.live_attempt(&call.attempt, control)?;
        Ok(())
    }

    pub(super) fn check_snapshot(
        &self,
        call: &GraphCall,
        store: &NativeStore,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if !Arc::ptr_eq(&self.attempt, &call.attempt) || self.call != call.call {
            return Err(Code::Denied.error("Graph invocation authority"));
        }
        control.check()?;
        store.check_managed_claim(&call.attempt)?;
        call.attempt.1.grant.remaining()?;
        Ok(())
    }

    pub(super) fn origin(
        &mut self,
        call: &GraphCall,
        store: &NativeStore,
        origin: ReadOrigin,
        control: &AnalysisReadControl,
        reserve: &mut dyn FnMut(usize) -> Result<Arc<dyn Any + Send + Sync>>,
    ) -> Result<PackageResultRefV1> {
        self.check_snapshot(call, store, control)?;
        if origin.revision > call.attempt.captured_revision() {
            return Err(Code::Denied.error("Graph origin cut"));
        }
        if let Some(reference) = self.origins.get(&origin) {
            return Ok(reference.clone());
        }
        let saved = self
            .prepared
            .snapshot
            .graph_origin(origin.writer, origin.revision)?;
        if saved.graph != call.graph
            || saved.instance != call.attempt.1.spec.id
            || saved.grant.selection.tenant_id != call.attempt.1.spec.tenant
        {
            return Err(Code::Denied.error("Graph result authority"));
        }
        saved.grant.permitted_by(&call.attempt.1.grant.selection)?;
        let lease = reserve(
            saved
                .reference
                .result_id
                .len()
                .saturating_mul(4)
                .saturating_add(16 * std::mem::size_of::<(ReadOrigin, PackageResultRefV1)>()),
        )?;
        self.origins.insert(origin, saved.reference.clone());
        self.leases.push(lease);
        Ok(saved.reference)
    }

    pub(super) fn into_preparation(mut self) -> GraphPreparation {
        self.prepared._leases.extend(
            self.leases
                .drain(..)
                .map(|lease| Box::new(lease) as Box<dyn Any + Send + Sync>),
        );
        self.prepared
    }
}
