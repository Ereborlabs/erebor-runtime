use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use araphor_analysis_sdk as sdk;
use araphor_graph::{Journal, ReadOrigin};

use super::{authority::GraphAuthority, GraphCall};
use crate::analysis::native::NativeStore;
use crate::analysis::PackageResultRefV1;
use crate::{AnalysisReadControl, PackageErrorCodeV1 as Code, Result};
use crate::{ManagedAttempt, ManagedBudget};

pub struct ManagedGraphTransaction {
    pub(super) call: GraphCall,
    pub(super) predecessors: Vec<Arc<ManagedGraphJournal>>,
    state: Mutex<State>,
    authority: Mutex<Option<GraphAuthority>>,
    pub(super) budget: Arc<dyn ManagedBudget>,
}

struct State {
    open: bool,
    work: Option<Work>,
}

pub(super) struct Work {
    pub(super) journal: Journal,
    pub(super) origins: BTreeMap<ReadOrigin, PackageResultRefV1>,
    pub(super) pending: BTreeMap<u64, Arc<ManagedGraphJournal>>,
    pub(super) leases: Vec<Arc<dyn Any + Send + Sync>>,
    pub(super) reads: BTreeSet<ReadRow>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
pub(super) struct ReadRow {
    pub(super) relation: u64,
    pub(super) writer: u64,
    pub(super) owner: Vec<u8>,
    pub(super) key: Vec<u8>,
    pub(super) revision: u64,
}

pub struct ManagedGraphJournal {
    pub(super) call: GraphCall,
    pub(super) predecessors: Vec<Arc<ManagedGraphJournal>>,
    pub(super) work: Work,
    pub(super) budget: Arc<dyn ManagedBudget>,
    pub(super) prepared: super::authority::GraphPreparation,
}

pub(super) struct Callback<'a> {
    owner: &'a ManagedGraphTransaction,
    pub(super) work: Option<Work>,
}

impl Drop for Callback<'_> {
    fn drop(&mut self) {
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.work = self.work.take();
    }
}

impl ManagedGraphTransaction {
    pub fn new(
        store: &NativeStore,
        attempt: Arc<ManagedAttempt>,
        call_id: u64,
        model: &sdk::Model,
        predecessors: Vec<Arc<ManagedGraphJournal>>,
        budget: Arc<dyn ManagedBudget>,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Self>> {
        let (call, authority) =
            GraphAuthority::bind(store, attempt, call_id, model, budget.as_ref(), control)?;
        let manifest = &call.attempt.1.spec.manifest;
        let mut ancestors = BTreeSet::new();
        let mut pending = manifest.calls[&call.call]
            .dependencies
            .iter()
            .copied()
            .collect::<Vec<_>>();
        while let Some(id) = pending.pop() {
            if ancestors.insert(id) {
                pending.extend(&manifest.calls[&id].dependencies);
            }
        }
        let mut seen = BTreeSet::new();
        let order = manifest.order()?;
        let mut position = 0;
        for prior in &predecessors {
            if !Arc::ptr_eq(&prior.call.attempt, &call.attempt)
                || prior.call.graph != call.graph
                || !ancestors.contains(&prior.call.call)
                || !seen.insert(prior.call.call)
            {
                return Err(Code::Denied.error("Graph predecessor authority"));
            }
            let next = order
                .iter()
                .position(|id| *id == prior.call.call)
                .ok_or_else(|| Code::Invalid.error("Graph predecessor call"))?;
            if next < position {
                return Err(Code::Invalid.error("Graph predecessor order"));
            }
            position = next + 1;
        }
        let journal = Journal::new(call.writer)?;
        Ok(Arc::new(Self {
            call,
            predecessors,
            budget,
            authority: Mutex::new(Some(authority)),
            state: Mutex::new(State {
                open: true,
                work: Some(Work {
                    journal,
                    origins: BTreeMap::new(),
                    pending: BTreeMap::new(),
                    leases: Vec::new(),
                    reads: BTreeSet::new(),
                }),
            }),
        }))
    }

    pub(super) fn reserve(
        budget: &dyn ManagedBudget,
        control: &AnalysisReadControl,
        bytes: usize,
        total: usize,
    ) -> araphor_graph::Result<Option<araphor_graph::native::Lease>> {
        control.check().map_err(araphor_graph::Error::backend)?;
        budget.check().map_err(araphor_graph::Error::backend)?;
        if total > budget.limit() {
            return Err(araphor_graph::Error::backend(
                Code::Limit.error("Graph invocation memory"),
            ));
        }
        if bytes == 0 {
            return Ok(None);
        }
        budget
            .reserve(bytes)
            .map(Some)
            .map_err(araphor_graph::Error::backend)
    }

    pub(super) fn authority(&self) -> Result<std::sync::MutexGuard<'_, Option<GraphAuthority>>> {
        let authority = self
            .authority
            .lock()
            .map_err(|_| Code::Incomplete.error("Graph authority lock"))?;
        if authority.is_none() {
            return Err(Code::Denied.error("Graph invocation closed"));
        }
        Ok(authority)
    }

    pub fn spec(&self) -> &sdk::GraphSpec {
        &self.call.spec
    }

    pub fn retain(&self, lease: Arc<dyn Any + Send + Sync>) -> Result<()> {
        let mut callback = self.callback()?;
        callback
            .work
            .as_mut()
            .ok_or_else(|| Code::Incomplete.error("Graph callback state"))?
            .leases
            .push(lease);
        Ok(())
    }

    pub(super) fn callback(&self) -> Result<Callback<'_>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Code::Incomplete.error("Graph invocation lock"))?;
        if !state.open {
            return Err(Code::Denied.error("Graph invocation closed"));
        }
        let work = state
            .work
            .take()
            .ok_or_else(|| Code::Denied.error("Graph callback overlap"))?;
        Ok(Callback {
            owner: self,
            work: Some(work),
        })
    }

    pub fn check(&self, store: &NativeStore, control: &AnalysisReadControl) -> Result<()> {
        self.authority()?
            .as_ref()
            .ok_or_else(|| Code::Incomplete.error("Graph invocation authority"))?
            .check(&self.call, store, control)
    }

    pub fn stage(
        &self,
        store: &NativeStore,
        name: &str,
        batch: sdk::RecordBatch,
        lease: Arc<dyn Any + Send + Sync>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let schema = self
            .call
            .spec
            .command_schema(name)
            .map_err(|_| Code::Denied.error("Graph command capability"))?;
        if batch.schema().as_ref() != &schema {
            return Err(Code::Invalid.error("Graph command schema"));
        }
        let mut callback = self.callback()?;
        let work = callback
            .work
            .as_mut()
            .ok_or_else(|| Code::Incomplete.error("Graph callback state"))?;
        let prepared = {
            let bound = self.authority()?;
            let authority = bound
                .as_ref()
                .ok_or_else(|| Code::Incomplete.error("Graph invocation authority"))?;
            authority.check_snapshot(&self.call, store, control)?;
            if name == "graph_clear" {
                work.journal.prepare_clear(batch)?
            } else {
                let relation = self.call.relations[name];
                let shape = self
                    .call
                    .spec
                    .relation(name)
                    .map_err(|_| Code::Denied.error("Graph stage relation"))?
                    .engine();
                let present = authority.prepared.view.presence(
                    self.call.writer,
                    relation,
                    &batch,
                    &|_, bytes, total| Self::reserve(self.budget.as_ref(), control, bytes, total),
                )?;
                work.journal.prepare(relation, &shape, batch, &present)?
            }
        };
        control.check()?;
        work.journal.publish(prepared)?;
        work.leases.push(lease);
        Ok(())
    }

    pub fn freeze(
        &self,
        store: &NativeStore,
        control: &AnalysisReadControl,
    ) -> Result<Arc<ManagedGraphJournal>> {
        self.check(store, control)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| Code::Incomplete.error("Graph invocation lock"))?;
        if !state.open {
            return Err(Code::Denied.error("Graph invocation closed"));
        }
        let work = state
            .work
            .take()
            .ok_or_else(|| Code::Denied.error("Graph callback active"))?;
        state.open = false;
        let prepared = self
            .authority
            .lock()
            .map_err(|_| Code::Incomplete.error("Graph authority lock"))?
            .take()
            .ok_or_else(|| Code::Incomplete.error("Graph invocation authority"))?
            .into_preparation();
        Ok(Arc::new(ManagedGraphJournal {
            call: self.call.clone(),
            predecessors: self.predecessors.clone(),
            work,
            budget: Arc::clone(&self.budget),
            prepared,
        }))
    }
}

impl GraphCall {
    pub(super) fn input_calls(&self) -> BTreeSet<u64> {
        let manifest = &self.attempt.1.spec.manifest;
        let mut calls = BTreeSet::new();
        let mut pending = vec![self.call];
        while let Some(call) = pending.pop() {
            if calls.insert(call) {
                pending.extend(&manifest.calls[&call].dependencies);
            }
        }
        calls
    }
}

impl std::fmt::Debug for ManagedGraphJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedGraphJournal")
            .field("call", &self.call.call)
            .field("writer", &self.call.writer)
            .finish_non_exhaustive()
    }
}
