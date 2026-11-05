use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use araphor_analysis_sdk as sdk;
use araphor_graph::{GraphStore, Journal, ReadOrigin};

use super::{authority::GraphAuthority, ManagedBudget, ManagedGraphCall};
use crate::analysis::PackageResultRefV1;
use crate::{AnalysisReadControl, AnalysisStore, PackageErrorCodeV1 as Code, Result};

pub struct ManagedGraphTransaction {
    pub(super) call: ManagedGraphCall,
    pub(super) predecessors: Vec<Arc<ManagedGraphJournal>>,
    state: Mutex<State>,
    authority: Mutex<Option<GraphAuthority>>,
    budget: Arc<dyn ManagedBudget>,
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ReadRow {
    pub(super) relation: u64,
    pub(super) writer: u64,
    pub(super) owner: Vec<u8>,
    pub(super) key: Vec<u8>,
    pub(super) revision: u64,
}

pub struct ManagedGraphJournal {
    pub(super) call: ManagedGraphCall,
    pub(super) predecessors: Vec<Arc<ManagedGraphJournal>>,
    pub(super) work: Work,
    pub(super) budget: Arc<dyn ManagedBudget>,
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
        store: &AnalysisStore,
        call: ManagedGraphCall,
        predecessors: Vec<Arc<ManagedGraphJournal>>,
        budget: Arc<dyn ManagedBudget>,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Self>> {
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
        let mut reader = store.reader_until(control)?;
        let authority = control.run(&mut reader, |reader| {
            GraphAuthority::bind(&call, store, reader, control, budget.as_ref())
        })?;
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

    pub fn check(&self, store: &AnalysisStore, control: &AnalysisReadControl) -> Result<()> {
        let mut reader = store.reader_until(control)?;
        control.run(&mut reader, |connection| {
            self.authority()?
                .as_ref()
                .ok_or_else(|| Code::Incomplete.error("Graph invocation authority"))?
                .check(&self.call, store, connection, control)
        })
    }

    pub fn stage(
        &self,
        store: &AnalysisStore,
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
        let mut reader = store.reader_until(control)?;
        let prepared = control.run(&mut reader, |connection| {
            self.authority()?
                .as_ref()
                .ok_or_else(|| Code::Incomplete.error("Graph invocation authority"))?
                .check(&self.call, store, connection, control)?;
            if name == "graph_clear" {
                return work.journal.prepare_clear(batch).map_err(Into::into);
            }
            let relation = self.call.relations[name];
            let shape = self
                .call
                .spec
                .relation(name)
                .map_err(|_| Code::Denied.error("Graph stage relation"))?
                .engine();
            let present = GraphStore::presence(
                connection,
                self.call.writer,
                relation,
                self.call.attempt.captured_revision(),
                &batch,
            )?;
            work.journal
                .prepare(relation, &shape, batch, &present)
                .map_err(Into::into)
        })?;
        control.check()?;
        work.journal.publish(prepared)?;
        work.leases.push(lease);
        Ok(())
    }

    pub fn freeze(
        &self,
        store: &AnalysisStore,
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
        self.authority
            .lock()
            .map_err(|_| Code::Incomplete.error("Graph authority lock"))?
            .take();
        Ok(Arc::new(ManagedGraphJournal {
            call: self.call.clone(),
            predecessors: self.predecessors.clone(),
            work,
            budget: Arc::clone(&self.budget),
        }))
    }
}

impl ManagedGraphCall {
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
