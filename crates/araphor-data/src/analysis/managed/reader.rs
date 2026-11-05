use std::collections::BTreeMap;
use std::sync::Arc;

use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::model::{Attempt, ManagedSpec, Record, Step};
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisStore, PackageErrorCodeV1 as Code, Result,
};

mod committed;
mod graph;
pub(in crate::analysis) use committed::CommittedOwners;
pub(in crate::analysis) use committed::{GraphDelta, GraphOrigin, GraphPublication, GraphRead};
pub(super) use committed::ResultOwners;

pub(in crate::analysis) struct SelectedOwner {
    pub(super) step: Step,
    pub(super) attempt: Attempt,
    pub(super) spec: ManagedSpec,
    pub(super) revision: u64,
}

pub(in crate::analysis) struct ProducerOwner {
    pub(super) record: Record,
    pub(super) selected: Arc<SelectedOwner>,
}

pub(in crate::analysis) struct PublicationOwner {
    selected: Arc<SelectedOwner>,
}

impl PublicationOwner {
    pub(in crate::analysis) fn revision(&self) -> u64 {
        self.selected.revision()
    }

    pub(in crate::analysis) fn grant(&self) -> &crate::PackageGrantV1 {
        self.selected.grant()
    }
}

impl SelectedOwner {
    pub(in crate::analysis) fn grant(&self) -> &crate::PackageGrantV1 {
        &self.attempt.capture.grant
    }

    pub(in crate::analysis) fn instance(&self) -> &str {
        &self.step.instance
    }

    pub(in crate::analysis) fn revision(&self) -> u64 {
        self.revision
    }
}

impl ProducerOwner {
    pub(in crate::analysis) fn grant(&self) -> &crate::PackageGrantV1 {
        self.selected.grant()
    }
}

// This owner is valid only inside its reader transaction.
pub(in crate::analysis) struct OwnerRead<'a> {
    store: &'a AnalysisStore,
    reader: &'a Connection,
    tenant: [u8; 16],
    control: &'a AnalysisReadControl,
    selected: BTreeMap<String, Arc<SelectedOwner>>,
    attempts: BTreeMap<(String, String), String>,
    producers: BTreeMap<String, Arc<ProducerOwner>>,
    contexts: BTreeMap<String, Arc<Vec<crate::AnalysisContextRefV1>>>,
    publications: BTreeMap<String, Option<Arc<PublicationOwner>>>,
    findings: Option<Arc<super::graph::projection::DomainProjection>>,
    memory: Option<super::PreparedMemory<'a>>,
    memory_failed: bool,
}

impl<'a> OwnerRead<'a> {
    pub(in crate::analysis) fn new(
        store: &'a AnalysisStore,
        reader: &'a Connection,
        tenant: [u8; 16],
        control: &'a AnalysisReadControl,
    ) -> Self {
        Self {
            store,
            reader,
            tenant,
            control,
            selected: BTreeMap::new(),
            attempts: BTreeMap::new(),
            producers: BTreeMap::new(),
            contexts: BTreeMap::new(),
            publications: BTreeMap::new(),
            findings: None,
            memory: None,
            memory_failed: false,
        }
    }

    pub(in crate::analysis) fn with_budget(
        store: &'a AnalysisStore,
        reader: &'a Connection,
        tenant: [u8; 16],
        control: &'a AnalysisReadControl,
        budget: &'a dyn super::ManagedBudget,
    ) -> Result<Self> {
        let mut owner = Self::new(store, reader, tenant, control);
        owner.memory = Some(super::PreparedMemory::new(control, budget)?);
        Ok(owner)
    }

    fn charge(
        &mut self,
        bytes: usize,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<()> {
        let result = if let Some(memory) = &mut self.memory {
            memory.charge(bytes)
        } else {
            charge(bytes, bytes)
        };
        self.memory_failed |= result.is_err();
        result
    }

    pub(in crate::analysis) fn memory_failed(&self) -> bool {
        self.memory_failed
    }

    pub(in crate::analysis) fn check_reader(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
    ) -> Result<()> {
        self.control.check()?;
        if tenant != self.tenant || !std::ptr::eq(reader, self.reader) {
            return Err(Code::Conflict.error("managed owner reader identity"));
        }
        Ok(())
    }

    fn bound(
        &mut self,
        id: &str,
        processor: &str,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<u64> {
        self.control.check()?;
        let (bytes, revision): (u64, u64) = self
            .reader
            .query_row(
                "SELECT octet_length(request_meta),commit_revision FROM analysis_results
             WHERE tenant_id=? AND result_id=? AND processor_id=?",
                params![self.tenant.as_slice(), id, processor],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "bound immutable managed owner",
            })?;
        let bytes = usize::try_from(bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(12))
            .and_then(|bytes| {
                bytes
                    .checked_add(id.len().saturating_mul(4))
                    .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<SelectedOwner>()))
            })
            .ok_or_else(|| Code::Limit.error("immutable managed owner memory"))?;
        self.charge(bytes, charge)?;
        Ok(revision)
    }

    fn bound_attempt(
        &mut self,
        instance: &str,
        attempt: &str,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<()> {
        self.control.check()?;
        let bytes: u64 = self
            .reader
            .query_row(
                "SELECT octet_length(a.contract)+octet_length(v.spec)+octet_length(v.scope)
             FROM managed_attempts a JOIN managed_versions v USING(tenant_id,instance_id,generation)
             WHERE a.tenant_id=? AND a.instance_id=? AND a.attempt_id=?",
                params![self.tenant.as_slice(), instance, attempt],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "bound selected owner contract",
            })?;
        let bytes = usize::try_from(bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(12))
            .ok_or_else(|| Code::Limit.error("selected owner contract memory"))?;
        self.charge(bytes, charge)
    }

    pub(in crate::analysis) fn selected(
        &mut self,
        id: &str,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Arc<SelectedOwner>> {
        self.control.check()?;
        if let Some(owner) = self.selected.get(id) {
            return Ok(Arc::clone(owner));
        }
        let revision = self.bound(id, "managed-definition-v1", charge)?;
        let owner = self
            .store
            .managed_results
            .selected(self.tenant, id, revision)?;
        self.bound_attempt(&owner.step.instance, &owner.step.attempt, charge)?;
        AnalysisStore::check_witness_pins(self.reader, id, &owner.step.witnesses)?;
        let step = &owner.step;
        let alias = (step.instance.clone(), step.attempt.clone());
        if self.attempts.get(&alias).is_some_and(|prior| prior != id) {
            return Err(Code::Conflict.error("immutable selected attempt identity"));
        }
        self.attempts.insert(alias, id.to_owned());
        self.selected.insert(id.to_owned(), Arc::clone(&owner));
        Ok(owner)
    }

    pub(in crate::analysis) fn producer(
        &mut self,
        id: &str,
        revision: u64,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Arc<ProducerOwner>> {
        self.control.check()?;
        if let Some(owner) = self.producers.get(id) {
            if owner.selected.revision() != revision {
                return Err(Code::Conflict.error("Graph producer revision"));
            }
            return Ok(Arc::clone(owner));
        }
        let saved = self.bound(id, "managed-package-v1", charge)?;
        if saved != revision {
            return Err(Code::Conflict.error("Graph producer revision"));
        }
        let owner = self
            .store
            .managed_results
            .producer(self.tenant, id, revision)?;
        let selected = owner
            .selected
            .attempt
            .receipt
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("unpublished managed result"))?;
        self.selected(&selected.selected.result_id, charge)?;
        AnalysisStore::check_witness_pins(self.reader, id, &owner.record.witnesses)?;
        self.producers.insert(id.to_owned(), Arc::clone(&owner));
        Ok(owner)
    }
}
