use std::collections::BTreeMap;
use std::sync::Arc;

use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::model::{Attempt, ManagedSpec, Record, Step};
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisStore, PackageErrorCodeV1 as Code, Result,
};

mod graph;

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
    reader: &'a Connection,
    tenant: [u8; 16],
    control: &'a AnalysisReadControl,
    selected: BTreeMap<String, Arc<SelectedOwner>>,
    attempts: BTreeMap<(String, String), String>,
    producers: BTreeMap<String, Arc<ProducerOwner>>,
    publications: BTreeMap<String, Option<Arc<PublicationOwner>>>,
    findings: Option<Arc<super::graph::projection::DomainProjection>>,
    memory: Option<super::PreparedMemory<'a>>,
    memory_failed: bool,
}

impl<'a> OwnerRead<'a> {
    pub(in crate::analysis) fn new(
        reader: &'a Connection,
        tenant: [u8; 16],
        control: &'a AnalysisReadControl,
    ) -> Self {
        Self {
            reader,
            tenant,
            control,
            selected: BTreeMap::new(),
            attempts: BTreeMap::new(),
            producers: BTreeMap::new(),
            publications: BTreeMap::new(),
            findings: None,
            memory: None,
            memory_failed: false,
        }
    }

    pub(in crate::analysis) fn with_budget(
        reader: &'a Connection,
        tenant: [u8; 16],
        control: &'a AnalysisReadControl,
        budget: &'a dyn super::ManagedBudget,
    ) -> Result<Self> {
        let mut owner = Self::new(reader, tenant, control);
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
    ) -> Result<()> {
        self.control.check()?;
        let bytes: u64 = self
            .reader
            .query_row(
                "SELECT octet_length(request_meta) FROM analysis_results
             WHERE tenant_id=? AND result_id=? AND processor_id=?",
                params![self.tenant.as_slice(), id, processor],
                |row| row.get(0),
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
        self.charge(bytes, charge)
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
        self.bound(id, "managed-definition-v1", charge)?;
        let (step, revision) = AnalysisStore::managed_step_header(self.reader, self.tenant, id)?;
        self.bound_attempt(&step.instance, &step.attempt, charge)?;
        let (attempt, spec) =
            AnalysisStore::validate_selected_owner(self.reader, self.tenant, id, &step, revision)?;
        let alias = (step.instance.clone(), step.attempt.clone());
        if self.attempts.get(&alias).is_some_and(|prior| prior != id) {
            return Err(Code::Conflict.error("immutable selected attempt identity"));
        }
        let owner = Arc::new(SelectedOwner {
            step,
            attempt,
            spec,
            revision,
        });
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
        self.bound(id, "managed-package-v1", charge)?;
        let (record, saved) = AnalysisStore::managed_meta_from(self.reader, self.tenant, id)?;
        if saved != revision {
            return Err(Code::Conflict.error("Graph producer revision"));
        }
        let alias = (record.instance.clone(), record.attempt.clone());
        let selected = match self.attempts.get(&alias) {
            Some(id) => id.clone(),
            None => {
                self.bound_attempt(&record.instance, &record.attempt, charge)?;
                let (attempt, _) = AnalysisStore::managed_call_owner(
                    self.reader,
                    self.tenant,
                    id,
                    revision,
                    &record,
                )?;
                attempt
                    .receipt
                    .ok_or_else(|| Code::Missing.error("managed producer receipt"))?
                    .selected
                    .result_id
            }
        };
        let selected = self.selected(&selected, charge)?;
        AnalysisStore::validate_call_header(
            self.reader,
            self.tenant,
            id,
            &record,
            revision,
            &selected.step,
            selected.revision,
            &selected.attempt,
            &selected.spec,
            charge,
        )?;
        let owner = Arc::new(ProducerOwner { record, selected });
        self.producers.insert(id.to_owned(), Arc::clone(&owner));
        Ok(owner)
    }
}
