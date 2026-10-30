use super::*;
use std::sync::Arc;

pub struct GraphLease(Arc<AnalysisStore>);

impl GraphLease {
    pub fn remove(&self, selection: &AnalysisSelectionV1) -> Result<()> {
        let _writer = self.0.writer_access()?;
        let mut owner = self
            .0
            .graph_owner
            .lock()
            .map_err(|_| self.0.state_error("the Graph interest lock is poisoned"))?;
        owner
            .as_mut()
            .ok_or_else(|| self.0.state_error("the Graph interest owner is absent"))?
            .retain(|value| value != selection);
        Ok(())
    }
}

impl Drop for GraphLease {
    fn drop(&mut self) {
        let _writer = self
            .0
            .writer
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.0
            .graph_owner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }
}

impl AnalysisStore {
    pub fn graph_enabled(&self) -> bool {
        self.graph_owner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .is_some_and(|owner| !owner.is_empty())
    }

    pub fn lease_graph(
        self: &Arc<Self>,
        selections: Vec<AnalysisSelectionV1>,
    ) -> Result<GraphLease> {
        if selections.is_empty() || selections.iter().any(|selection| !selection.valid()) {
            return self.reject("the Graph interest is invalid");
        }
        let _writer = self.writer_access()?;
        let mut owner = self
            .graph_owner
            .lock()
            .map_err(|_| self.state_error("the Graph interest lock is poisoned"))?;
        if owner.is_some() {
            return crate::AnalysisConflictSnafu.fail();
        }
        *owner = Some(selections);
        Ok(GraphLease(Arc::clone(self)))
    }

    pub(in crate::analysis) fn graph_interested(
        &self,
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<bool> {
        Ok(self
            .graph_owner
            .lock()
            .map_err(|_| self.state_error("the Graph interest lock is poisoned"))?
            .as_ref()
            .is_some_and(|owner| owner.iter().any(|scope| scope.includes_source(source))))
    }

    fn graph_registration_from(
        &self,
        reader: &Connection,
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<(String, bool, u64)>> {
        if !source.valid() {
            return self.reject("the Graph source is invalid");
        }
        reader.query_row("SELECT class,retired,retirement_revision FROM processor_progress WHERE processor_id=? AND method_version=? AND tenant_id=? AND stream_key=?",params![GRAPH_PROCESSOR,GRAPH_SCHEMA_VERSION,source.tenant_id.as_slice(),source.key()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional().context(AnalysisDatabaseSnafu {operation:"read Graph registration"})
    }

    pub(in crate::analysis) fn graph_registration_required(
        &self,
        reader: &Connection,
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<bool> {
        match self.graph_registration_from(reader, source)? {
            None => Ok(true),
            Some((kind, false, _)) if kind == "required" => Ok(false),
            _ => crate::AnalysisConflictSnafu.fail(),
        }
    }

    pub fn register_graph(&self, source: &EvidenceIntakeIdentityV1) -> Result<()> {
        let mut writer = self.writer_access()?;
        if !self.graph_registration_required(writer.get()?, source)? {
            return Ok(());
        }
        let floor = Self::read_receipt_from(writer.get()?, &self.root, source, &source.key())?
            .map_or(0, |receipt| receipt.retained_floor);
        self.register_graph_locked(writer.get_mut()?, source, floor, || Ok(()))
    }

    pub fn register_graph_guarded(
        &self,
        source: &EvidenceIntakeIdentityV1,
        captured: u64,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<bool> {
        let mut writer = self.writer_access()?;
        if let Some((kind, retired, revision)) =
            self.graph_registration_from(writer.get()?, source)?
        {
            if kind != "required" || (retired && revision <= captured) {
                return crate::AnalysisConflictSnafu.fail();
            }
            check()?;
            return Ok(!retired);
        }
        let floor = Self::read_receipt_from(writer.get()?, &self.root, source, &source.key())?
            .map_or(0, |receipt| receipt.retained_floor);
        self.register_graph_locked(writer.get_mut()?, source, floor, check)?;
        Ok(true)
    }

    pub(in crate::analysis) fn register_graph_locked(
        &self,
        writer: &mut Connection,
        source: &EvidenceIntakeIdentityV1,
        floor: u64,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let start = floor
            .checked_add(1)
            .ok_or_else(|| self.state_error("the Graph cursor is exhausted"))?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin Graph registration",
        })?;
        let revision = Self::read_meta_from(&transaction, &self.root)?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the Graph revision is exhausted"))?;
        transaction.execute("INSERT INTO processor_progress VALUES (?, ?, ?, ?, 'required', ?, ?, 0, 0, ?, ?, false, '', '', 0, 0, '')",params![GRAPH_PROCESSOR,GRAPH_SCHEMA_VERSION,source.tenant_id.as_slice(),source.key(),floor,floor,start,floor]).context(AnalysisDatabaseSnafu {operation:"insert Graph registration"})?;
        self.check_revision_limits(&transaction, source.tenant_id)?;
        Self::record_revision(&transaction, revision, &["processor_progress"])?;
        check()?;
        self.commit_metadata(transaction, "commit Graph registration")?;
        self.revision.send_replace(revision);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
