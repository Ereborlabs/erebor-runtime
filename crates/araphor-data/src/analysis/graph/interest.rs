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
        let owner = owner
            .as_mut()
            .ok_or_else(|| self.0.state_error("the Graph interest owner is absent"))?;
        let enabled = !owner.is_empty();
        owner.retain(|value| value != selection);
        if enabled && owner.is_empty() {
            self.0.controls.send_replace(());
        }
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
        let removed = self.0
            .graph_owner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if removed.is_some_and(|owner| !owner.is_empty()) {
            self.0.controls.send_replace(());
        }
    }
}

impl AnalysisStore {
    pub fn graph_members(
        &self, selection: &AnalysisSelectionV1, control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<(u64,Vec<(EvidenceIntakeIdentityV1,bool,bool)>)> {
        if !selection.valid() { return self.reject("the Graph inventory selection is invalid"); }
        self.read_snapshot(|reader| {
            control.check()?;
            let revision = Self::read_meta_from(reader,&self.root)?.commit_revision;
            let mut query = reader.prepare(
                "SELECT source.identity_json,NOT coalesce(progress.retired,false),progress.stream_key IS NOT NULL,
                    octet_length(encode(source.identity_json))
                 FROM source_receipts source LEFT JOIN processor_progress progress
                    ON progress.tenant_id=source.tenant_id AND progress.stream_key=source.stream_key
                    AND progress.processor_id=? AND progress.method_version=? WHERE source.tenant_id=?",
            ).context(AnalysisDatabaseSnafu { operation:"prepare Graph source inventory" })?;
            let mut rows = query.query(params![GRAPH_PROCESSOR,GRAPH_SCHEMA_VERSION,selection.tenant_id.as_slice()])
                .context(AnalysisDatabaseSnafu { operation:"read Graph source inventory" })?;
            let mut members = Vec::new();
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu { operation:"advance Graph source inventory" })? {
                control.check()?;
                let bytes: u64 = row.get(3).context(AnalysisDatabaseSnafu { operation:"bound Graph source inventory" })?;
                let bytes = usize::try_from(bytes).ok().and_then(|bytes| bytes.checked_mul(4))
                    .and_then(|bytes| bytes.checked_add(4*std::mem::size_of::<(EvidenceIntakeIdentityV1,bool,bool)>()))
                    .ok_or_else(|| PackageErrorCodeV1::Limit.error("Graph source inventory memory"))?;
                charge(bytes)?;
                let (identity,active,present): (String,bool,bool) = (|| -> duckdb::Result<_> {
                    Ok((row.get(0)?,row.get(1)?,row.get(2)?))
                })().context(AnalysisDatabaseSnafu { operation:"decode Graph source inventory" })?;
                let identity: EvidenceIntakeIdentityV1 = serde_json::from_str(&identity)
                    .map_err(|_| PackageErrorCodeV1::Invalid.error("Graph source inventory identity"))?;
                if !identity.valid() || identity.tenant_id!=selection.tenant_id {
                    return self.reject("the Graph inventory source is invalid");
                }
                if selection.includes_source(&identity) { members.push((identity,active,present)); }
            }
            members.sort_unstable();
            Ok((revision,members))
        })
    }

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
        self.controls.send_replace(());
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
            .map_or(0, |(receipt, _)| receipt.retained_floor);
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
            .map_or(0, |(receipt, _)| receipt.retained_floor);
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
        transaction.execute("INSERT INTO processor_versions VALUES (?, ?, ?, ?, 'required', ?, ?, 0, 0, ?, ?, false, '', '', 0, 0, '', ?)",params![GRAPH_PROCESSOR,GRAPH_SCHEMA_VERSION,source.tenant_id.as_slice(),source.key(),floor,floor,start,floor,revision]).context(AnalysisDatabaseSnafu {operation:"insert Graph registration"})?;
        self.check_revision_limits(&transaction, source.tenant_id)?;
        Self::record_revision(&transaction, revision, &["processor_progress"])?;
        check()?;
        self.commit_metadata(transaction, "commit Graph registration")?;
        self.revision.send_replace(revision);
        self.inputs.metadata(revision, super::super::inputs::InputChange::Processor(&ProcessorScopeV1 {
            identity: source.clone(), processor_id: GRAPH_PROCESSOR.into(), method_version: u64::from(GRAPH_SCHEMA_VERSION),
        }));
        self.activations.send_replace(revision);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
