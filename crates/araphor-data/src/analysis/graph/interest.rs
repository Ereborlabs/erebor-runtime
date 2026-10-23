use super::*;

pub struct GraphLease(Arc<AnalysisStore>);

impl GraphLease {
    pub fn remove(&self, selection: &AnalysisSelectionV1) -> Result<()> {
        let _writer = self.0.writer_access()?;
        let mut current = self
            .0
            .graph_owner
            .lock()
            .map_err(|_| self.0.state_error("the Graph interest lock is poisoned"))?;
        let scopes = current
            .as_mut()
            .ok_or_else(|| self.0.state_error("the Graph interest owner is absent"))?;
        scopes.retain(|scope| scope != selection);
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
            .is_some_and(|scopes| !scopes.is_empty())
    }

    pub fn lease_graph(
        self: &Arc<Self>,
        selections: Vec<AnalysisSelectionV1>,
    ) -> Result<GraphLease> {
        if selections.is_empty() || selections.iter().any(|selection| !selection.valid()) {
            return self.reject("the Graph interest is invalid");
        }
        let _writer = self.writer_access()?;
        let mut current = self
            .graph_owner
            .lock()
            .map_err(|_| self.state_error("the Graph interest lock is poisoned"))?;
        if current.is_some() {
            return AnalysisConflictSnafu.fail();
        }
        *current = Some(selections);
        Ok(GraphLease(Arc::clone(self)))
    }

    pub(in crate::analysis) fn graph_interested(
        &self,
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<bool> {
        let current = self
            .graph_owner
            .lock()
            .map_err(|_| self.state_error("the Graph interest lock is poisoned"))?;
        Ok(current.as_ref().is_some_and(|scopes| {
            scopes
                .iter()
                .any(|selection| selection.includes_source(source))
        }))
    }
}

#[cfg(test)]
mod tests;
