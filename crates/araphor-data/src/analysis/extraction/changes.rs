use super::*;

#[cfg(test)]
mod tests;

pub(in crate::analysis) struct RemovedRange {
    pub(in crate::analysis) identity: RawIdentity,
    pub(in crate::analysis) first: u64,
    pub(in crate::analysis) last: u64,
    pub(in crate::analysis) revision: u64,
}



impl AnalysisExtractionV1 {
    pub(super) fn remove_raw(
        &mut self,
        capture: &mut super::tables::Capture<'_>,
        removed: &RemovedRange,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        control.check()?;
        capture.remove(
            &removed.identity,
            AnalysisGapV1 {
                first_cursor: removed.first,
                last_cursor: removed.last,
                commit_revision: removed.revision,
            },
            &mut self.sink(control),
        )
    }
}
