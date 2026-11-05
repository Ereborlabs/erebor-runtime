use super::*;

mod headers;
pub(super) use headers::{SourceHeader, SourceHeaders};

impl AnalysisStore {
    pub(super) fn check_selected_source(
        &self,
        receipt: &AnalysisSourceReceiptV1,
        covered: u64,
    ) -> Result<()> {
        if covered != receipt.contiguous_cursor {
            return self.reject("the selected source has an unrecorded input gap");
        }
        Ok(())
    }
}
