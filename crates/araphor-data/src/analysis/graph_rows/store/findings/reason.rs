use crate::analysis::graph_rows::store::{FindingReasonV1, FindingRows, Result};
impl FindingRows {
    pub fn validate_reason(reason: &FindingReasonV1, package: &str) -> Result<()> {
        crate::analysis::graph_rows::store::validation::Validation::validate_reason(reason, package)
            .map_err(Into::into)
    }
}
