use super::evaluation::ResultContext;
use super::{AnalysisPackageOwner, PackageReceiptV1};
use crate::analysis::PackageResultV1;

impl AnalysisPackageOwner {
    pub(crate) fn receipt(result: &PackageResultV1) -> crate::Result<PackageReceiptV1> {
        let metadata: ResultContext = AnalysisPackageOwner::decode(&result.commit.metadata)?;
        Ok(PackageReceiptV1 {
            target: metadata.target,
            artifact: metadata.artifact,
            result_id: result.commit.result_id.clone(),
            commit_revision: result.commit_revision,
            input_revisions: metadata.inputs,
            coverage: metadata.coverage,
            stale: result.stale,
        })
    }
}
