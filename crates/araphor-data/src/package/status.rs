use araphor_analysis_sdk as sdk;

use super::evaluation::ResultContext;
use super::{
    AnalysisPackageOwner, PackageArtifactV1, PackageExportStatusV1, PackageReadinessV1,
    PackageReceiptV1,
};
use crate::analysis::{PackageActivationV1, PackageResultV1};

impl PackageExportStatusV1 {
    pub(super) fn new(
        artifact: &PackageArtifactV1,
        model: &sdk::Model,
        active: &PackageActivationV1,
        readiness: PackageReadinessV1,
        results: Vec<PackageReceiptV1>,
    ) -> Self {
        Self {
            descriptor: model.clone(),
            revision: active.revision.clone(),
            targets: artifact
                .implementations
                .iter()
                .filter(|target| target.export() == model.name)
                .map(|target| target.target().into())
                .collect(),
            readiness,
            active: active.active,
            activation_revision: active.generation,
            results,
            dependencies: artifact
                .descriptor
                .dependencies
                .iter()
                .filter(|dependency| dependency.model == model.name)
                .cloned()
                .collect(),
            fixtures: artifact
                .fixtures
                .iter()
                .filter(|fixture| fixture.export == model.name)
                .map(|fixture| fixture.name.clone())
                .collect(),
        }
    }
}

impl TryFrom<&PackageResultV1> for PackageReceiptV1 {
    type Error = crate::Error;

    fn try_from(result: &PackageResultV1) -> crate::Result<Self> {
        let metadata: ResultContext = AnalysisPackageOwner::decode(&result.metadata)?;
        Ok(Self {
            result_id: result.result_id.clone(),
            commit_revision: result.commit_revision,
            input_revisions: metadata.inputs,
            coverage: metadata.coverage,
            stale: result.stale,
        })
    }
}
