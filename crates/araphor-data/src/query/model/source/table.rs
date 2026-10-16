use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{ModelInputRequest, ModelSource};
use crate::analysis::{PackageKeyV1, PackageResultRefV1};
use crate::package::{
    AnalysisPackageOwner, InstalledContext, PackageErrorCodeV1 as Code, ResultContext,
};
use crate::{QueryOwner, Result};

impl QueryOwner {
    pub(in crate::query::model) fn output_table(
        &self,
        request: &ModelInputRequest<'_>,
        reference: &sdk::OutputRef,
        port: &sdk::Port,
    ) -> Result<ModelSource> {
        let key = PackageKeyV1 {
            tenant_id: request.grant.selection.tenant_id,
            scope_id: request.activation.key.scope_id.clone(),
            package_id: reference.package.clone(),
            export: reference.export.clone(),
        };
        let active = self
            .store
            .package_activation(&key)?
            .filter(|active| active.active && active.revision == reference.revision)
            .ok_or_else(|| Code::Incomplete.error("dependency activation"))?;
        let id = active
            .result_id
            .ok_or_else(|| Code::Incomplete.error("dependency result"))?;
        let result = self
            .store
            .package_result(key.tenant_id, &id)?
            .filter(|result| {
                !result.stale
                    && result.commit.activation.key == key
                    && result.commit.activation.revision == reference.revision
            })
            .ok_or_else(|| Code::Incomplete.error("dependency freshness"))?;
        let commit_revision = result.commit_revision;
        let result = result.commit;
        let installed: InstalledContext =
            AnalysisPackageOwner::decode(&result.activation.metadata)?;
        AnalysisPackageOwner::permits(request.grant, &installed.grant)?;
        let packet: sdk::wire::Output = AnalysisPackageOwner::decode(&result.datasets)?;
        let dataset = packet
            .datasets
            .iter()
            .find(|dataset| dataset.name == reference.output)
            .ok_or_else(|| Code::Invalid.error("dependency dataset"))?;
        let mut data = dataset
            .decode(
                &port.schema,
                sdk::Limits {
                    max_bytes: request
                        .model
                        .limits
                        .max_bytes
                        .min(self.limits.input_bytes as u64),
                    ..request.model.limits
                },
            )
            .context(crate::AnalysisContractSnafu)?;
        data.name = port.name.clone();
        let metadata: ResultContext = AnalysisPackageOwner::decode(&result.metadata)?;
        let (witnesses, contexts) = self
            .store
            .package_evidence(key.tenant_id, std::slice::from_ref(&result.result_id))?;
        let bytes = data
            .batches
            .iter()
            .map(|batch| {
                batch
                    .get_array_memory_size()
                    .saturating_add(std::mem::size_of::<sdk::RecordBatch>())
            })
            .sum();
        Ok(ModelSource {
            input: sdk::Input {
                data,
                revision: sdk::Revision {
                    owner: format!("{}.{}", reference.package, reference.export),
                    id: format!("{}:{}", result.result_id, commit_revision),
                    window: None,
                },
                coverage: metadata.coverage,
            },
            witnesses,
            contexts,
            dependencies: vec![PackageResultRefV1 {
                result_id: result.result_id,
                commit_revision,
            }],
            source_revisions: Vec::new(),
            _lease: self.budget.retained_input(bytes)?,
        })
    }
}
