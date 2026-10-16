use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::super::operation::ModelRun;
use super::ModelInputRequest;
use crate::analysis::{PackageKeyV1, PackageResultRefV1};
use crate::package::{
    AnalysisPackageOwner, InstalledContext, PackageErrorCodeV1 as Code, ResultContext,
};
use crate::Result;

impl ModelRun<'_> {
    pub(in crate::model) fn output_table(
        &mut self,
        request: &ModelInputRequest<'_>,
        reference: &sdk::OutputRef,
        port: &sdk::Port,
    ) -> Result<sdk::Input> {
        let key = PackageKeyV1 {
            tenant_id: request.grant.selection.tenant_id,
            scope_id: request.activation.key.scope_id.clone(),
            package_id: reference.package.clone(),
            export: reference.export.clone(),
        };
        let active = self
            .owner
            .store()
            .package_activation(&key)?
            .filter(|active| active.active && active.revision == reference.revision)
            .ok_or_else(|| Code::Incomplete.error("dependency activation"))?;
        let id = active
            .result_id
            .ok_or_else(|| Code::Incomplete.error("dependency result"))?;
        let result = self
            .owner
            .store()
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
        self.input_memory.try_resize(
            request
                .model
                .limits
                .max_bytes
                .min(self.owner.limits().input_bytes as u64) as usize,
        )?;
        let mut data = dataset
            .decode(
                &port.schema,
                sdk::Limits {
                    max_bytes: request
                        .model
                        .limits
                        .max_bytes
                        .min(self.owner.limits().input_bytes as u64),
                    ..request.model.limits
                },
            )
            .context(crate::AnalysisContractSnafu)?;
        data.name = port.name.clone();
        let metadata: ResultContext = AnalysisPackageOwner::decode(&result.metadata)?;
        let (witnesses, contexts) = self
            .owner
            .store()
            .package_evidence(key.tenant_id, std::slice::from_ref(&result.result_id))?;
        for batch in &data.batches {
            self.owner
                .memory()
                .retain_input(batch, &mut self.input_memory)?;
        }
        self.inputs.witnesses.extend(witnesses);
        self.inputs.contexts.extend(contexts);
        self.inputs.dependencies.push(PackageResultRefV1 {
            result_id: result.result_id.clone(),
            commit_revision,
        });
        Ok(sdk::Input {
            data,
            revision: sdk::Revision {
                owner: format!("{}.{}", reference.package, reference.export),
                id: format!("{}:{}", result.result_id, commit_revision),
                window: None,
            },
            coverage: metadata.coverage,
        })
    }
}
