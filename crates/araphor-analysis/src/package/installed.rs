use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use snafu::ResultExt as _;

use crate::{AnalysisReadControl, Result};

use super::owner::InstalledContext;
use super::{
    AnalysisPackageOwner, InstalledRefV1, PackageActionV1 as Action, PackageErrorCodeV1 as Code,
};

mod commit;
mod control;
mod history;
mod read;
pub(super) mod snapshot;

use snapshot::InstalledSnapshot;

#[derive(Clone)]
pub struct InstalledAnalysis {
    pub(super) owner: Arc<AnalysisPackageOwner>,
    scope: String,
    tenant: Option<[u8; 16]>,
    snapshot: Option<Arc<InstalledSnapshot>>,
    historical: bool,
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(super) _directory: Option<Arc<tempfile::TempDir>>,
}

pub struct InstalledEvaluation {
    pub descriptor: sdk::Package,
    pub revision: String,
    pub target: String,
    pub artifact: Option<super::PackageArtifactIdentityV1>,
    pub evaluation: sdk::Evaluation,
    pub output: sdk::Output,
    _output_memory: MemoryReservation,
    _input_memory: MemoryReservation,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl InstalledAnalysis {
    pub fn new(owner: Arc<AnalysisPackageOwner>, scope: &str) -> Result<Self> {
        araphor_data::validate_package_name(scope)?;
        Ok(Self {
            owner,
            scope: scope.into(),
            tenant: None,
            snapshot: None,
            historical: false,
            #[cfg(any(test, feature = "test-fixtures"))]
            _directory: None,
        })
    }

    pub fn evaluate(
        &self,
        tenant: [u8; 16],
        package: &str,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<InstalledEvaluation> {
        let permit = self.owner.operation()?;
        control.check()?;
        if evaluation.allocated_bytes() > self.owner.query.limits().input_bytes {
            return crate::ModelLimitSnafu {
                resource: "analysis input memory",
                limit: self.owner.query.limits().input_bytes,
            }
            .fail();
        }
        let active = self.active(tenant, package, &evaluation.export)?;
        let context: InstalledContext = AnalysisPackageOwner::decode(&active.metadata)?;
        let control = AnalysisPackageOwner::grant_control(
            &context.grant,
            Arc::new(control.within(control.remaining()?)?),
        )?;
        let _watch = control::AuthorityWatch::start(self.owner.authority.clone(), control.clone())?;
        self.owner.check(&context.grant, Action::Run)?;
        if context.grant.selection != crate::AnalysisSelectionV1::tenant(tenant) {
            return Err(Code::Denied.error("host-prepared input scope").into());
        }
        let bundle = self.bundle(tenant, &context.root)?;
        self.owner
            .authority
            .admit(&context.grant, &bundle.admission())?;
        let (artifact, model, admitted) =
            bundle.export(package, &active.revision, &evaluation.export)?;
        let implementation = admitted.implementation(artifact)?;
        if !artifact.prepared(&evaluation.export) {
            return Err(Code::Unsupported.error("host-prepared target").into());
        }
        let mut input_memory = self
            .owner
            .query
            .memory()
            .reserve_input(evaluation.allocated_bytes())?;
        let mut effective = evaluation.clone();
        if implementation.target() == "wasm" {
            effective.context.limits = self.owner.component_limits(effective.context.limits);
        }
        effective.parameters = araphor_data::decode_parameters(
            &model.parameters,
            araphor_data::parameter_values(
                context.parameters.as_ref(),
                package,
                &evaluation.export,
            ),
        )?;
        input_memory.try_resize(effective.allocated_bytes())?;
        let mut arrays = 0usize;
        for batch in effective
            .inputs
            .iter()
            .flat_map(|input| &input.data.batches)
            .chain(effective.parameters.iter())
            .chain(
                effective
                    .checkpoint
                    .iter()
                    .flat_map(|state| &state.datasets)
                    .flat_map(|data| &data.batches),
            )
        {
            self.owner
                .query
                .memory()
                .retain_input(batch, &mut input_memory)?;
            arrays = arrays.saturating_add(
                batch
                    .columns()
                    .iter()
                    .map(|array| array.get_buffer_memory_size())
                    .sum::<usize>(),
            );
        }
        input_memory.try_resize(effective.allocated_bytes().saturating_sub(arrays))?;
        artifact
            .descriptor
            .validate_evaluation(&effective)
            .context(crate::AnalysisContractSnafu)?;
        let result = self
            .owner
            .evaluate_artifact(tenant, artifact, admitted, &effective, &control);
        self.owner.check(&context.grant, Action::Run)?;
        self.owner
            .authority
            .admit(&context.grant, &bundle.admission())?;
        control.check()?;
        let (output, output_memory) = result?.into_parts();
        let target = implementation.target().to_owned();
        let identity = bundle.identity(package, &evaluation.export)?;
        let bytes = artifact
            .descriptor
            .allocated_bytes()
            .checked_add(active.revision.capacity())
            .and_then(|bytes| bytes.checked_add(target.capacity()))
            .and_then(|bytes| {
                bytes.checked_add(
                    identity
                        .as_ref()
                        .map_or(0, super::PackageArtifactIdentityV1::allocated_bytes),
                )
            })
            .ok_or_else(|| Code::Limit.error("installed result memory"))?;
        input_memory.try_grow(bytes)?;
        Ok(InstalledEvaluation {
            descriptor: artifact.descriptor.clone(),
            revision: active.revision,
            target,
            artifact: identity,
            evaluation: effective,
            output,
            _output_memory: output_memory,
            _input_memory: input_memory,
            _permit: permit,
        })
    }
}
