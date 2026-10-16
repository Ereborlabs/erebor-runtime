use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::{AnalysisReadControl, Result};

use super::owner::InstalledContext;
use super::{AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code};

mod commit;
mod control;
mod history;
mod provenance;
mod read;
pub(super) mod snapshot;

use snapshot::InstalledSnapshot;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstalledRefV1 {
    pub package_id: String,
    pub export: String,
    pub revision: String,
    pub generation: u64,
    pub root: super::PackageRefV1,
    pub parameters: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<super::PackageArtifactIdentityV1>,
}

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
    _lease: crate::query::QueryLease,
    _metadata: crate::query::QueryLease,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl InstalledAnalysis {
    pub fn new(owner: Arc<AnalysisPackageOwner>, scope: &str) -> Result<Self> {
        AnalysisPackageOwner::name(scope)?;
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
        self.owner.query.check_analysis_input(evaluation)?;
        let active = self.active(tenant, package, &evaluation.export)?;
        let context: InstalledContext = AnalysisPackageOwner::decode(&active.metadata)?;
        let control = AnalysisPackageOwner::grant_control(
            &context.grant,
            Arc::new(control.within(control.remaining()?)?),
        )?;
        let _watch = control::AuthorityWatch::start(self.owner.authority.clone(), control.clone())?;
        self.owner.check(&context.grant, Action::Run)?;
        if context.grant.selection != crate::AnalysisSelectionV1::tenant(tenant) {
            return Err(Code::Denied.error("host-prepared input scope"));
        }
        let bundle = self.bundle(tenant, &context.root)?;
        self.owner
            .authority
            .admit(&context.grant, &bundle.admission())?;
        let (artifact, model, admitted) =
            bundle.export(package, &active.revision, &evaluation.export)?;
        let implementation = artifact.implementation(&evaluation.export)?;
        if !artifact.prepared(&evaluation.export) {
            return Err(Code::Unsupported.error("host-prepared target"));
        }
        let mut effective = evaluation.clone();
        if implementation.target() == "wasm" {
            effective.context.limits = self.owner.query.component_limits(effective.context.limits);
        }
        effective.parameters = crate::QueryOwner::model_parameters(
            &model.parameters,
            AnalysisPackageOwner::parameter_values(
                context.parameters.as_ref(),
                package,
                &evaluation.export,
            ),
        )?;
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
        let (output, lease) = result?.into_parts();
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
        let metadata = self.owner.query.retain_analysis_input(bytes)?;
        Ok(InstalledEvaluation {
            descriptor: artifact.descriptor.clone(),
            revision: active.revision,
            target,
            artifact: identity,
            evaluation: effective,
            output,
            _lease: lease,
            _metadata: metadata,
            _permit: permit,
        })
    }
}
