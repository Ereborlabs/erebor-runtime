use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use crate::analysis::PackageActivationV1;
use crate::{AnalysisReadControl, Result};

use super::owner::InstalledContext;
use super::{AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code};

mod commit;
mod control;
mod history;
mod provenance;
mod read;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstalledRefV1 {
    pub package_id: String,
    pub export: String,
    pub revision: String,
    pub generation: u64,
    pub root: super::PackageRefV1,
    pub parameters: Option<serde_json::Value>,
}

#[derive(Clone)]
pub struct InstalledAnalysis {
    pub(super) owner: Arc<AnalysisPackageOwner>,
    scope: String,
    tenant: Option<[u8; 16]>,
    pins: Option<Arc<Vec<PackageActivationV1>>>,
    historical: bool,
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(super) _directory: Option<Arc<tempfile::TempDir>>,
}

pub struct InstalledEvaluation {
    pub descriptor: sdk::Package,
    pub revision: String,
    pub evaluation: sdk::Evaluation,
    pub output: sdk::Output,
    _lease: crate::query::QueryLease,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl InstalledAnalysis {
    pub fn new(owner: Arc<AnalysisPackageOwner>, scope: &str) -> Result<Self> {
        AnalysisPackageOwner::name(scope)?;
        Ok(Self {
            owner,
            scope: scope.into(),
            tenant: None,
            pins: None,
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
        let bundle = self.owner.load_bundle(tenant, &context.root)?;
        self.owner.authority.admit(&context.grant, &bundle)?;
        let artifact = bundle
            .artifacts
            .iter()
            .find(|artifact| {
                artifact.descriptor.id == package && artifact.descriptor.revision == active.revision
            })
            .ok_or_else(|| Code::Missing.error("installed artifact"))?;
        if !artifact.prepared(&evaluation.export) {
            return Err(Code::Unsupported.error("host-prepared target"));
        }
        let model = artifact
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == evaluation.export)
            .ok_or_else(|| Code::Missing.error("installed export"))?;
        let mut effective = evaluation.clone();
        effective.context.limits = self.owner.query.component_limits(effective.context.limits);
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
            .evaluate_artifact(tenant, artifact, &effective, &control);
        self.owner.check(&context.grant, Action::Run)?;
        self.owner.authority.admit(&context.grant, &bundle)?;
        control.check()?;
        let (output, lease) = result?.into_parts();
        Ok(InstalledEvaluation {
            descriptor: artifact.descriptor.clone(),
            revision: active.revision,
            evaluation: effective,
            output,
            _lease: lease,
            _permit: permit,
        })
    }
}
