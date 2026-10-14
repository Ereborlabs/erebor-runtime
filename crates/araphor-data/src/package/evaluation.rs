use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::analysis::{PackageActivationV1, PackageCommitV1, PackageResultRefV1};
use crate::{AnalysisReadControl, Result};

use super::owner::InstalledContext;
use super::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code, PackageGrantV1,
    PackageResponseV1,
};

mod preparation;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ResultContext {
    #[serde(default = "ResultContext::sql_target")]
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<super::PackageArtifactIdentityV1>,
    pub context: sdk::EvaluationContext,
    pub inputs: Vec<sdk::Revision>,
    pub input_coverage: Vec<sdk::Coverage>,
    pub coverage: sdk::Coverage,
}

impl ResultContext {
    fn sql_target() -> String {
        "sql".into()
    }
}

pub(super) struct PackageRun<'a> {
    pub scope: &'a str,
    pub package: &'a str,
    pub export: Option<&'a str>,
    pub id: &'a str,
    pub parameters: Option<serde_json::Value>,
}

impl AnalysisPackageOwner {
    pub(super) fn run(
        &self,
        grant: &PackageGrantV1,
        request: PackageRun<'_>,
        control: &AnalysisReadControl,
    ) -> Result<PackageResponseV1> {
        let PackageRun {
            scope,
            package,
            export,
            id,
            parameters,
        } = request;
        Self::name(id)?;
        self.check(grant, Action::Run)?;
        let activations = self.activations(grant.selection.tenant_id, scope, package)?;
        let active = activations
            .first()
            .ok_or_else(|| Code::Missing.error("installed package"))?;
        let context: InstalledContext = Self::decode(&active.metadata)?;
        if context.grant.selection != grant.selection {
            return Err(Code::Conflict.error("activation scope or parameters"));
        }
        let bundle = self.load_bundle(grant.selection.tenant_id, &context.root)?;
        self.authority.admit(grant, &bundle)?;
        let root = super::PackageRefV1 {
            package_id: package.into(),
            revision: active.revision.clone(),
        };
        let mut receipts = Vec::new();
        for reference in bundle.order_for(&root, export)? {
            let key = Self::key(grant, scope, &reference);
            let mut active = self
                .store
                .package_activation(&key)?
                .filter(|active| active.active && active.revision == reference.package.revision)
                .ok_or_else(|| Code::Incomplete.error("model activation"))?;
            let mut saved: InstalledContext = Self::decode(&active.metadata)?;
            Self::permits(grant, &saved.grant)?;
            if let Some(parameters) = &parameters {
                let requested =
                    Self::parameter_values(Some(parameters), &key.package_id, &key.export);
                let installed =
                    Self::parameter_values(saved.parameters.as_ref(), &key.package_id, &key.export);
                if requested != installed {
                    return Err(Code::Conflict.error("activation parameters"));
                }
            }
            if saved.grant != *grant {
                let _lifecycle = self
                    .lifecycle
                    .lock()
                    .map_err(|_| Code::Conflict.error("package lifecycle lock"))?;
                saved.grant = grant.clone();
                active = self.authorize_commit(grant, Action::Run, &bundle, || {
                    self.store.renew_package(
                        &active,
                        &Self::encode(&saved)?,
                        &grant.principal,
                        || control.check(),
                    )
                })?;
            }
            if let Some(receipt) =
                self.evaluate_active(&active, id, false, Some(&bundle), control)?
            {
                receipts.push((active.key.export, active.key.package_id, receipt));
            }
        }
        let mut response = self.inspect(grant, scope, package, Some(&bundle), control)?;
        for (export, _, receipt) in receipts
            .into_iter()
            .filter(|(_, owner, _)| owner == package)
        {
            let result = self
                .store
                .package_result(grant.selection.tenant_id, &receipt.result_id)?
                .ok_or_else(|| Code::Missing.error("committed receipt"))?;
            if let Some(status) = response
                .exports
                .iter_mut()
                .find(|status| status.descriptor.name == export)
            {
                status.results = vec![super::PackageReceiptV1::try_from(&result)?];
            }
        }
        Ok(response)
    }

    pub(super) fn evaluate_active(
        &self,
        active: &PackageActivationV1,
        id: &str,
        automatic: bool,
        known: Option<&super::PackageBundleV1>,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageResultRefV1>> {
        let context: InstalledContext = Self::decode(&active.metadata)?;
        control.check()?;
        let loaded;
        let bundle = match known.filter(|bundle| bundle.root == context.root) {
            Some(bundle) => bundle,
            None => {
                loaded = self.load_bundle(active.key.tenant_id, &context.root)?;
                &loaded
            }
        };
        self.check(&context.grant, Action::Run)?;
        self.authority.admit(&context.grant, bundle)?;
        if !automatic {
            let result_id = Self::result_id(active, id)?;
            if let Some(previous) = self
                .store
                .package_result(active.key.tenant_id, &result_id)?
            {
                let artifact = bundle.artifact(&super::PackageRefV1 {
                    package_id: active.key.package_id.clone(),
                    revision: active.revision.clone(),
                })?;
                if previous.request != Self::request(active, id, &context, artifact)? {
                    return Err(Code::Conflict.error("evaluation retry"));
                }
                control.check()?;
                self.check(&context.grant, Action::Run)?;
                return Ok(Some(PackageResultRefV1 {
                    result_id,
                    commit_revision: previous.commit_revision,
                }));
            }
        }
        let result = self.prepare_run(active, bundle, id, false, automatic, control);
        let prepared = match result {
            Ok(Some(prepared)) => prepared,
            Ok(None) => return Ok(None),
            Err(error @ crate::Error::AnalysisBusy { .. }) => return Err(error),
            Err(error) => {
                self.failed(active, &error, control)?;
                return Err(error);
            }
        };
        let receipt = self.authorize_commit(&context.grant, Action::Run, bundle, || {
            self.store.commit_package(&prepared, || control.check())
        })?;
        Ok(Some(receipt))
    }

    pub(super) fn prepare(
        &self,
        active: &PackageActivationV1,
        bundle: &super::PackageBundleV1,
        id: &str,
        rebuild: bool,
        control: &AnalysisReadControl,
    ) -> Result<PackageCommitV1> {
        self.prepare_run(active, bundle, id, rebuild, false, control)?
            .ok_or_else(|| Code::Conflict.error("prepared evaluation"))
    }

    fn result_id(active: &PackageActivationV1, id: &str) -> Result<String> {
        Ok(format!(
            "package-{}",
            crate::digest::InputRevision::of(&(&active.key, id))
                .context(crate::PackageEncodingSnafu)?
        ))
    }

    fn request(
        active: &PackageActivationV1,
        id: &str,
        context: &InstalledContext,
        artifact: &super::PackageArtifactV1,
    ) -> Result<Vec<u8>> {
        let implementation = artifact.implementation(&active.key.export)?;
        if implementation.target() == "native" {
            return Self::encode(&(
                &active.key,
                &active.revision,
                id,
                &context.grant.selection,
                &context.parameters,
                implementation.target(),
                implementation.identity()?,
            ));
        }
        Self::encode(&(
            &active.key,
            &active.revision,
            id,
            &context.grant.selection,
            &context.parameters,
        ))
    }
}
