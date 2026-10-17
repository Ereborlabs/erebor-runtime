use snafu::ResultExt as _;

use crate::analysis::{PackageActivationV1, PackageResultRefV1};
use crate::{AnalysisReadControl, Result};

use super::installed::snapshot::InstalledBundle;
use super::owner::InstalledContext;
use super::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code, PackageGrantV1,
    PackageResponseV1,
};

mod preparation;

pub(crate) use araphor_data::ResultContext;

#[derive(Clone, Copy)]
pub(super) struct RunPreparation<'a> {
    pub(super) inputs: Option<&'a std::sync::Arc<araphor_query::inputs::InputSet>>,
    pub(super) id: &'a str,
    pub(super) rebuild: bool,
    pub(super) now: u64,
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
        araphor_data::validate_package_name(id)?;
        self.check(grant, Action::Run)?;
        let activations = self.activations(grant.selection.tenant_id, scope, package)?;
        let active = activations
            .first()
            .ok_or_else(|| Code::Missing.error("installed package"))?;
        let context: InstalledContext = Self::decode(&active.metadata)?;
        if context.grant.selection != grant.selection {
            return Err(Code::Conflict
                .error("activation scope or parameters")
                .into());
        }
        let bundle = self.load_installed(grant.selection.tenant_id, &context.root)?;
        let admitted = bundle.admission();
        self.authority.admit(grant, &admitted)?;
        let root = super::PackageRefV1 {
            package_id: package.into(),
            revision: active.revision.clone(),
        };
        let mut receipts = Vec::new();
        for reference in bundle.value.order_for(&root, export)? {
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
                    araphor_data::parameter_values(Some(parameters), &key.package_id, &key.export);
                let installed = araphor_data::parameter_values(
                    saved.parameters.as_ref(),
                    &key.package_id,
                    &key.export,
                );
                if requested != installed {
                    return Err(Code::Conflict.error("activation parameters").into());
                }
            }
            if saved.grant != *grant {
                let _lifecycle = self
                    .lifecycle
                    .lock()
                    .map_err(|_| Code::Conflict.error("package lifecycle lock"))?;
                saved.grant = grant.clone();
                active = self.authorize_commit(grant, Action::Run, &admitted, || {
                    self.store.renew_package(
                        &active,
                        &Self::encode(&saved)?,
                        &grant.principal,
                        || control.check(),
                    )
                })?;
            }
            let loaded;
            let selected = if saved.root == bundle.value.root {
                &bundle
            } else {
                loaded = self.load_installed(grant.selection.tenant_id, &saved.root)?;
                &loaded
            };
            if let Some(receipt) = self.evaluate_active(&active, id, selected, control)? {
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
                status.results = vec![Self::receipt(&result)?];
            }
        }
        Ok(response)
    }

    pub(super) fn evaluate_active(
        &self,
        active: &PackageActivationV1,
        id: &str,
        bundle: &InstalledBundle,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageResultRefV1>> {
        let context: InstalledContext = Self::decode(&active.metadata)?;
        control.check()?;
        if bundle.value.root != context.root {
            return Err(Code::Conflict.error("activation package root").into());
        }
        let admission = bundle.admission();
        self.check(&context.grant, Action::Run)?;
        self.authority.admit(&context.grant, &admission)?;
        let result_id = Self::result_id(active, id)?;
        if let Some(previous) = self
            .store
            .package_result(active.key.tenant_id, &result_id)?
        {
            let artifact = bundle.value.artifact(&super::PackageRefV1 {
                package_id: active.key.package_id.clone(),
                revision: active.revision.clone(),
            })?;
            if previous.commit.request != Self::request(active, id, &context, artifact)? {
                return Err(Code::Conflict.error("evaluation retry").into());
            }
            control.check()?;
            self.check(&context.grant, Action::Run)?;
            return Ok(Some(PackageResultRefV1 {
                result_id,
                commit_revision: previous.commit_revision,
            }));
        }
        let result = self.prepare_at(
            active,
            bundle,
            RunPreparation {
                inputs: None,
                id,
                rebuild: false,
                now: Self::now(),
            },
            control,
        );
        let prepared = match result {
            Ok(Some(prepared)) => prepared,
            Ok(None) => return Ok(None),
            Err(error) if error.is_busy() => return Err(error),
            Err(error) => {
                self.failed(active, &error, control)?;
                return Err(error);
            }
        };
        let receipt = self.authorize_commit(&context.grant, Action::Run, &admission, || {
            self.store.commit_package(&prepared, || control.check())
        })?;
        Ok(Some(receipt))
    }

    fn result_id(active: &PackageActivationV1, id: &str) -> Result<String> {
        Ok(format!(
            "package-{}",
            crate::InputRevision::of(&(&active.key, id)).context(crate::PackageEncodingSnafu)?
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
            ))
            .map_err(Into::into);
        }
        Self::encode(&(
            &active.key,
            &active.revision,
            id,
            &context.grant.selection,
            &context.parameters,
        ))
        .map_err(Into::into)
    }
}
