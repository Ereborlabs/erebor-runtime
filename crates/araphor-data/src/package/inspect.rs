use crate::analysis::{PackageActivationV1, PackageKeyV1};
use crate::{AnalysisReadControl, Result};

use super::owner::InstalledContext;
use super::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageArtifactV1, PackageBundleV1,
    PackageDatasetV1, PackageErrorCodeV1 as Code, PackageExportStatusV1, PackageGrantV1,
    PackageOutputV1, PackageReceiptV1, PackageResponseV1,
};

pub(super) struct PackageQuery<'a> {
    pub scope: &'a str,
    pub package: &'a str,
    pub export: &'a str,
    pub id: Option<&'a str>,
    pub sql: &'a str,
}

impl AnalysisPackageOwner {
    pub(super) fn activations(
        &self,
        tenant: [u8; 16],
        scope: &str,
        package: &str,
    ) -> Result<Vec<PackageActivationV1>> {
        let selected = self
            .store
            .package_activations(tenant, scope, Some(package))?;
        if selected.len() > 64 {
            return Err(Code::Limit.error("package exports"));
        }
        Ok(selected)
    }

    pub(super) fn inspect(
        &self,
        grant: &PackageGrantV1,
        scope: &str,
        package: &str,
        admitted: Option<&PackageBundleV1>,
        control: &AnalysisReadControl,
    ) -> Result<PackageResponseV1> {
        self.check(grant, Action::Inspect)?;
        self.refresh_package(grant, scope, package, admitted, control)?;
        let mut exports = Vec::new();
        for active in self.activations(grant.selection.tenant_id, scope, package)? {
            let context: InstalledContext = Self::decode(&active.metadata)?;
            Self::permits(grant, &context.grant)?;
            let loaded;
            let artifact = match admitted
                .filter(|bundle| bundle.root == context.root)
                .and_then(|bundle| {
                    bundle.artifacts.iter().find(|artifact| {
                        artifact.descriptor.id == package
                            && artifact.descriptor.revision == active.revision
                    })
                }) {
                Some(artifact) => artifact,
                None => {
                    let stored = self
                        .store
                        .package_revision(active.key.tenant_id, package, &active.revision)?
                        .ok_or_else(|| Code::Missing.error("installed artifact"))?;
                    loaded = Self::decode::<PackageArtifactV1>(&stored.artifact)?;
                    &loaded
                }
            };
            let model = artifact
                .descriptor
                .exports
                .iter()
                .find(|model| model.name == active.key.export)
                .ok_or_else(|| Code::Missing.error("installed export"))?;
            let mut results = Vec::new();
            for result in self.store.package_results(&active.key)? {
                let installed: InstalledContext = Self::decode(&result.activation.metadata)?;
                match Self::permits(grant, &installed.grant) {
                    Err(crate::Error::Package {
                        code: Code::Denied, ..
                    }) => continue,
                    permitted => permitted?,
                }
                results.push(PackageReceiptV1::try_from(&result)?);
            }
            let readiness = if !active.active
                && matches!(context.readiness, super::PackageReadinessV1::Ready)
            {
                super::PackageReadinessV1::Inactive
            } else if active.checkpoint_revision > context.status_checkpoint {
                super::PackageReadinessV1::Ready
            } else {
                context.readiness
            };
            exports.push(PackageExportStatusV1::new(
                artifact, model, &active, readiness, results,
            ));
        }
        self.check(grant, Action::Inspect)?;
        Ok(PackageResponseV1 {
            scope_id: scope.into(),
            package_id: package.into(),
            exports,
            tests: Vec::new(),
            output: None,
        })
    }

    pub fn read_output(
        &self,
        grant: &PackageGrantV1,
        scope: &str,
        package: &str,
        export: &str,
        id: &str,
    ) -> Result<PackageOutputV1> {
        self.check(grant, Action::Inspect)?;
        let key = PackageKeyV1 {
            tenant_id: grant.selection.tenant_id,
            scope_id: scope.into(),
            package_id: package.into(),
            export: export.into(),
        };
        self.store
            .package_activation(&key)?
            .ok_or_else(|| Code::Missing.error("package scope"))?;
        let result = self
            .store
            .package_result(key.tenant_id, id)?
            .filter(|result| result.key == key)
            .ok_or_else(|| Code::Missing.error("package result"))?;
        let installed: InstalledContext = Self::decode(&result.activation.metadata)?;
        Self::permits(grant, &installed.grant)?;
        let mut output: PackageOutputV1 = Self::decode(&result.datasets)?;
        output.checkpoint = if result.checkpoint.is_empty() {
            None
        } else {
            Some(Self::decode(&result.checkpoint)?)
        };
        self.check(grant, Action::Inspect)?;
        Ok(output)
    }

    pub(super) fn query_output(
        &self,
        grant: &PackageGrantV1,
        request: PackageQuery<'_>,
        control: &AnalysisReadControl,
    ) -> Result<PackageResponseV1> {
        let PackageQuery {
            scope,
            package,
            export,
            id,
            sql,
        } = request;
        self.check(grant, Action::Inspect)?;
        let key = PackageKeyV1 {
            tenant_id: grant.selection.tenant_id,
            scope_id: scope.into(),
            package_id: package.into(),
            export: export.into(),
        };
        let active = self
            .store
            .package_activation(&key)?
            .ok_or_else(|| Code::Missing.error("package scope"))?;
        let id = id
            .or(active.result_id.as_deref())
            .ok_or_else(|| Code::Missing.error("package result"))?;
        if active.result_id.as_deref() == Some(id) {
            self.refresh_package(grant, scope, package, None, control)?;
        }
        let stored = self
            .store
            .package_result(key.tenant_id, id)?
            .filter(|result| result.key == key)
            .ok_or_else(|| Code::Missing.error("package result"))?;
        let revision = self
            .store
            .package_revision(key.tenant_id, package, &stored.revision)?
            .ok_or_else(|| Code::Missing.error("result artifact"))?;
        let artifact: PackageArtifactV1 = Self::decode(&revision.artifact)?;
        let model = artifact
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == export)
            .ok_or_else(|| Code::Missing.error("result export"))?;
        let output = self
            .read_output(grant, scope, package, export, id)?
            .decode(model)?;
        control.check()?;
        let query = self.query.query_datasets(
            key.tenant_id,
            &output.datasets,
            sql,
            model.limits,
            control,
        )?;
        let schema = query
            .data
            .batches
            .first()
            .ok_or_else(|| Code::Invalid.error("query output schema"))?
            .schema();
        let dataset = PackageDatasetV1::encode(&query.data, &schema, model.limits)?;
        let mut response = PackageResponseV1 {
            scope_id: scope.into(),
            package_id: package.into(),
            exports: Vec::new(),
            tests: Vec::new(),
            output: None,
        };
        let current = active.active && active.revision == stored.revision;
        let readiness = if current {
            super::PackageReadinessV1::Ready
        } else {
            super::PackageReadinessV1::Inactive
        };
        let mut status = PackageExportStatusV1::new(
            &artifact,
            model,
            &stored.activation,
            readiness,
            vec![PackageReceiptV1::try_from(&stored)?],
        );
        status.active = current;
        if status.activation_revision == 0 {
            status.activation_revision = stored.commit_revision;
        }
        response.exports = vec![status];
        response.output = Some(PackageOutputV1 {
            datasets: vec![dataset],
            ..Default::default()
        });
        self.check(grant, Action::Inspect)?;
        Ok(response)
    }

    pub(super) fn permits(grant: &PackageGrantV1, installed: &PackageGrantV1) -> Result<()> {
        Self::permits_selection(grant, &installed.selection)
    }

    pub(super) fn permits_selection(
        grant: &PackageGrantV1,
        selection: &crate::AnalysisSelectionV1,
    ) -> Result<()> {
        if grant.selection != *selection
            && grant.selection != crate::AnalysisSelectionV1::tenant(selection.tenant_id)
        {
            return Err(Code::Denied.error("whole package scope"));
        }
        Ok(())
    }
}
