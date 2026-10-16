use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::PackageActivationV1;
use crate::{AnalysisReadControl, Result};

use super::owner::InstalledContext;
use super::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageBundleV1, PackageErrorCodeV1 as Code,
    PackageGrantV1, PackageRefV1, PackageResponseV1,
};
use araphor_data::ModelRef;

impl AnalysisPackageOwner {
    pub(super) fn remove(
        &self,
        grant: &PackageGrantV1,
        scope: &str,
        package: &str,
        control: &AnalysisReadControl,
    ) -> Result<PackageResponseV1> {
        self.check(grant, Action::Remove)?;
        let selected = self
            .store
            .package_activations(grant.selection.tenant_id, scope, None)?;
        let mut roots = BTreeSet::new();
        let mut dependency = false;
        for active in &selected {
            let context: InstalledContext = Self::decode(&active.metadata)?;
            if context.root.package_id == package {
                Self::permits(grant, &context.grant)?;
                roots.insert(context.root);
            } else if active.key.package_id == package {
                Self::permits(grant, &context.grant)?;
                dependency = true;
            }
        }
        if roots.is_empty() && dependency {
            return Err(Code::Conflict
                .error("package is required by another installation")
                .into());
        }
        for root in roots {
            let bundle = self.load_bundle(grant.selection.tenant_id, &root)?;
            let admitted = super::PackageBundleRef::new(&bundle)?;
            self.authorize_commit(grant, Action::Remove, &admitted, || {
                self.remove_closure(grant, scope, &bundle, true, control)
            })?;
        }
        self.inspect(grant, scope, package, None, control)
    }

    pub(super) fn prune_package(
        &self,
        grant: &PackageGrantV1,
        scope: &str,
        bundle: &PackageBundleV1,
        control: &AnalysisReadControl,
    ) -> araphor_data::Result<()> {
        self.remove_closure(grant, scope, bundle, false, control)
    }

    pub(super) fn prune_orphans(
        &self,
        selected: &PackageActivationV1,
    ) -> Result<Option<PackageActivationV1>> {
        let _lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Code::Conflict.error("package lifecycle lock"))?;
        let key = &selected.key;
        let current = self
            .activations(key.tenant_id, &key.scope_id, &key.package_id)?
            .into_iter()
            .find(|active| active.key.export == key.export);
        let Some(current) = current else {
            return Ok(None);
        };
        let context: InstalledContext = Self::decode(&current.metadata)?;
        let roots = self.activations(key.tenant_id, &key.scope_id, &context.root.package_id)?;
        let mut replacements = BTreeSet::new();
        for root in &roots {
            let installed: InstalledContext = Self::decode(&root.metadata)?;
            if installed.root != context.root
                && installed.root.package_id == root.key.package_id
                && installed.root.revision == root.revision
            {
                replacements.insert(installed.root);
            }
        }
        for replacement in replacements {
            let bundle = self.load_bundle(key.tenant_id, &replacement)?;
            if !bundle
                .artifact(&replacement)?
                .descriptor
                .exports
                .iter()
                .all(|model| {
                    roots.iter().any(|active| {
                        active.key.export == model.name && active.revision == replacement.revision
                    })
                })
            {
                continue;
            }
            let obsolete = self.load_bundle(key.tenant_id, &context.root)?;
            let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
            self.prune_package(&context.grant, &key.scope_id, &obsolete, &control)?;
            return Ok(self
                .activations(key.tenant_id, &key.scope_id, &key.package_id)?
                .into_iter()
                .find(|active| active.key.export == key.export));
        }
        Ok(Some(current))
    }

    fn remove_closure(
        &self,
        grant: &PackageGrantV1,
        scope: &str,
        bundle: &PackageBundleV1,
        removing: bool,
        control: &AnalysisReadControl,
    ) -> araphor_data::Result<()> {
        let installed = self
            .store
            .package_activations(grant.selection.tenant_id, scope, None)?;
        let mut models = BTreeMap::new();
        let mut roots = BTreeMap::new();
        for active in installed {
            let context: InstalledContext = Self::decode(&active.metadata)?;
            let key = ModelRef {
                package: PackageRefV1 {
                    package_id: active.key.package_id.clone(),
                    revision: active.revision.clone(),
                },
                export: active.key.export.clone(),
            };
            if key.package == context.root
                && key.package != bundle.root
                && (!removing || key.package.package_id != bundle.root.package_id)
            {
                roots.insert(context.root.clone(), context.clone());
            }
            models.insert(key, (active, context));
        }
        let mut retained = BTreeMap::new();
        for root in roots.keys() {
            control.check()?;
            for model in self.load_bundle(grant.selection.tenant_id, root)?.order()? {
                if models.contains_key(&model) {
                    retained.entry(model).or_insert_with(|| root.clone());
                }
            }
        }
        for model in bundle.order()? {
            let Some((active, mut context)) = models.remove(&model) else {
                continue;
            };
            control.check()?;
            Self::permits(grant, &context.grant)?;
            if let Some(root) = retained.get(&model) {
                if context.root == bundle.root {
                    let replacement = &roots[root];
                    context.root = root.clone();
                    context.grant = replacement.grant.clone();
                    self.rehome_package(&active, &context, control)?;
                }
            } else {
                self.store
                    .remove_package(&active.key, active.generation, || control.check())?;
            }
        }
        for artifact in &bundle.artifacts {
            self.store.collect_package(
                grant.selection.tenant_id,
                &artifact.descriptor.id,
                &artifact.descriptor.revision,
            )?;
        }
        Ok(())
    }

    fn rehome_package(
        &self,
        active: &PackageActivationV1,
        context: &InstalledContext,
        control: &AnalysisReadControl,
    ) -> araphor_data::Result<()> {
        self.store.renew_package(
            active,
            &Self::encode(context)?,
            &context.grant.principal,
            || control.check(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
