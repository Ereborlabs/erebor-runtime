use std::collections::BTreeSet;

use crate::{AnalysisReadControl, Result};

use super::owner::InstalledContext;
use super::{AnalysisPackageOwner, PackageActionV1, PackageBundleV1, PackageGrantV1, PackageRefV1};

impl AnalysisPackageOwner {
    pub(super) fn refresh_package(
        &self,
        grant: &PackageGrantV1,
        scope: &str,
        package: &str,
        admitted: Option<&PackageBundleV1>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let mut seen = BTreeSet::new();
        for installed in self.activations(grant.selection.tenant_id, scope, package)? {
            let context: InstalledContext = Self::decode(&installed.metadata)?;
            Self::permits(grant, &context.grant)?;
            let loaded;
            let bundle = match admitted.filter(|bundle| bundle.root == context.root) {
                Some(bundle) => bundle,
                None => {
                    loaded = self.load_bundle(installed.key.tenant_id, &context.root)?;
                    &loaded
                }
            };
            let root = PackageRefV1 {
                package_id: package.into(),
                revision: installed.revision.clone(),
            };
            for reference in bundle.order_for(&root, Some(&installed.key.export))? {
                control.check()?;
                let key = Self::key(grant, scope, &reference);
                if !seen.insert((key.package_id.clone(), key.export.clone())) {
                    continue;
                }
                let Some(active) = self.store.package_activation(&key)? else {
                    continue;
                };
                if !active.active || active.revision != reference.package.revision {
                    continue;
                }
                if active.result_id.is_none() {
                    continue;
                }
                self.check(grant, PackageActionV1::Inspect)?;
                let mut context: InstalledContext = Self::decode(&active.metadata)?;
                Self::permits(grant, &context.grant)?;
                let selection = context.grant.selection.clone();
                context.grant = grant.clone();
                context.grant.selection = selection;
                self.model_run(
                    &active,
                    &context,
                    bundle,
                    super::evaluation::RunPreparation {
                        id: "inspect",
                        rebuild: false,
                        automatic: true,
                        now: Self::now(),
                    },
                    PackageActionV1::Inspect,
                    control,
                )?;
            }
        }
        Ok(())
    }
}
