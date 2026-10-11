use araphor_analysis_sdk as sdk;
use std::collections::BTreeSet;

use crate::analysis::PackageActivationV1;
use crate::{AnalysisReadControl, Result};

use super::evaluation::ResultContext;
use super::owner::InstalledContext;
use super::{
    AnalysisPackageOwner, PackageActionV1, PackageArtifactV1, PackageGrantV1, PackageRefV1,
};

impl AnalysisPackageOwner {
    pub(super) fn refresh_package(
        &self,
        grant: &PackageGrantV1,
        scope: &str,
        package: &str,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let mut seen = BTreeSet::new();
        for installed in self.activations(grant.selection.tenant_id, scope, package)? {
            let context: InstalledContext = Self::decode(&installed.metadata)?;
            Self::permits(grant, &context.grant)?;
            let bundle = self.load_bundle(installed.key.tenant_id, &context.root)?;
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
                let artifact = bundle.artifact(&reference.package)?;
                let model = artifact
                    .descriptor
                    .exports
                    .iter()
                    .find(|model| model.name == reference.export)
                    .ok_or_else(|| super::PackageErrorCodeV1::Missing.error("installed export"))?;
                self.refresh(&active, artifact, model, grant, control)?;
            }
        }
        Ok(())
    }

    pub(super) fn refresh(
        &self,
        active: &PackageActivationV1,
        artifact: &PackageArtifactV1,
        model: &sdk::Model,
        grant: &PackageGrantV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let Some(id) = &active.result_id else {
            return Ok(());
        };
        if !active.active {
            return Ok(());
        }
        let Some(result) = self.store.package_result(active.key.tenant_id, id)? else {
            return Ok(());
        };
        if result.stale {
            return Ok(());
        }
        let saved: ResultContext = Self::decode(&result.metadata)?;
        let mut context: InstalledContext = Self::decode(&active.metadata)?;
        Self::permits(grant, &context.grant)?;
        let selection = context.grant.selection.clone();
        context.grant = grant.clone();
        context.grant.selection = selection;
        let now = Self::clock_tick(Self::now());
        let now = if Self::clock_tick(saved.context.time_utc_ns as u64) == now {
            saved.context.time_utc_ns as u64
        } else {
            now
        };
        let clocked = artifact
            .sql(&model.name)
            .map(|(_, program)| program.uses_clock(model))
            .transpose()?
            .unwrap_or(false);
        let clock_changed = Self::clock_changed(clocked, saved.context.time_utc_ns, now);
        let inputs = self.inputs(
            super::inputs::InputRequest {
                activation: active,
                artifact,
                model,
                context: &context,
                now,
                action: PackageActionV1::Inspect,
            },
            control,
        );
        let unchanged = match inputs {
            Ok(inputs) => {
                saved.inputs
                    == inputs
                        .inputs
                        .iter()
                        .map(|input| input.revision.clone())
                        .collect::<Vec<_>>()
                    && saved.input_coverage
                        == inputs
                            .inputs
                            .iter()
                            .map(|input| input.coverage.clone())
                            .collect::<Vec<_>>()
            }
            Err(crate::Error::Package {
                code: super::PackageErrorCodeV1::Missing | super::PackageErrorCodeV1::Incomplete,
                ..
            }) => false,
            Err(error) => return Err(error),
        };
        control.check()?;
        if !unchanged || clock_changed {
            self.store.mark_package_stale(active)?;
        }
        Ok(())
    }
}
