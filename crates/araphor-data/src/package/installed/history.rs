use std::collections::BTreeSet;
use std::sync::Arc;

use crate::Result;

use super::super::owner::InstalledContext;
use super::super::{AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code};
use super::snapshot::{InstalledBundle, InstalledSnapshot};
use super::{InstalledAnalysis, InstalledRefV1};

impl InstalledAnalysis {
    pub fn refs(&self) -> Result<Vec<InstalledRefV1>> {
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("unpinned installed references"))?;
        snapshot
            .pins
            .iter()
            .map(|pin| {
                let context: InstalledContext = AnalysisPackageOwner::decode(&pin.metadata)?;
                let bundle = snapshot.bundle(&context.root)?;
                let artifact = bundle.value.artifact(&super::super::PackageRefV1 {
                    package_id: pin.key.package_id.clone(),
                    revision: pin.revision.clone(),
                })?;
                let implementation = artifact.implementation(&pin.key.export)?;
                Ok(InstalledRefV1 {
                    package_id: pin.key.package_id.clone(),
                    export: pin.key.export.clone(),
                    revision: pin.revision.clone(),
                    generation: pin.generation,
                    root: context.root,
                    parameters: context.parameters,
                    target: Some(implementation.target().into()),
                    artifact: implementation.identity()?,
                })
            })
            .collect()
    }

    pub fn pin_at(&self, tenant: [u8; 16], references: &[InstalledRefV1]) -> Result<Self> {
        if references.is_empty() || references.len() > crate::analysis::MAX_PACKAGE_ROWS {
            return Err(Code::Invalid.error("historical installed references"));
        }
        let mut current = self.clone();
        current.snapshot = None;
        let current = current.snapshot(tenant)?;
        let mut pins = Vec::new();
        let mut bundles = Vec::<Arc<InstalledBundle>>::new();
        let mut seen = BTreeSet::new();
        for reference in references {
            if reference.generation == 0 || !seen.insert((&reference.package_id, &reference.export))
            {
                return Err(Code::Invalid.error("historical installed reference"));
            }
            for name in [
                &reference.package_id,
                &reference.export,
                &reference.revision,
                &reference.root.package_id,
                &reference.root.revision,
            ] {
                AnalysisPackageOwner::name(name)?;
            }
            let mut pin = current.active(tenant, &reference.package_id, &reference.export)?;
            let mut context: InstalledContext = AnalysisPackageOwner::decode(&pin.metadata)?;
            self.owner.check(&context.grant, Action::Run)?;
            let bundle = if let Some(bundle) = bundles
                .iter()
                .chain(
                    current
                        .snapshot
                        .iter()
                        .flat_map(|snapshot| &snapshot.bundles),
                )
                .find(|bundle| bundle.value.root == reference.root)
            {
                bundle.clone()
            } else {
                InstalledBundle::new(
                    &self.owner.query,
                    self.owner.load_bundle(tenant, &reference.root)?,
                )?
            };
            self.owner.authority.admit(&context.grant, &bundle.value)?;
            let artifact = bundle
                .value
                .artifacts
                .iter()
                .find(|artifact| {
                    artifact.descriptor.id == reference.package_id
                        && artifact.descriptor.revision == reference.revision
                        && artifact.prepared(&reference.export)
                })
                .ok_or_else(|| Code::Missing.error("historical installed export"))?;
            let model = artifact
                .descriptor
                .exports
                .iter()
                .find(|model| model.name == reference.export)
                .ok_or_else(|| Code::Missing.error("historical export declaration"))?;
            let implementation = artifact.implementation(&reference.export)?;
            let identity = implementation.identity()?;
            if reference
                .target
                .as_deref()
                .is_some_and(|target| target != implementation.target())
                || reference
                    .artifact
                    .as_ref()
                    .is_some_and(|recorded| identity.as_ref() != Some(recorded))
            {
                return Err(Code::Conflict.error("historical installed artifact"));
            }
            crate::QueryOwner::model_parameters(
                &model.parameters,
                AnalysisPackageOwner::parameter_values(
                    reference.parameters.as_ref(),
                    &reference.package_id,
                    &reference.export,
                ),
            )?;
            context.root = reference.root.clone();
            context.parameters = reference.parameters.clone();
            pin.revision = reference.revision.clone();
            pin.generation = reference.generation;
            pin.metadata = AnalysisPackageOwner::encode(&context)?;
            if !bundles
                .iter()
                .any(|entry| entry.value.root == reference.root)
            {
                bundles.push(bundle);
            }
            pins.push(pin);
        }
        let mut historical = current;
        historical.snapshot = Some(InstalledSnapshot::new(&self.owner.query, pins, bundles)?);
        historical.historical = true;
        Ok(historical)
    }
}
