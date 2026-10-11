use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;

use crate::analysis::PackageActivationV1;
use crate::Result;

use super::super::owner::InstalledContext;
use super::super::{AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code};
use super::snapshot::InstalledSnapshot;
use super::InstalledAnalysis;

impl InstalledAnalysis {
    pub fn snapshot(&self, tenant: [u8; 16]) -> Result<Self> {
        if self.tenant.is_some_and(|value| value != tenant) {
            return Err(Code::Denied.error("installed snapshot tenant"));
        }
        if self.snapshot.is_some() {
            return Ok(self.clone());
        }
        let _lifecycle = self
            .owner
            .lifecycle
            .lock()
            .map_err(|_| Code::Conflict.error("package lifecycle lock"))?;
        let mut pins = Vec::new();
        let mut bundles = Vec::<Arc<super::snapshot::InstalledBundle>>::new();
        let mut roots = BTreeSet::new();
        for active in self
            .owner
            .store
            .package_activations(tenant, &self.scope, None)?
        {
            if !active.active {
                continue;
            }
            let context: InstalledContext = AnalysisPackageOwner::decode(&active.metadata)?;
            let bundle = if let Some(bundle) = bundles
                .iter()
                .find(|bundle| bundle.value.root == context.root)
            {
                bundle.clone()
            } else {
                let bundle = self.bundle(tenant, &context.root)?;
                bundles.push(bundle.clone());
                bundle
            };
            let Some(artifact) = bundle
                .value
                .artifacts
                .iter()
                .find(|artifact| artifact.descriptor.id == active.key.package_id)
            else {
                return Err(Code::Missing.error("installed artifact"));
            };
            if !artifact.prepared(&active.key.export) {
                continue;
            }
            self.owner.check(&context.grant, Action::Run)?;
            self.owner.authority.admit(&context.grant, &bundle.value)?;
            roots.insert(context.root);
            pins.push(active);
        }
        bundles.retain(|bundle| roots.contains(&bundle.value.root));
        let mut snapshot = self.clone();
        snapshot.tenant = Some(tenant);
        snapshot.snapshot = Some(InstalledSnapshot::new(&self.owner.query, pins, bundles)?);
        Ok(snapshot)
    }

    pub fn descriptors(&self, tenant: [u8; 16]) -> Result<Vec<sdk::Package>> {
        let snapshot = self.snapshot(tenant)?;
        let mut descriptors = BTreeMap::new();
        for active in snapshot.pins() {
            if descriptors.contains_key(&active.key.package_id) {
                continue;
            }
            let context: InstalledContext = AnalysisPackageOwner::decode(&active.metadata)?;
            let bundle = snapshot.bundle(tenant, &context.root)?;
            let artifact = bundle
                .value
                .artifacts
                .iter()
                .find(|artifact| {
                    artifact.descriptor.id == active.key.package_id
                        && artifact.descriptor.revision == active.revision
                })
                .ok_or_else(|| Code::Missing.error("installed descriptor"))?;
            let mut descriptor = artifact.descriptor.clone();
            descriptor.exports.retain(|model| {
                snapshot
                    .pins()
                    .iter()
                    .any(|pin| pin.key.package_id == descriptor.id && pin.key.export == model.name)
            });
            descriptors.insert(descriptor.id.clone(), descriptor);
        }
        Ok(descriptors.into_values().collect())
    }

    pub fn revisions(&self) -> Vec<(String, String)> {
        self.pins()
            .iter()
            .map(|pin| (pin.key.package_id.clone(), pin.revision.clone()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub(super) fn active(
        &self,
        tenant: [u8; 16],
        package: &str,
        export: &str,
    ) -> Result<PackageActivationV1> {
        if self.tenant.is_some_and(|value| value != tenant) {
            return Err(Code::Denied.error("installed snapshot tenant"));
        }
        let active = if let Some(snapshot) = &self.snapshot {
            snapshot
                .pins
                .iter()
                .find(|pin| pin.key.package_id == package && pin.key.export == export)
                .cloned()
        } else {
            let _lifecycle = self
                .owner
                .lifecycle
                .lock()
                .map_err(|_| Code::Conflict.error("package lifecycle lock"))?;
            self.owner
                .store
                .package_activations(tenant, &self.scope, Some(package))?
                .into_iter()
                .find(|active| active.active && active.key.export == export)
        };
        active.ok_or_else(|| Code::Missing.error("active installed export"))
    }
}

#[cfg(test)]
mod tests;
