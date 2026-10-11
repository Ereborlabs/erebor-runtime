use std::sync::Arc;

use araphor_analysis_builtins::{discovery::Discovery, graph::Detector};

use crate::{AnalysisReadControl, Result};

use super::{
    AnalysisPackageOwner, InstalledAnalysis, PackageArtifactV1, PackageBundleV1, PackageGrantV1,
    PackageImplementationV1,
};

#[cfg(any(test, feature = "test-fixtures"))]
mod testing;

impl AnalysisPackageOwner {
    pub const DOMAIN_SCOPE: &'static str = "analysis";

    pub fn required_bundles() -> Vec<PackageBundleV1> {
        let definitions: [(araphor_analysis_sdk::Package, &[u8]); 4] = [
            (
                Discovery::package(),
                include_bytes!("../../../araphor-analysis-builtins/artifacts/discovery.wasm"),
            ),
            (
                Detector::Process.descriptor(),
                include_bytes!("../../../araphor-analysis-builtins/artifacts/process.wasm"),
            ),
            (
                Detector::Credentials.descriptor(),
                include_bytes!("../../../araphor-analysis-builtins/artifacts/credentials.wasm"),
            ),
            (
                Detector::Kubernetes.descriptor(),
                include_bytes!("../../../araphor-analysis-builtins/artifacts/kubernetes.wasm"),
            ),
        ];
        definitions
            .into_iter()
            .map(|(descriptor, bytes)| {
                let implementations = vec![PackageImplementationV1::Wasm {
                    exports: descriptor
                        .exports
                        .iter()
                        .map(|model| model.name.clone())
                        .collect(),
                    inputs: None,
                    artifact: bytes.to_vec(),
                }];
                let artifact = PackageArtifactV1 {
                    descriptor,
                    implementations,
                    fixtures: Vec::new(),
                };
                PackageBundleV1 {
                    schema_version: 1,
                    root: artifact.reference(),
                    artifacts: vec![artifact],
                }
            })
            .collect()
    }

    pub fn ensure_required(
        self: &Arc<Self>,
        grant: &PackageGrantV1,
        control: &AnalysisReadControl,
    ) -> Result<InstalledAnalysis> {
        let _permit = self.operation()?;
        let _lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| super::PackageErrorCodeV1::Conflict.error("package lifecycle lock"))?;
        for bundle in Self::required_bundles() {
            control.check()?;
            let activations = self.activations(
                grant.selection.tenant_id,
                Self::DOMAIN_SCOPE,
                &bundle.root.package_id,
            )?;
            if activations.is_empty() {
                let export = &bundle.artifacts[0].descriptor.exports[0].name;
                let key = crate::analysis::PackageKeyV1 {
                    tenant_id: grant.selection.tenant_id,
                    scope_id: Self::DOMAIN_SCOPE.into(),
                    package_id: bundle.root.package_id.clone(),
                    export: export.clone(),
                };
                if self.store.package_activation(&key)?.is_some() {
                    continue;
                }
                self.install(grant, Self::DOMAIN_SCOPE, &bundle, None, false, control)?;
            }
        }
        InstalledAnalysis::new(self.clone(), Self::DOMAIN_SCOPE)
    }
}
