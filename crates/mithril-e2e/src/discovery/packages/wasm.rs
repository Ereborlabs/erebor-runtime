use araphor_data::{PackageArtifactV1, PackageBundleV1, PackageImplementationV1};
use araphor_detector_example::BurstDetector;

const COMPONENT: &[u8] = araphor_analysis_builtins::components::DETECTOR;

pub(super) fn bundle() -> PackageBundleV1 {
    let descriptor = BurstDetector::package();
    let artifact = PackageArtifactV1 {
        implementations: vec![PackageImplementationV1::Wasm {
            exports: descriptor
                .exports
                .iter()
                .map(|model| model.name.clone())
                .collect(),

            artifact: COMPONENT.to_vec(),
        }],
        descriptor,
        fixtures: Vec::new(),
    };
    PackageBundleV1 {
        schema_version: 1,
        root: artifact.reference(),
        artifacts: vec![artifact],
    }
}
