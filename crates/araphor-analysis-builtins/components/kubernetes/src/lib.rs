use araphor_analysis_builtins::graph::Detector;
use araphor_analysis_sdk as sdk;

pub struct KubernetesComponent;

impl sdk::Guest for KubernetesComponent {
    fn package() -> sdk::Package {
        Detector::Kubernetes.descriptor()
    }
    fn compute(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        Detector::Kubernetes.compute(checked)
    }
}

#[cfg(target_arch = "wasm32")]
sdk::export_component!(KubernetesComponent);

#[cfg(not(target_arch = "wasm32"))]
sdk::export_native!(KubernetesComponent);
