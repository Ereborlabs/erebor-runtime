use araphor_analysis_builtins::graph::Detector;
use araphor_analysis_sdk as sdk;

pub struct KubernetesComponent;

impl sdk::guest::Guest for KubernetesComponent {
    fn package() -> sdk::Package {
        Detector::Kubernetes.descriptor()
    }
    fn evaluate(evaluation: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        Detector::Kubernetes.evaluate(evaluation)
    }

    fn evaluate_checked(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        Detector::Kubernetes.evaluate_checked(checked)
    }
}

#[cfg(target_arch = "wasm32")]
sdk::export_component!(KubernetesComponent);

#[cfg(not(target_arch = "wasm32"))]
sdk::export_native!(KubernetesComponent);
