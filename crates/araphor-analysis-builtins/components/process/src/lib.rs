use araphor_analysis_builtins::graph::Detector;
use araphor_analysis_sdk as sdk;

pub struct ProcessComponent;

impl sdk::guest::Guest for ProcessComponent {
    fn package() -> sdk::Package {
        Detector::Process.descriptor()
    }
    fn evaluate(evaluation: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        Detector::Process.evaluate(evaluation)
    }

    fn evaluate_checked(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        Detector::Process.evaluate_checked(checked)
    }
}

#[cfg(target_arch = "wasm32")]
sdk::export_component!(ProcessComponent);

#[cfg(not(target_arch = "wasm32"))]
sdk::export_native!(ProcessComponent);
