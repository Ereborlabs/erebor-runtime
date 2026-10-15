use araphor_analysis_builtins::graph::Detector;
use araphor_analysis_sdk as sdk;

pub struct CredentialsComponent;

impl sdk::guest::Guest for CredentialsComponent {
    fn package() -> sdk::Package {
        Detector::Credentials.descriptor()
    }
    fn evaluate(evaluation: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        Detector::Credentials.evaluate(evaluation)
    }

    fn evaluate_checked(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        Detector::Credentials.evaluate_checked(checked)
    }
}

#[cfg(target_arch = "wasm32")]
sdk::export_component!(CredentialsComponent);

#[cfg(not(target_arch = "wasm32"))]
sdk::export_native!(CredentialsComponent);
