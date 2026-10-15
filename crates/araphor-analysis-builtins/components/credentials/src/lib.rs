use araphor_analysis_builtins::graph::Detector;
use araphor_analysis_sdk as sdk;

pub struct CredentialsComponent;

impl sdk::Guest for CredentialsComponent {
    fn package() -> sdk::Package {
        Detector::Credentials.descriptor()
    }
    fn compute(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        Detector::Credentials.compute(checked)
    }
}

#[cfg(target_arch = "wasm32")]
sdk::export_component!(CredentialsComponent);

#[cfg(not(target_arch = "wasm32"))]
sdk::export_native!(CredentialsComponent);
