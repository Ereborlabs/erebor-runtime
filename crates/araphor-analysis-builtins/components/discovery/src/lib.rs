use araphor_analysis_builtins::discovery::Discovery;
use araphor_analysis_sdk as sdk;

pub struct DiscoveryComponent;

impl sdk::guest::Guest for DiscoveryComponent {
    fn package() -> sdk::Package {
        Discovery::package()
    }
    fn evaluate(evaluation: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        Discovery::evaluate(evaluation)
    }

    fn evaluate_checked(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        Discovery::evaluate_checked(checked)
    }
}

#[cfg(target_arch = "wasm32")]
sdk::export_component!(DiscoveryComponent);

#[cfg(not(target_arch = "wasm32"))]
sdk::export_native!(DiscoveryComponent);
