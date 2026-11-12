use araphor_analysis_builtins::causal::Causal;
use araphor_analysis_sdk as sdk;

pub struct CausalComponent;

impl sdk::Guest for CausalComponent {
    fn package() -> sdk::Package {
        Causal::descriptor()
    }
    fn compute(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        Causal::compute(checked)
    }
}

#[cfg(target_arch = "wasm32")]
sdk::export_component!(CausalComponent);

#[cfg(not(target_arch = "wasm32"))]
sdk::export_native!(CausalComponent);
