use araphor_analysis_builtins::discovery::Discovery;
use araphor_analysis_sdk as sdk;

#[cfg(target_arch = "wasm32")]
sdk::export_component!(Discovery);

#[cfg(not(target_arch = "wasm32"))]
sdk::export_native!(Discovery);
