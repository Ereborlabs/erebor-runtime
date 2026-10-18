wasmtime::component::bindgen!({
    path: "../araphor-analysis-sdk/src/bindings/analysis.wit",
    world: "analysis-package",
    imports: { default: trappable },
});

araphor_analysis_sdk::component_conversions!(araphor::analysis::types);
