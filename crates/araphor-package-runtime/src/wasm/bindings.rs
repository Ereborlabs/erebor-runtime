wasmtime::component::bindgen!({
    path: "../araphor-analysis-sdk/src/bindings/analysis.wit",
    world: "analysis-package",
    imports: { default: trappable },
    with: {
        "araphor:analysis/graph.transaction": super::execution::HostTransaction,
    },
});

araphor_analysis_sdk::component_conversions!(araphor::analysis::types);
