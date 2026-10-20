use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WasmLimits {
    pub fuel: Option<u64>,
    pub memory_bytes: Option<usize>,
    pub cache_bytes: Option<usize>,
    pub cache_entries: Option<usize>,
    pub compiler_bytes: Option<u64>,
    pub data_bytes: Option<u64>,
    pub timeout: Option<Duration>,
    pub allocation_bytes: Option<usize>,
    pub host_calls: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_sections: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_depth: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_functions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_types: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_operators: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_instances: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_parameters: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_results: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_operators: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_depth: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_locals: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_elements: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tables: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memories: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instances: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub wasm: WasmLimits,
    pub native: crate::native::NativeLimits,
}
