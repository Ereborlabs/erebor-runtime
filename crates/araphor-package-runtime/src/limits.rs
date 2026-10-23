use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WasmLimits {
    pub fuel: Option<u64>,
    pub memory_bytes: Option<usize>,
    pub cache_bytes: Option<usize>,
    pub cache_entries: Option<usize>,
    pub compiler_bytes: Option<u64>,
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

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn quotas_default_unset() -> TestResult {
        let limits: Limits = serde_json::from_str("{}")?;
        assert_eq!(limits, Limits::default());
        assert_eq!(
            serde_json::to_value(limits.wasm)?,
            serde_json::json!({
                "fuel": null,
                "memory_bytes": null,
                "cache_bytes": null,
                "cache_entries": null,
                "compiler_bytes": null,
                "timeout": null,
                "allocation_bytes": null,
                "host_calls": null,
            })
        );
        Ok(())
    }

    #[test]
    fn quotas_use_runtime_config() -> TestResult {
        let limits = Limits {
            wasm: WasmLimits {
                fuel: Some(100_000_000),
                memory_bytes: Some(256 * 1024 * 1024),
                cache_bytes: Some(80 * 1024 * 1024),
                cache_entries: Some(16),
                compiler_bytes: Some(1024 * 1024 * 1024),
                timeout: Some(Duration::from_secs(5)),
                allocation_bytes: Some(32 * 1024 * 1024),
                host_calls: Some(4096),
                ..Default::default()
            },
            ..Default::default()
        };
        let decoded: Limits = serde_json::from_value(serde_json::to_value(limits)?)?;
        assert_eq!(decoded, limits);
        assert!(serde_json::from_str::<Limits>(r#"{"wasm":{"unknown":1}}"#).is_err());
        assert!(serde_json::from_str::<Limits>(r#"{"native":{"unknown":1}}"#).is_err());
        Ok(())
    }
}
