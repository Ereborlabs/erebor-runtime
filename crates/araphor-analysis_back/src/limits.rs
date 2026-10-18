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
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisLimits {
    pub wasm: WasmLimits,
    pub native: crate::NativeLimits,
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn quotas_default_unset() -> TestResult {
        let limits: AnalysisLimits = serde_json::from_str("{}")?;
        assert_eq!(limits, AnalysisLimits::default());
        assert_eq!(
            serde_json::to_value(limits.wasm)?,
            serde_json::json!({
                "fuel": null,
                "memory_bytes": null,
                "cache_bytes": null,
                "cache_entries": null,
                "compiler_bytes": null,
                "data_bytes": null,
                "timeout": null,
                "allocation_bytes": null,
                "host_calls": null,
            })
        );
        Ok(())
    }

    #[test]
    fn quotas_use_runtime_config() -> TestResult {
        let limits = AnalysisLimits {
            wasm: WasmLimits {
                fuel: Some(100_000_000),
                memory_bytes: Some(256 * 1024 * 1024),
                cache_bytes: Some(80 * 1024 * 1024),
                cache_entries: Some(16),
                compiler_bytes: Some(1024 * 1024 * 1024),
                data_bytes: Some(32 * 1024 * 1024),
                timeout: Some(Duration::from_secs(5)),
                allocation_bytes: Some(32 * 1024 * 1024),
                host_calls: Some(4096),
            },
            ..Default::default()
        };
        let decoded: AnalysisLimits = serde_json::from_value(serde_json::to_value(limits)?)?;
        assert_eq!(decoded, limits);
        assert!(serde_json::from_str::<AnalysisLimits>(r#"{"wasm":{"unknown":1}}"#).is_err());
        assert!(serde_json::from_str::<AnalysisLimits>(r#"{"native":{"unknown":1}}"#).is_err());
        Ok(())
    }
}
