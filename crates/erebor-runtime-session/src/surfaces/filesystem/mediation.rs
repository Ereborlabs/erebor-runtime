use erebor_runtime_core::SurfaceMediationDecision;

pub(super) struct FilesystemMediationDocument<'a> {
    value: &'a serde_json::Value,
}

impl<'a> FilesystemMediationDocument<'a> {
    pub(super) const fn new(value: &'a serde_json::Value) -> Self {
        Self { value }
    }

    pub(super) fn into_decision(self) -> Result<SurfaceMediationDecision, String> {
        Ok(SurfaceMediationDecision::from_parts(
            self.required_string("kind")?,
            self.optional_string("replacement_surface")
                .unwrap_or_else(|| String::from("filesystem")),
            self.optional_string("endpoint").unwrap_or_default(),
            self.optional_string("lease_id").unwrap_or_default(),
            self.optional_string("print_line").unwrap_or_default(),
            self.value
                .get("keepalive")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        ))
    }

    fn required_string(&self, key: &str) -> Result<String, String> {
        self.optional_string(key)
            .ok_or_else(|| format!("mediation `{key}` is required"))
    }

    fn optional_string(&self, key: &str) -> Option<String> {
        self.value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
    }
}
