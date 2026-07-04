use erebor_runtime_core::SurfaceMediationDecision;

pub(super) fn mediation_decision(
    value: &serde_json::Value,
) -> Result<SurfaceMediationDecision, String> {
    let kind = required_string(value, "kind")?;
    let replacement_surface =
        optional_string(value, "replacement_surface").unwrap_or_else(|| String::from("filesystem"));
    let endpoint = optional_string(value, "endpoint").unwrap_or_default();
    let mut decision = SurfaceMediationDecision::new(kind, replacement_surface, endpoint);

    if let Some(lease_id) = optional_string(value, "lease_id") {
        decision = decision.with_lease_id(lease_id);
    }
    if let Some(print_line) = optional_string(value, "print_line") {
        decision = decision.with_print_line(print_line);
    }
    if let Some(keepalive) = value.get("keepalive").and_then(serde_json::Value::as_bool) {
        decision = decision.with_keepalive(keepalive);
    }

    Ok(decision)
}

fn required_string(value: &serde_json::Value, key: &str) -> Result<String, String> {
    optional_string(value, key).ok_or_else(|| format!("mediation `{key}` is required"))
}

fn optional_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}
