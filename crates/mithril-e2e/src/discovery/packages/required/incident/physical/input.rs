use std::fs;

use erebor_runtime_client::{AraphorClient, AraphorError, AraphorProfile};
use erebor_runtime_ipc::araphor as wire;
use serde_json::{json, Value};

use super::super::super::super::Result;

pub(super) fn configure(config: &mut Value) -> Result<()> {
    let issuer = config
        .pointer("/client/auth/oidc/issuer_url")
        .and_then(Value::as_str)
        .ok_or("physical OIDC issuer")?
        .to_owned();
    let tenant = config
        .pointer("/allowed_nodes/0/tenant_id")
        .and_then(Value::as_str)
        .ok_or("physical tenant")?
        .to_owned();
    let id = uuid::Uuid::parse_str(&tenant)?.into_bytes();
    let (grant, routes) = super::super::super::input::notification_inputs(id);
    config["graph_enabled"] = json!(true);
    config["discovery"] = json!(false);
    config["client"]["investigation"] = json!({});
    config["client"]["auth"]["service"] = json!({
        "introspection_url": format!("{issuer}/introspect"),
        "audience": "mithril-vm-query", "max_age_seconds": 300,
    });
    config["client"]["auth"]["oidc"]["client_secret_path"] =
        json!("/etc/mithril/service-client-secret");
    config["client"]["auth"]["investigators"] = json!([{
        "subject": "mithril-vm-operator", "tenant_id": tenant,
    }]);
    config["notifications"] = json!({"grants": [grant], "routes": routes});
    Ok(())
}

pub(super) async fn checked_client(profile: AraphorProfile) -> Result<AraphorClient> {
    let invalid = tempfile::NamedTempFile::new()?;
    fs::write(invalid.path(), b"unissued-query-token")?;
    let other = uuid::Uuid::from_bytes([240; 16]).to_string();
    assert_ne!(other, profile.tenant_id);
    for (tenant, credential, code) in [
        (
            profile.tenant_id.clone(),
            invalid.path().to_path_buf(),
            tonic::Code::Unauthenticated,
        ),
        (
            other,
            profile.credential_file.clone(),
            tonic::Code::PermissionDenied,
        ),
    ] {
        let mut denied = profile.clone();
        denied.tenant_id = tenant;
        denied.credential_file = credential;
        let client = AraphorClient::connect(denied).await?;
        let reply = client
            .query(wire::QueryRequest {
                sql: "SELECT 1".into(),
                ..Default::default()
            })
            .await;
        let Err(AraphorError::Rpc { source, .. }) = reply else {
            return Err("physical query authentication did not reject the requested scope".into());
        };
        assert_eq!(source.code(), code);
    }
    Ok(AraphorClient::connect(profile).await?)
}

pub(super) fn monotonic() -> Result<u64> {
    let at = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    Ok(
        std::time::Duration::new(at.tv_sec.try_into()?, at.tv_nsec.try_into()?)
            .as_nanos()
            .try_into()?,
    )
}

#[test]
fn service_config_valid() -> Result<()> {
    let mut config: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/kubernetes/pid-reuse-control-v1.json"
    )))?;
    config["client"]["auth"]["oidc"]["issuer_url"] = json!("https://localhost:19445");
    configure(&mut config)?;
    let auth: mithril_control::ClientAuthConfig =
        serde_json::from_value(config["client"]["auth"].clone())?;
    auth.validate()?;
    assert!(auth.oidc.client_secret_path.is_some());
    Ok(())
}
