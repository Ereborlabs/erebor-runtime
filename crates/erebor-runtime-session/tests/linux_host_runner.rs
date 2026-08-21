use erebor_runtime_core::{RuntimeConfig, RuntimeConfigError};

#[test]
fn removed_linux_process_interception_config_is_rejected() {
    let result = RuntimeConfig::from_json_str(
        r#"
        {
          "policies": ["policy.json"],
          "session": {
            "enabled": true,
            "runner": { "kind": "linux_host" },
            "interception": {
              "enabled": true,
              "backend": "linux_ptrace"
            }
          }
        }
        "#,
    );

    assert!(matches!(
        result,
        Err(RuntimeConfigError::InvalidJson { .. })
    ));
}
