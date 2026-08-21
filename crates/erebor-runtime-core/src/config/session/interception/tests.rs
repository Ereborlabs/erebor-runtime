use crate::config::test_prelude::*;

#[test]
fn loads_config_with_multiple_session_surfaces() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                },
                "terminal": { "enabled": true }
              }
            }
            "#,
    )?;

    assert_eq!(
        config.enabled_surfaces(),
        vec![SessionSurfaceKind::BrowserCdp, SessionSurfaceKind::Terminal]
    );

    Ok(())
}

#[test]
fn removed_session_interception_is_disabled_and_stale_configuration_fails(
) -> Result<(), RuntimeConfigError> {
    let default_config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
    )?;
    let default_plan = default_config.surface_start_plan()?;

    assert!(!default_config.session_interception().enabled());
    assert!(!default_plan.interception().enabled());

    let stale = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "interception": {
                  "enabled": true,
                  "backend": "linux_ptrace",
                  "operations": [
                    "process_exec",
                    "file_read",
                    "process_exec",
                    "socket_connect"
                  ]
                }
              },
              "surfaces": {
                "terminal": { "enabled": true },
                "network": { "enabled": true }
              }
            }
            "#,
    );
    assert!(matches!(stale, Err(RuntimeConfigError::InvalidJson { .. })));

    Ok(())
}

#[test]
fn rejects_enabled_session_interception() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "interception": {
                  "enabled": true,
                  "operations": ["process_exec", "file_read", "socket_connect"]
                }
              },
              "surfaces": {
                "network": { "enabled": true }
              }
            }
            "#,
    );
    assert!(matches!(
        error,
        Err(RuntimeConfigError::InvalidSessionInterceptionConfig { .. })
    ));
}

#[test]
fn rejects_enabled_session_interception_without_operations() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "interception": {
                  "enabled": true,
                  "operations": []
                }
              }
            }
            "#,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::InvalidSessionInterceptionConfig { .. })
    ));
}

#[test]
fn rejects_terminal_process_guard_config() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "process_guard": { "enabled": true }
                }
              }
            }
            "#,
    );

    assert!(matches!(error, Err(RuntimeConfigError::InvalidJson { .. })));
}
