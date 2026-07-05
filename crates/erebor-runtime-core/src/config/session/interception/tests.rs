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
fn session_interception_is_explicit_runtime_config() -> Result<(), RuntimeConfigError> {
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

    let guarded_config = RuntimeConfig::from_json_str(
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
    )?;
    let guarded_plan = guarded_config.surface_start_plan()?;
    let interception = guarded_plan.interception();
    let capabilities = guarded_config.session_interception_capabilities();

    assert!(interception.enabled());
    assert_eq!(
        interception.backend(),
        SessionInterceptionBackendKind::LinuxPtrace
    );
    assert_eq!(
        interception.operations(),
        &[
            SessionInterceptionOperation::ProcessExec,
            SessionInterceptionOperation::FileRead,
            SessionInterceptionOperation::SocketConnect
        ]
    );
    assert_eq!(capabilities.operations().len(), 3);
    assert!(capabilities
        .operations()
        .iter()
        .any(
            |operation| operation.operation() == SessionInterceptionOperation::ProcessExec
                && operation.backend_supported()
                && operation.surface_enabled()
                && operation.effective()
        ));
    assert!(capabilities
        .operations()
        .iter()
        .any(
            |operation| operation.operation() == SessionInterceptionOperation::FileRead
                && operation.owning_surface() == "filesystem"
                && operation.backend_supported()
                && !operation.surface_enabled()
                && !operation.effective()
        ));

    Ok(())
}

#[test]
fn session_interception_capabilities_distinguish_backend_and_surface_support(
) -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
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
    )?;
    let capabilities = config.session_interception_capabilities();
    let process_exec = capabilities
        .operations()
        .iter()
        .find(|operation| operation.operation() == SessionInterceptionOperation::ProcessExec)
        .context(NoSessionSurfacesSnafu)?;
    let file_read = capabilities
        .operations()
        .iter()
        .find(|operation| operation.operation() == SessionInterceptionOperation::FileRead)
        .context(NoSessionSurfacesSnafu)?;
    let socket_connect = capabilities
        .operations()
        .iter()
        .find(|operation| operation.operation() == SessionInterceptionOperation::SocketConnect)
        .context(NoSessionSurfacesSnafu)?;

    assert!(process_exec.backend_supported());
    assert!(!process_exec.surface_enabled());
    assert!(!process_exec.effective());
    assert!(file_read.backend_supported());
    assert!(!file_read.surface_enabled());
    assert!(!file_read.effective());
    assert!(!socket_connect.backend_supported());
    assert!(socket_connect.surface_enabled());
    assert!(!socket_connect.effective());

    Ok(())
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
