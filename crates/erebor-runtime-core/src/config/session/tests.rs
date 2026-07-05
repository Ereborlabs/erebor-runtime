use crate::config::test_prelude::*;

#[test]
fn rejects_unknown_session_diagnostic() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": { "enabled": true }
            }
            "#,
    )?;

    let error = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::Docker,
        SessionId::new("session-1"),
        "list-workspace",
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::UnknownSessionDiagnostic { name, .. })
            if name == "list-workspace"
    ));
    Ok(())
}

#[test]
fn rejects_duplicate_session_diagnostic_names() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "diagnostics": [
                  { "name": "status", "command": ["true"] },
                  { "name": "status", "command": ["true"] }
                ]
              }
            }
            "#,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::DuplicateSessionDiagnosticName { name, .. })
            if name == "status"
    ));
}

#[test]
fn rejects_empty_session_diagnostic_command() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "diagnostics": [
                  { "name": "status", "command": [] }
                ]
              }
            }
            "#,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::EmptySessionDiagnosticCommand { name, .. })
            if name == "status"
    ));
}

#[test]
fn rejects_empty_session_command() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": { "enabled": true }
            }
            "#,
    )?;

    let error = SessionRunPlan::from_config(
        &config,
        SessionRunnerKind::Docker,
        SessionId::new("session-1"),
        Vec::new(),
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::EmptySessionCommand { .. })
    ));
    Ok(())
}

#[test]
fn rejects_invalid_session_adopt_pid() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": { "enabled": true }
            }
            "#,
    )?;

    let error = SessionAdoptPlan::from_config(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new("session-1"),
        0,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::InvalidSessionAdoptPid { .. })
    ));
    Ok(())
}
