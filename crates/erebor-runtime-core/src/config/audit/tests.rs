use crate::config::test_prelude::*;

#[test]
fn audit_command_logging_can_be_overridden_per_surface() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "audit": {
                "surfaces": {
                  "terminal": {
                    "level": "all",
                    "debug_commands": []
                  },
                  "browser_cdp": {
                    "level": "non_allow",
                    "debug_methods": ["Runtime.evaluate"],
                    "debug_actions": ["browser_script_eval"]
                  }
                }
              },
              "session": {
                "enabled": true
              }
            }
            "#,
    )?;

    assert_eq!(
        config.audit.surfaces().terminal().level(),
        AuditCommandLogLevel::All
    );
    assert!(config
        .audit
        .surfaces()
        .terminal()
        .debug_commands()
        .is_empty());
    assert_eq!(
        config.audit.surfaces().browser_cdp().level(),
        AuditCommandLogLevel::NonAllow
    );
    assert_eq!(
        config.audit.surfaces().browser_cdp().debug_methods(),
        &[String::from("Runtime.evaluate")]
    );
    assert_eq!(
        config.audit.surfaces().browser_cdp().debug_actions(),
        &[String::from("browser_script_eval")]
    );
    Ok(())
}

#[test]
fn rejects_config_level_audit_jsonl_storage() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "audit": {
                "jsonl": "audit/pilot.jsonl"
              },
              "session": {
                "enabled": true
              }
            }
            "#,
    );

    assert!(matches!(error, Err(RuntimeConfigError::InvalidJson { .. })));
}

#[test]
fn audit_surface_defaults_are_surface_specific() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true
              }
            }
            "#,
    )?;

    assert_eq!(
        config.audit.surfaces().terminal().debug_commands(),
        &[String::from("sleep")]
    );
    assert!(config
        .audit
        .surfaces()
        .browser_cdp()
        .debug_methods()
        .is_empty());
    assert!(config
        .audit
        .surfaces()
        .browser_cdp()
        .debug_actions()
        .is_empty());
    assert!(config.audit.surfaces().mcp().debug_tools().is_empty());
    assert!(config
        .audit
        .surfaces()
        .network()
        .debug_operations()
        .is_empty());
    assert!(config.audit.surfaces().saas().debug_operations().is_empty());
    assert!(config.audit.surfaces().desktop().debug_actions().is_empty());
    assert!(config
        .audit
        .surfaces()
        .internal_system()
        .debug_operations()
        .is_empty());

    Ok(())
}

#[test]
fn partial_terminal_audit_config_keeps_default_debug_commands() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "audit": {
                "surfaces": {
                  "terminal": {
                    "level": "signal"
                  }
                }
              },
              "session": {
                "enabled": true
              }
            }
            "#,
    )?;

    assert_eq!(
        config.audit.surfaces().terminal().level(),
        AuditCommandLogLevel::Signal
    );
    assert_eq!(
        config.audit.surfaces().terminal().debug_commands(),
        &[String::from("sleep")]
    );
    Ok(())
}

#[test]
fn explicit_empty_terminal_debug_commands_override_default() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "audit": {
                "surfaces": {
                  "terminal": {
                    "debug_commands": []
                  }
                }
              },
              "session": {
                "enabled": true
              }
            }
            "#,
    )?;

    assert!(config
        .audit
        .surfaces()
        .terminal()
        .debug_commands()
        .is_empty());
    Ok(())
}

#[test]
fn audit_debug_commands_cannot_be_empty() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "audit": {
                "surfaces": {
                  "terminal": {
                    "debug_commands": [""]
                  }
                }
              },
              "session": {
                "enabled": true
              }
            }
            "#,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::EmptyAuditDebugMatcher { matcher, .. })
            if matcher == "terminal.debug_commands"
    ));
}
