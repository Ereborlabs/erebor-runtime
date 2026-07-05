use crate::config::test_prelude::*;

#[test]
fn terminal_process_interception_is_generic_runtime_config() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "interception": {
                  "enabled": true
                }
              },
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "process_interception": {
                    "enabled": true,
                    "mode": "shim",
                    "handlers": [
                      {
                        "id": "managed-browser-cdp",
                        "decision": "mediate",
                        "kind": "managed_browser_cdp",
                        "match": {
                          "executables": ["google-chrome", "chromium"],
                          "required_args": ["--remote-debugging-port"],
                          "require_remote_debugging_port": true
                        },
                        "requested_endpoint": {
                          "source": "remote_debugging_port",
                          "bind": "127.0.0.1",
                          "allowed_ports": [9222]
                        },
                        "replacement": {
                          "surface": "browser_cdp"
                        },
                        "environment": {
                          "prepend_path": true,
                          "executable_env": ["CHROME_PATH"]
                        },
                        "compatibility": {
                          "print_devtools_listening_line": true,
                          "keepalive": true
                        }
                      }
                    ]
                  }
                },
                "browser_cdp": {
                  "enabled": true,
                  "listen": "127.0.0.1:9222"
                }
              }
            }
            "#,
    )?;

    let terminal = config
        .surface_start_plan()?
        .terminal()
        .context(NoSessionSurfacesSnafu)?
        .clone();
    let interception = terminal.process_interception();
    let handler = interception
        .handlers()
        .first()
        .context(NoSessionSurfacesSnafu)?;

    assert!(interception.enabled());
    assert_eq!(interception.mode(), TerminalProcessMediationMode::Shim);
    assert_eq!(handler.id(), "managed-browser-cdp");
    assert_eq!(handler.decision(), ProcessInterceptionDecision::Mediate);
    assert_eq!(
        handler.kind(),
        ProcessMediationHandlerKind::ManagedBrowserCdp
    );
    assert_eq!(
        handler.requested_endpoint().source(),
        ProcessMediationEndpointSource::RemoteDebuggingPort
    );
    assert_eq!(
        handler.matcher().executables(),
        &["google-chrome", "chromium"]
    );
    assert_eq!(handler.requested_endpoint().allowed_ports(), &[9222]);
    assert_eq!(handler.environment().executable_env(), &["CHROME_PATH"]);

    Ok(())
}

#[test]
fn managed_browser_process_interception_can_use_lazy_requested_port(
) -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "interception": {
                  "enabled": true
                }
              },
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "process_interception": {
                    "enabled": true,
                    "handlers": [
                      {
                        "id": "managed-browser-cdp",
                        "decision": "mediate",
                        "kind": "managed_browser_cdp",
                        "match": {
                          "executables": ["google-chrome"],
                          "required_args": ["--remote-debugging-port"],
                          "require_remote_debugging_port": true
                        },
                        "requested_endpoint": {
                          "source": "remote_debugging_port",
                          "bind": "127.0.0.1"
                        },
                        "replacement": {
                          "surface": "browser_cdp",
                          "private_endpoint": {
                            "port_strategy": "requested_plus_offset",
                            "port_offset": 1
                          }
                        }
                      }
                    ]
                  }
                },
                "browser_cdp": {
                  "enabled": true,
                  "listen": "127.0.0.1:0"
                }
              }
            }
            "#,
    )?;

    let start_plan = config.surface_start_plan()?;
    let browser = start_plan.browser_cdp().context(NoSessionSurfacesSnafu)?;
    let handler = start_plan
        .terminal()
        .context(NoSessionSurfacesSnafu)?
        .process_interception()
        .handlers()
        .first()
        .context(NoSessionSurfacesSnafu)?;

    assert_eq!(browser.listen().port(), 0);
    assert!(handler.requested_endpoint().allowed_ports().is_empty());
    assert_eq!(
        handler.replacement().private_endpoint().port_strategy(),
        ProcessMediationPrivatePortStrategy::RequestedPlusOffset
    );
    assert_eq!(handler.replacement().private_endpoint().port_offset(), 1);

    Ok(())
}

#[test]
fn rejects_process_mediation_without_session_interception() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "process_interception": {
                    "enabled": true,
                    "handlers": [
                      {
                        "id": "managed-browser-cdp",
                        "kind": "managed_browser_cdp",
                        "match": { "executables": ["google-chrome"] }
                      }
                    ]
                  }
                },
                "browser_cdp": {
                  "enabled": true,
                  "listen": "127.0.0.1:0"
                }
              }
            }
            "#,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::InvalidProcessMediationConfig { .. })
    ));
}

#[test]
fn rejects_process_mediation_without_browser_cdp_surface() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "interception": {
                  "enabled": true
                }
              },
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "process_interception": {
                    "enabled": true,
                    "handlers": [
                      {
                        "id": "managed-browser-cdp",
                        "kind": "managed_browser_cdp",
                        "match": { "executables": ["google-chrome"] }
                      }
                    ]
                  }
                }
              }
            }
            "#,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::InvalidProcessMediationConfig { .. })
    ));
}

#[test]
fn rejects_requested_private_port_offset_zero() -> Result<(), Box<dyn std::error::Error>> {
    let result = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "interception": {
                  "enabled": true
                }
              },
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "process_interception": {
                    "enabled": true,
                    "handlers": [
                      {
                        "id": "managed-browser-cdp",
                        "decision": "mediate",
                        "kind": "managed_browser_cdp",
                        "match": {
                          "executables": ["google-chrome"],
                          "required_args": ["--remote-debugging-port"],
                          "require_remote_debugging_port": true
                        },
                        "replacement": {
                          "surface": "browser_cdp",
                          "private_endpoint": {
                            "port_strategy": "requested_plus_offset",
                            "port_offset": 0
                          }
                        }
                      }
                    ]
                  }
                },
                "browser_cdp": {
                  "enabled": true,
                  "listen": "127.0.0.1:0"
                }
              }
            }
            "#,
    );
    let error = match result {
        Ok(_) => {
            return Err(
                std::io::Error::other("zero private endpoint offset should be rejected").into(),
            );
        }
        Err(error) => error,
    };

    assert!(matches!(
        error,
        RuntimeConfigError::InvalidProcessMediationConfig { .. }
    ));
    assert!(error.to_string().contains("port_offset must be positive"));
    Ok(())
}
