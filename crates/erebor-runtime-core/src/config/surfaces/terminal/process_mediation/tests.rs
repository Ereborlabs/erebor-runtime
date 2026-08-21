use crate::config::test_prelude::*;

#[test]
fn rejects_removed_process_interception_config() {
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
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::InvalidSessionInterceptionConfig { .. })
    ));
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
