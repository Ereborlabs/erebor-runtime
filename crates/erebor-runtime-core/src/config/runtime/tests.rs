use crate::config::test_prelude::*;

#[test]
fn rejects_config_without_policies() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": [],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                }
              }
            }
            "#,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::MissingPolicy { .. })
    ));
}

#[test]
fn rejects_empty_policy_paths() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": [""],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                }
              }
            }
            "#,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::EmptyPolicyPath { .. })
    ));
}

#[test]
fn rejects_config_without_enabled_session_surfaces_or_session() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {}
            }
            "#,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::NoSessionSurfaces { .. })
    ));
}

#[test]
fn rejects_session_registry_path_config() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "registry_path": ".erebor/sessions"
              }
            }
            "#,
    );

    assert!(matches!(error, Err(RuntimeConfigError::InvalidJson { .. })));
}

#[test]
fn rejects_empty_docker_session_image() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": { "docker": { "image": "" } }
              }
            }
            "#,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::EmptyDockerSessionImage { .. })
    ));
}

#[test]
fn rejects_browser_cdp_without_local_ws_url() {
    let error = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "wss://browser.example/ws"
                }
              }
            }
            "#,
    );

    assert!(matches!(
        error,
        Err(RuntimeConfigError::BrowserCdpInvalidBrowserUrl { .. })
    ));
}
