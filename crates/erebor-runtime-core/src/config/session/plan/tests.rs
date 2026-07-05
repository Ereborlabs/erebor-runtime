use crate::config::test_prelude::*;

#[test]
fn creates_start_plan_from_config() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json", "policies/terminal.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo",
                  "listen": "127.0.0.1:3738"
                },
                "terminal": { "enabled": true }
              }
            }
            "#,
    )?;
    let plan = config.surface_start_plan()?;

    assert_eq!(plan.policies().len(), 2);
    assert!(plan.contains_surface(SessionSurfaceKind::BrowserCdp));
    assert!(plan.contains_surface(SessionSurfaceKind::Terminal));
    assert!(!plan.contains_surface(SessionSurfaceKind::Mcp));
    assert!(plan.terminal().is_some());
    assert_eq!(
        plan.browser_cdp().map(|config| config.browser_url()),
        Some(Some("ws://127.0.0.1:9222/devtools/browser/demo"))
    );
    assert_eq!(
        plan.browser_cdp().map(|config| config.listen()),
        Some(SocketAddr::from(([127, 0, 0, 1], 3738)))
    );

    Ok(())
}

#[test]
fn creates_session_run_plan_from_config() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw", "kind": "agent" },
                "workspace": "/tmp/erebor-workspace",
                "runner": {
                  "kind": "docker",
                  "docker": {
                    "image": "erebor/openclaw-pilot:local",
                    "network": "none",
                    "workdir": "/work"
                  }
                }
              },
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "tty": true,
                  "policies": ["policies/terminal.json"]
                }
              }
            }
            "#,
    )?;

    let plan = SessionRunPlan::from_config(
        &config,
        SessionRunnerKind::Docker,
        SessionId::new("session-1"),
        vec![String::from("openclaw"), String::from("--help")],
    )?;

    assert_eq!(plan.policies(), &[Path::new("policies/browser.json")]);
    assert_eq!(
        plan.audit().surfaces().terminal().level(),
        AuditCommandLogLevel::Signal
    );
    assert_eq!(
        plan.audit().surfaces().terminal().debug_commands(),
        &[String::from("sleep")]
    );
    assert_eq!(plan.session_id().as_str(), "session-1");
    assert_eq!(plan.actor().id, "openclaw");
    assert_eq!(plan.workspace(), Some(Path::new("/tmp/erebor-workspace")));
    assert_eq!(plan.runner().kind(), SessionRunnerKind::Docker);
    assert_eq!(
        plan.runner().docker().image(),
        "erebor/openclaw-pilot:local"
    );
    assert_eq!(plan.runner().docker().network(), "none");
    assert_eq!(plan.runner().docker().workdir(), Path::new("/work"));
    assert!(plan.terminal().tty());
    assert_eq!(
        plan.terminal().policies(),
        &[PathBuf::from("policies/terminal.json")]
    );
    assert_eq!(plan.command(), ["openclaw", "--help"]);

    Ok(())
}

#[test]
fn session_surface_start_plan_uses_host_reachable_browser_listen_for_docker_bridge(
) -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": {
                  "docker": {
                    "image": "alpine:3.20",
                    "network": "bridge"
                  }
                }
              },
              "surfaces": {
                "terminal": { "enabled": true },
                "browser_cdp": {
                  "enabled": true,
                  "listen": "127.0.0.1:0"
                }
              }
            }
            "#,
    )?;
    let session = SessionRunPlan::from_config(
        &config,
        SessionRunnerKind::Docker,
        SessionId::new("session-1"),
        vec![String::from("printenv")],
    )?;

    let start_plan = config.surface_start_plan_for_session(&session)?;

    assert_eq!(
        start_plan.browser_cdp().map(|config| config.listen()),
        Some(SocketAddr::from(([0, 0, 0, 0], 0)))
    );
    Ok(())
}

#[test]
fn creates_session_run_plan_from_named_diagnostic() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw" },
                "diagnostics": [
                  {
                    "name": "list-workspace",
                    "description": "List workspace files",
                    "command": ["sh", "-lc", "ls -la /workspace | head"]
                  }
                ],
                "runner": {
                  "docker": {
                    "image": "alpine:3.20",
                    "network": "none",
                    "workdir": "/workspace"
                  }
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
    )?;

    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::Docker,
        SessionId::new("session-1"),
        "list-workspace",
    )?;

    assert_eq!(plan.diagnostic(), Some("list-workspace"));
    assert_eq!(plan.command(), ["sh", "-lc", "ls -la /workspace | head"]);
    assert_eq!(
        plan.registry_path(),
        Path::new(crate::DEFAULT_SESSION_REGISTRY_PATH)
    );
    Ok(())
}
