use crate::config::test_prelude::*;

#[test]
fn docker_command_plan_wraps_session_command() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw" },
                "workspace": "/tmp/erebor-workspace",
                "runner": {
                  "docker": {
                    "image": "erebor/openclaw-pilot:local",
                    "network": "none",
                    "workdir": "/work"
                  }
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
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

    assert_eq!(
        plan.registry_path(),
        Path::new("/tmp/erebor-workspace/.erebor/sessions")
    );
    let launch = DockerSessionCommandPlan::from_session_run_plan(&plan);

    assert_eq!(launch.program(), "docker");
    assert_eq!(
        launch.args(),
        &[
            "run",
            "--rm",
            "--name",
            "erebor-session-1",
            "--label",
            "dev.erebor.session_id=session-1",
            "--label",
            "dev.erebor.actor_id=openclaw",
            "--network",
            "none",
            "-e",
            "EREBOR_SESSION_ID=session-1",
            "-e",
            "EREBOR_ACTOR_ID=openclaw",
            "-e",
            "EREBOR_SESSION_RUNNER=docker",
            "-v",
            "/tmp/erebor-workspace:/work",
            "-w",
            "/work",
            "erebor/openclaw-pilot:local",
            "openclaw",
            "--help"
        ]
    );
    Ok(())
}

#[test]
fn docker_command_plan_allocates_tty_when_requested() -> Result<(), RuntimeConfigError> {
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
                "terminal": { "enabled": true, "tty": true }
              }
            }
            "#,
    )?;
    let plan = SessionRunPlan::from_config(
        &config,
        SessionRunnerKind::Docker,
        SessionId::new("session-tty"),
        vec![String::from("openclaw")],
    )?;

    let launch = DockerSessionCommandPlan::from_session_run_plan(&plan);

    assert!(launch.args().iter().any(|argument| argument == "-i"));
    assert!(launch.args().iter().any(|argument| argument == "-t"));
    Ok(())
}

#[test]
fn docker_command_plan_injects_session_side_resource_environment() -> Result<(), RuntimeConfigError>
{
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": {
                  "docker": {
                    "image": "alpine:3.20",
                    "network": "none"
                  }
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
    )?;
    let plan = SessionRunPlan::from_config(
        &config,
        SessionRunnerKind::Docker,
        SessionId::new("session-1"),
        vec![
            String::from("printenv"),
            String::from("EREBOR_BROWSER_CDP_URL"),
        ],
    )?;

    let launch = DockerSessionCommandPlan::from_session_run_plan_with_environment(
        &plan,
        &[(
            String::from("EREBOR_BROWSER_CDP_URL"),
            String::from("ws://127.0.0.1:3738/"),
        )],
    );

    assert!(launch
        .args()
        .windows(2)
        .any(|args| args[0] == "-e" && args[1] == "EREBOR_BROWSER_CDP_URL=ws://127.0.0.1:3738/"));
    Ok(())
}

#[test]
fn docker_command_plan_can_start_detached_session_container() -> Result<(), RuntimeConfigError> {
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
                "terminal": { "enabled": true }
              }
            }
            "#,
    )?;
    let plan = SessionRunPlan::from_config(
        &config,
        SessionRunnerKind::Docker,
        SessionId::new("session-detached"),
        vec![String::from("openclaw")],
    )?;

    let launch =
        DockerSessionCommandPlan::detached_from_session_run_plan_with_command_and_environment(
            &plan,
            &[(
                String::from("EREBOR_BROWSER_CDP_URL"),
                String::from("ws://127.0.0.1:3738/"),
            )],
            &[
                String::from("sh"),
                String::from("-lc"),
                String::from("sleep 3600"),
            ],
        );

    assert!(launch.args().iter().any(|argument| argument == "-d"));
    assert!(launch.args().windows(2).any(|args| args[0] == "-e"
        && args[1] == "EREBOR_BROWSER_CDP_URL=ws://host.docker.internal:3738/"));
    assert!(launch.args().ends_with(&[
        String::from("alpine:3.20"),
        String::from("sh"),
        String::from("-lc"),
        String::from("sleep 3600"),
    ]));
    Ok(())
}

#[test]
fn docker_command_plan_rewrites_loopback_endpoints_for_bridge_network(
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
                "terminal": { "enabled": true }
              }
            }
            "#,
    )?;
    let plan = SessionRunPlan::from_config(
        &config,
        SessionRunnerKind::Docker,
        SessionId::new("session-1"),
        vec![String::from("printenv")],
    )?;

    let launch = DockerSessionCommandPlan::from_session_run_plan_with_environment(
        &plan,
        &[(
            String::from("EREBOR_BROWSER_CDP_URL"),
            String::from("ws://0.0.0.0:3738/"),
        )],
    );

    assert!(launch
        .args()
        .windows(2)
        .any(|args| args[0] == "--add-host" && args[1] == "host.docker.internal:host-gateway"));
    assert!(launch.args().windows(2).any(|args| args[0] == "-e"
        && args[1] == "EREBOR_BROWSER_CDP_URL=ws://host.docker.internal:3738/"));
    Ok(())
}
