use crate::config::test_prelude::*;

#[test]
fn linux_host_command_plan_relaunches_local_command_with_session_environment(
) -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw" },
                "workspace": "/tmp/erebor-workspace",
                "runner": {
                  "kind": "linux_host"
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
        SessionRunnerKind::LinuxHost,
        SessionId::new("session-1"),
        vec![String::from("openclaw"), String::from("--help")],
    )?;

    let launch = LinuxHostSessionCommandPlan::from_session_run_plan_with_environment(
        &plan,
        &[(
            String::from("EREBOR_BROWSER_CDP_URL"),
            String::from("ws://127.0.0.1:3738/"),
        )],
    );

    assert_eq!(launch.program(), "openclaw");
    assert_eq!(launch.args(), &["--help"]);
    assert_eq!(
        launch.current_dir(),
        Some(Path::new("/tmp/erebor-workspace"))
    );
    assert!(launch
        .environment()
        .contains(&(String::from("EREBOR_SESSION_ID"), String::from("session-1"))));
    assert!(launch
        .environment()
        .contains(&(String::from("EREBOR_ACTOR_ID"), String::from("openclaw"))));
    assert!(launch.environment().contains(&(
        String::from("EREBOR_SESSION_RUNNER"),
        String::from("linux-host")
    )));
    assert!(launch.environment().contains(&(
        String::from("EREBOR_BROWSER_CDP_URL"),
        String::from("ws://127.0.0.1:3738/")
    )));
    Ok(())
}

#[test]
fn linux_host_command_plan_can_wrap_command_with_process_guard() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": {
                  "kind": "linux-host"
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
        SessionRunnerKind::LinuxHost,
        SessionId::new("session-guard"),
        vec![
            String::from("python3"),
            String::from("-c"),
            String::from("print('hello')"),
        ],
    )?;
    let mut options = LinuxHostSessionCommandOptions::default();
    options.add_wrapper_program("/tmp/erebor-linux-process-guard");
    options.add_environment("EREBOR_PROCESS_GUARD", "linux-ptrace");

    let launch = LinuxHostSessionCommandPlan::from_session_run_plan_with_environment_and_options(
        &plan,
        &[],
        &options,
    );

    assert_eq!(launch.program(), "/tmp/erebor-linux-process-guard");
    assert_eq!(launch.args(), &["python3", "-c", "print('hello')"]);
    assert!(launch.environment().contains(&(
        String::from("EREBOR_PROCESS_GUARD"),
        String::from("linux-ptrace")
    )));
    Ok(())
}

#[test]
fn linux_host_command_plan_can_stack_outer_wrapper_before_process_guard(
) -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": {
                  "kind": "linux-host"
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
        SessionRunnerKind::LinuxHost,
        SessionId::new("session-wrapper-stack"),
        vec![
            String::from("python3"),
            String::from("-c"),
            String::from("print('hello')"),
        ],
    )?;
    let mut options = LinuxHostSessionCommandOptions::default();
    options.add_wrapper_program("/tmp/erebor-linux-process-guard");
    options.add_outer_wrapper_program("/tmp/erebor-filesystem-overlay");

    let launch = LinuxHostSessionCommandPlan::from_session_run_plan_with_environment_and_options(
        &plan,
        &[],
        &options,
    );

    assert_eq!(launch.program(), "/tmp/erebor-filesystem-overlay");
    assert_eq!(
        launch.args(),
        &[
            "/tmp/erebor-linux-process-guard",
            "python3",
            "-c",
            "print('hello')"
        ]
    );
    Ok(())
}

#[test]
fn linux_host_adopt_plan_sets_guard_pid_environment() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw" },
                "workspace": "/tmp/erebor-workspace",
                "runner": {
                  "kind": "linux-host"
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
    )?;
    let plan = SessionAdoptPlan::from_config(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new("session-adopt"),
        4242,
    )?;
    let mut options = LinuxHostSessionCommandOptions::default();
    options.add_wrapper_program("/tmp/erebor-linux-process-guard");
    options.add_environment("EREBOR_PROCESS_GUARD", "linux-ptrace");

    let launch = LinuxHostSessionCommandPlan::from_session_adopt_plan_with_environment_and_options(
        &plan,
        &[],
        &options,
    );

    assert_eq!(launch.program(), "/tmp/erebor-linux-process-guard");
    assert!(launch.args().is_empty());
    assert_eq!(
        launch.current_dir(),
        Some(Path::new("/tmp/erebor-workspace"))
    );
    assert!(launch
        .environment()
        .contains(&(String::from("EREBOR_GUARD_ADOPT_PID"), String::from("4242"))));
    assert!(launch.environment().contains(&(
        String::from("EREBOR_SESSION_RUNNER"),
        String::from("linux-host")
    )));
    Ok(())
}
