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
fn linux_host_command_plan_can_wrap_command() -> Result<(), RuntimeConfigError> {
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
        SessionId::new("session-wrapper"),
        vec![
            String::from("python3"),
            String::from("-c"),
            String::from("print('hello')"),
        ],
    )?;
    let mut options = LinuxHostSessionCommandOptions::default();
    options.add_wrapper_program("/tmp/erebor-session-wrapper");
    options.add_environment("EREBOR_SESSION_WRAPPER", "enabled");

    let launch = LinuxHostSessionCommandPlan::from_session_run_plan_with_environment_and_options(
        &plan,
        &[],
        &options,
    );

    assert_eq!(launch.program(), "/tmp/erebor-session-wrapper");
    assert_eq!(launch.args(), &["python3", "-c", "print('hello')"]);
    assert!(launch.environment().contains(&(
        String::from("EREBOR_SESSION_WRAPPER"),
        String::from("enabled")
    )));
    Ok(())
}

#[test]
fn linux_host_command_plan_can_stack_outer_and_inner_wrappers() -> Result<(), RuntimeConfigError> {
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
    options.add_wrapper_program("/tmp/erebor-session-wrapper");
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
            "/tmp/erebor-session-wrapper",
            "python3",
            "-c",
            "print('hello')"
        ]
    );
    Ok(())
}

#[test]
fn linux_host_command_plan_removes_inherited_shell_startup_inputs() -> Result<(), RuntimeConfigError>
{
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "session": { "enabled": true, "runner": { "kind": "linux_host" } },
              "surfaces": { "terminal": { "enabled": true } }
            }
            "#,
    )?;
    let plan = SessionRunPlan::from_config(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new("session-sanitized-shell"),
        vec![
            String::from("/bin/sh"),
            String::from("-c"),
            String::from("true"),
        ],
    )?;
    let mut options = LinuxHostSessionCommandOptions::default();
    for key in ["BASH_ENV", "ENV", "KSH_ENV", "ZDOTDIR", "SHELL"] {
        options.remove_environment(key);
    }
    options.add_environment("SHELL", "/bin/sh");

    let launch = LinuxHostSessionCommandPlan::from_session_run_plan_with_environment_and_options(
        &plan,
        &[],
        &options,
    );

    assert_eq!(
        launch.removed_environment(),
        &["BASH_ENV", "ENV", "KSH_ENV", "ZDOTDIR", "SHELL"]
    );
    assert!(launch
        .environment()
        .contains(&(String::from("SHELL"), String::from("/bin/sh"))));
    Ok(())
}

#[test]
fn linux_host_adopt_plan_preserves_target_working_directory() -> Result<(), RuntimeConfigError> {
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
    options.add_wrapper_program("/tmp/erebor-session-wrapper");

    let launch = LinuxHostSessionCommandPlan::from_session_adopt_plan_with_environment_and_options(
        &plan,
        &[],
        &options,
    );

    assert_eq!(launch.program(), "/tmp/erebor-session-wrapper");
    assert!(launch.args().is_empty());
    assert_eq!(
        launch.current_dir(),
        Some(Path::new("/tmp/erebor-workspace"))
    );
    assert!(launch.environment().contains(&(
        String::from("EREBOR_SESSION_RUNNER"),
        String::from("linux-host")
    )));
    Ok(())
}
