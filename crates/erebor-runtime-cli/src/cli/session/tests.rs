use std::path::PathBuf;

use erebor_runtime_core::{SessionAdoptTarget, SessionRunnerKind};

use super::{
    args::{SessionAdoptArgs, SessionDiagnoseArgs, SessionRunArgs, SessionRunnerArg},
    SessionPlanBuilder,
};
use crate::cli::{config_paths::RuntimeConfigLoader, test_support::TempJsonFile};

#[test]
fn session_run_builds_docker_session_plan() -> Result<(), Box<dyn std::error::Error>> {
    let config = TempJsonFile::write(
        r#"
        {
          "policies": ["policies/browser.json"],
          "session": {
            "enabled": true,
            "actor": { "id": "openclaw", "kind": "agent" },
            "workspace": "workspace",
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
            "terminal": { "enabled": true, "tty": true }
          }
        }
        "#,
    )?;
    let args = SessionRunArgs {
        config: config.path().to_path_buf(),
        runner: SessionRunnerArg::Docker,
        command: vec![String::from("openclaw"), String::from("--help")],
    };
    let runtime_config = RuntimeConfigLoader::read(config.path())?;

    let plan = SessionPlanBuilder::new(&runtime_config, &args.config).run(&args)?;
    let base_dir = config
        .path()
        .parent()
        .ok_or_else(|| std::io::Error::other("missing config parent"))?;

    assert_eq!(plan.actor().id, "openclaw");
    assert_eq!(
        plan.policies(),
        vec![base_dir.join("policies/browser.json")].as_slice()
    );
    assert_eq!(plan.workspace(), Some(base_dir.join("workspace").as_path()));
    assert_eq!(
        plan.registry_path(),
        base_dir
            .join("workspace")
            .join(".erebor/sessions")
            .as_path()
    );
    assert_eq!(
        plan.runner().docker().image(),
        "erebor/openclaw-pilot:local"
    );
    assert_eq!(plan.runner().docker().network(), "none");
    assert!(plan.terminal().tty());
    assert_eq!(plan.command(), ["openclaw", "--help"]);
    Ok(())
}

#[test]
fn session_run_builds_linux_host_session_plan() -> Result<(), Box<dyn std::error::Error>> {
    let config = TempJsonFile::write(
        r#"
        {
          "policies": ["policies/browser.json"],
          "session": {
            "enabled": true,
            "actor": { "id": "openclaw", "kind": "agent" },
            "workspace": "workspace",
            "runner": { "kind": "linux_host" }
          },
          "surfaces": {
            "terminal": { "enabled": true }
          }
        }
        "#,
    )?;
    let args = SessionRunArgs {
        config: config.path().to_path_buf(),
        runner: SessionRunnerArg::LinuxHost,
        command: vec![String::from("openclaw")],
    };
    let runtime_config = RuntimeConfigLoader::read(config.path())?;

    let plan = SessionPlanBuilder::new(&runtime_config, &args.config).run(&args)?;

    assert_eq!(plan.actor().id, "openclaw");
    assert_eq!(plan.runner().kind(), SessionRunnerKind::LinuxHost);
    assert_eq!(plan.command(), ["openclaw"]);
    Ok(())
}

#[test]
fn session_diagnose_builds_named_diagnostic_plan() -> Result<(), Box<dyn std::error::Error>> {
    let config = TempJsonFile::write(
        r#"
        {
          "policies": ["policies/browser.json"],
          "session": {
            "enabled": true,
            "actor": { "id": "openclaw", "kind": "agent" },
            "diagnostics": [
              {
                "name": "list-workspace",
                "command": ["sh", "-lc", "ls -la /workspace | head"]
              }
            ],
            "runner": {
              "kind": "docker",
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
    let args = SessionDiagnoseArgs {
        config: config.path().to_path_buf(),
        runner: SessionRunnerArg::Docker,
        name: String::from("list-workspace"),
    };
    let runtime_config = RuntimeConfigLoader::read(config.path())?;

    let plan = SessionPlanBuilder::new(&runtime_config, &args.config).diagnostic(&args)?;

    assert_eq!(plan.actor().id, "openclaw");
    assert_eq!(plan.diagnostic(), Some("list-workspace"));
    assert_eq!(plan.command(), ["sh", "-lc", "ls -la /workspace | head"]);
    Ok(())
}

#[test]
fn session_adopt_args_translate_to_service_target() {
    let args = SessionAdoptArgs {
        config: PathBuf::from("pilot-session.json"),
        runner: SessionRunnerArg::LinuxHost,
        pid: None,
        match_pattern: Some(String::from("openclaw")),
    };

    assert_eq!(args.target(), SessionAdoptTarget::process_match("openclaw"));
}
