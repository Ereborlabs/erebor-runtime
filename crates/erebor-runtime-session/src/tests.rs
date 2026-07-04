use std::{fs, path::Path};

use erebor_runtime_core::{
    DockerSessionCommandPlan, LinuxHostSessionCommandPlan, RuntimeConfig, SessionRunPlan,
    SessionRunnerKind,
};
use erebor_runtime_events::SessionId;

use crate::{
    interception_backend::process_interception_executable_env,
    session_side_resources::start_session_side_resources,
};

#[test]
fn managed_browser_interception_defaults_browser_executable_env_vars(
) -> Result<(), Box<dyn std::error::Error>> {
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
                    "kind": "managed_browser_cdp",
                    "match": { "executables": ["google-chrome"] }
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
        .ok_or_else(|| std::io::Error::other("missing terminal surface"))?
        .clone();
    let handler = terminal
        .process_interception()
        .handlers()
        .first()
        .ok_or_else(|| std::io::Error::other("missing process interception handler"))?;

    let variables = process_interception_executable_env(handler);

    assert!(variables.contains(&String::from("CHROME_PATH")));
    assert!(variables.contains(&String::from("BROWSER")));
    assert!(variables.contains(&String::from("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH")));
    assert!(variables.contains(&String::from("PUPPETEER_EXECUTABLE_PATH")));
    Ok(())
}

#[test]
fn managed_browser_example_uses_lazy_requested_browser_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| std::io::Error::other("missing repo root"))?;
    let config_path = repo_root.join("examples/governed-openclaw-pilot/session-config.json");
    let config = RuntimeConfig::from_json_str(&fs::read_to_string(config_path)?)?;
    let browser_cdp = config
        .surface_start_plan()?
        .browser_cdp()
        .ok_or_else(|| std::io::Error::other("missing browser CDP surface"))?
        .clone();
    let terminal = config
        .surface_start_plan()?
        .terminal()
        .ok_or_else(|| std::io::Error::other("missing terminal surface"))?
        .clone();
    let handler = terminal
        .process_interception()
        .handlers()
        .first()
        .ok_or_else(|| std::io::Error::other("missing process interception handler"))?;

    assert_eq!(handler.id(), "managed-browser-cdp");
    assert_eq!(browser_cdp.listen().port(), 0);
    assert_eq!(browser_cdp.browser_url(), None);
    assert!(browser_cdp.owns_browser());
    assert!(handler.requested_endpoint().allowed_ports().is_empty());
    assert_eq!(
        handler.replacement().private_endpoint().port_strategy(),
        erebor_runtime_core::ProcessMediationPrivatePortStrategy::RequestedPlusOffset
    );
    assert_eq!(handler.replacement().private_endpoint().port_offset(), 1);
    assert_eq!(
        handler.replacement().surface(),
        erebor_runtime_core::ProcessMediationReplacementSurface::BrowserCdp
    );
    Ok(())
}

#[test]
fn session_side_resources_inject_runtime_interception_broker_environment(
) -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = test_dir("runtime-interception-env")?;
    let policy_path = write_policy(&test_dir)?;
    let config = RuntimeConfig::from_json_str(&format!(
        r#"{{
          "policies": ["{}"],
          "session": {{
            "enabled": true,
            "actor": {{ "id": "openclaw" }},
            "runner": {{ "kind": "linux_host" }},
            "interception": {{ "enabled": true }}
          }},
          "surfaces": {{
            "terminal": {{
              "enabled": true
            }}
          }}
        }}
        "#,
        policy_path.display()
    ))?;
    let linux_plan = SessionRunPlan::from_config(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new("runtime-interception-env"),
        vec![String::from("true")],
    )?;
    let linux_resources = start_session_side_resources(&config, &linux_plan, None)?;
    let linux_launch =
        LinuxHostSessionCommandPlan::from_session_run_plan_with_environment_and_options(
            &linux_plan,
            linux_resources.environment(),
            linux_resources.linux_host_options(),
        );
    let linux_interception_path = environment_value(
        linux_launch.environment(),
        "EREBOR_RUNTIME_INTERCEPTION_PATH",
    )
    .ok_or_else(|| std::io::Error::other("missing Linux host runtime interception path"))?;

    assert!(linux_launch.environment().contains(&(
        String::from("EREBOR_RUNTIME_INTERCEPTION_PROTOCOL"),
        String::from("erebor_ipc_v1")
    )));
    assert!(linux_launch.environment().contains(&(
        String::from("EREBOR_RUNTIME_INTERCEPTION_TRANSPORT"),
        String::from("unix")
    )));
    assert!(linux_launch.environment().contains(&(
        String::from("EREBOR_RUNTIME_INTERCEPTION_TIMEOUT_MS"),
        String::from("25")
    )));
    assert!(linux_interception_path.ends_with("runtime-interception.sock"));

    let docker_plan = SessionRunPlan::from_config(
        &config,
        SessionRunnerKind::Docker,
        SessionId::new("runtime-interception-env-docker"),
        vec![String::from("true")],
    )?;
    let docker_resources = start_session_side_resources(&config, &docker_plan, None)?;
    let docker_launch =
        DockerSessionCommandPlan::from_session_run_plan_with_environment_and_options(
            &docker_plan,
            docker_resources.environment(),
            docker_resources.docker_options(),
        );
    let docker_args = docker_launch.args().join("\n");

    assert!(docker_args.contains("EREBOR_RUNTIME_INTERCEPTION_PROTOCOL=erebor_ipc_v1"));
    assert!(docker_args.contains("EREBOR_RUNTIME_INTERCEPTION_TRANSPORT=unix"));
    assert!(docker_args.contains("EREBOR_RUNTIME_INTERCEPTION_TIMEOUT_MS=25"));
    assert!(docker_args.contains(
        "EREBOR_RUNTIME_INTERCEPTION_PATH=/erebor/interception/runtime-interception.sock"
    ));
    assert!(docker_args.contains("/erebor/interception:ro"));
    fs::remove_dir_all(test_dir)?;
    Ok(())
}

fn environment_value(environment: &[(String, String)], key: &str) -> Option<String> {
    environment
        .iter()
        .find_map(|(candidate, value)| (candidate == key).then(|| value.clone()))
}

fn test_dir(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
    let path = std::env::temp_dir().join(format!(
        "erebor-session-resources-{name}-{}",
        std::process::id()
    ));
    let _result = fs::remove_dir_all(&path);
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn write_policy(test_dir: &Path) -> Result<std::path::PathBuf, std::io::Error> {
    let policy_path = test_dir.join("policy.json");
    fs::write(
        &policy_path,
        r#"
        {
          "rules": [
            {
              "id": "deny-raw-cdp",
              "match": {
                "surface": "terminal",
                "action": "process_exec",
                "command_contains": "remote-debugging-port"
              },
              "decision": "deny",
              "reason": "raw CDP process launch is denied"
            }
          ]
        }
        "#,
    )?;
    Ok(policy_path)
}
