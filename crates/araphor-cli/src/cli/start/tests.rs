use erebor_runtime_core::{SessionSurfaceDefinition, SessionSurfaceKind};

use super::{StartArgs, StartCommand};
use crate::cli::test_support::TempJsonFile;

#[test]
fn start_builds_surface_launch_plan() -> Result<(), Box<dyn std::error::Error>> {
    let config = TempJsonFile::write(
        r#"
        {
          "policies": ["policies/browser.json"],
          "surfaces": {
            "browser_cdp": {
              "enabled": true,
              "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo",
              "listen": "127.0.0.1:3738"
            }
          }
        }
        "#,
    )?;
    let args = StartArgs {
        config: config.path().to_path_buf(),
        listen: "127.0.0.1:3737".parse()?,
    };

    let plan = StartCommand::new(&args).launch_plan()?;

    assert_eq!(plan.control_listen(), "127.0.0.1:3737".parse()?);
    assert_eq!(
        plan.policy_paths(),
        vec![config
            .path()
            .parent()
            .ok_or_else(|| std::io::Error::other("missing config parent"))?
            .join("policies/browser.json")]
    );
    assert_eq!(plan.surfaces(), vec![SessionSurfaceKind::BrowserCdp]);
    let browser_cdp = match &plan.definitions()[0] {
        SessionSurfaceDefinition::BrowserCdp(browser_cdp) => browser_cdp,
        SessionSurfaceDefinition::Terminal(_) => {
            return Err(std::io::Error::other("expected browser CDP surface").into());
        }
        SessionSurfaceDefinition::Filesystem(_) => {
            return Err(std::io::Error::other("expected browser CDP surface").into());
        }
    };
    assert_eq!(browser_cdp.listen(), "127.0.0.1:3738".parse()?);
    assert_eq!(
        browser_cdp.browser_url(),
        Some("ws://127.0.0.1:9222/devtools/browser/demo")
    );
    Ok(())
}

#[test]
fn start_preserves_absolute_policy_paths() -> Result<(), Box<dyn std::error::Error>> {
    let absolute_policy_path =
        std::env::temp_dir().join(format!("erebor-runtime-policy-{}.json", std::process::id()));
    let config = TempJsonFile::write(&format!(
        r#"
        {{
          "policies": ["{}"],
          "surfaces": {{
            "browser_cdp": {{
              "enabled": true,
              "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
            }}
          }}
        }}
        "#,
        absolute_policy_path.display()
    ))?;
    let args = StartArgs {
        config: config.path().to_path_buf(),
        listen: "127.0.0.1:3737".parse()?,
    };

    let plan = StartCommand::new(&args).launch_plan()?;

    assert_eq!(plan.policy_paths(), vec![absolute_policy_path]);
    Ok(())
}

#[test]
fn start_rejects_invalid_runtime_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = TempJsonFile::write(
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
    )?;
    let args = StartArgs {
        config: config.path().to_path_buf(),
        listen: "127.0.0.1:3737".parse()?,
    };

    assert!(StartCommand::new(&args).launch_plan().is_err());
    Ok(())
}

#[test]
fn start_builds_terminal_surface_launch_plan() -> Result<(), Box<dyn std::error::Error>> {
    let config = TempJsonFile::write(
        r#"
        {
          "policies": ["policies/browser.json"],
          "surfaces": {
            "browser_cdp": {
              "enabled": true,
              "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
            },
            "terminal": { "enabled": true }
          }
        }
        "#,
    )?;
    let args = StartArgs {
        config: config.path().to_path_buf(),
        listen: "127.0.0.1:3737".parse()?,
    };

    let plan = StartCommand::new(&args).launch_plan()?;

    assert_eq!(
        plan.surfaces(),
        vec![SessionSurfaceKind::BrowserCdp, SessionSurfaceKind::Terminal]
    );
    assert_eq!(plan.definitions().len(), 2);
    assert!(matches!(
        plan.definitions()[1],
        SessionSurfaceDefinition::Terminal(_)
    ));
    Ok(())
}
