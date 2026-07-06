use std::path::PathBuf;

use erebor_runtime_core::{SessionSurfaceDefinition, SessionSurfaceKind};

use super::{ProxyCdpArgs, ProxyCdpCommand};
use crate::cli::parse_ws_url;

#[test]
fn dev_proxy_builds_the_same_surface_launch_plan_shape() -> Result<(), Box<dyn std::error::Error>> {
    let args = ProxyCdpArgs {
        browser_url: parse_ws_url("ws://127.0.0.1:9222/devtools/browser/demo")?,
        policy: PathBuf::from("policies/browser.json"),
        listen: "127.0.0.1:3738".parse()?,
    };

    let plan = ProxyCdpCommand::new(&args).launch_plan()?;

    assert_eq!(
        plan.policy_paths(),
        vec![PathBuf::from("policies/browser.json")]
    );
    assert_eq!(plan.surfaces(), vec![SessionSurfaceKind::BrowserCdp]);
    assert_eq!(plan.definitions().len(), 1);
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
