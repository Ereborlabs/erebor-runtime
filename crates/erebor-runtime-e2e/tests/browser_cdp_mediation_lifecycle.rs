#[path = "support/browser_cdp_mediation.rs"]
#[allow(dead_code)]
mod browser_cdp_mediation;
#[path = "support/cli.rs"]
#[allow(dead_code)]
mod cli;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_host {
    use erebor_runtime_e2e::E2eError;

    use crate::{
        browser_cdp_mediation::{BrowserCdpMediationHost, BrowserCdpMediationLifecycle},
        cli::{E2eWorkspace, EreborCliFixture},
    };

    #[test]
    fn managed_browser_cdp_lifecycle_mediates_process_launch() -> Result<(), E2eError> {
        let Some(host) = BrowserCdpMediationHost::detect() else {
            eprintln!(
                "skipping managed browser CDP mediation lifecycle e2e: Chrome or timeout is unavailable"
            );
            return Ok(());
        };

        let erebor_runtime = EreborCliFixture::build()?;
        let workspace = E2eWorkspace::create("browser-cdp-mediation")?;
        let lifecycle = BrowserCdpMediationLifecycle::prepare(workspace.path(), &host)?;

        let output = erebor_runtime.run_expect_failure_in_env(
            workspace.path(),
            [
                "session",
                "diagnose",
                "--runner",
                "linux-host",
                "--config",
                lifecycle.config_path().to_string_lossy().as_ref(),
                "managed-browser-cdp",
            ],
            lifecycle.command_environment()?,
        )?;

        assert!(output.contains(&lifecycle.devtools_listening_line()));
        lifecycle.assert_original_command_not_executed()?;

        let audit = lifecycle.audit(workspace.path())?.read()?;
        assert!(
            audit.contains("\"policy_decision\":{\"type\":\"mediate\""),
            "expected a mediated policy decision in audit:\n{audit}"
        );
        assert!(audit.contains("\"handler_id\":\"managed-browser-cdp\""));
        assert!(audit.contains("\"rule_id\":\"erebor-process-interception-managed-browser-cdp\""));
        assert!(audit.contains(&lifecycle.governed_endpoint_prefix()));
        Ok(())
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn browser_cdp_mediation_lifecycle_e2e_is_host_specific() {
    eprintln!("skipping browser CDP mediation lifecycle e2e on non-x86_64 Linux host");
}
