use crate::config::test_prelude::*;

#[test]
fn creates_owned_browser_surface_config_without_browser_url() -> Result<(), RuntimeConfigError> {
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser": {
                    "headless": false,
                    "user_data_dir": "/tmp/erebor-browser-profile"
                  }
                }
              }
            }
            "#,
    )?;
    let start_plan = config.surface_start_plan()?;
    let browser_cdp = start_plan.browser_cdp().context(NoSessionSurfacesSnafu)?;

    assert_eq!(browser_cdp.browser_url(), None);
    assert!(browser_cdp.owns_browser());
    assert!(!browser_cdp.browser().headless());
    assert_eq!(
        browser_cdp.browser().user_data_dir(),
        Some(Path::new("/tmp/erebor-browser-profile"))
    );
    Ok(())
}
