use std::{fs, path::Path};

use erebor_runtime_core::RuntimeConfig;

#[test]
fn managed_browser_example_uses_an_owned_browser_endpoint() -> Result<(), Box<dyn std::error::Error>>
{
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

    assert_eq!(browser_cdp.listen().port(), 0);
    assert_eq!(browser_cdp.browser_url(), None);
    assert!(browser_cdp.owns_browser());
    Ok(())
}
