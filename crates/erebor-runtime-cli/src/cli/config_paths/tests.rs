use super::ConfigPathResolver;

#[test]
fn relative_config_paths_resolve_from_absolute_config_base(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = erebor_runtime_core::RuntimeConfig::from_json_str(
        r#"
        {
          "policies": ["policy.json"],
          "session": {
            "enabled": true,
            "workspace": "../.."
          },
          "surfaces": {
            "browser_cdp": {
              "enabled": true,
              "policies": ["browser-policy.json"]
            },
            "terminal": {
              "enabled": true,
              "policies": ["terminal-policy.json"]
            },
            "filesystem": {
              "enabled": true,
              "policies": ["filesystem-policy.json"],
              "volumes": [
                {
                  "id": "workspace",
                  "host_path": "host-workspace",
                  "session_path": "session-workspace",
                  "mode": "writable"
                }
              ]
            }
          }
        }
        "#,
    )?;

    ConfigPathResolver::from_config_path(std::path::Path::new(
        "examples/governed-openclaw-pilot/session-config.json",
    ))
    .resolve(&mut config);

    let current_dir = std::env::current_dir()?;
    assert_eq!(
        config.policies,
        vec![current_dir.join("examples/governed-openclaw-pilot/policy.json")]
    );
    assert_eq!(
        config.session.workspace,
        Some(current_dir.join("examples/governed-openclaw-pilot/../.."))
    );
    assert_eq!(
        config.surfaces.browser_cdp.policies,
        vec![current_dir.join("examples/governed-openclaw-pilot/browser-policy.json")]
    );
    assert_eq!(
        config.surfaces.terminal.policies,
        vec![current_dir.join("examples/governed-openclaw-pilot/terminal-policy.json")]
    );
    assert_eq!(
        config.surfaces.filesystem.policies,
        vec![current_dir.join("examples/governed-openclaw-pilot/filesystem-policy.json")]
    );
    assert_eq!(
        config.surfaces.filesystem.volumes[0].host_path,
        current_dir.join("examples/governed-openclaw-pilot/host-workspace")
    );
    assert_eq!(
        config.surfaces.filesystem.volumes[0].session_path,
        current_dir.join("examples/governed-openclaw-pilot/session-workspace")
    );
    Ok(())
}
