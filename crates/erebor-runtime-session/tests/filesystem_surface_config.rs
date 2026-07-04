use erebor_runtime_core::{
    FilesystemBackendKind, RuntimeConfig, SessionSurfaceDefinition, SessionSurfaceKind,
    SessionSurfaceLaunchPlan,
};

#[test]
fn filesystem_surface_config_builds_launch_plan() -> Result<(), Box<dyn std::error::Error>> {
    let config = RuntimeConfig::from_json_str(
        r#"
        {
          "policies": ["policy.json"],
          "surfaces": {
            "terminal": { "enabled": true },
            "filesystem": {
              "enabled": true,
              "backend": { "kind": "linux_ostree_overlay" },
              "volumes": [
                {
                  "id": "workspace",
                  "host_path": "/tmp/erebor-host",
                  "session_path": "/tmp/erebor-session",
                  "mode": "writable"
                }
              ]
            }
          }
        }
        "#,
    )?;
    let start_plan = config.surface_start_plan()?;
    let launch_plan =
        SessionSurfaceLaunchPlan::from_start_plan("127.0.0.1:0".parse()?, &start_plan)?;

    assert_eq!(
        launch_plan.surfaces(),
        vec![SessionSurfaceKind::Terminal, SessionSurfaceKind::Filesystem]
    );
    let filesystem = launch_plan
        .definitions()
        .iter()
        .find_map(|definition| match definition {
            SessionSurfaceDefinition::Filesystem(config) => Some(config),
            SessionSurfaceDefinition::BrowserCdp(_) | SessionSurfaceDefinition::Terminal(_) => None,
        })
        .ok_or_else(|| std::io::Error::other("missing filesystem definition"))?;

    assert_eq!(
        filesystem.backend().kind(),
        FilesystemBackendKind::LinuxOstreeOverlay
    );
    assert_eq!(filesystem.volumes()[0].id(), "workspace");

    Ok(())
}
