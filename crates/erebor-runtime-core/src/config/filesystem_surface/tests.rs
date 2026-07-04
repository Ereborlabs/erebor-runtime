use std::io;

use crate::{
    FilesystemBackendKind, FilesystemVolumeMode, RuntimeConfig, RuntimeConfigError,
    SessionInterceptionOperation, SessionInterceptionOperationCapability, SessionSurfaceKind,
};

#[test]
fn accepts_filesystem_surface_config_and_reports_file_capabilities(
) -> Result<(), Box<dyn std::error::Error>> {
    let config = RuntimeConfig::from_json_str(
        r#"
        {
          "policies": ["policy.json"],
          "session": {
            "interception": {
              "enabled": true,
              "backend": "linux_ptrace",
              "operations": ["file_open", "file_read", "file_mutation"]
            }
          },
          "surfaces": {
            "filesystem": {
              "enabled": true,
              "backend": { "kind": "linux_ostree_overlay" },
              "policies": ["filesystem-policy.json"],
              "volumes": [
                {
                  "id": "workspace",
                  "host_path": "/tmp/erebor-host",
                  "session_path": "/tmp/erebor-session",
                  "mode": "writable"
                }
              ],
              "revert": {
                "promote_on_session_finish": true,
                "retain_layers": true,
                "preimage_size_limit_bytes": 104857600
              }
            }
          }
        }
        "#,
    )?;
    let plan = config.surface_start_plan()?;
    let filesystem = plan
        .filesystem()
        .ok_or_else(|| io::Error::other("missing filesystem surface config"))?;

    assert_eq!(
        config.enabled_surfaces(),
        vec![SessionSurfaceKind::Filesystem]
    );
    assert!(plan.contains_surface(SessionSurfaceKind::Filesystem));
    assert_eq!(
        filesystem.policies(),
        [std::path::PathBuf::from("filesystem-policy.json")]
    );
    assert_eq!(
        filesystem.backend().kind(),
        FilesystemBackendKind::LinuxOstreeOverlay
    );
    assert_eq!(filesystem.volumes().len(), 1);
    assert_eq!(filesystem.volumes()[0].id(), "workspace");
    assert_eq!(
        filesystem.volumes()[0].mode(),
        FilesystemVolumeMode::Writable
    );
    assert!(filesystem.revert().promote_on_session_finish());
    assert!(filesystem.revert().retain_layers());
    assert_eq!(filesystem.revert().preimage_size_limit_bytes(), 104_857_600);

    let capabilities = config.session_interception_capabilities();
    for operation in [
        SessionInterceptionOperation::FileOpen,
        SessionInterceptionOperation::FileRead,
        SessionInterceptionOperation::FileMutation,
    ] {
        let capability = capability_for(capabilities.operations(), operation)?;
        assert_eq!(capability.owning_surface(), "filesystem");
        assert!(capability.surface_enabled());
        assert!(!capability.backend_supported());
        assert!(!capability.effective());
    }

    Ok(())
}

#[test]
fn accepts_enabled_filesystem_surface_without_declared_volumes(
) -> Result<(), Box<dyn std::error::Error>> {
    let config = RuntimeConfig::from_json_str(
        r#"
        {
          "policies": ["policy.json"],
          "surfaces": {
            "filesystem": {
              "enabled": true
            }
          }
        }
        "#,
    )?;
    let plan = config.surface_start_plan()?;
    let filesystem = plan
        .filesystem()
        .ok_or_else(|| io::Error::other("missing filesystem surface config"))?;

    assert_eq!(
        config.enabled_surfaces(),
        vec![SessionSurfaceKind::Filesystem]
    );
    assert!(filesystem.volumes().is_empty());

    Ok(())
}

#[test]
fn rejects_invalid_filesystem_volume_ids() {
    assert_invalid_filesystem_config(
        r#"
        {
          "policies": ["policy.json"],
          "surfaces": {
            "filesystem": {
              "enabled": true,
              "volumes": [
                {
                  "id": "bad/id",
                  "host_path": "/tmp/host",
                  "session_path": "/tmp/session"
                }
              ]
            }
          }
        }
        "#,
    );
}

#[test]
fn rejects_empty_filesystem_volume_paths() {
    assert_invalid_filesystem_config(
        r#"
        {
          "policies": ["policy.json"],
          "surfaces": {
            "filesystem": {
              "enabled": true,
              "volumes": [
                {
                  "id": "workspace",
                  "host_path": "",
                  "session_path": "/tmp/session"
                }
              ]
            }
          }
        }
        "#,
    );
}

#[test]
fn rejects_duplicate_filesystem_volume_ids() {
    assert_invalid_filesystem_config(
        r#"
        {
          "policies": ["policy.json"],
          "surfaces": {
            "filesystem": {
              "enabled": true,
              "volumes": [
                {
                  "id": "workspace",
                  "host_path": "/tmp/host-a",
                  "session_path": "/tmp/session-a"
                },
                {
                  "id": "workspace",
                  "host_path": "/tmp/host-b",
                  "session_path": "/tmp/session-b"
                }
              ]
            }
          }
        }
        "#,
    );
}

#[test]
fn rejects_unsupported_filesystem_backend_kinds() {
    assert_invalid_filesystem_config(
        r#"
        {
          "policies": ["policy.json"],
          "surfaces": {
            "filesystem": {
              "enabled": true,
              "backend": { "kind": "docker_overlay" },
              "volumes": [
                {
                  "id": "workspace",
                  "host_path": "/tmp/host",
                  "session_path": "/tmp/session"
                }
              ]
            }
          }
        }
        "#,
    );
}

fn capability_for(
    capabilities: &[SessionInterceptionOperationCapability],
    operation: SessionInterceptionOperation,
) -> Result<&SessionInterceptionOperationCapability, io::Error> {
    capabilities
        .iter()
        .find(|capability| capability.operation() == operation)
        .ok_or_else(|| io::Error::other("missing interception capability"))
}

fn assert_invalid_filesystem_config(source: &str) {
    assert!(matches!(
        RuntimeConfig::from_json_str(source),
        Err(RuntimeConfigError::InvalidFilesystemSurfaceConfig { .. })
    ));
}
