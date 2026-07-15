use std::{fs, fs::File, io::Read, path::Path};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use erebor_runtime_core::{CodexDeploymentMode, CodexProfileLayerConfig};
use erebor_runtime_filesystem::LinuxReadOnlySessionProjection;
use sha2::{Digest, Sha256};
use snafu::{ensure, ResultExt};

use super::error::{
    ArtifactDigestMismatchSnafu, ArtifactDirectoryUnsafeSnafu, ArtifactNotFleetProtectedSnafu,
    FilesystemProjectionSnafu, ReadArtifactSnafu,
};
use super::CodexSessionError;

pub(crate) struct CodexArtifactProjection;

impl CodexArtifactProjection {
    pub(crate) fn projections(
        profile: &CodexProfileLayerConfig,
    ) -> Result<Vec<LinuxReadOnlySessionProjection>, CodexSessionError> {
        Self::verify(profile)?;
        let hook_directory = profile.managed_hook_source.parent().ok_or_else(|| {
            CodexSessionError::IncompatibleProfile {
                reason: String::from("managed hook source has no parent directory"),
                location: snafu::Location::default(),
            }
        })?;
        let hook_target_directory = profile.managed_hook_path.parent().ok_or_else(|| {
            CodexSessionError::IncompatibleProfile {
                reason: String::from("managed hook path has no parent directory"),
                location: snafu::Location::default(),
            }
        })?;
        let projections = vec![
            LinuxReadOnlySessionProjection::new(
                &profile.requirements_source,
                "/etc/codex/requirements.toml",
            )
            .context(FilesystemProjectionSnafu)?,
            LinuxReadOnlySessionProjection::new(hook_directory, hook_target_directory)
                .context(FilesystemProjectionSnafu)?,
        ];
        Ok(projections)
    }

    fn verify(profile: &CodexProfileLayerConfig) -> Result<(), CodexSessionError> {
        Self::verify_managed_hook_directory(profile)?;
        for (path, digest) in [
            (&profile.requirements_source, &profile.requirements_sha256),
            (&profile.managed_hook_source, &profile.managed_hook_sha256),
            (&profile.shell_startup_source, &profile.shell_startup_sha256),
        ] {
            Self::verify_file(path, digest, profile)?;
        }
        Ok(())
    }

    fn verify_managed_hook_directory(
        profile: &CodexProfileLayerConfig,
    ) -> Result<(), CodexSessionError> {
        let hook_directory = profile.managed_hook_source.parent().ok_or_else(|| {
            CodexSessionError::IncompatibleProfile {
                reason: String::from("managed hook source has no parent directory"),
                location: snafu::Location::default(),
            }
        })?;
        let metadata = fs::symlink_metadata(hook_directory).context(ReadArtifactSnafu {
            path: hook_directory,
        })?;
        ensure!(
            metadata.file_type().is_dir(),
            ArtifactDirectoryUnsafeSnafu {
                path: hook_directory.to_path_buf()
            }
        );
        if profile.deployment == CodexDeploymentMode::FleetManaged {
            Self::verify_fleet_ancestor_protection(&profile.managed_hook_source, profile)?;
            Self::verify_fleet_ancestor_protection(&profile.shell_startup_source, profile)?;
            Self::verify_fleet_ancestor_protection(&profile.requirements_source, profile)?;
        }

        for entry in fs::read_dir(hook_directory).context(ReadArtifactSnafu {
            path: hook_directory,
        })? {
            let entry = entry.context(ReadArtifactSnafu {
                path: hook_directory,
            })?;
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).context(ReadArtifactSnafu { path: &path })?;
            ensure!(
                metadata.file_type().is_file()
                    && (path == profile.managed_hook_source
                        || path == profile.shell_startup_source),
                ArtifactDirectoryUnsafeSnafu { path }
            );
        }
        Ok(())
    }

    fn verify_file(
        path: &Path,
        expected_digest: &str,
        profile: &CodexProfileLayerConfig,
    ) -> Result<(), CodexSessionError> {
        let metadata = fs::symlink_metadata(path).context(ReadArtifactSnafu { path })?;
        ensure!(
            metadata.file_type().is_file(),
            ArtifactDirectoryUnsafeSnafu {
                path: path.to_path_buf()
            }
        );
        if profile.deployment == CodexDeploymentMode::FleetManaged {
            Self::verify_fleet_protection(path, &metadata)?;
        }
        let mut file = File::open(path).context(ReadArtifactSnafu { path })?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = file.read(&mut buffer).context(ReadArtifactSnafu { path })?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        ensure!(
            format!("{:x}", digest.finalize()) == expected_digest,
            ArtifactDigestMismatchSnafu {
                path: path.to_path_buf()
            }
        );
        Ok(())
    }

    fn verify_fleet_ancestor_protection(
        artifact: &Path,
        profile: &CodexProfileLayerConfig,
    ) -> Result<(), CodexSessionError> {
        let mut ancestor = artifact.parent();
        while let Some(path) = ancestor {
            let metadata = fs::symlink_metadata(path).context(ReadArtifactSnafu { path })?;
            ensure!(
                metadata.file_type().is_dir(),
                ArtifactDirectoryUnsafeSnafu {
                    path: path.to_path_buf()
                }
            );
            Self::verify_fleet_protection(path, &metadata)?;
            if path == profile.trust_root {
                return Ok(());
            }
            ancestor = path.parent();
        }
        ArtifactDirectoryUnsafeSnafu {
            path: profile.trust_root.clone(),
        }
        .fail()
    }

    #[cfg(unix)]
    fn verify_fleet_protection(
        path: &Path,
        metadata: &fs::Metadata,
    ) -> Result<(), CodexSessionError> {
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            ArtifactNotFleetProtectedSnafu {
                path: path.to_path_buf()
            }
        );
        Ok(())
    }

    #[cfg(not(unix))]
    fn verify_fleet_protection(
        path: &Path,
        _metadata: &fs::Metadata,
    ) -> Result<(), CodexSessionError> {
        ArtifactNotFleetProtectedSnafu {
            path: path.to_path_buf(),
        }
        .fail()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use erebor_runtime_core::{
        CodexDeploymentMode, CodexHookEvent, CodexHookEventSchemaLayerConfig, CodexHookShellKind,
        CodexProfileLayerConfig, SessionRunnerKind,
    };
    use sha2::{Digest, Sha256};

    use super::CodexArtifactProjection;

    #[test]
    fn verified_profile_artifacts_project_only_the_requirements_and_managed_hook_directory(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("erebor-codex-artifacts-{}", std::process::id()));
        let _result = fs::remove_dir_all(&root);
        let hooks = root.join("hooks");
        fs::create_dir_all(&hooks)?;
        let requirements = root.join("requirements.toml");
        let hook = hooks.join("erebor-codex-hook");
        let shell_startup = hooks.join("shell-startup");
        fs::write(&requirements, "allow_managed_hooks_only = true")?;
        fs::write(&hook, "#!/bin/sh\nexit 0\n")?;
        fs::write(&shell_startup, "set -eu\n")?;
        let profile = CodexProfileLayerConfig {
            id: String::from("test-profile"),
            runner: SessionRunnerKind::LinuxHost,
            executable: root.join("codex"),
            deployment: CodexDeploymentMode::LocalCooperative,
            profile_sha256: "a".repeat(64),
            trust_root: root.clone(),
            requirements_source: requirements.clone(),
            requirements_sha256: hash(&requirements)?,
            managed_hook_source: hook.clone(),
            managed_hook_sha256: hash(&hook)?,
            managed_hook_path: "/usr/lib/erebor/codex-hooks/erebor-codex-hook".into(),
            shell_startup_source: shell_startup.clone(),
            shell_startup_sha256: hash(&shell_startup)?,
            shell_startup_path: "/usr/lib/erebor/codex-hooks/shell-startup".into(),
            hook_shell: CodexHookShellKind::Direct,
            hook_exec_history: vec![
                root.join("codex"),
                "/usr/lib/erebor/codex-hooks/erebor-codex-hook".into(),
            ],
            event_schemas: vec![CodexHookEventSchemaLayerConfig {
                event: CodexHookEvent::SessionStart,
                sha256: "b".repeat(64),
            }],
        };

        let projections = CodexArtifactProjection::projections(&profile)?;
        assert_eq!(projections.len(), 2);
        assert_eq!(projections[0].source(), requirements);
        assert_eq!(
            projections[0].target(),
            std::path::Path::new("/etc/codex/requirements.toml")
        );
        assert_eq!(projections[1].source(), hooks);
        assert_eq!(
            projections[1].target(),
            std::path::Path::new("/usr/lib/erebor/codex-hooks")
        );

        fs::write(hooks.join("untrusted-startup"), "exit 1\n")?;
        assert!(matches!(
            CodexArtifactProjection::projections(&profile),
            Err(super::CodexSessionError::ArtifactDirectoryUnsafe { .. })
        ));
        fs::remove_file(hooks.join("untrusted-startup"))?;
        let mut fleet_profile = profile.clone();
        fleet_profile.deployment = CodexDeploymentMode::FleetManaged;
        assert!(matches!(
            CodexArtifactProjection::projections(&fleet_profile),
            Err(super::CodexSessionError::ArtifactNotFleetProtected { .. })
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn hash(path: &std::path::Path) -> Result<String, std::io::Error> {
        Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
    }
}
