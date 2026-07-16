use std::{
    fs,
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use snafu::{ensure, ResultExt};

use crate::{
    error::{
        InspectReadOnlySessionProjectionSnafu, InvalidReadOnlySessionProjectionSnafu,
        SetReadOnlySessionWrapperPermissionsSnafu, WriteReadOnlySessionWrapperSnafu,
    },
    FilesystemSessionStorage, Result,
};

const WRAPPER_FILE: &str = "linux-read-only-session-view.sh";
const CHILD_ARG: &str = "--erebor-read-only-child";

/// One host artifact made visible at an exact path only inside a Linux session
/// mount namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxReadOnlySessionProjection {
    source: PathBuf,
    target: PathBuf,
}

impl LinuxReadOnlySessionProjection {
    pub fn new(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Result<Self> {
        let projection = Self {
            source: source.into(),
            target: target.into(),
        };
        projection.validate_path_shape()?;
        Ok(projection)
    }

    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }

    fn validate_path_shape(&self) -> Result<()> {
        for path in [&self.source, &self.target] {
            ensure!(
                path.is_absolute()
                    && !path.components().any(|component| {
                        matches!(
                            component,
                            Component::CurDir | Component::ParentDir | Component::Prefix(_)
                        )
                    }),
                InvalidReadOnlySessionProjectionSnafu {
                    artifact: self.source.clone(),
                    target: self.target.clone(),
                    reason: String::from("source and target must be absolute normalized paths")
                }
            );
        }
        ensure!(
            self.target.parent().is_some(),
            InvalidReadOnlySessionProjectionSnafu {
                artifact: self.source.clone(),
                target: self.target.clone(),
                reason: String::from("target cannot be the filesystem root")
            }
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxReadOnlySessionView {
    wrapper_path: PathBuf,
}

impl LinuxReadOnlySessionView {
    pub fn prepare(
        storage: &FilesystemSessionStorage,
        projections: &[LinuxReadOnlySessionProjection],
    ) -> Result<Self> {
        let mounts = LinuxReadOnlyProjectionPlanner::new(projections).prepare()?;
        let wrapper_path = storage.work_path().join(WRAPPER_FILE);
        LinuxReadOnlyWrapperFile::new(&wrapper_path).write(&mounts)?;
        Ok(Self { wrapper_path })
    }

    #[must_use]
    pub fn wrapper_path(&self) -> &Path {
        &self.wrapper_path
    }
}

struct LinuxReadOnlyProjectionPlanner<'a> {
    projections: &'a [LinuxReadOnlySessionProjection],
}

impl<'a> LinuxReadOnlyProjectionPlanner<'a> {
    const fn new(projections: &'a [LinuxReadOnlySessionProjection]) -> Self {
        Self { projections }
    }

    fn prepare(&self) -> Result<Vec<LinuxReadOnlySessionProjection>> {
        let mut prepared = Vec::with_capacity(self.projections.len());
        for projection in self.projections {
            projection.validate_path_shape()?;
            let canonical = fs::canonicalize(projection.source()).context(
                InspectReadOnlySessionProjectionSnafu {
                    path: projection.source().to_path_buf(),
                },
            )?;
            ensure!(
                canonical == projection.source(),
                InvalidReadOnlySessionProjectionSnafu {
                    artifact: projection.source().to_path_buf(),
                    target: projection.target().to_path_buf(),
                    reason: String::from("source must not resolve through a symbolic link")
                }
            );
            ensure!(
                !projection.target().starts_with(projection.source()),
                InvalidReadOnlySessionProjectionSnafu {
                    artifact: projection.source().to_path_buf(),
                    target: projection.target().to_path_buf(),
                    reason: String::from("target cannot be below source")
                }
            );
            prepared.push(projection.clone());
        }
        for (index, current) in prepared.iter().enumerate() {
            for other in prepared.iter().skip(index + 1) {
                ensure!(
                    current.target() != other.target(),
                    InvalidReadOnlySessionProjectionSnafu {
                        artifact: other.source().to_path_buf(),
                        target: other.target().to_path_buf(),
                        reason: format!(
                            "target conflicts with projection from `{}`",
                            current.source().display()
                        )
                    }
                );
            }
        }
        Ok(prepared)
    }
}

struct LinuxReadOnlyWrapperFile<'a> {
    path: &'a Path,
}

impl<'a> LinuxReadOnlyWrapperFile<'a> {
    const fn new(path: &'a Path) -> Self {
        Self { path }
    }

    fn write(&self, projections: &[LinuxReadOnlySessionProjection]) -> Result<()> {
        fs::write(
            self.path,
            LinuxReadOnlyWrapperScript::new(projections).render(),
        )
        .context(WriteReadOnlySessionWrapperSnafu { path: self.path })?;
        self.set_permissions()
    }

    #[cfg(unix)]
    fn set_permissions(&self) -> Result<()> {
        let mut permissions = fs::metadata(self.path)
            .context(SetReadOnlySessionWrapperPermissionsSnafu { path: self.path })?
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(self.path, permissions)
            .context(SetReadOnlySessionWrapperPermissionsSnafu { path: self.path })
    }

    #[cfg(not(unix))]
    fn set_permissions(&self) -> Result<()> {
        Ok(())
    }
}

struct LinuxReadOnlyWrapperScript<'a> {
    projections: &'a [LinuxReadOnlySessionProjection],
}

impl<'a> LinuxReadOnlyWrapperScript<'a> {
    const fn new(projections: &'a [LinuxReadOnlySessionProjection]) -> Self {
        Self { projections }
    }

    fn render(&self) -> String {
        let mut script = String::from("#!/bin/sh\nset -eu\n\n");
        script.push_str(&format!(
            "if [ \"${{1:-}}\" = '{CHILD_ARG}' ]; then\n  shift\n"
        ));
        script.push_str("  cleanup() {\n    set +e\n");
        for projection in self.projections.iter().rev() {
            script.push_str(&format!(
                "    umount {} >/dev/null 2>&1 || true\n",
                Self::sh(projection.target())
            ));
        }
        script.push_str("  }\n  trap cleanup EXIT INT TERM\n");
        for projection in self.projections {
            let source = Self::sh(projection.source());
            let target = Self::sh(projection.target());
            let Some(target_parent) = projection.target().parent() else {
                continue;
            };
            let parent = Self::sh(target_parent);
            script.push_str(&format!(
                "  if [ ! -d {parent} ]; then echo 'erebor read-only projection target parent is not preinstalled: {parent}' >&2; exit 1; fi\n"
            ));
            script.push_str(&format!(
                "  if [ -d {source} ] && [ ! -d {target} ]; then echo 'erebor read-only directory projection target is not preinstalled: {target}' >&2; exit 1; fi\n"
            ));
            script.push_str(&format!(
                "  if [ ! -d {source} ] && [ ! -f {target} ]; then echo 'erebor read-only file projection target is not preinstalled: {target}' >&2; exit 1; fi\n"
            ));
            script.push_str(&format!("  mount --bind {source} {target}\n"));
            script.push_str(&format!("  mount -o remount,bind,ro {target}\n"));
        }
        script
            .push_str("  if [ \"${EREBOR_DROP_MOUNT_NAMESPACE_CAPABILITIES:-}\" = \"1\" ]; then\n");
        script.push_str("    command -v setpriv >/dev/null 2>&1 || { echo 'erebor read-only projection requires setpriv to drop temporary mount capabilities' >&2; exit 126; }\n");
        script.push_str(
            "    exec setpriv --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- \"$@\"\n",
        );
        script.push_str("  fi\n");
        script.push_str("  exec \"$@\"\nfi\n\n");
        script.push_str("command -v unshare >/dev/null 2>&1\ncommand -v mount >/dev/null 2>&1\ncommand -v umount >/dev/null 2>&1\n");
        script.push_str("if [ \"$(id -u)\" != \"0\" ] && unshare -U --map-current-user --keep-caps -m true >/dev/null 2>&1; then\n");
        script.push_str(&format!("  exec env EREBOR_DROP_MOUNT_NAMESPACE_CAPABILITIES=1 unshare -U --map-current-user --keep-caps -m --propagation private -- \"$0\" '{CHILD_ARG}' \"$@\"\n"));
        script.push_str("fi\n");
        script.push_str(&format!(
            "exec unshare -m --propagation private -- \"$0\" '{CHILD_ARG}' \"$@\"\n"
        ));
        script
    }

    fn sh(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{LinuxReadOnlySessionProjection, LinuxReadOnlySessionView};
    use crate::{FilesystemSessionStorage, FilesystemVolumeMode, FilesystemVolumeStorageRequest};

    #[test]
    fn renders_a_read_only_namespace_wrapper_for_file_and_directory(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("erebor-read-only-view-{}", std::process::id()));
        let _result = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("host"))?;
        fs::create_dir_all(root.join("target"))?;
        let source_file = root.join("artifact.toml");
        let source_directory = root.join("hooks");
        fs::write(&source_file, "hooks = true")?;
        fs::create_dir_all(&source_directory)?;
        let storage = FilesystemSessionStorage::prepare(
            root.join("record"),
            [FilesystemVolumeStorageRequest::new(
                "project",
                root.join("host"),
                root.join("target"),
                FilesystemVolumeMode::Writable,
            )?],
        )?;
        let view = LinuxReadOnlySessionView::prepare(
            &storage,
            &[
                LinuxReadOnlySessionProjection::new(&source_file, "/etc/codex/requirements.toml")?,
                LinuxReadOnlySessionProjection::new(
                    &source_directory,
                    "/usr/lib/erebor/codex-hooks",
                )?,
            ],
        )?;
        let script = fs::read_to_string(view.wrapper_path())?;
        assert!(script.contains("--erebor-read-only-child"));
        assert!(script.contains("mount --bind"));
        assert!(script.contains("remount,bind,ro"));
        assert!(script.contains("/etc/codex/requirements.toml"));
        assert!(script.contains("/usr/lib/erebor/codex-hooks"));
        assert!(script.contains("target parent is not preinstalled"));
        assert!(script.contains("EREBOR_DROP_MOUNT_NAMESPACE_CAPABILITIES=1"));
        assert!(script.contains("setpriv --inh-caps=-all --ambient-caps=-all --bounding-set=-all"));
        assert!(!script.contains("mkdir -p"));
        assert!(!script.contains(": >"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_a_symbolic_link_source() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            let root =
                std::env::temp_dir().join(format!("erebor-read-only-link-{}", std::process::id()));
            let _result = fs::remove_dir_all(&root);
            fs::create_dir_all(&root)?;
            let source = root.join("source");
            let link = root.join("link");
            fs::write(&source, "content")?;
            std::os::unix::fs::symlink(&source, &link)?;
            let projection =
                LinuxReadOnlySessionProjection::new(&link, "/etc/codex/requirements.toml")?;
            let request = FilesystemVolumeStorageRequest::new(
                "project",
                &root,
                root.join("session"),
                FilesystemVolumeMode::Writable,
            )?;
            let storage = FilesystemSessionStorage::prepare(root.join("record"), [request])?;
            assert!(LinuxReadOnlySessionView::prepare(&storage, &[projection]).is_err());
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }
}
