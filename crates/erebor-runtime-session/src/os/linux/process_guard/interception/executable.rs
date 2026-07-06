use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub(super) struct RealExecutableResolver;

impl RealExecutableResolver {
    pub(super) fn executable_name(path: &str) -> Option<String> {
        Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(ToOwned::to_owned)
    }

    pub(super) fn from_environment(invoked: &str) -> Option<PathBuf> {
        let path = env::var_os("PATH")?;
        let shim_dir = env::var_os("EREBOR_PROCESS_INTERCEPTION_SHIM_DIR").map(PathBuf::from);
        let current_exe = env::current_exe().ok();

        Self::with_path(invoked, shim_dir.as_deref(), &path, current_exe.as_deref())
    }

    fn with_path(
        invoked: &str,
        shim_dir: Option<&Path>,
        path: impl AsRef<std::ffi::OsStr>,
        current_exe: Option<&Path>,
    ) -> Option<PathBuf> {
        env::split_paths(&path)
            .filter(|directory| {
                !shim_dir.is_some_and(|shim_dir| Self::paths_equal(directory, shim_dir))
            })
            .map(|directory| directory.join(invoked))
            .filter(|candidate| {
                !current_exe.is_some_and(|current_exe| Self::paths_equal(candidate, current_exe))
            })
            .find(|candidate| Self::is_executable_file(candidate))
    }

    fn is_executable_file(path: &Path) -> bool {
        let Ok(metadata) = fs::metadata(path) else {
            return false;
        };

        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }

    fn paths_equal(left: &Path, right: &Path) -> bool {
        if left == right {
            return true;
        }

        match (fs::canonicalize(left), fs::canonicalize(right)) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, os::unix::fs::PermissionsExt, path::PathBuf};

    use super::RealExecutableResolver;

    #[test]
    fn matches_invoked_executable_basename() {
        assert_eq!(
            RealExecutableResolver::executable_name("/tmp/erebor/shims/google-chrome"),
            Some(String::from("google-chrome"))
        );
    }

    #[test]
    fn allow_decision_resolves_real_executable_after_shim_dir() {
        let root = unique_temp_dir("allow-real-executable");
        let _ = fs::remove_dir_all(&root);
        let shim_dir = root.join("shims");
        let real_dir = root.join("bin");
        fs::create_dir_all(&shim_dir).expect("create shim dir");
        fs::create_dir_all(&real_dir).expect("create real dir");

        let real_chrome = real_dir.join("google-chrome");
        fs::write(&real_chrome, "#!/bin/sh\n").expect("write executable");
        fs::set_permissions(&real_chrome, fs::Permissions::from_mode(0o755))
            .expect("mark executable");

        let path = env::join_paths([shim_dir.as_path(), real_dir.as_path()]).expect("join path");
        let resolved =
            RealExecutableResolver::with_path("google-chrome", Some(&shim_dir), &path, None);

        assert_eq!(resolved, Some(real_chrome));

        fs::remove_dir_all(root).expect("remove temp dir");
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "erebor-process-interception-{name}-{}",
            std::process::id()
        ))
    }
}
