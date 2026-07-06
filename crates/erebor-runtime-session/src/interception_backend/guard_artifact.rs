use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use snafu::ResultExt;

use crate::{
    error::{GuardConfigSnafu, GuardIoSnafu},
    SessionExecutionError,
};

const LINUX_PROCESS_GUARD_BINARY: &str = "erebor-linux-process-guard";

pub(crate) struct LinuxProcessGuardArtifact;

impl LinuxProcessGuardArtifact {
    pub(crate) fn resolve() -> Result<PathBuf, SessionExecutionError> {
        let current_exe = std::env::current_exe().context(GuardIoSnafu)?;
        let candidates = Self::candidates(&current_exe);
        candidates
            .iter()
            .find(|candidate| is_executable_file(candidate))
            .cloned()
            .ok_or_else(|| {
                let searched = candidates
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                GuardConfigSnafu {
                    reason: format!(
                        "could not find shipped `{LINUX_PROCESS_GUARD_BINARY}` executable; searched: {searched}"
                    ),
                }
                .build()
            })
    }

    pub(crate) fn candidates(current_exe: &Path) -> Vec<PathBuf> {
        let mut candidates = Vec::new();

        if let Some(build_process_guard) = option_env!("EREBOR_BUILD_LINUX_PROCESS_GUARD") {
            candidates.push(PathBuf::from(build_process_guard));
        }

        if let Some(binary_dir) = current_exe.parent() {
            candidates.push(binary_dir.join(LINUX_PROCESS_GUARD_BINARY));

            if binary_dir
                .file_name()
                .is_some_and(|name| name == std::ffi::OsStr::new("deps"))
            {
                if let Some(target_dir) = binary_dir.parent() {
                    candidates.push(target_dir.join(LINUX_PROCESS_GUARD_BINARY));
                }
            }
        }

        candidates
    }
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::LinuxProcessGuardArtifact;

    #[test]
    fn process_guard_candidates_prefer_current_build_output() {
        let Some(build_process_guard) = option_env!("EREBOR_BUILD_LINUX_PROCESS_GUARD") else {
            return;
        };

        let candidates =
            LinuxProcessGuardArtifact::candidates(Path::new("/tmp/target/debug/deps/test-bin"));

        assert_eq!(
            candidates.first(),
            Some(&PathBuf::from(build_process_guard))
        );
    }
}
