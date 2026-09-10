use std::fs;
use std::path::Path;

const MAXIMUM_DIAGNOSTIC_BYTES: usize = 8 * 1024;

pub(super) fn output(paths: &[&Path]) -> String {
    paths
        .iter()
        .map(|path| {
            let output = fs::read(path)
                .map(|bytes| {
                    let start = bytes.len().saturating_sub(MAXIMUM_DIAGNOSTIC_BYTES);
                    String::from_utf8_lossy(&bytes[start..]).trim().to_owned()
                })
                .unwrap_or_else(|error| format!("unavailable: {error}"));
            format!("{}: {output:?}", path.display())
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use snafu::ResultExt as _;

    use super::super::WAIT_LIMIT;
    use super::output;
    use crate::error::{InvalidInputSnafu, IoSnafu};
    use crate::process::ProcessFixture;

    #[test]
    fn exit_reports_output() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: Path::new("runtime process diagnostic fixture"),
        })?;
        let request = temporary.path().join("missing-request.json");
        let stderr_path = temporary.path().join("runtime.stderr");
        let stderr = fs::File::create(&stderr_path).context(IoSnafu { path: &stderr_path })?;
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let script = ProcessFixture::script(&repo_root, "process_exit.py")?;
        let child = Command::new("python3")
            .arg(&script)
            .args(["17", "hook failed"])
            .stderr(Stdio::from(stderr))
            .spawn()
            .context(IoSnafu { path: &script })?;
        let mut process = ProcessFixture::new(child, &script);

        let error = match process.wait_path(
            &request,
            "the fixture request",
            WAIT_LIMIT,
            || Ok(request.exists().then_some(())),
            || output(&[&stderr_path]),
        ) {
            Err(error) => error,
            Ok(()) => {
                return InvalidInputSnafu {
                    path: &request,
                    reason: "an exited runtime published a missing request",
                }
                .fail()
            }
        };
        let message = error.to_string();
        assert!(message.contains("exit status: 17"), "{message}");
        assert!(message.contains("hook failed"), "{message}");
        Ok(())
    }
}
