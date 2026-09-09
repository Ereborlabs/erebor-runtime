use std::fs;
use std::path::Path;
use std::process::Child;

use snafu::ResultExt as _;

use super::WAIT_LIMIT;
use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::wait_for;
use crate::Result;

const MAXIMUM_DIAGNOSTIC_BYTES: usize = 8 * 1024;

pub(super) fn wait_for_path(
    child: &mut Child,
    path: &Path,
    operation: &str,
    output_paths: &[&Path],
) -> Result<()> {
    wait_for(
        path,
        operation,
        WAIT_LIMIT,
        || {
            if path.exists() {
                return Ok(Some(()));
            }
            if let Some(status) = child.try_wait().context(IoSnafu { path })? {
                return InvalidInputSnafu {
                    path,
                    reason: format!(
                        "the runtime process exited with {status} before {operation}; {}",
                        output_summary(output_paths)
                    ),
                }
                .fail();
            }
            Ok(None)
        },
        || {
            format!(
                "the runtime process is still running; {}",
                output_summary(output_paths)
            )
        },
    )
}

fn output_summary(paths: &[&Path]) -> String {
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
    use std::path::Path;
    use std::process::{Command, Stdio};

    use snafu::ResultExt as _;

    use super::wait_for_path;
    use crate::error::{InvalidInputSnafu, IoSnafu};

    #[test]
    fn runtime_request_wait_reports_process_exit_and_output() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: Path::new("runtime process diagnostic fixture"),
        })?;
        let request = temporary.path().join("missing-request.json");
        let stderr_path = temporary.path().join("runtime.stderr");
        let stderr = fs::File::create(&stderr_path).context(IoSnafu { path: &stderr_path })?;
        let mut child = Command::new("/bin/sh")
            .args(["-c", "printf 'hook failed' >&2; exit 17"])
            .stderr(Stdio::from(stderr))
            .spawn()
            .context(IoSnafu {
                path: Path::new("/bin/sh"),
            })?;

        let error =
            match wait_for_path(&mut child, &request, "the fixture request", &[&stderr_path]) {
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
