use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, ExitCode, Stdio},
};
fn main() -> ExitCode {
    let Some(marker) = std::env::args().nth(1) else {
        return ExitCode::FAILURE;
    };
    let mut hook = match Command::new("/usr/lib/erebor/codex-hooks/erebor-codex-hook")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(hook) => hook,
        Err(error) => {
            return failure(
                &marker,
                &format!(
                    "failed to launch the projected managed hook: {error}; profile={:?}; hook_exists={}; hook_parent_exists={}",
                    std::env::var("EREBOR_CODEX_PROFILE_ID"),
                    Path::new("/usr/lib/erebor/codex-hooks/erebor-codex-hook").exists(),
                    Path::new("/usr/lib/erebor/codex-hooks").exists(),
                ),
            );
        }
    };
    if let Some(mut input) = hook.stdin.take() {
        if let Err(error) = input.write_all(br#"{"hook_event_name":"session_start"}"#) {
            return failure(&marker, &format!("failed to write hook input: {error}"));
        }
    }
    match hook.wait_with_output() {
        Ok(output) => {
            if output.status.success() && fs::write(&marker, output.stdout).is_ok() {
                ExitCode::SUCCESS
            } else {
                failure(
                    &marker,
                    &format!(
                        "managed hook failed: status={} stderr={}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    ),
                )
            }
        }
        Err(error) => failure(
            &marker,
            &format!("failed to wait for managed hook: {error}"),
        ),
    }
}

fn failure(marker: &str, reason: &str) -> ExitCode {
    let diagnostic = Path::new(marker).with_extension("diagnostic");
    let _result = fs::write(diagnostic, reason);
    ExitCode::FAILURE
}
