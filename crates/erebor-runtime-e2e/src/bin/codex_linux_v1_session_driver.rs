use std::{
    env, fs,
    io::Write,
    path::Path,
    process::{Command, ExitCode, Stdio},
};

const ASSERT_UNATTRIBUTED_EFFECT_ENV: &str = "EREBOR_CODEX_LINUX_V1_ASSERT_UNATTRIBUTED_EFFECT";
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
        let event = if env::var_os(ASSERT_UNATTRIBUTED_EFFECT_ENV).is_some() {
            br#"{"hook_event_name":"PreToolUse","session_id":"thread-1","turn_id":"turn-1","tool_use_id":"tool-1","tool_name":"Bash","tool_input":{"command":"/bin/true"}}"#
                .as_slice()
        } else {
            br#"{"hook_event_name":"session_start"}"#.as_slice()
        };
        if let Err(error) = input.write_all(event) {
            return failure(&marker, &format!("failed to write hook input: {error}"));
        }
    }
    match hook.wait_with_output() {
        Ok(output) => {
            if !output.status.success() {
                failure(
                    &marker,
                    &format!(
                        "managed hook failed: status={} stderr={}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    ),
                )
            } else if env::var_os(ASSERT_UNATTRIBUTED_EFFECT_ENV).is_some()
                && !unattributed_effect_is_delegated()
            {
                failure(
                    &marker,
                    "an unattributed /bin/true effect was not delegated to the generic interception policy",
                )
            } else if fs::write(&marker, output.stdout).is_ok() {
                if env::var_os(ASSERT_UNATTRIBUTED_EFFECT_ENV).is_some() {
                    let diagnostic = Path::new(&marker).with_extension("diagnostic");
                    let _result = fs::write(diagnostic, "unattributed-effect-delegated");
                }
                ExitCode::SUCCESS
            } else {
                failure(&marker, "failed to write managed hook result marker")
            }
        }
        Err(error) => failure(
            &marker,
            &format!("failed to wait for managed hook: {error}"),
        ),
    }
}

fn unattributed_effect_is_delegated() -> bool {
    match Command::new("/bin/true").status() {
        Ok(status) => status.success(),
        Err(_error) => false,
    }
}

fn failure(marker: &str, reason: &str) -> ExitCode {
    let diagnostic = Path::new(marker).with_extension("diagnostic");
    let _result = fs::write(diagnostic, reason);
    ExitCode::FAILURE
}
