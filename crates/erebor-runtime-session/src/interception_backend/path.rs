use std::path::PathBuf;

use erebor_runtime_core::SessionInterceptionBackendKind;

pub(crate) fn linux_cgroup_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

pub(crate) fn linux_ptrace_backend_session_dir(session_id: &str, instance_id: u64) -> PathBuf {
    std::env::temp_dir()
        .join("erebor-runtime")
        .join("sessions")
        .join(path_component(session_id, "unknown-session"))
        .join("interception")
        .join(SessionInterceptionBackendKind::LinuxPtrace.as_str())
        .join("process-guard")
        .join(std::process::id().to_string())
        .join(instance_id.to_string())
}

fn path_component(value: &str, fallback: &str) -> String {
    let component = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();

    if component.is_empty() || matches!(component.as_str(), "." | "..") {
        fallback.to_owned()
    } else {
        component
    }
}
