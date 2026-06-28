use std::{fs, io, path::Path};

use erebor_runtime_core::{
    RuntimeConfig, SessionAdoptPlan, SessionAdoptTarget, SessionRunOutcome, SessionRunnerKind,
};
use erebor_runtime_events::SessionId;
use snafu::Location;

use crate::{adopt_session_plan, SessionExecutionError};

pub fn adopt_session_target(
    config: &RuntimeConfig,
    runner_kind: SessionRunnerKind,
    session_id: SessionId,
    target: SessionAdoptTarget,
) -> Result<SessionRunOutcome, SessionExecutionError> {
    let plan = build_session_adopt_plan_for_target(config, runner_kind, session_id, target)?;
    adopt_session_plan(config, &plan)
}

fn build_session_adopt_plan_for_target(
    config: &RuntimeConfig,
    runner_kind: SessionRunnerKind,
    session_id: SessionId,
    target: SessionAdoptTarget,
) -> Result<SessionAdoptPlan, SessionExecutionError> {
    let pid = resolve_session_adopt_target(&target, Path::new("/proc"))?;
    SessionAdoptPlan::from_config(config, runner_kind, session_id, pid)
        .map_err(SessionExecutionError::invalid_config)
}

fn resolve_session_adopt_target(
    target: &SessionAdoptTarget,
    proc_root: &Path,
) -> Result<i32, SessionExecutionError> {
    match target {
        SessionAdoptTarget::Pid(pid) => Ok(*pid),
        SessionAdoptTarget::ProcessMatch(pattern) => resolve_process_match(pattern, proc_root),
    }
}

fn resolve_process_match(pattern: &str, proc_root: &Path) -> Result<i32, SessionExecutionError> {
    let candidates = matching_processes(pattern, proc_root)?;
    match candidates.as_slice() {
        [] => Err(SessionExecutionError::adopt_match_not_found(pattern)),
        [candidate] => Ok(candidate.pid),
        _ => Err(SessionExecutionError::adopt_match_ambiguous(
            pattern,
            candidates
                .iter()
                .map(ProcessMatch::display)
                .collect::<Vec<_>>(),
        )),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessMatch {
    pid: i32,
    label: String,
}

impl ProcessMatch {
    fn display(&self) -> String {
        format!("{}:{}", self.pid, self.label)
    }
}

fn matching_processes(
    pattern: &str,
    proc_root: &Path,
) -> Result<Vec<ProcessMatch>, SessionExecutionError> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err(SessionExecutionError::invalid_adopt_target(
            "process match pattern cannot be empty",
        ));
    }

    let entries = fs::read_dir(proc_root).map_err(|error| read_process_table(proc_root, error))?;
    let current_pid = std::process::id() as i32;
    let mut matches = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|error| read_process_table(proc_root, error))?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        if pid == current_pid {
            continue;
        }

        let process_dir = entry.path();
        let comm = fs::read_to_string(process_dir.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        let cmdline = fs::read(process_dir.join("cmdline"))
            .ok()
            .map(|bytes| format_cmdline(&bytes))
            .unwrap_or_default();
        if comm.contains(pattern) || cmdline.contains(pattern) {
            let label = if cmdline.is_empty() { comm } else { cmdline };
            matches.push(ProcessMatch { pid, label });
        }
    }

    matches.sort_by_key(|candidate| candidate.pid);
    Ok(matches)
}

fn read_process_table(path: &Path, source: io::Error) -> SessionExecutionError {
    SessionExecutionError::ReadProcessTable {
        path: path.to_path_buf(),
        source,
        location: Location::default(),
    }
}

fn format_cmdline(bytes: &[u8]) -> String {
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use erebor_runtime_core::SessionAdoptTarget;

    use super::{resolve_session_adopt_target, SessionExecutionError};

    static FAKE_PROC_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn adopt_match_resolves_unique_process() -> Result<(), Box<dyn std::error::Error>> {
        let proc_root = create_fake_proc(&[
            (1234, "openclaw", &["openclaw", "gateway", "run"][..]),
            (2234, "bash", &["bash"][..]),
        ])?;

        let pid = resolve_session_adopt_target(
            &SessionAdoptTarget::process_match("openclaw"),
            &proc_root,
        )?;

        assert_eq!(pid, 1234);
        let _result = fs::remove_dir_all(proc_root);
        Ok(())
    }

    #[test]
    fn adopt_match_fails_for_ambiguous_processes() -> Result<(), Box<dyn std::error::Error>> {
        let proc_root = create_fake_proc(&[
            (1234, "openclaw", &["openclaw"][..]),
            (2234, "node", &["node", "/tmp/openclaw-worker.js"][..]),
        ])?;

        let error = resolve_session_adopt_target(
            &SessionAdoptTarget::process_match("openclaw"),
            &proc_root,
        );

        assert!(matches!(
            error,
            Err(SessionExecutionError::AdoptMatchAmbiguous { .. })
        ));
        let _result = fs::remove_dir_all(proc_root);
        Ok(())
    }

    #[test]
    fn adopt_match_fails_when_no_process_matches() -> Result<(), Box<dyn std::error::Error>> {
        let proc_root = create_fake_proc(&[(1234, "bash", &["bash"][..])])?;

        let error = resolve_session_adopt_target(
            &SessionAdoptTarget::process_match("openclaw"),
            &proc_root,
        );

        assert!(matches!(
            error,
            Err(SessionExecutionError::AdoptMatchNotFound { .. })
        ));
        let _result = fs::remove_dir_all(proc_root);
        Ok(())
    }

    fn create_fake_proc(
        processes: &[(i32, &str, &[&str])],
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let instance = FAKE_PROC_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "erebor-runtime-session-proc-{}-{instance}",
            std::process::id(),
        ));
        let _result = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        for (pid, comm, argv) in processes {
            write_fake_process(&root, *pid, comm, argv)?;
        }
        Ok(root)
    }

    fn write_fake_process(
        root: &Path,
        pid: i32,
        comm: &str,
        argv: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("comm"), format!("{comm}\n"))?;
        let mut cmdline = Vec::new();
        for argument in argv {
            cmdline.extend_from_slice(argument.as_bytes());
            cmdline.push(0);
        }
        fs::write(dir.join("cmdline"), cmdline)?;
        Ok(())
    }
}
