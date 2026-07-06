use std::{
    env, fs,
    path::PathBuf,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{ipc, proc_parent_pid, sys::Pid};

pub(super) struct GuardBrokerEnvironment;

impl GuardBrokerEnvironment {
    pub(super) fn endpoint() -> Result<Option<ipc::RuntimeInterceptionEndpoint>, String> {
        let path = match env::var("EREBOR_RUNTIME_INTERCEPTION_PATH") {
            Ok(path) if !path.is_empty() => path,
            _ => return Ok(None),
        };
        let token = env::var("EREBOR_RUNTIME_INTERCEPTION_TOKEN")
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| String::from("EREBOR_RUNTIME_INTERCEPTION_TOKEN is required"))?;
        let timeout_ms = env::var("EREBOR_RUNTIME_INTERCEPTION_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(25);

        Ok(Some(ipc::RuntimeInterceptionEndpoint {
            path,
            token,
            timeout_ms,
        }))
    }

    pub(super) fn hello() -> Result<ipc::GuardHello, String> {
        Ok(ipc::GuardHello {
            session_id: Self::required("EREBOR_SESSION_ID")?,
            actor_id: env::var("EREBOR_ACTOR_ID").unwrap_or_else(|_| String::from("agent")),
            guard_pid: process::id() as i64,
            runner_kind: env::var("EREBOR_SESSION_RUNNER")
                .unwrap_or_else(|_| String::from("linux_host")),
            platform: String::from("linux-x86_64"),
            capabilities: Self::capabilities(),
        })
    }

    pub(super) fn operation_enabled(operation: &str) -> bool {
        match env::var("EREBOR_GUARD_INTERCEPTION_OPERATIONS") {
            Ok(source) => source
                .split(|character: char| character == ',' || character.is_ascii_whitespace())
                .any(|value| value == operation),
            Err(_) => operation == "process_exec",
        }
    }

    pub(super) fn proc_cwd(pid: Pid) -> String {
        fs::read_link(format!("/proc/{pid}/cwd"))
            .unwrap_or_else(|_| PathBuf::from("<unknown>"))
            .display()
            .to_string()
    }

    pub(super) fn current_unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }

    pub(super) fn process_exec_request(
        pid: Pid,
        path: &str,
        argv: &[String],
    ) -> ipc::InterceptionRequest {
        let timestamp = Self::current_unix_timestamp();
        ipc::InterceptionRequest {
            request_id: timestamp,
            actor_id: env::var("EREBOR_ACTOR_ID").unwrap_or_else(|_| String::from("agent")),
            source: ipc::InterceptionSource::Ptrace,
            pid: i64::from(pid),
            ppid: proc_parent_pid(pid).map_or(0, i64::from),
            executable: path.to_owned(),
            argv: argv.to_vec(),
            cwd: Self::proc_cwd(pid),
            matched_handler_id: String::new(),
            timestamp: format!("unix:{timestamp}"),
            operation: ipc::InterceptionOperation::ProcessExec,
            file: None,
        }
    }

    fn capabilities() -> Vec<String> {
        let mut capabilities = vec![String::from("interception_request")];
        for operation in ["process_exec", "file_open", "file_read", "file_mutation"] {
            if Self::operation_enabled(operation) {
                capabilities.push(format!("{operation}_router"));
            }
        }
        capabilities
    }

    fn required(key: &str) -> Result<String, String> {
        env::var(key)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{key} is required"))
    }
}
