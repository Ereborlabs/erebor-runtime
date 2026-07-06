use std::{
    env, fs,
    path::PathBuf,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{ipc, InterceptionHandler};

pub(super) struct InterceptionBrokerClient<'a> {
    handler: &'a InterceptionHandler,
    invoked: &'a str,
    args: &'a [String],
}

impl<'a> InterceptionBrokerClient<'a> {
    pub(super) fn new(
        handler: &'a InterceptionHandler,
        invoked: &'a str,
        args: &'a [String],
    ) -> Self {
        Self {
            handler,
            invoked,
            args,
        }
    }

    pub(super) fn request_decision(&self) -> Result<ipc::InterceptionDecision, String> {
        let endpoint = BrokerEnvironment::endpoint()?;
        let hello = BrokerEnvironment::hello()?;
        let mut connection = ipc::RuntimeInterceptionConnection::connect(&endpoint, hello)?;
        let request = self.request();
        connection.request_decision(&request)
    }

    fn request(&self) -> ipc::InterceptionRequest {
        let timestamp = BrokerEnvironment::current_unix_timestamp();
        ipc::InterceptionRequest {
            request_id: timestamp,
            actor_id: env::var("EREBOR_ACTOR_ID").unwrap_or_else(|_| String::from("agent")),
            source: ipc::InterceptionSource::Shim,
            pid: process::id() as i64,
            ppid: BrokerEnvironment::proc_parent_pid_for_self().unwrap_or(0) as i64,
            executable: self.invoked.to_owned(),
            argv: self.args.to_vec(),
            cwd: env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("<unknown>"))
                .display()
                .to_string(),
            matched_handler_id: self.handler.id.clone(),
            timestamp: format!("unix:{timestamp}"),
            operation: ipc::InterceptionOperation::ProcessExec,
            file: None,
        }
    }
}

struct BrokerEnvironment;

impl BrokerEnvironment {
    fn endpoint() -> Result<ipc::RuntimeInterceptionEndpoint, String> {
        let path = Self::required("EREBOR_RUNTIME_INTERCEPTION_PATH")?;
        let token = Self::required("EREBOR_RUNTIME_INTERCEPTION_TOKEN")?;
        let timeout_ms = env::var("EREBOR_RUNTIME_INTERCEPTION_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(25);

        Ok(ipc::RuntimeInterceptionEndpoint {
            path,
            token,
            timeout_ms,
        })
    }

    fn hello() -> Result<ipc::GuardHello, String> {
        Ok(ipc::GuardHello {
            session_id: Self::required("EREBOR_SESSION_ID")?,
            actor_id: env::var("EREBOR_ACTOR_ID").unwrap_or_else(|_| String::from("agent")),
            guard_pid: process::id() as i64,
            runner_kind: env::var("EREBOR_SESSION_RUNNER")
                .unwrap_or_else(|_| String::from("linux_host")),
            platform: String::from("linux-x86_64"),
            capabilities: vec![String::from("interception_request")],
        })
    }

    fn required(key: &str) -> Result<String, String> {
        env::var(key)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{key} is required for broker-backed process interception"))
    }

    fn proc_parent_pid_for_self() -> Option<i32> {
        let source = fs::read_to_string("/proc/self/stat").ok()?;
        let (_command, rest) = source.rsplit_once(')')?;
        rest.split_whitespace().nth(1)?.parse().ok()
    }

    fn current_unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::{InterceptionBrokerClient, InterceptionHandler};

    #[test]
    fn interception_request_uses_connection_bound_session_model() {
        let handler = InterceptionHandler::new(
            String::from("managed-browser-cdp"),
            vec![String::from("google-chrome")],
        );
        let args = vec![String::from("google-chrome"), String::from("--flag")];
        let client = InterceptionBrokerClient::new(&handler, "google-chrome", &args);
        let request = client.request();

        assert_eq!(request.matched_handler_id, "managed-browser-cdp");
        assert_eq!(request.executable, "google-chrome");
        assert_eq!(request.argv.len(), 2);
    }
}
