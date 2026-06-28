use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{self, Command},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::ipc;

const MAX_HANDLERS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
struct InterceptionHandler {
    id: String,
    executables: Vec<String>,
}

pub(super) fn try_handle_configured_interception() -> Option<i32> {
    let args = env::args().collect::<Vec<_>>();
    let invoked = args
        .first()
        .and_then(|arg| executable_name(arg))
        .unwrap_or_else(|| String::from("unknown"));
    let handlers = parse_interception_handlers();
    let handler = handlers
        .iter()
        .find(|handler| handler.matches_executable(&invoked))?;

    Some(handle_interception(handler, &invoked, &args))
}

fn handle_interception(handler: &InterceptionHandler, invoked: &str, args: &[String]) -> i32 {
    match request_broker_decision(handler, invoked, args) {
        Ok(decision) => apply_broker_decision(handler, invoked, args, &decision),
        Err(reason) => fail_closed(&reason, handler, invoked, args, None),
    }
}

fn apply_broker_decision(
    handler: &InterceptionHandler,
    invoked: &str,
    args: &[String],
    decision: &ipc::InterceptionDecision,
) -> i32 {
    match decision.kind {
        ipc::InterceptionDecisionKind::Allow => handle_allow(handler, invoked, args, decision),
        ipc::InterceptionDecisionKind::Deny => fail_closed(
            &decision.reason,
            handler,
            invoked,
            args,
            decision.deny_exit_code,
        ),
        ipc::InterceptionDecisionKind::RequireApproval => fail_closed(
            &format!(
                "{}; approval leases are not available to this guard yet",
                decision.reason
            ),
            handler,
            invoked,
            args,
            Some(126),
        ),
        ipc::InterceptionDecisionKind::Mediate => {
            handle_mediation(handler, invoked, args, decision)
        }
        ipc::InterceptionDecisionKind::Unknown => fail_closed(
            "broker returned an unknown process interception decision",
            handler,
            invoked,
            args,
            Some(126),
        ),
    }
}

fn handle_allow(
    handler: &InterceptionHandler,
    invoked: &str,
    args: &[String],
    decision: &ipc::InterceptionDecision,
) -> i32 {
    let target = decision
        .allow_exec_target
        .as_deref()
        .filter(|target| !target.is_empty())
        .map(PathBuf::from)
        .or_else(|| real_executable_for_shim(invoked));
    let Some(target) = target else {
        return fail_closed(
            "broker allowed launch, but no real executable was found after the Erebor shim",
            handler,
            invoked,
            args,
            Some(126),
        );
    };

    write_interception_audit(
        handler,
        invoked,
        args,
        "allow",
        "allow",
        &decision.reason,
        None,
    );

    let error = Command::new(&target).args(&args[1..]).exec();
    fail_closed(
        &format!("allowed process exec failed: {error}"),
        handler,
        invoked,
        args,
        Some(126),
    )
}

fn handle_mediation(
    handler: &InterceptionHandler,
    invoked: &str,
    args: &[String],
    decision: &ipc::InterceptionDecision,
) -> i32 {
    let Some(mediation) = decision.mediate.as_ref() else {
        return fail_closed(
            "broker returned a mediate decision without mediation details",
            handler,
            invoked,
            args,
            Some(126),
        );
    };
    write_interception_audit(
        handler,
        invoked,
        args,
        "allow",
        "mediate",
        &decision.reason,
        Some(&mediation.endpoint),
    );

    if !mediation.print_line.is_empty() {
        eprintln!("{}", mediation.print_line);
    }

    if mediation.keepalive {
        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }

    0
}

impl InterceptionHandler {
    fn matches_executable(&self, invoked: &str) -> bool {
        self.executables
            .iter()
            .any(|executable| executable == invoked)
    }
}

fn parse_interception_handlers() -> Vec<InterceptionHandler> {
    let source = env::var("EREBOR_PROCESS_INTERCEPTION_HANDLERS").unwrap_or_default();
    parse_interception_handlers_from_source(&source)
}

fn parse_interception_handlers_from_source(source: &str) -> Vec<InterceptionHandler> {
    source
        .lines()
        .take(MAX_HANDLERS)
        .filter_map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            let id = fields.first().copied().unwrap_or_default();
            if id.is_empty() {
                return None;
            }
            let executables = match fields.as_slice() {
                // Phase 2 format: id<TAB>executable[,executable]
                [_id, executables] => split_csv(executables),
                // Phase 1 compatibility: id<TAB>decision<TAB>kind<TAB>executables...
                [_id, _decision, _kind, executables, ..] => split_csv(executables),
                _ => Vec::new(),
            };
            if executables.is_empty() {
                return None;
            }

            Some(InterceptionHandler {
                id: id.to_owned(),
                executables,
            })
        })
        .collect()
}

fn split_csv(source: &str) -> Vec<String> {
    source
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn request_broker_decision(
    handler: &InterceptionHandler,
    invoked: &str,
    args: &[String],
) -> Result<ipc::InterceptionDecision, String> {
    let endpoint = control_endpoint_from_env()?;
    let hello = guard_hello_from_env()?;
    let mut connection = ipc::GuardBrokerConnection::connect(&endpoint, hello)?;
    let request = interception_request_from_invocation(handler, invoked, args);
    connection.request_decision(&request)
}

fn control_endpoint_from_env() -> Result<ipc::ControlEndpoint, String> {
    let path = required_env("EREBOR_SESSION_CONTROL_PATH")?;
    let token = required_env("EREBOR_SESSION_CONTROL_TOKEN")?;
    let timeout_ms = env::var("EREBOR_SESSION_CONTROL_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(25);

    Ok(ipc::ControlEndpoint {
        path,
        token,
        timeout_ms,
    })
}

fn guard_hello_from_env() -> Result<ipc::GuardHello, String> {
    Ok(ipc::GuardHello {
        session_id: required_env("EREBOR_SESSION_ID")?,
        actor_id: env::var("EREBOR_ACTOR_ID").unwrap_or_else(|_| String::from("agent")),
        guard_pid: process::id() as i64,
        runner_kind: env::var("EREBOR_SESSION_RUNNER")
            .unwrap_or_else(|_| String::from("linux_host")),
        platform: String::from("linux-x86_64"),
        capabilities: vec![String::from("interception_request")],
    })
}

fn interception_request_from_invocation(
    handler: &InterceptionHandler,
    invoked: &str,
    args: &[String],
) -> ipc::InterceptionRequest {
    ipc::InterceptionRequest {
        request_id: current_unix_timestamp(),
        actor_id: env::var("EREBOR_ACTOR_ID").unwrap_or_else(|_| String::from("agent")),
        pid: process::id() as i64,
        ppid: proc_parent_pid_for_self().unwrap_or(0) as i64,
        executable: invoked.to_owned(),
        argv: args.to_vec(),
        cwd: env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("<unknown>"))
            .display()
            .to_string(),
        matched_handler_id: handler.id.clone(),
        timestamp: format!("unix:{}", current_unix_timestamp()),
    }
}

fn required_env(key: &str) -> Result<String, String> {
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

fn executable_name(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
}

fn real_executable_for_shim(invoked: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    let shim_dir = env::var_os("EREBOR_PROCESS_INTERCEPTION_SHIM_DIR").map(PathBuf::from);
    let current_exe = env::current_exe().ok();

    real_executable_for_shim_with_path(invoked, shim_dir.as_deref(), &path, current_exe.as_deref())
}

fn real_executable_for_shim_with_path(
    invoked: &str,
    shim_dir: Option<&Path>,
    path: impl AsRef<std::ffi::OsStr>,
    current_exe: Option<&Path>,
) -> Option<PathBuf> {
    env::split_paths(&path)
        .filter(|directory| !shim_dir.is_some_and(|shim_dir| paths_equal(directory, shim_dir)))
        .map(|directory| directory.join(invoked))
        .filter(|candidate| {
            !current_exe.is_some_and(|current_exe| paths_equal(candidate, current_exe))
        })
        .find(|candidate| is_executable_file(candidate))
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

fn fail_closed(
    reason: &str,
    handler: &InterceptionHandler,
    invoked: &str,
    args: &[String],
    exit_code: Option<i32>,
) -> i32 {
    write_interception_audit(handler, invoked, args, "deny", "deny", reason, None);
    eprintln!("erebor linux process guard interception: {reason}");
    exit_code.unwrap_or(126)
}

fn write_interception_audit(
    handler: &InterceptionHandler,
    invoked: &str,
    args: &[String],
    final_decision: &str,
    policy_decision: &str,
    reason: &str,
    governed_endpoint: Option<&str>,
) {
    let audit_path = match env::var("EREBOR_GUARD_AUDIT_JSONL") {
        Ok(path) if !path.is_empty() => path,
        _ => return,
    };

    let Ok(mut file) = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&audit_path)
    else {
        return;
    };

    let session_id =
        env::var("EREBOR_SESSION_ID").unwrap_or_else(|_| String::from("unknown-session"));
    let actor_id = env::var("EREBOR_ACTOR_ID").unwrap_or_else(|_| String::from("agent"));
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let command = args.join(" ");
    let event_id = format!(
        "{}-process-interception-{}-{}",
        session_id, handler.id, timestamp
    );
    let governed_endpoint = governed_endpoint.unwrap_or("");

    let _ = write!(
        file,
        "{{\"event\":{{\"id\":{},\"session_id\":{},\"actor\":{{\"id\":{},\"kind\":\"agent\"}},\"surface\":\"terminal\",\"action\":\"process_exec\",\"target\":{{\"label\":{},\"uri\":null}},\"payload\":{{\"kind\":\"process_interception\",\"handler_id\":{},\"governed_endpoint\":{},\"argv_summary\":{},\"command\":[",
        json_string(&event_id),
        json_string(&session_id),
        json_string(&actor_id),
        json_string(invoked),
        json_string(&handler.id),
        json_string(governed_endpoint),
        json_string(&command)
    );
    for (index, argument) in args.iter().enumerate() {
        if index > 0 {
            let _ = write!(file, ",");
        }
        let _ = write!(file, "{}", json_string(argument));
    }
    let _ = writeln!(
        file,
        "]}},\"risk\":{{\"level\":\"high\",\"reasons\":[{}]}},\"timestamp\":\"unix:{}\"}},\"policy_decision\":{{\"type\":\"{}\",\"reason\":{},\"rule_id\":{}}},\"final_decision\":{{\"type\":\"{}\",\"reason\":{},\"rule_id\":{}}}}}",
        json_string(reason),
        timestamp,
        policy_decision,
        json_string(reason),
        json_string(&format!("erebor-process-interception-{}", handler.id)),
        final_decision,
        json_string(reason),
        json_string(&format!("erebor-process-interception-{}", handler.id))
    );
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character < ' ' => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use std::{env, fs, os::unix::fs::PermissionsExt, path::PathBuf};

    use super::{
        apply_broker_decision, executable_name, interception_request_from_invocation,
        parse_interception_handlers_from_source, real_executable_for_shim_with_path,
        InterceptionHandler,
    };

    #[test]
    fn parses_process_interception_handler_environment_format_for_matching_only() {
        let handlers = parse_interception_handlers_from_source(
            "managed-browser-cdp\tgoogle-chrome,chromium\nlegacy\tmediate\tmanaged_browser_cdp\tchrome\t9222\tws://127.0.0.1:9222/\ttrue\tfalse\n",
        );

        assert_eq!(handlers.len(), 2);
        assert_eq!(handlers[0].id, "managed-browser-cdp");
        assert_eq!(
            handlers[0].executables,
            vec![String::from("google-chrome"), String::from("chromium")]
        );
        assert_eq!(handlers[1].id, "legacy");
        assert_eq!(handlers[1].executables, vec![String::from("chrome")]);
    }

    #[test]
    fn interception_request_uses_connection_bound_session_model() {
        let handler = InterceptionHandler {
            id: String::from("managed-browser-cdp"),
            executables: vec![String::from("google-chrome")],
        };
        let request = interception_request_from_invocation(
            &handler,
            "google-chrome",
            &[String::from("google-chrome"), String::from("--flag")],
        );

        assert_eq!(request.matched_handler_id, "managed-browser-cdp");
        assert_eq!(request.executable, "google-chrome");
        assert_eq!(request.argv.len(), 2);
    }

    #[test]
    fn matches_invoked_executable_basename() {
        assert_eq!(
            executable_name("/tmp/erebor/shims/google-chrome"),
            Some(String::from("google-chrome"))
        );
    }

    #[test]
    fn applies_generic_broker_mediation_without_browser_specific_kind_check() {
        let handler = InterceptionHandler {
            id: String::from("api-mediator"),
            executables: vec![String::from("tool")],
        };
        let decision = super::ipc::InterceptionDecision {
            request_id: 1,
            kind: super::ipc::InterceptionDecisionKind::Mediate,
            rule_id: String::from("mediate-api"),
            reason: String::from("route launch to mediated surface"),
            allow_exec_target: None,
            deny_exit_code: None,
            mediate: Some(super::ipc::MediateDecision {
                kind: String::from("future_api"),
                replacement_surface: String::from("api"),
                endpoint: String::from("local://api"),
                lease_id: String::from("lease"),
                print_line: String::new(),
                keepalive: false,
            }),
        };

        let status = apply_broker_decision(&handler, "tool", &[String::from("tool")], &decision);

        assert_eq!(status, 0);
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
            real_executable_for_shim_with_path("google-chrome", Some(&shim_dir), &path, None);

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
