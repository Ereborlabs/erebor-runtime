use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_HANDLERS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
struct InterceptionHandler {
    id: String,
    decision: String,
    kind: String,
    executables: Vec<String>,
    allowed_ports: Vec<u16>,
    governed_endpoint: String,
    print_devtools_listening_line: bool,
    keepalive: bool,
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
    match handler.decision.as_str() {
        "mediate" => handle_mediation(handler, invoked, args),
        "deny" => fail_closed(
            "configured process interception denied this launch",
            handler,
            invoked,
            args,
        ),
        "allow" => handle_allow(handler, invoked, args),
        _ => fail_closed(
            "configured process interception decision is not supported by this guard",
            handler,
            invoked,
            args,
        ),
    }
}

fn handle_allow(handler: &InterceptionHandler, invoked: &str, args: &[String]) -> i32 {
    let Some(target) = real_executable_for_shim(invoked) else {
        return fail_closed(
            "configured process interception allowed launch, but no real executable was found after the Erebor shim",
            handler,
            invoked,
            args,
        );
    };

    write_interception_audit(
        handler,
        invoked,
        args,
        remote_debugging_port(&args[1..]),
        "allow",
        "allow",
        &format!(
            "process launch allowed through to real executable {}",
            target.display()
        ),
    );

    let error = Command::new(&target).args(&args[1..]).exec();
    fail_closed(
        &format!("allowed process exec failed: {error}"),
        handler,
        invoked,
        args,
    )
}

fn handle_mediation(handler: &InterceptionHandler, invoked: &str, args: &[String]) -> i32 {
    if handler.kind != "managed_browser_cdp" {
        return fail_closed(
            "process interception handler kind is not supported by this guard",
            handler,
            invoked,
            args,
        );
    }

    let Some(requested_port) = remote_debugging_port(&args[1..]) else {
        return fail_closed(
            "managed_browser_cdp interception requires --remote-debugging-port",
            handler,
            invoked,
            args,
        );
    };
    let allowed_ports = handler.effective_allowed_ports();
    if !allowed_ports.contains(&requested_port) {
        return fail_closed(
            &format!("requested remote debugging port {requested_port} is not allowed"),
            handler,
            invoked,
            args,
        );
    }

    let Some(endpoint_port) = endpoint_port(&handler.governed_endpoint) else {
        return fail_closed(
            "governed endpoint does not include a parseable port",
            handler,
            invoked,
            args,
        );
    };
    if endpoint_port != requested_port {
        return fail_closed(
            &format!(
                "requested port {requested_port} does not match governed endpoint port {endpoint_port}"
            ),
            handler,
            invoked,
            args,
        );
    }

    write_interception_audit(
        handler,
        invoked,
        args,
        Some(requested_port),
        "allow",
        "mediate",
        "browser launch mediated to Erebor-owned governed CDP",
    );

    if handler.print_devtools_listening_line {
        eprintln!(
            "DevTools listening on {}",
            devtools_browser_url(&handler.governed_endpoint)
        );
    }

    if handler.keepalive {
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

    fn effective_allowed_ports(&self) -> Vec<u16> {
        if self.allowed_ports.is_empty() {
            endpoint_port(&self.governed_endpoint).into_iter().collect()
        } else {
            self.allowed_ports.clone()
        }
    }
}

fn parse_interception_handlers() -> Vec<InterceptionHandler> {
    let source = env::var("EREBOR_PROCESS_INTERCEPTION_HANDLERS")
        .unwrap_or_default();
    parse_interception_handlers_from_source(&source)
}

fn parse_interception_handlers_from_source(source: &str) -> Vec<InterceptionHandler> {
    source
        .lines()
        .take(MAX_HANDLERS)
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let id = fields.next().unwrap_or_default();
            if id.is_empty() {
                return None;
            }
            let decision = fields.next().unwrap_or_default();
            let kind = fields.next().unwrap_or_default();
            let executables = split_csv(fields.next().unwrap_or_default());
            let allowed_ports = split_csv(fields.next().unwrap_or_default())
                .into_iter()
                .filter_map(|port| port.parse::<u16>().ok())
                .collect::<Vec<_>>();
            let governed_endpoint = fields.next().unwrap_or_default();
            if decision.is_empty()
                || kind.is_empty()
                || executables.is_empty()
                || governed_endpoint.is_empty()
            {
                return None;
            }

            Some(InterceptionHandler {
                id: id.to_owned(),
                decision: decision.to_owned(),
                kind: kind.to_owned(),
                executables,
                allowed_ports,
                governed_endpoint: governed_endpoint.to_owned(),
                print_devtools_listening_line: parse_bool(fields.next(), true),
                keepalive: parse_bool(fields.next(), true),
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

fn parse_bool(value: Option<&str>, default: bool) -> bool {
    match value.unwrap_or_default() {
        "true" | "1" | "yes" => true,
        "false" | "0" | "no" => false,
        _ => default,
    }
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

    real_executable_for_shim_with_path(
        invoked,
        shim_dir.as_deref(),
        &path,
        current_exe.as_deref(),
    )
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

fn remote_debugging_port(args: &[String]) -> Option<u16> {
    let mut iter = args.iter().peekable();
    while let Some(argument) = iter.next() {
        if let Some(port) = argument.strip_prefix("--remote-debugging-port=") {
            return port.parse().ok();
        }
        if argument == "--remote-debugging-port" {
            return iter.peek().and_then(|port| port.parse().ok());
        }
    }

    None
}

fn endpoint_port(endpoint: &str) -> Option<u16> {
    let endpoint = endpoint
        .strip_prefix("ws://")
        .or_else(|| endpoint.strip_prefix("http://"))?;
    let host = endpoint.split('/').next().unwrap_or(endpoint);
    host.rsplit_once(':')?.1.parse().ok()
}

fn devtools_browser_url(endpoint: &str) -> String {
    format!(
        "{}/devtools/browser/erebor-managed-browser",
        endpoint.trim_end_matches('/')
    )
}

fn fail_closed(
    reason: &str,
    handler: &InterceptionHandler,
    invoked: &str,
    args: &[String],
) -> i32 {
    write_interception_audit(
        handler,
        invoked,
        args,
        remote_debugging_port(&args[1..]),
        "deny",
        "deny",
        reason,
    );
    eprintln!("erebor linux process guard interception: {reason}");
    126
}

fn write_interception_audit(
    handler: &InterceptionHandler,
    invoked: &str,
    args: &[String],
    requested_port: Option<u16>,
    final_decision: &str,
    policy_decision: &str,
    reason: &str,
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
    let requested_port_label = requested_port
        .map(|port| port.to_string())
        .unwrap_or_else(|| String::from("none"));
    let requested_port_json =
        requested_port.map_or_else(|| String::from("null"), |port| port.to_string());
    let event_id = format!("{session_id}-process-interception-{requested_port_label}-{timestamp}");

    let _ = write!(
        file,
        "{{\"event\":{{\"id\":{},\"session_id\":{},\"actor\":{{\"id\":{},\"kind\":\"agent\"}},\"surface\":\"terminal\",\"action\":\"process_exec\",\"target\":{{\"label\":{},\"uri\":null}},\"payload\":{{\"kind\":\"process_interception\",\"handler_id\":{},\"interception_decision\":{},\"interception_kind\":{},\"requested_port\":{},\"governed_endpoint\":{},\"argv_summary\":{},\"command\":[",
        json_string(&event_id),
        json_string(&session_id),
        json_string(&actor_id),
        json_string(invoked),
        json_string(&handler.id),
        json_string(&handler.decision),
        json_string(&handler.kind),
        requested_port_json,
        json_string(&handler.governed_endpoint),
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
    use std::{
        env, fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
    };

    use super::{
        devtools_browser_url, endpoint_port, executable_name,
        parse_interception_handlers_from_source, real_executable_for_shim_with_path,
        remote_debugging_port,
    };

    #[test]
    fn parses_process_interception_handler_environment_format() {
        let handlers = parse_interception_handlers_from_source(
            "managed-browser-cdp\tmediate\tmanaged_browser_cdp\tgoogle-chrome,chromium\t9222\tws://127.0.0.1:9222/\ttrue\tfalse\n",
        );

        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].id, "managed-browser-cdp");
        assert_eq!(handlers[0].decision, "mediate");
        assert_eq!(handlers[0].kind, "managed_browser_cdp");
        assert_eq!(
            handlers[0].executables,
            vec![String::from("google-chrome"), String::from("chromium")]
        );
        assert_eq!(handlers[0].allowed_ports, vec![9222]);
        assert_eq!(handlers[0].governed_endpoint, "ws://127.0.0.1:9222/");
        assert!(handlers[0].print_devtools_listening_line);
        assert!(!handlers[0].keepalive);
    }

    #[test]
    fn extracts_remote_debugging_port_from_chrome_argv() {
        assert_eq!(
            remote_debugging_port(&[
                String::from("--headless"),
                String::from("--remote-debugging-port=9222")
            ]),
            Some(9222)
        );
        assert_eq!(
            remote_debugging_port(&[
                String::from("--remote-debugging-port"),
                String::from("9223")
            ]),
            Some(9223)
        );
    }

    #[test]
    fn parses_endpoint_port_and_devtools_line() {
        assert_eq!(endpoint_port("ws://127.0.0.1:9222/"), Some(9222));
        assert_eq!(
            devtools_browser_url("ws://127.0.0.1:9222/"),
            "ws://127.0.0.1:9222/devtools/browser/erebor-managed-browser"
        );
    }

    #[test]
    fn matches_invoked_executable_basename() {
        assert_eq!(
            executable_name("/tmp/erebor/shims/google-chrome"),
            Some(String::from("google-chrome"))
        );
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
