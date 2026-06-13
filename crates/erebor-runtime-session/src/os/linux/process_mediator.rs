use std::{
    env,
    fs::OpenOptions,
    io::Write,
    path::Path,
    process,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_HANDLERS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
struct MediationHandler {
    id: String,
    kind: String,
    executables: Vec<String>,
    allowed_ports: Vec<u16>,
    governed_endpoint: String,
    print_devtools_listening_line: bool,
    keepalive: bool,
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let invoked = args
        .first()
        .and_then(|arg| executable_name(arg))
        .unwrap_or_else(|| String::from("unknown"));
    let handlers = parse_handlers();
    let Some(handler) = handlers
        .iter()
        .find(|handler| handler.matches_executable(&invoked))
    else {
        fail_closed(
            "no process mediation handler matched invoked executable",
            None,
            &invoked,
            &args,
        );
    };

    if handler.kind != "managed_browser_cdp" {
        fail_closed(
            "process mediation handler kind is not supported by this shim",
            Some(handler),
            &invoked,
            &args,
        );
    }

    let Some(requested_port) = remote_debugging_port(&args[1..]) else {
        fail_closed(
            "managed_browser_cdp mediation requires --remote-debugging-port",
            Some(handler),
            &invoked,
            &args,
        );
    };
    let allowed_ports = handler.effective_allowed_ports();
    if !allowed_ports.contains(&requested_port) {
        fail_closed(
            &format!("requested remote debugging port {requested_port} is not allowed"),
            Some(handler),
            &invoked,
            &args,
        );
    }

    let Some(endpoint_port) = endpoint_port(&handler.governed_endpoint) else {
        fail_closed(
            "governed endpoint does not include a parseable port",
            Some(handler),
            &invoked,
            &args,
        );
    };
    if endpoint_port != requested_port {
        fail_closed(
            &format!(
                "requested port {requested_port} does not match governed endpoint port {endpoint_port}"
            ),
            Some(handler),
            &invoked,
            &args,
        );
    }

    write_mediation_audit(handler, &invoked, &args, requested_port, "allow", "mediate");

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
}

impl MediationHandler {
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

fn parse_handlers() -> Vec<MediationHandler> {
    let source = env::var("EREBOR_PROCESS_MEDIATION_HANDLERS").unwrap_or_default();
    parse_handlers_from_source(&source)
}

fn parse_handlers_from_source(source: &str) -> Vec<MediationHandler> {
    source
        .lines()
        .take(MAX_HANDLERS)
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let id = fields.next().unwrap_or_default();
            if id.is_empty() {
                return None;
            }
            let kind = fields.next().unwrap_or_default();
            let executables = split_csv(fields.next().unwrap_or_default());
            let allowed_ports = split_csv(fields.next().unwrap_or_default())
                .into_iter()
                .filter_map(|port| port.parse::<u16>().ok())
                .collect::<Vec<_>>();
            let governed_endpoint = fields.next().unwrap_or_default();
            if kind.is_empty() || executables.is_empty() || governed_endpoint.is_empty() {
                return None;
            }

            Some(MediationHandler {
                id: id.to_owned(),
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
    handler: Option<&MediationHandler>,
    invoked: &str,
    args: &[String],
) -> ! {
    if let Some(handler) = handler {
        if let Some(port) = remote_debugging_port(&args[1..]) {
            write_mediation_audit(handler, invoked, args, port, "deny", "deny");
        }
    }
    eprintln!("erebor process mediator: {reason}");
    process::exit(126);
}

fn write_mediation_audit(
    handler: &MediationHandler,
    invoked: &str,
    args: &[String],
    requested_port: u16,
    final_decision: &str,
    policy_decision: &str,
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

    let session_id = env::var("EREBOR_SESSION_ID").unwrap_or_else(|_| String::from("unknown-session"));
    let actor_id = env::var("EREBOR_ACTOR_ID").unwrap_or_else(|_| String::from("agent"));
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let command = args.join(" ");
    let event_id = format!("{session_id}-process-mediation-{requested_port}-{timestamp}");
    let reason = if final_decision == "allow" {
        "browser launch mediated to Erebor-owned governed CDP"
    } else {
        "browser launch mediation failed closed"
    };

    let _ = write!(
        file,
        "{{\"event\":{{\"id\":{},\"session_id\":{},\"actor\":{{\"id\":{},\"kind\":\"agent\"}},\"surface\":\"terminal\",\"action\":\"process_exec\",\"target\":{{\"label\":{},\"uri\":null}},\"payload\":{{\"kind\":\"process_launch_mediation\",\"handler_id\":{},\"mediation_kind\":{},\"requested_port\":{},\"governed_endpoint\":{},\"argv_summary\":{},\"command\":[",
        json_string(&event_id),
        json_string(&session_id),
        json_string(&actor_id),
        json_string(invoked),
        json_string(&handler.id),
        json_string(&handler.kind),
        requested_port,
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
        json_string(&format!("erebor-process-mediation-{}", handler.id)),
        final_decision,
        json_string(reason),
        json_string(&format!("erebor-process-mediation-{}", handler.id))
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
    use super::{
        devtools_browser_url, endpoint_port, executable_name, parse_handlers_from_source,
        remote_debugging_port,
    };

    #[test]
    fn parses_handler_environment_format() {
        let handlers = parse_handlers_from_source(
            "managed-browser-cdp\tmanaged_browser_cdp\tgoogle-chrome,chromium\t9222\tws://127.0.0.1:9222/\ttrue\tfalse\n",
        );

        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].id, "managed-browser-cdp");
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
}
