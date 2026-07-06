use std::{
    env,
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{
    rules::{ProcessRule, ProcessRuleDecision},
    sys::{LinuxSys, Pid},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditCommandLogLevel {
    All,
    Signal,
    NonAllow,
}

pub(super) fn write_process_audit(
    sequence: u64,
    pid: Pid,
    path: &str,
    argv: &[String],
    text: &str,
    rule: Option<&ProcessRule>,
) {
    let audit_path = match env::var("EREBOR_GUARD_AUDIT_JSONL") {
        Ok(path) if !path.is_empty() => path,
        _ => return,
    };
    if !should_write_process_audit(path, argv, rule) {
        return;
    }

    let Ok(mut file) = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&audit_path)
    else {
        eprintln!(
            "erebor linux process guard: failed to open audit log {}: {}",
            audit_path,
            LinuxSys::errno_message(LinuxSys::errno())
        );
        return;
    };

    let session_id =
        env::var("EREBOR_SESSION_ID").unwrap_or_else(|_| String::from("unknown-session"));
    let actor_id = env::var("EREBOR_ACTOR_ID").unwrap_or_else(|_| String::from("agent"));
    let tty = env::var("EREBOR_TERMINAL_TTY").unwrap_or_else(|_| String::from("false"));
    let cwd = env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("<unknown>"))
        .display()
        .to_string();
    let event_id = format!("{session_id}-process-exec-{pid}-{sequence}");
    let policy_decision = rule.map_or("allow", |rule| rule.decision.policy_decision_type());
    let final_decision = rule.map_or("allow", |rule| rule.decision.final_decision_type());
    let risk = match rule.map(|rule| rule.decision) {
        Some(ProcessRuleDecision::Allow) => "low",
        Some(ProcessRuleDecision::Deny | ProcessRuleDecision::RequireApproval) => "high",
        None => "medium",
    };
    let reason = rule.map_or("agent-issued process execution attempt", |rule| {
        rule.reason.as_str()
    });
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    let _ = write!(
        file,
        "{{\"event\":{{\"id\":{},\"session_id\":{},\"actor\":{{\"id\":{},\"kind\":\"agent\"}},\"surface\":\"terminal\",\"action\":\"process_exec\",\"target\":{{\"label\":{},\"uri\":null}},\"payload\":{{\"kind\":\"agent_process_exec_attempt\",\"terminal\":{{\"surface\":\"terminal\",\"tty\":{},\"interception_path\":\"linux_ptrace\"}},\"working_directory\":{},\"parent_process\":\"linux-process-guard\",\"argv_summary\":{},\"command\":[",
        json_string(&event_id),
        json_string(&session_id),
        json_string(&actor_id),
        json_string(path),
        if tty == "true" { "true" } else { "false" },
        json_string(&cwd),
        json_string(text)
    );
    for (index, argument) in argv.iter().enumerate() {
        if index > 0 {
            let _ = write!(file, ",");
        }
        let _ = write!(file, "{}", json_string(argument));
    }
    let _ = write!(
        file,
        "]}},\"risk\":{{\"level\":\"{}\",\"reasons\":[{}]}},\"timestamp\":\"unix:{}\"}},\"policy_decision\":{{\"type\":\"{}\"",
        risk,
        json_string(reason),
        timestamp,
        policy_decision
    );
    if let Some(rule) = rule {
        let _ = write!(
            file,
            ",\"reason\":{},\"rule_id\":{}",
            json_string(&rule.reason),
            json_string(&rule.rule_id)
        );
        if rule.decision == ProcessRuleDecision::RequireApproval {
            let _ = write!(file, ",\"approval_id\":null");
        }
    }
    let _ = write!(
        file,
        "}},\"final_decision\":{{\"type\":\"{}\"",
        final_decision
    );
    if let Some(rule) = rule {
        let final_reason = match rule.decision {
            ProcessRuleDecision::Allow => rule.reason.as_str(),
            ProcessRuleDecision::Deny => rule.reason.as_str(),
            ProcessRuleDecision::RequireApproval => {
                "process execution requires verification but no terminal approval provider is available"
            }
        };
        let _ = write!(
            file,
            ",\"reason\":{},\"rule_id\":{}",
            json_string(final_reason),
            json_string(&rule.rule_id)
        );
    }
    let _ = writeln!(file, "}}}}");
}

fn should_write_process_audit(path: &str, argv: &[String], rule: Option<&ProcessRule>) -> bool {
    if rule.is_some_and(|rule| rule.decision != ProcessRuleDecision::Allow) {
        return true;
    }

    match audit_command_log_level() {
        AuditCommandLogLevel::All => true,
        AuditCommandLogLevel::NonAllow => false,
        AuditCommandLogLevel::Signal => !matches_debug_command(path, argv),
    }
}

fn audit_command_log_level() -> AuditCommandLogLevel {
    match env::var("EREBOR_GUARD_AUDIT_TERMINAL_LEVEL")
        .unwrap_or_else(|_| String::from("signal"))
        .as_str()
    {
        "all" => AuditCommandLogLevel::All,
        "non_allow" => AuditCommandLogLevel::NonAllow,
        _ => AuditCommandLogLevel::Signal,
    }
}

fn matches_debug_command(path: &str, argv: &[String]) -> bool {
    let debug_commands = audit_debug_commands();
    if debug_commands.is_empty() {
        return false;
    }

    let mut tokens = Vec::new();
    tokens.push(path);
    if let Some(first) = argv.first() {
        tokens.push(first);
    }

    tokens.iter().any(|token| {
        debug_commands
            .iter()
            .any(|debug_command| command_token_matches(token, debug_command))
    })
}

fn audit_debug_commands() -> Vec<String> {
    match env::var("EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS") {
        Ok(source) => source
            .lines()
            .map(str::trim)
            .filter(|command| !command.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Err(_) => vec![String::from("sleep")],
    }
}

fn command_token_matches(token: &str, debug_command: &str) -> bool {
    token == debug_command
        || basename(token) == debug_command
        || basename(debug_command) == token
        || basename(token) == basename(debug_command)
}

fn basename(value: &str) -> &str {
    value
        .rsplit_once('/')
        .map_or(value, |(_prefix, basename)| basename)
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
    use std::env;

    use super::super::rules::{ProcessRule, ProcessRuleDecision};
    use super::{json_string, should_write_process_audit};

    #[test]
    fn default_audit_filter_suppresses_allowed_sleep() {
        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_LEVEL");
        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS");

        assert!(!should_write_process_audit(
            "/usr/bin/sleep",
            &[String::from("sleep"), String::from("0.25")],
            None,
        ));
    }

    #[test]
    fn all_audit_level_logs_allowed_sleep() {
        env::set_var("EREBOR_GUARD_AUDIT_TERMINAL_LEVEL", "all");
        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS");

        assert!(should_write_process_audit(
            "/usr/bin/sleep",
            &[String::from("sleep"), String::from("0.25")],
            None,
        ));

        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_LEVEL");
    }

    #[test]
    fn audit_filter_always_logs_denied_sleep() {
        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_LEVEL");
        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS");
        let rule = ProcessRule {
            token: String::from("sleep"),
            reason: String::from("sleep denied"),
            rule_id: String::from("deny-sleep"),
            decision: ProcessRuleDecision::Deny,
        };

        assert!(should_write_process_audit(
            "/usr/bin/sleep",
            &[String::from("sleep"), String::from("0.25")],
            Some(&rule),
        ));
    }

    #[test]
    fn json_string_escapes_audit_values() {
        assert_eq!(
            json_string("quote\" slash\\ newline\n tab\t"),
            "\"quote\\\" slash\\\\ newline\\n tab\\t\""
        );
    }
}
