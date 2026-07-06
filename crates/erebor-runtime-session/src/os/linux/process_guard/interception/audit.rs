use std::{
    env,
    fs::OpenOptions,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use super::InterceptionHandler;

pub(super) struct InterceptionAudit<'a> {
    handler: &'a InterceptionHandler,
    invoked: &'a str,
    args: &'a [String],
    final_decision: &'a str,
    policy_decision: &'a str,
    reason: &'a str,
    governed_endpoint: Option<&'a str>,
}

impl<'a> InterceptionAudit<'a> {
    pub(super) fn allow(
        handler: &'a InterceptionHandler,
        invoked: &'a str,
        args: &'a [String],
        reason: &'a str,
    ) -> Self {
        Self {
            handler,
            invoked,
            args,
            final_decision: "allow",
            policy_decision: "allow",
            reason,
            governed_endpoint: None,
        }
    }

    pub(super) fn mediate(
        handler: &'a InterceptionHandler,
        invoked: &'a str,
        args: &'a [String],
        reason: &'a str,
        governed_endpoint: &'a str,
    ) -> Self {
        Self {
            handler,
            invoked,
            args,
            final_decision: "allow",
            policy_decision: "mediate",
            reason,
            governed_endpoint: Some(governed_endpoint),
        }
    }

    pub(super) fn deny(
        handler: &'a InterceptionHandler,
        invoked: &'a str,
        args: &'a [String],
        reason: &'a str,
    ) -> Self {
        Self {
            handler,
            invoked,
            args,
            final_decision: "deny",
            policy_decision: "deny",
            reason,
            governed_endpoint: None,
        }
    }

    pub(super) fn write(&self) {
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
        let command = self.args.join(" ");
        let event_id = format!(
            "{}-process-interception-{}-{}",
            session_id, self.handler.id, timestamp
        );
        let governed_endpoint = self.governed_endpoint.unwrap_or("");

        let _ = write!(
            file,
            "{{\"event\":{{\"id\":{},\"session_id\":{},\"actor\":{{\"id\":{},\"kind\":\"agent\"}},\"surface\":\"terminal\",\"action\":\"process_exec\",\"target\":{{\"label\":{},\"uri\":null}},\"payload\":{{\"kind\":\"process_interception\",\"handler_id\":{},\"governed_endpoint\":{},\"argv_summary\":{},\"command\":[",
            json_string(&event_id),
            json_string(&session_id),
            json_string(&actor_id),
            json_string(self.invoked),
            json_string(&self.handler.id),
            json_string(governed_endpoint),
            json_string(&command)
        );
        for (index, argument) in self.args.iter().enumerate() {
            if index > 0 {
                let _ = write!(file, ",");
            }
            let _ = write!(file, "{}", json_string(argument));
        }
        let _ = writeln!(
            file,
            "]}},\"risk\":{{\"level\":\"high\",\"reasons\":[{}]}},\"timestamp\":\"unix:{}\"}},\"policy_decision\":{{\"type\":\"{}\",\"reason\":{},\"rule_id\":{}}},\"final_decision\":{{\"type\":\"{}\",\"reason\":{},\"rule_id\":{}}}}}",
            json_string(self.reason),
            timestamp,
            self.policy_decision,
            json_string(self.reason),
            json_string(&format!("erebor-process-interception-{}", self.handler.id)),
            self.final_decision,
            json_string(self.reason),
            json_string(&format!("erebor-process-interception-{}", self.handler.id))
        );
    }
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
