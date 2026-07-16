use std::env;

const MAX_RULES: usize = 64;
pub(super) const MAX_TEXT: usize = 4096;

#[derive(Clone, Debug)]
pub(super) struct ProcessRule {
    pub(super) token: String,
    pub(super) reason: String,
    pub(super) decision: ProcessRuleDecision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProcessRuleDecision {
    Allow,
    Deny,
    RequireApproval,
}

impl ProcessRuleDecision {
    fn from_guard_env(value: Option<&str>) -> Self {
        match value.unwrap_or_default() {
            "allow" => Self::Allow,
            "require_approval" | "require_verification" => Self::RequireApproval,
            _ => Self::Deny,
        }
    }
}

pub(super) fn parse_rules() -> Vec<ProcessRule> {
    let source = env::var("EREBOR_GUARD_RULES")
        .or_else(|_| env::var("EREBOR_GUARD_DENY_RULES"))
        .unwrap_or_default();
    parse_rules_from_source(&source)
}

fn parse_rules_from_source(source: &str) -> Vec<ProcessRule> {
    source
        .lines()
        .take(MAX_RULES)
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let token = fields.next().unwrap_or_default();
            if token.is_empty() {
                return None;
            }
            let reason = fields
                .next()
                .filter(|reason| !reason.is_empty())
                .unwrap_or("process execution denied by Erebor policy")
                .to_owned();
            // The third field remains reserved for the policy rule id so
            // existing guard-rule environment values retain their shape. The
            // guard sends decisions to the broker; it no longer owns an
            // independently persisted audit record.
            let _reserved_rule_id = fields.next();
            Some(ProcessRule {
                token: token.to_owned(),
                reason,
                decision: ProcessRuleDecision::from_guard_env(fields.next()),
            })
        })
        .collect()
}

pub(super) fn command_text(path: &str, argv: &[String]) -> String {
    let mut text = String::new();
    text.push_str(path);
    for argument in argv {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(argument);
        if text.len() >= MAX_TEXT {
            text.truncate(MAX_TEXT);
            break;
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::{command_text, parse_rules_from_source, ProcessRuleDecision, MAX_RULES, MAX_TEXT};

    #[test]
    fn parses_deny_rules_from_guard_environment_format() {
        let rules = parse_rules_from_source(
            "/tmp/erebor/shims/google-chrome\tmanaged shim\tallow-shim\tallow\nremote-debugging-port\traw CDP is denied\tdeny-raw-cdp\nchromium\t\t\n\n",
        );

        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].token, "/tmp/erebor/shims/google-chrome");
        assert_eq!(rules[0].reason, "managed shim");
        assert_eq!(rules[0].decision, ProcessRuleDecision::Allow);
        assert_eq!(rules[1].token, "remote-debugging-port");
        assert_eq!(rules[1].reason, "raw CDP is denied");
        assert_eq!(rules[1].decision, ProcessRuleDecision::Deny);
        assert_eq!(rules[2].token, "chromium");
        assert_eq!(rules[2].reason, "process execution denied by Erebor policy");
        assert_eq!(rules[2].decision, ProcessRuleDecision::Deny);
    }

    #[test]
    fn generated_shim_allow_rule_wins_before_raw_cdp_deny() {
        let rules = parse_rules_from_source(
            "/tmp/erebor/shims/google-chrome\tmanaged shim\tallow-shim\tallow\nremote-debugging-port\traw CDP is denied\tdeny-raw-cdp\tdeny\n",
        );
        let command_text =
            "/bin/sh sh -c exec \"$0\" \"$@\" /tmp/erebor/shims/google-chrome --remote-debugging-port=1000";
        let matched = rules
            .iter()
            .find(|rule| command_text.contains(&rule.token))
            .expect("expected shim allow rule to match first");

        assert_eq!(matched.decision, ProcessRuleDecision::Allow);
    }

    #[test]
    fn parses_verification_rules_from_guard_environment_format() {
        let rules = parse_rules_from_source(
            "git push\tgit push needs verification\tverify-git-push\trequire_approval\n",
        );

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].token, "git push");
        assert_eq!(rules[0].reason, "git push needs verification");
        assert_eq!(rules[0].decision, ProcessRuleDecision::RequireApproval);
    }

    #[test]
    fn ignores_empty_rule_tokens_and_caps_rule_count() {
        let source = (0..(MAX_RULES + 5))
            .map(|index| format!("token-{index}\treason-{index}\trule-{index}"))
            .chain([String::from("\tmissing token\tmissing-token")])
            .collect::<Vec<_>>()
            .join("\n");

        let rules = parse_rules_from_source(&source);

        assert_eq!(rules.len(), MAX_RULES);
        assert_eq!(rules[0].token, "token-0");
    }

    #[test]
    fn command_text_preserves_path_and_arguments_with_spaces() {
        let text = command_text(
            "/bin/sh",
            &[
                String::from("sh"),
                String::from("-lc"),
                String::from("echo hello world"),
            ],
        );

        assert_eq!(text, "/bin/sh sh -lc echo hello world");
    }

    #[test]
    fn command_text_is_bounded() {
        let text = command_text("/bin/echo", &[String::from("x".repeat(MAX_TEXT * 2))]);

        assert_eq!(text.len(), MAX_TEXT);
        assert!(text.starts_with("/bin/echo "));
    }
}
