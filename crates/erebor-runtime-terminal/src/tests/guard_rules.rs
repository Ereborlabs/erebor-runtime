use crate::{TerminalProcessGuardDecision, TerminalProcessGuardRule, TerminalProcessGuardRules};

#[test]
fn guard_rules_serialize_for_docker_environment() {
    let rules = TerminalProcessGuardRules::new(vec![
        TerminalProcessGuardRule::new(
            "/tmp/erebor/shims/google-chrome",
            "managed shim launch",
            "allow-mediated-browser",
            TerminalProcessGuardDecision::Allow,
        ),
        TerminalProcessGuardRule::new(
            "remote-debugging-port",
            "raw CDP\nis denied",
            "deny\tcdp",
            TerminalProcessGuardDecision::Deny,
        ),
    ]);

    assert_eq!(
            rules.to_docker_env_value(),
            "/tmp/erebor/shims/google-chrome\tmanaged shim launch\tallow-mediated-browser\tallow\nremote-debugging-port\traw CDP is denied\tdeny cdp\tdeny"
        );
}

#[test]
fn guard_rules_can_prepend_generated_allow_rules() {
    let mut rules = TerminalProcessGuardRules::new(vec![TerminalProcessGuardRule::new(
        "remote-debugging-port",
        "raw CDP is denied",
        "deny-raw-cdp",
        TerminalProcessGuardDecision::Deny,
    )]);

    rules.prepend(vec![TerminalProcessGuardRule::new(
        "/tmp/erebor/shims/google-chrome",
        "managed browser launch shim",
        "allow-managed-browser-cdp-shim",
        TerminalProcessGuardDecision::Allow,
    )]);

    assert_eq!(rules.rules().len(), 2);
    assert_eq!(
        rules.rules()[0].decision(),
        TerminalProcessGuardDecision::Allow
    );
    assert_eq!(
        rules.rules()[1].decision(),
        TerminalProcessGuardDecision::Deny
    );
}
