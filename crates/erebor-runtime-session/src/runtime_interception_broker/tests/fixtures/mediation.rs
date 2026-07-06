use std::fs;

use erebor_runtime_core::{RuntimeConfig, TerminalSurfaceConfig};

pub(crate) struct TerminalMediationFixture;

impl TerminalMediationFixture {
    pub(crate) fn terminal_config() -> Result<TerminalSurfaceConfig, Box<dyn std::error::Error>> {
        let config = Self::runtime_config_with_allowed_ports(
            "127.0.0.1:9222",
            r#",
                          "allowed_ports": [9222]"#,
        )?;
        Ok(config
            .surface_start_plan()?
            .terminal()
            .ok_or_else(|| std::io::Error::other("missing terminal config"))?
            .clone())
    }

    pub(crate) fn runtime_config(
        browser_cdp_listen: &str,
    ) -> Result<RuntimeConfig, Box<dyn std::error::Error>> {
        Self::runtime_config_with_allowed_ports(browser_cdp_listen, "")
    }

    fn runtime_config_with_allowed_ports(
        browser_cdp_listen: &str,
        allowed_ports_fragment: &str,
    ) -> Result<RuntimeConfig, Box<dyn std::error::Error>> {
        let policy_path = std::env::temp_dir().join(format!(
            "erebor-broker-mediation-policy-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::write(&policy_path, r#"{"rules":[]}"#)?;

        Ok(RuntimeConfig::from_json_str(&format!(
            r#"
                {{
                  "policies": ["{}"],
                  "session": {{
                    "interception": {{
                      "enabled": true
                    }}
                  }},
                  "surfaces": {{
                    "terminal": {{
                      "enabled": true,
                      "process_interception": {{
                        "enabled": true,
                        "handlers": [
                          {{
                            "id": "managed-browser-cdp",
                            "decision": "mediate",
                            "kind": "managed_browser_cdp",
                            "match": {{
                              "executables": ["google-chrome"],
                              "required_args": ["--remote-debugging-port"],
                              "require_remote_debugging_port": true
                            }},
                            "requested_endpoint": {{
                              "source": "remote_debugging_port",
                              "bind": "127.0.0.1"{allowed_ports_fragment}
                            }},
                            "replacement": {{
                              "surface": "browser_cdp",
                              "private_endpoint": {{
                                "port_strategy": "requested_plus_offset",
                                "port_offset": 1
                              }}
                            }},
                            "compatibility": {{
                              "print_devtools_listening_line": true,
                              "keepalive": true
                            }}
                          }}
                        ]
                      }}
                    }},
                    "browser_cdp": {{
                      "enabled": true,
                      "listen": "{browser_cdp_listen}",
                      "browser_url": "ws://127.0.0.1:9/devtools/browser/fake"
                    }}
                  }}
                }}
                "#,
            policy_path.display(),
        ))?)
    }
}
