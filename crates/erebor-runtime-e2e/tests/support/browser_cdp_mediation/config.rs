use std::{
    fs,
    path::{Path, PathBuf},
};

use erebor_runtime_e2e::{error::IoSnafu, E2eError};
use snafu::ResultExt;

use super::ports::PortPair;

pub struct MediationLifecycleConfig<'a> {
    workspace: &'a Path,
    policy_path: &'a Path,
    ports: PortPair,
}

impl<'a> MediationLifecycleConfig<'a> {
    pub const fn new(workspace: &'a Path, policy_path: &'a Path, ports: PortPair) -> Self {
        Self {
            workspace,
            policy_path,
            ports,
        }
    }

    pub fn write(&self, output_dir: &Path) -> Result<PathBuf, E2eError> {
        let config_path = output_dir.join("browser-cdp-mediation-config.json");
        fs::write(&config_path, self.source()).context(IoSnafu)?;
        Ok(config_path)
    }

    fn source(&self) -> String {
        format!(
            r#"{{
              "policies": ["{}"],
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw", "kind": "agent" }},
                "workspace": "{}",
                "diagnostics": [
                  {{
                    "name": "managed-browser-cdp",
                    "command": [
                      "sh",
                      "-lc",
                      "timeout 3 google-chrome --remote-debugging-port={} about:blank"
                    ]
                  }}
                ],
                "runner": {{ "kind": "linux_host" }},
                "interception": {{
                  "enabled": true,
                  "backend": "linux_ptrace",
                  "operations": ["process_exec"]
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
                          "bind": "127.0.0.1",
                          "allowed_ports": [{}]
                        }},
                        "replacement": {{
                          "surface": "browser_cdp",
                          "private_endpoint": {{
                            "port_strategy": "requested_plus_offset",
                            "port_offset": {}
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
                  "listen": "127.0.0.1:0",
                  "browser": {{ "headless": true }}
                }}
              }}
            }}"#,
            self.policy_path.display(),
            self.workspace.display(),
            self.ports.governed(),
            self.ports.governed(),
            self.ports.private() - self.ports.governed(),
        )
    }
}

pub fn write_empty_policy(workspace: &Path) -> Result<PathBuf, E2eError> {
    let policy_path = workspace.join("empty-policy.json");
    fs::write(&policy_path, r#"{ "rules": [] }"#).context(IoSnafu)?;
    Ok(policy_path)
}
