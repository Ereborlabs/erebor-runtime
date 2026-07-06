#[path = "support/cli.rs"]
#[allow(dead_code)]
mod cli;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_host {
    use std::{
        fs,
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
        path::{Path, PathBuf},
        process::{Command, Stdio},
    };

    use erebor_runtime_e2e::{error::IoSnafu, E2eError};
    use snafu::ResultExt;

    use crate::cli::{external_error, E2eWorkspace, EreborCliFixture};

    #[test]
    fn managed_browser_cdp_lifecycle_mediates_process_launch() -> Result<(), E2eError> {
        if !HostRequirements::available() {
            eprintln!("skipping managed browser CDP mediation lifecycle e2e: Chrome or timeout is unavailable");
            return Ok(());
        }

        let erebor_runtime = EreborCliFixture::build()?;
        let workspace = E2eWorkspace::create("browser-cdp-mediation")?;
        let ports = PortPair::allocate()?;
        let policy_path = write_empty_policy(workspace.path())?;
        let config_path = MediationLifecycleConfig::new(workspace.path(), &policy_path, ports)
            .write(workspace.path())?;

        let output = erebor_runtime.run_expect_failure_in(
            workspace.path(),
            [
                "session",
                "diagnose",
                "--runner",
                "linux-host",
                "--config",
                config_path.to_string_lossy().as_ref(),
                "managed-browser-cdp",
            ],
        )?;

        assert!(output.contains(&format!(
            "DevTools listening on ws://127.0.0.1:{}/devtools/browser/erebor-managed-browser",
            ports.governed()
        )));

        let audit = SessionAudit::from_workspace(workspace.path())?.read()?;
        assert!(audit.contains("\"policy_decision\":{\"type\":\"mediate\""));
        assert!(audit.contains("\"handler_id\":\"managed-browser-cdp\""));
        assert!(audit.contains("\"rule_id\":\"erebor-process-interception-managed-browser-cdp\""));
        assert!(audit.contains(&format!("ws://127.0.0.1:{}/", ports.governed())));
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct PortPair {
        governed: u16,
        private: u16,
    }

    impl PortPair {
        fn allocate() -> Result<Self, E2eError> {
            for _attempt in 0..32 {
                let governed = free_port()?;
                let Some(private) = governed.checked_add(1) else {
                    continue;
                };
                if TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), private))
                    .is_ok()
                {
                    return Ok(Self { governed, private });
                }
            }

            Err(external_error(
                "allocate governed/private CDP ports",
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "could not reserve adjacent loopback ports",
                ),
            ))
        }

        const fn governed(self) -> u16 {
            self.governed
        }

        const fn private(self) -> u16 {
            self.private
        }
    }

    struct MediationLifecycleConfig<'a> {
        workspace: &'a Path,
        policy_path: &'a Path,
        ports: PortPair,
    }

    impl<'a> MediationLifecycleConfig<'a> {
        const fn new(workspace: &'a Path, policy_path: &'a Path, ports: PortPair) -> Self {
            Self {
                workspace,
                policy_path,
                ports,
            }
        }

        fn write(&self, output_dir: &Path) -> Result<PathBuf, E2eError> {
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

    struct SessionAudit {
        path: PathBuf,
    }

    impl SessionAudit {
        fn from_workspace(workspace: &Path) -> Result<Self, E2eError> {
            let registry = workspace.join(".erebor/sessions");
            let mut candidates = Vec::new();
            for entry in fs::read_dir(&registry).context(IoSnafu)? {
                let path = entry.context(IoSnafu)?.path().join("audit.jsonl");
                if path.exists() {
                    candidates.push(path);
                }
            }
            if candidates.len() == 1 {
                Ok(Self {
                    path: candidates.remove(0),
                })
            } else {
                Err(external_error(
                    "locate session audit",
                    std::io::Error::other(format!(
                        "expected one audit under {}, got {}",
                        registry.display(),
                        candidates.len()
                    )),
                ))
            }
        }

        fn read(&self) -> Result<String, E2eError> {
            fs::read_to_string(&self.path).context(IoSnafu)
        }
    }

    struct HostRequirements;

    impl HostRequirements {
        fn available() -> bool {
            command_available("timeout") && ChromeRequirement::available()
        }
    }

    struct ChromeRequirement;

    impl ChromeRequirement {
        fn available() -> bool {
            std::env::var_os("EREBOR_E2E_CHROME_BIN")
                .or_else(|| std::env::var_os("EREBOR_BROWSER_BIN"))
                .is_some_and(|path| Path::new(&path).is_file())
                || [
                    "google-chrome",
                    "google-chrome-stable",
                    "chromium",
                    "chromium-browser",
                ]
                .into_iter()
                .any(command_available)
        }
    }

    fn write_empty_policy(workspace: &Path) -> Result<PathBuf, E2eError> {
        let policy_path = workspace.join("empty-policy.json");
        fs::write(&policy_path, r#"{ "rules": [] }"#).context(IoSnafu)?;
        Ok(policy_path)
    }

    fn free_port() -> Result<u16, E2eError> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).context(IoSnafu)?;
        Ok(listener.local_addr().context(IoSnafu)?.port())
    }

    fn command_available(command: &str) -> bool {
        Command::new(command)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn browser_cdp_mediation_lifecycle_e2e_is_host_specific() {
    eprintln!("skipping browser CDP mediation lifecycle e2e on non-x86_64 Linux host");
}
