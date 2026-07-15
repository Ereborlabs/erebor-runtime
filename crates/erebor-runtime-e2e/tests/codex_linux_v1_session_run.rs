#[allow(dead_code)]
#[path = "support/cli.rs"]
mod cli;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use std::{fs, path::Path};

    use sha2::{Digest, Sha256};

    use crate::cli::{E2eWorkspace, EreborCliFixture};

    #[test]
    fn managed_hook_uses_the_guarded_session_run_channel() -> Result<(), Box<dyn std::error::Error>>
    {
        if !managed_projection_anchors_exist() {
            eprintln!(
                "skipping managed Codex session fixture: root-managed projection anchors are not installed"
            );
            return Ok(());
        }
        let workspace = E2eWorkspace::create("codex-managed-hook-session-run")?;
        let root = workspace.path();
        let trust = root.join("trust");
        let hooks = trust.join("hooks");
        fs::create_dir_all(&hooks)?;
        let requirements = trust.join("requirements.toml");
        let startup = hooks.join("shell-startup");
        let hook = hooks.join("erebor-codex-hook");
        fs::write(&requirements, "allow_managed_hooks_only = true\n")?;
        fs::write(&startup, "# managed startup\n")?;
        fs::copy(
            Path::new(env!("CARGO_BIN_EXE_codex-linux-v1-test-hook")),
            &hook,
        )?;
        let marker = root.join("hook-result.json");
        let policy = root.join("policy.json");
        fs::write(&policy, r#"{ "rules": [] }"#)?;
        let driver = Path::new(env!("CARGO_BIN_EXE_codex-linux-v1-session-driver"));
        let requirements_hash = hash(&requirements)?;
        let hook_hash = hash(&hook)?;
        let startup_hash = hash(&startup)?;
        let config = root.join("runtime.json");
        fs::write(
            &config,
            format!(
                r#"{{
          "policies":["{}"],
          "session":{{"enabled":true,"runner":{{"kind":"linux_host"}},"interception":{{"enabled":true}}}},
          "surfaces":{{
            "terminal":{{"enabled":true,"process_mediation":{{"enabled":true,"handlers":[{{
              "id":"unused-browser-handler","kind":"managed_browser_cdp",
              "match":{{"executables":["never-invoked-by-this-fixture"]}}
            }}]}}}},
            "browser_cdp":{{"enabled":true}},
            "filesystem":{{"enabled":true}}
          }},
          "codex":{{"enabled":true,"profiles":[{{
            "id":"fixture","runner":"linux_host","executable":"{}","deployment":"local_cooperative","profile_sha256":"{}",
            "trust_root":"{}","requirements_source":"{}","requirements_sha256":"{}",
            "managed_hook_source":"{}","managed_hook_sha256":"{}","managed_hook_path":"/usr/lib/erebor/codex-hooks/erebor-codex-hook",
            "shell_startup_source":"{}","shell_startup_sha256":"{}","shell_startup_path":"/usr/lib/erebor/codex-hooks/shell-startup",
            "hook_exec_history":["{}","/usr/lib/erebor/codex-hooks/erebor-codex-hook"],
            "event_schemas":[{{"event":"session_start","sha256":"{}"}}]
          }}]}}
        }}"#,
                policy.display(),
                driver.display(),
                "a".repeat(64),
                trust.display(),
                requirements.display(),
                requirements_hash,
                hook.display(),
                hook_hash,
                startup.display(),
                startup_hash,
                driver.display(),
                "b".repeat(64)
            ),
        )?;
        let result = EreborCliFixture::build()?.run_in(
            root,
            [
                "session",
                "run",
                "--runner",
                "linux-host",
                "--config",
                config.to_str().ok_or("config path")?,
                driver.to_str().ok_or("driver path")?,
                marker.to_str().ok_or("marker path")?,
            ],
        );
        if let Err(error) = result {
            let diagnostic = fs::read_to_string(marker.with_extension("diagnostic"))
                .unwrap_or_else(|_error| String::from("no driver diagnostic was written"));
            return Err(
                format!("managed hook session run failed: {error}; driver: {diagnostic}").into(),
            );
        }
        assert_eq!(fs::read(&marker)?, br#"{"continue":true}"#);
        Ok(())
    }
    fn hash(path: &Path) -> Result<String, std::io::Error> {
        Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
    }

    fn managed_projection_anchors_exist() -> bool {
        Path::new("/etc/codex/requirements.toml").is_file()
            && Path::new("/usr/lib/erebor/codex-hooks").is_dir()
            && Path::new("/run/erebor").is_dir()
    }
}
