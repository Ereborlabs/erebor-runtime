use crate::{CodexHookEvent, RuntimeConfig, RuntimeConfigError};

fn profile_source(profile: &str) -> String {
    format!(
        r#"{{
          "policies": ["policies/default.json"],
          "session": {{ "enabled": true, "runner": {{ "kind": "linux_host" }} }},
          "surfaces": {{ "filesystem": {{ "enabled": true }} }},
          "codex": {{
            "enabled": true,
            "profiles": [{profile}]
          }}
        }}"#
    )
}

fn profile_with(fields: &str) -> String {
    format!(
        r#"{{
          "id": "vscode-app-server",
          "runner": "linux_host",
          "executable": "/opt/codex/codex",
          "executable_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "deployment": "fleet_managed",
          "trust_root": "/var/lib/erebor/codex",
          "requirements_source": "/var/lib/erebor/codex/requirements.toml",
          "requirements_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "managed_hook_source": "/var/lib/erebor/codex/hooks/erebor-codex-hook",
          "managed_hook_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "managed_hook_path": "/usr/lib/erebor/codex-hooks/erebor-codex-hook",
          "shell_startup_source": "/var/lib/erebor/codex/hooks/shell-startup",
          "shell_startup_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
          "shell_startup_path": "/usr/lib/erebor/codex-hooks/shell-startup",
          "hook_shell": "direct",
          "hook_exec_history": [
            "/opt/codex/codex",
            "/usr/lib/erebor/codex-hooks/erebor-codex-hook"
          ],
          "event_schemas": [{{
            "event": "session_start",
            "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
          }}]
          {fields}
        }}"#
    )
}

#[test]
fn parses_a_valid_linux_codex_profile() -> Result<(), Box<dyn std::error::Error>> {
    let config = RuntimeConfig::from_json_str(&profile_source(&profile_with("")))?;
    let profile = config
        .codex
        .matching_profile(std::path::Path::new("/opt/codex/codex"))
        .ok_or("missing matching Codex profile")?;

    assert_eq!(profile.id, "vscode-app-server");
    assert_eq!(profile.event_schemas[0].event, CodexHookEvent::SessionStart);
    assert!(!profile.app_server_transport.enabled);
    Ok(())
}

#[test]
fn parses_an_explicit_brokered_app_server_profile() -> Result<(), Box<dyn std::error::Error>> {
    let config = RuntimeConfig::from_json_str(&profile_source(&profile_with(
        ",\n          \"app_server_transport\": { \"enabled\": true }",
    )))?;
    let profile = config
        .codex
        .matching_profile(std::path::Path::new("/opt/codex/codex"))
        .ok_or("missing matching Codex profile")?;

    assert!(profile.app_server_transport.enabled);
    Ok(())
}

#[test]
fn parses_a_pinned_app_server_command_dispatch_envelope() -> Result<(), Box<dyn std::error::Error>>
{
    let config = RuntimeConfig::from_json_str(&profile_source(&profile_with(
        ",\n          \"app_server_transport\": { \"enabled\": true, \"command_dispatch\": { \"program\": \"codex-linux-sandbox\", \"shell\": \"/usr/bin/zsh\", \"sandbox_launcher\": { \"path\": \"/var/lib/erebor/codex/bin/codex-resources/bwrap\", \"sha256\": \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\" } } }",
    )))?;
    let profile = config
        .codex
        .matching_profile(std::path::Path::new("/opt/codex/codex"))
        .ok_or("missing matching Codex profile")?;
    let dispatch = profile
        .app_server_transport
        .command_dispatch
        .as_ref()
        .ok_or("missing command dispatch envelope")?;

    assert_eq!(dispatch.program, "codex-linux-sandbox");
    assert_eq!(dispatch.shell, std::path::Path::new("/usr/bin/zsh"));
    assert_eq!(
        dispatch
            .sandbox_launcher
            .as_ref()
            .ok_or("missing sandbox launcher")?
            .path,
        std::path::Path::new("/var/lib/erebor/codex/bin/codex-resources/bwrap")
    );
    Ok(())
}

#[test]
fn rejects_a_relative_app_server_command_dispatch_shell() {
    let source = profile_source(&profile_with(
        ",\n          \"app_server_transport\": { \"enabled\": true, \"command_dispatch\": { \"program\": \"codex-linux-sandbox\", \"shell\": \"zsh\" } }",
    ));

    assert!(matches!(
        RuntimeConfig::from_json_str(&source),
        Err(RuntimeConfigError::InvalidCodexGovernanceConfig { .. })
    ));
}

#[test]
fn rejects_unknown_app_server_transport_configuration() {
    let source = profile_source(&profile_with(
        ",\n          \"app_server_transport\": { \"enabled\": true, \"unknown\": true }",
    ));
    assert!(matches!(
        RuntimeConfig::from_json_str(&source),
        Err(RuntimeConfigError::InvalidJson { .. })
    ));
}

#[test]
fn rejects_a_mutable_profile_path() {
    let source = profile_source(&profile_with("")).replace(
        "/var/lib/erebor/codex/hooks/erebor-codex-hook",
        "/tmp/erebor-codex-hook",
    );
    let result = RuntimeConfig::from_json_str(&source);

    assert!(matches!(
        result,
        Err(RuntimeConfigError::InvalidCodexGovernanceConfig { .. })
    ));
}

#[test]
fn rejects_a_fleet_executable_in_a_mutable_path() {
    let source = profile_source(&profile_with("")).replace("/opt/codex/codex", "/tmp/codex");

    assert!(matches!(
        RuntimeConfig::from_json_str(&source),
        Err(RuntimeConfigError::InvalidCodexGovernanceConfig { .. })
    ));
}

#[test]
fn rejects_a_profile_outside_its_trust_root() {
    let source = profile_source(&profile_with("")).replace(
        "/var/lib/erebor/codex/requirements.toml",
        "/opt/erebor/requirements.toml",
    );
    let result = RuntimeConfig::from_json_str(&source);

    assert!(matches!(
        result,
        Err(RuntimeConfigError::InvalidCodexGovernanceConfig { .. })
    ));
}

#[test]
fn rejects_missing_executable_fingerprint_and_incompatible_runner() {
    let missing_fingerprint = profile_source(&profile_with("")).replace(
        "\"executable_sha256\": \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",",
        "",
    );
    assert!(matches!(
        RuntimeConfig::from_json_str(&missing_fingerprint),
        Err(RuntimeConfigError::InvalidJson { .. })
    ));

    let incompatible_runner = profile_source(&profile_with(""))
        .replace("\"runner\": \"linux_host\"", "\"runner\": \"docker\"");
    assert!(matches!(
        RuntimeConfig::from_json_str(&incompatible_runner),
        Err(RuntimeConfigError::InvalidCodexGovernanceConfig { .. })
    ));
}

#[test]
fn rejects_unknown_hook_events_and_conflicting_profiles() {
    let unknown_event = profile_source(&profile_with(""))
        .replace("\"event\": \"session_start\"", "\"event\": \"unknown\"");
    assert!(matches!(
        RuntimeConfig::from_json_str(&unknown_event),
        Err(RuntimeConfigError::InvalidJson { .. })
    ));

    let profile = profile_with("");
    let conflicting = profile_source(&format!("{profile},{profile}"));
    assert!(matches!(
        RuntimeConfig::from_json_str(&conflicting),
        Err(RuntimeConfigError::InvalidCodexGovernanceConfig { .. })
    ));
}

#[test]
fn rejects_an_unpinned_hook_exec_history() {
    let source = profile_source(&profile_with("")).replace(
        "\"/usr/lib/erebor/codex-hooks/erebor-codex-hook\"\n          ],",
        "\"/tmp/untrusted-hook\"\n          ],",
    );
    assert!(matches!(
        RuntimeConfig::from_json_str(&source),
        Err(RuntimeConfigError::InvalidCodexGovernanceConfig { .. })
    ));
}

#[test]
fn rejects_a_hook_shell_with_the_wrong_exec_history_shape() {
    let source = profile_source(&profile_with(""))
        .replace("\"hook_shell\": \"direct\"", "\"hook_shell\": \"zsh\"");

    assert!(matches!(
        RuntimeConfig::from_json_str(&source),
        Err(RuntimeConfigError::InvalidCodexGovernanceConfig { .. })
    ));
}

#[test]
fn rejects_a_hook_shell_with_an_incompatible_interpreter() {
    let source = profile_source(&profile_with(""))
        .replace("\"hook_shell\": \"direct\"", "\"hook_shell\": \"zsh\"")
        .replace(
            "\"/opt/codex/codex\",\n            \"/usr/lib/erebor/codex-hooks/erebor-codex-hook\"",
            "\"/opt/codex/codex\",\n            \"/usr/bin/bash\",\n            \"/usr/lib/erebor/codex-hooks/erebor-codex-hook\"",
        );

    assert!(matches!(
        RuntimeConfig::from_json_str(&source),
        Err(RuntimeConfigError::InvalidCodexGovernanceConfig { .. })
    ));
}
