use std::{
    fs,
    path::{Path, PathBuf},
};

use erebor_runtime_e2e::{
    error::{IoSnafu, JsonSnafu},
    E2eError,
};
use serde_json::{json, Value};
use snafu::ResultExt;

pub struct CliCommandFixture {
    workspace: PathBuf,
    registry_path: PathBuf,
    session_dir: PathBuf,
    session_id: String,
    policy_path: PathBuf,
    event_path: PathBuf,
    config_path: PathBuf,
    audit_path: PathBuf,
    prompt_path: PathBuf,
}

impl CliCommandFixture {
    const SESSION_ID: &'static str = "session-cli-command-owners";
    const RULE_ID: &'static str = "deny-rm";
    const DENY_REASON: &'static str = "destructive shell command denied";

    pub fn write(workspace: &Path) -> Result<Self, E2eError> {
        let fixture = Self::new(workspace);
        fs::create_dir_all(&fixture.session_dir).context(IoSnafu)?;
        fixture.write_policy()?;
        fixture.write_event()?;
        fixture.write_config()?;
        fixture.write_audit()?;
        fixture.write_prompt()?;
        fixture.write_registry_record()?;
        Ok(fixture)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn policy_path(&self) -> &Path {
        &self.policy_path
    }

    pub fn event_path(&self) -> &Path {
        &self.event_path
    }

    pub fn prompt_path(&self) -> &Path {
        &self.prompt_path
    }

    fn new(workspace: &Path) -> Self {
        let session_id = Self::SESSION_ID.to_owned();
        let registry_path = workspace.join(".erebor/sessions");
        let session_dir = registry_path.join(&session_id);

        Self {
            workspace: workspace.to_path_buf(),
            registry_path,
            session_dir: session_dir.clone(),
            session_id,
            policy_path: session_dir.join("policy.json"),
            event_path: session_dir.join("event.json"),
            config_path: session_dir.join("config.json"),
            audit_path: session_dir.join("audit.jsonl"),
            prompt_path: session_dir.join("prompt.txt"),
        }
    }

    fn write_policy(&self) -> Result<(), E2eError> {
        Self::write_json(&self.policy_path, &self.policy_document())
    }

    fn write_event(&self) -> Result<(), E2eError> {
        Self::write_json(&self.event_path, &self.event_document())
    }

    fn write_config(&self) -> Result<(), E2eError> {
        Self::write_json(&self.config_path, &self.config_document())
    }

    fn write_audit(&self) -> Result<(), E2eError> {
        let line = serde_json::to_string(&self.audit_record()).context(JsonSnafu)?;
        fs::write(&self.audit_path, format!("{line}\n")).context(IoSnafu)
    }

    fn write_prompt(&self) -> Result<(), E2eError> {
        fs::write(
            &self.prompt_path,
            "delete temp files under Erebor governance\n",
        )
        .context(IoSnafu)
    }

    fn write_registry_record(&self) -> Result<(), E2eError> {
        Self::write_json(
            &self.session_dir.join("session.json"),
            &self.registry_record(),
        )
    }

    fn write_json(path: &Path, value: &Value) -> Result<(), E2eError> {
        fs::write(
            path,
            serde_json::to_string_pretty(value).context(JsonSnafu)?,
        )
        .context(IoSnafu)
    }

    fn path_string(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    fn policy_document(&self) -> Value {
        json!({
            "rules": [
                {
                    "id": Self::RULE_ID,
                    "match": {
                        "surface": "terminal",
                        "action": "process_exec",
                        "command_contains": "rm -rf"
                    },
                    "decision": "deny",
                    "reason": Self::DENY_REASON
                }
            ]
        })
    }

    fn event_document(&self) -> Value {
        json!({
            "id": "evt-cli-command-owners-1",
            "session_id": self.session_id.as_str(),
            "actor": {
                "id": "daemon-cli-e2e",
                "kind": "agent"
            },
            "surface": "terminal",
            "action": "process_exec",
            "target": {
                "label": "shell command",
                "uri": "process://sh"
            },
            "payload": {
                "command": ["sh", "-lc", "rm -rf /tmp/erebor-cli-fixture"],
                "argv_summary": "sh -lc rm -rf /tmp/erebor-cli-fixture",
                "cwd": Self::path_string(&self.workspace)
            },
            "risk": {
                "level": "high",
                "reasons": ["destructive filesystem mutation"]
            },
            "timestamp": "2026-07-06T00:00:00Z"
        })
    }

    fn config_document(&self) -> Value {
        json!({
            "policies": [Self::path_string(&self.policy_path)],
            "session": {
                "enabled": true,
                "actor": {
                    "id": "daemon-cli-e2e",
                    "kind": "agent"
                },
                "runner": {
                    "kind": "linux_host"
                },
                "interception": {
                    "enabled": true
                }
            },
            "surfaces": {
                "terminal": {
                    "enabled": true
                }
            }
        })
    }

    fn audit_record(&self) -> Value {
        json!({
            "event": self.event_document(),
            "policy_decision": self.deny_decision(),
            "final_decision": self.deny_decision()
        })
    }

    fn deny_decision(&self) -> Value {
        json!({
            "type": "deny",
            "reason": Self::DENY_REASON,
            "rule_id": Self::RULE_ID
        })
    }

    fn registry_record(&self) -> Value {
        json!({
            "schema_version": 1,
            "session_id": self.session_id.as_str(),
            "status": "failed",
            "actor_id": "daemon-cli-e2e",
            "actor_kind": "agent",
            "runner": "linux_host",
            "surfaces": ["terminal"],
            "workspace": Self::path_string(&self.workspace),
            "command": ["sh", "-lc", "rm -rf /tmp/erebor-cli-fixture"],
            "diagnostic": null,
            "registry_path": Self::path_string(&self.registry_path),
            "session_dir": Self::path_string(&self.session_dir),
            "audit_path": Self::path_string(&self.audit_path),
            "config_artifact_path": Self::path_string(&self.config_path),
            "source_config_path": Self::path_string(&self.config_path),
            "policy_artifact_paths": [Self::path_string(&self.policy_path)],
            "source_policy_paths": [Self::path_string(&self.policy_path)],
            "started_at_unix_ms": 1783296000000_u64,
            "ended_at_unix_ms": 1783296001000_u64,
            "exit_code": 126,
            "failure": Self::DENY_REASON
        })
    }
}
