use std::{
    fs,
    path::{Path, PathBuf},
};

use erebor_runtime_e2e::{
    error::{IoSnafu, JsonSnafu},
    E2eError,
};
use serde_json::Value;
use snafu::ResultExt;

use crate::cli::external_error;

pub struct SessionReviewConfig;

impl SessionReviewConfig {
    pub fn write_diagnostic(test_dir: &Path, policy_path: &Path) -> Result<PathBuf, E2eError> {
        Self::write(
            test_dir,
            policy_path,
            r#"
                    "diagnostics": [
                      {
                        "name": "raw-cdp",
                        "command": ["sh", "--remote-debugging-port=9222"]
                      }
                    ],
            "#,
        )
    }

    pub fn write_registry(test_dir: &Path, policy_path: &Path) -> Result<PathBuf, E2eError> {
        Self::write(test_dir, policy_path, "")
    }

    fn write(
        test_dir: &Path,
        policy_path: &Path,
        diagnostic_fragment: &str,
    ) -> Result<PathBuf, E2eError> {
        let config_path = test_dir.join("session-config.json");
        fs::write(
            &config_path,
            format!(
                r#"{{
                  "policies": ["{}"],
                  "session": {{
                    "enabled": true,
                    "actor": {{ "id": "test-agent", "kind": "agent" }},
                    {}
                    "runner": {{ "kind": "linux_host" }},
                    "interception": {{ "enabled": true }}
                  }},
                  "surfaces": {{
                    "terminal": {{
                      "enabled": true
                    }}
                  }}
                }}"#,
                policy_path.display(),
                diagnostic_fragment
            ),
        )
        .context(IoSnafu)?;
        Ok(config_path)
    }
}

pub struct SessionReviewPolicy;

impl SessionReviewPolicy {
    pub fn write(test_dir: &Path) -> Result<PathBuf, E2eError> {
        let policy_path = test_dir.join("policy.json");
        fs::write(
            &policy_path,
            r#"
            {
              "rules": [
                {
                  "id": "deny-raw-cdp",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "command_contains": "remote-debugging-port"
                  },
                  "decision": "deny",
                  "reason": "raw CDP process launch is denied"
                }
              ]
            }
            "#,
        )
        .context(IoSnafu)?;
        Ok(policy_path)
    }
}

pub struct SessionRegistry<'a> {
    workspace: &'a Path,
}

impl<'a> SessionRegistry<'a> {
    pub const fn new(workspace: &'a Path) -> Self {
        Self { workspace }
    }

    pub fn single_record(&self) -> Result<Value, E2eError> {
        let registry = self.workspace.join(".erebor/sessions");
        let mut records = Vec::new();
        for entry in fs::read_dir(&registry).context(IoSnafu)? {
            let path = entry.context(IoSnafu)?.path().join("session.json");
            if path.exists() {
                let source = fs::read_to_string(&path).context(IoSnafu)?;
                records.push(serde_json::from_str::<Value>(&source).context(JsonSnafu)?);
            }
        }
        if records.len() == 1 {
            Ok(records.remove(0))
        } else {
            Err(external_error(
                "read registry record",
                std::io::Error::other(format!(
                    "expected exactly one registry record under {}, got {}",
                    registry.display(),
                    records.len()
                )),
            ))
        }
    }
}

pub fn json_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, E2eError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            external_error(
                "read JSON string",
                std::io::Error::other(format!("missing string field at {pointer}")),
            )
        })
}
