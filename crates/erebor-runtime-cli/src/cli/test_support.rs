use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) struct TempJsonFile {
    path: PathBuf,
}

impl TempJsonFile {
    pub(super) fn write(source: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "erebor-runtime-cli-{nanos}-{}.json",
            std::process::id()
        ));
        fs::write(&path, source)?;
        Ok(Self { path })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempJsonFile {
    fn drop(&mut self) {
        let _cleanup = fs::remove_file(&self.path);
    }
}

pub(super) struct RegistrySessionFixture {
    session_dir: PathBuf,
}

impl RegistrySessionFixture {
    pub(super) fn write_invalid_audit(
        session_id: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let registry = PathBuf::from(".erebor/sessions");
        let session_dir = registry.join(session_id);
        fs::create_dir_all(&session_dir)?;
        let audit_path = session_dir.join("audit.jsonl");
        let policy_path = session_dir.join("policy.json");
        let config_path = session_dir.join("config.json");
        fs::write(&audit_path, "{not-json}\n")?;
        fs::write(&policy_path, r#"{"rules":[]}"#)?;
        fs::write(
            &config_path,
            r#"{"policies":["policy.json"],"session":{"enabled":true}}"#,
        )?;
        Self::write_record(
            &registry,
            session_id,
            &audit_path,
            &policy_path,
            &config_path,
        )?;
        Ok(Self { session_dir })
    }

    fn write_record(
        registry: &Path,
        session_id: &str,
        audit_path: &Path,
        policy_path: &Path,
        config_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session_dir = registry.join(session_id);
        fs::write(
            session_dir.join("session.json"),
            format!(
                r#"{{
                  "schema_version": 1,
                  "session_id": "{session_id}",
                  "status": "succeeded",
                  "actor_id": "test-agent",
                  "actor_kind": "agent",
                  "runner": "linux-host",
                  "surfaces": ["terminal"],
                  "workspace": null,
                  "command": ["true"],
                  "diagnostic": null,
                  "registry_path": "{}",
                  "session_dir": "{}",
                  "audit_path": "{}",
                  "config_artifact_path": "{}",
                  "source_config_path": null,
                  "policy_artifact_paths": ["{}"],
                  "source_policy_paths": [],
                  "started_at_unix_ms": 1,
                  "ended_at_unix_ms": 2,
                  "exit_code": 0,
                  "failure": null
                }}"#,
                registry.display(),
                session_dir.display(),
                audit_path.display(),
                config_path.display(),
                policy_path.display(),
            ),
        )?;
        Ok(())
    }
}

impl Drop for RegistrySessionFixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.session_dir);
    }
}
