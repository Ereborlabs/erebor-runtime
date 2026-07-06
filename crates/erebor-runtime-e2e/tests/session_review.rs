#[path = "support/cli.rs"]
mod cli;
#[path = "support/session_review.rs"]
mod review_support;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_host {
    use std::path::Path;

    use erebor_runtime_e2e::{error::JsonSnafu, E2eError};
    use serde_json::Value;
    use snafu::ResultExt;

    use crate::cli::{E2eWorkspace, EreborCliFixture};
    use crate::review_support::{
        json_string, SessionRegistry, SessionReviewConfig, SessionReviewPolicy,
    };

    #[test]
    fn session_review_commands_render_governed_process_audit() -> Result<(), E2eError> {
        let erebor_runtime = EreborCliFixture::build()?;
        let workspace = E2eWorkspace::create("session-review")?;
        let test_dir = workspace.path();
        let policy_path = SessionReviewPolicy::write(test_dir)?;
        let config_path = SessionReviewConfig::write_diagnostic(test_dir, &policy_path)?;

        let diagnostic = erebor_runtime.run_expect_failure_in(
            test_dir,
            [
                "session",
                "diagnose",
                "--runner",
                "linux-host",
                "--config",
                config_path.to_string_lossy().as_ref(),
                "raw-cdp",
            ],
        )?;
        assert!(
            diagnostic.contains("guarded session diagnostic failed"),
            "expected governed diagnostic denial, got {diagnostic}"
        );

        let registry_record = SessionRegistry::new(test_dir).single_record()?;
        let session_id = json_string(&registry_record, "/session_id")?.to_owned();
        let audit_path = std::path::PathBuf::from(json_string(&registry_record, "/audit_path")?);
        assert!(audit_path.exists());
        assert!(Path::new(json_string(&registry_record, "/policy_artifact_paths/0")?).exists());
        assert!(Path::new(json_string(&registry_record, "/config_artifact_path")?).exists());
        let list = erebor_runtime.run_in(test_dir, ["session", "ls"])?;
        let show = erebor_runtime.run_in(test_dir, ["session", "show", session_id.as_str()])?;
        let describe =
            erebor_runtime.run_in(test_dir, ["session", "describe", session_id.as_str()])?;
        let describe_json = erebor_runtime.run_in(
            test_dir,
            [
                "session",
                "describe",
                session_id.as_str(),
                "--format",
                "json",
            ],
        )?;
        let review: Value = serde_json::from_str(&describe_json).context(JsonSnafu)?;

        assert!(list.contains(session_id.as_str()));
        assert!(list.contains("terminal"));
        assert!(show.contains("test-agent"));
        assert!(show.contains("deny-raw-cdp"));
        assert!(show.contains("Policy sha256:"));
        assert!(describe.contains("Denied Event"));
        assert!(describe.contains("process_exec"));
        assert!(describe.contains("linux_ptrace_process_guard"));
        assert!(describe.contains("exec_denied_before_child_gained_authority"));
        assert!(describe.contains("Raw payload sha256:"));
        assert_eq!(
            review
                .pointer("/summary/session_id")
                .and_then(Value::as_str),
            Some(session_id.as_str())
        );
        assert_eq!(
            review
                .pointer("/important_decisions/0/rule_id")
                .and_then(Value::as_str),
            Some("deny-raw-cdp")
        );
        assert_eq!(
            review
                .pointer("/important_decisions/0/controlled_path_backend")
                .and_then(Value::as_str),
            Some("linux_ptrace_process_guard")
        );
        assert_eq!(
            review
                .pointer("/important_decisions/0/final_effect")
                .and_then(Value::as_str),
            Some("exec_denied_before_child_gained_authority")
        );
        let raw_payload_sha256 = review
            .pointer("/important_decisions/0/raw_payload_sha256")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert_eq!(raw_payload_sha256.len(), 64);

        Ok(())
    }

    #[test]
    fn session_run_creates_registry_and_review_commands_read_it() -> Result<(), E2eError> {
        let erebor_runtime = EreborCliFixture::build()?;
        let workspace = E2eWorkspace::create("session-registry")?;
        let test_dir = workspace.path();
        let policy_path = SessionReviewPolicy::write(test_dir)?;
        let config_path = SessionReviewConfig::write_registry(test_dir, &policy_path)?;

        let run = erebor_runtime.run_expect_failure_in(
            test_dir,
            [
                "session",
                "run",
                "--runner",
                "linux-host",
                "--config",
                config_path.to_string_lossy().as_ref(),
                "sh",
                "--remote-debugging-port=9222",
            ],
        )?;
        assert!(
            run.contains("session runner `linux-host` exited unsuccessfully"),
            "expected governed run denial, got {run}"
        );

        let registry_record = SessionRegistry::new(test_dir).single_record()?;
        let session_id = json_string(&registry_record, "/session_id")?;
        let registry_path = test_dir.join(".erebor/sessions");
        assert!(registry_path.join(session_id).join("session.json").exists());
        assert_eq!(json_string(&registry_record, "/status")?, "failed");
        assert!(registry_record
            .pointer("/ended_at_unix_ms")
            .and_then(Value::as_u64)
            .is_some());
        assert!(Path::new(json_string(&registry_record, "/audit_path")?).exists());
        assert!(Path::new(json_string(&registry_record, "/config_artifact_path")?).exists());
        assert!(Path::new(json_string(&registry_record, "/policy_artifact_paths/0")?).exists());

        let list = erebor_runtime.run_in(test_dir, ["session", "ls"])?;
        let show = erebor_runtime.run_in(test_dir, ["session", "show", session_id])?;
        let describe_json = erebor_runtime.run_in(
            test_dir,
            ["session", "describe", session_id, "--format", "json"],
        )?;
        let review: Value = serde_json::from_str(&describe_json).context(JsonSnafu)?;

        assert!(list.contains(session_id));
        assert!(list.contains("failed"));
        assert!(list.contains("terminal"));
        assert!(show.contains("test-agent"));
        assert!(show.contains("deny-raw-cdp"));
        assert!(show.contains("Policy sha256:"));
        assert_eq!(
            review
                .pointer("/summary/session_id")
                .and_then(Value::as_str),
            Some(session_id)
        );
        assert_eq!(
            review
                .pointer("/important_decisions/0/rule_id")
                .and_then(Value::as_str),
            Some("deny-raw-cdp")
        );
        assert_eq!(
            review
                .pointer("/important_decisions/0/controlled_path_backend")
                .and_then(Value::as_str),
            Some("linux_ptrace_process_guard")
        );

        Ok(())
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn session_review_e2e_is_host_specific() {
    eprintln!("skipping session review e2e on non-x86_64 Linux host");
}
