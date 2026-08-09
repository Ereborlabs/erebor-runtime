#[path = "support/session_review.rs"]
mod review_support;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_host {
    use std::{error::Error as StdError, fs, path::Path};

    use erebor_runtime_audit::{SessionReviewOutputFormat, SessionReviewSource};
    use erebor_runtime_core::{RuntimeConfig, SessionRunPlan, SessionRunnerKind};
    use erebor_runtime_e2e::error::JsonSnafu;
    use erebor_runtime_events::SessionId;
    use erebor_runtime_session::{SessionExecutionError, SessionExecutionService};
    use serde_json::Value;
    use snafu::ResultExt;

    use crate::review_support::{
        json_string, SessionRegistry, SessionReviewConfig, SessionReviewPolicy,
    };

    #[test]
    fn session_review_renders_governed_process_audit() -> Result<(), Box<dyn StdError>> {
        let workspace = tempfile::tempdir()?;
        let test_dir = workspace.path();
        let policy_path = SessionReviewPolicy::write(test_dir)?;
        let config_path = SessionReviewConfig::write_diagnostic(test_dir, &policy_path)?;
        let config = RuntimeConfig::from_json_str(&fs::read_to_string(&config_path)?)?;
        let mut plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-review-diagnostic"),
            "raw-cdp",
        )?;
        plan.set_config_path(&config_path);
        let diagnostic = SessionExecutionService::run_diagnostic(&config, &plan);
        assert!(
            matches!(
                diagnostic,
                Err(SessionExecutionError::DiagnosticFailed { .. })
            ),
            "expected governed diagnostic denial, got {diagnostic:?}"
        );

        let registry_record = SessionRegistry::new(test_dir).single_record()?;
        let session_id = json_string(&registry_record, "/session_id")?.to_owned();
        let audit_path = std::path::PathBuf::from(json_string(&registry_record, "/audit_path")?);
        assert!(audit_path.exists());
        assert!(Path::new(json_string(&registry_record, "/policy_artifact_paths/0")?).exists());
        assert!(Path::new(json_string(&registry_record, "/config_artifact_path")?).exists());
        let reviews = SessionReviewSource::new(test_dir.join(".erebor/sessions"));
        let list = reviews.render_list(SessionReviewOutputFormat::Text)?;
        let show = reviews.render_show(session_id.as_str(), SessionReviewOutputFormat::Text)?;
        let describe =
            reviews.render_describe(session_id.as_str(), SessionReviewOutputFormat::Text)?;
        let describe_json =
            reviews.render_describe(session_id.as_str(), SessionReviewOutputFormat::Json)?;
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
    fn session_run_creates_registry_and_review_source_reads_it() -> Result<(), Box<dyn StdError>> {
        let workspace = tempfile::tempdir()?;
        let test_dir = workspace.path();
        let policy_path = SessionReviewPolicy::write(test_dir)?;
        let config_path = SessionReviewConfig::write_registry(test_dir, &policy_path)?;
        let config = RuntimeConfig::from_json_str(&fs::read_to_string(&config_path)?)?;
        let mut plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-review-run"),
            vec!["sh".to_owned(), "--remote-debugging-port=9222".to_owned()],
        )?;
        plan.set_config_path(&config_path);
        assert!(SessionExecutionService::run_plan(&config, &plan).is_err());

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

        let reviews = SessionReviewSource::new(test_dir.join(".erebor/sessions"));
        let list = reviews.render_list(SessionReviewOutputFormat::Text)?;
        let show = reviews.render_show(session_id, SessionReviewOutputFormat::Text)?;
        let describe_json = reviews.render_describe(session_id, SessionReviewOutputFormat::Json)?;
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
