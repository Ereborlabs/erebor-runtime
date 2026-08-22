#[path = "support/session_review.rs"]
mod review_support;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_host {
    use std::{error::Error as StdError, fs, path::Path};

    use erebor_runtime_audit::{SessionReviewOutputFormat, SessionReviewSource};
    use erebor_runtime_core::{RuntimeConfig, SessionRunPlan, SessionRunnerKind};
    use erebor_runtime_events::SessionId;
    use erebor_runtime_session::{SessionExecutionError, SessionExecutionService};
    use serde_json::Value;

    use crate::review_support::{
        json_string, SessionRegistry, SessionReviewConfig, SessionReviewPolicy,
    };

    #[test]
    fn session_review_lists_a_failed_diagnostic_without_interception(
    ) -> Result<(), Box<dyn StdError>> {
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
            "expected failed diagnostic, got {diagnostic:?}"
        );

        let registry_record = SessionRegistry::new(test_dir).single_record()?;
        let session_id = json_string(&registry_record, "/session_id")?.to_owned();
        let audit_path = std::path::PathBuf::from(json_string(&registry_record, "/audit_path")?);
        assert!(!audit_path.exists());
        assert!(Path::new(json_string(&registry_record, "/policy_artifact_paths/0")?).exists());
        assert!(Path::new(json_string(&registry_record, "/config_artifact_path")?).exists());
        let reviews = SessionReviewSource::new(test_dir.join(".erebor/sessions"));
        let list = reviews.render_list(SessionReviewOutputFormat::Text)?;

        assert!(list.contains(session_id.as_str()));
        assert!(list.contains("terminal"));
        assert!(list.contains("failed"));

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
        assert!(!Path::new(json_string(&registry_record, "/audit_path")?).exists());
        assert!(Path::new(json_string(&registry_record, "/config_artifact_path")?).exists());
        assert!(Path::new(json_string(&registry_record, "/policy_artifact_paths/0")?).exists());

        let reviews = SessionReviewSource::new(test_dir.join(".erebor/sessions"));
        let list = reviews.render_list(SessionReviewOutputFormat::Text)?;

        assert!(list.contains(session_id));
        assert!(list.contains("failed"));
        assert!(list.contains("terminal"));

        Ok(())
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn session_review_e2e_is_host_specific() {
    eprintln!("skipping session review e2e on non-x86_64 Linux host");
}
