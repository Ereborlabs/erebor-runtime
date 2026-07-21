use std::io::{self, Write};

use erebor_runtime_client::DaemonClient;
use erebor_runtime_core::{RuntimeConfig, SessionRunPlan};
use erebor_runtime_events::SessionId;
use erebor_runtime_ipc::v1::{
    SessionAttachRequest, SessionCreateRequest, SessionEnvironmentEntry, SessionPruneRequest,
    SessionRecord,
};
use erebor_runtime_session::SessionExecutionService;
use snafu::ResultExt;

use crate::error::{
    CliError, DaemonClientSnafu, DaemonRuntimeSnafu, InvalidConfigSnafu,
    InvalidSessionCommandSnafu, SessionExecutionSnafu,
};

use super::config_paths::RuntimeConfigLoader;

mod args;

use args::{
    GenericSessionCreateArgs, GenericSessionRequestArgs, OptionalGenericSessionRequestArgs,
    SessionAttachArgs, SessionCommand, SessionEventsArgs, SessionLogsArgs, SessionRunArgs,
};

pub(super) use args::SessionArgs;

pub(super) struct SessionCommandOwner<'a> {
    args: &'a SessionArgs,
}

impl<'a> SessionCommandOwner<'a> {
    pub(super) const fn new(args: &'a SessionArgs) -> Self {
        Self { args }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        if matches!(&self.args.command, SessionCommand::Run(args) if args.config.is_some()) {
            return self.run_codex();
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        runtime.block_on(self.execute_daemon())
    }

    fn run_codex(&self) -> Result<(), CliError> {
        let SessionCommand::Run(args) = &self.args.command else {
            unreachable!("only a configured session run selects the transitional Codex path");
        };
        if args.idempotency_key.is_some() || args.request.has_generic_identity() {
            return InvalidSessionCommandSnafu {
                reason: String::from(
                    "the temporary Codex run path cannot be combined with generic daemon identities",
                ),
            }
            .fail();
        }
        let config_path = args.config.as_ref().ok_or_else(|| {
            InvalidSessionCommandSnafu {
                reason: String::from("temporary Codex run requires --config"),
            }
            .build()
        })?;
        let config = RuntimeConfigLoader::read(config_path)?;
        let plan = SessionPlanBuilder::new(&config, config_path).run(args)?;
        let codex_profile = plan
            .command()
            .first()
            .and_then(|command| config.codex.matching_profile(std::path::Path::new(command)));
        if !codex_profile.is_some_and(|profile| profile.app_server_transport.enabled) {
            return InvalidSessionCommandSnafu {
                reason: String::from(
                    "the only remaining foreground path requires an exact configured Codex App Server profile",
                ),
            }
            .fail();
        }
        SessionExecutionService::run_plan(&config, &plan)
            .context(SessionExecutionSnafu)
            .map(|_outcome| ())
    }

    async fn execute_daemon(&self) -> Result<(), CliError> {
        let client = DaemonClient::local();
        match &self.args.command {
            SessionCommand::Create(args) => self.create(&client, args).await?,
            SessionCommand::Run(args) => self.run_generic(&client, args).await?,
            SessionCommand::Start(args) => Self::write_record(
                client
                    .session_start(&args.session_id, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Ps => {
                for record in client
                    .session_list()
                    .await
                    .context(DaemonClientSnafu)?
                    .sessions
                {
                    Self::write_record(record);
                }
            }
            SessionCommand::Inspect(args) => Self::write_record(
                client
                    .session_inspect(&args.session_id)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Logs(args) => self.logs(&client, args).await?,
            SessionCommand::Attach(args) => self.attach(&client, args).await?,
            SessionCommand::Events(args) => self.events(&client, args).await?,
            SessionCommand::Stop(args) => Self::write_record(
                client
                    .session_stop(&args.session_id, args.grace_seconds, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Kill(args) => Self::write_record(
                client
                    .session_kill(&args.session_id, &args.signal, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Wait(args) => Self::write_record(
                client
                    .session_wait(&args.session_id, args.after_generation)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Remove(args) => Self::write_record(
                client
                    .session_remove(&args.session_id, args.force, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Prune(args) => {
                let result = client
                    .session_prune(
                        SessionPruneRequest {
                            terminal_before_unix_ms: args.terminal_before_unix_ms,
                            maximum_sessions: args.maximum_sessions,
                        },
                        &args.idempotency_key,
                    )
                    .await
                    .context(DaemonClientSnafu)?;
                println!("pruned_sessions={}", result.pruned_sessions);
                for session_id in result.retained_session_ids {
                    println!("session_id={session_id}");
                }
            }
        }
        Ok(())
    }

    async fn create(
        &self,
        client: &DaemonClient,
        args: &GenericSessionCreateArgs,
    ) -> Result<(), CliError> {
        let response = client
            .session_create(args.request.to_request(), &args.idempotency_key)
            .await
            .context(DaemonClientSnafu)?;
        Self::write_create(response);
        Ok(())
    }

    async fn run_generic(
        &self,
        client: &DaemonClient,
        args: &SessionRunArgs,
    ) -> Result<(), CliError> {
        let request = args.request.to_generic_request()?;
        let key = args.idempotency_key.as_deref().ok_or_else(|| {
            InvalidSessionCommandSnafu {
                reason: String::from("generic run requires --idempotency-key"),
            }
            .build()
        })?;
        let created = client
            .session_create(request, key)
            .await
            .context(DaemonClientSnafu)?;
        Self::write_create(created.clone());
        let started = client
            .session_start(&created.session_id, &format!("{key}:start"))
            .await
            .context(DaemonClientSnafu)?;
        Self::write_record(started);
        if !args.request.detached {
            self.follow_attached(client, &created.session_id, args.request.tty, key)
                .await?;
        }
        Ok(())
    }

    async fn follow_attached(
        &self,
        client: &DaemonClient,
        session_id: &str,
        request_input_lease: bool,
        key: &str,
    ) -> Result<(), CliError> {
        let attachment = client
            .session_attach(
                SessionAttachRequest {
                    session_id: session_id.to_owned(),
                    after_output_sequence: 0,
                    request_input_lease,
                    client_instance_id: String::from("erebor-cli-run"),
                },
                &format!("{key}:attach"),
            )
            .await
            .context(DaemonClientSnafu)?;
        println!(
            "session_id={} read_only={} input_lease_id={} input_lease_expires_unix_ms={}",
            attachment.session_id,
            attachment.read_only,
            attachment.input_lease_id,
            attachment.input_lease_expires_unix_ms,
        );
        let mut stdout_cursor = 0;
        let mut stderr_cursor = 0;
        loop {
            stdout_cursor = Self::write_stream_page(
                client
                    .session_logs(session_id, "stdout", stdout_cursor, 256)
                    .await
                    .context(DaemonClientSnafu)?,
            )?;
            stderr_cursor = Self::write_stream_page(
                client
                    .session_logs(session_id, "stderr", stderr_cursor, 256)
                    .await
                    .context(DaemonClientSnafu)?,
            )?;
            let record = client
                .session_inspect(session_id)
                .await
                .context(DaemonClientSnafu)?;
            if matches!(
                record.state.as_str(),
                "succeeded" | "failed" | "interrupted" | "removed"
            ) {
                Self::write_record(record);
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    fn write_stream_page(page: erebor_runtime_client::SessionLogPage) -> Result<u64, CliError> {
        let mut output = io::stdout().lock();
        for record in page.records {
            output
                .write_all(&record.data)
                .context(crate::error::WriteSessionOutputSnafu)?;
        }
        Ok(page.end.durable_cursor)
    }

    async fn logs(&self, client: &DaemonClient, args: &SessionLogsArgs) -> Result<(), CliError> {
        let page = client
            .session_logs(
                &args.session_id,
                &args.stream,
                args.after_sequence,
                args.maximum_records,
            )
            .await
            .context(DaemonClientSnafu)?;
        let mut output = io::stdout().lock();
        for record in page.records {
            output
                .write_all(&record.data)
                .context(crate::error::WriteSessionOutputSnafu)?;
        }
        writeln!(
            output,
            "durable_cursor={} truncated_before_cursor={}",
            page.end.durable_cursor, page.end.truncated_before_cursor
        )
        .context(crate::error::WriteSessionOutputSnafu)?;
        Ok(())
    }

    async fn attach(
        &self,
        client: &DaemonClient,
        args: &SessionAttachArgs,
    ) -> Result<(), CliError> {
        let response = client
            .session_attach(
                SessionAttachRequest {
                    session_id: args.session_id.clone(),
                    after_output_sequence: args.after_output_sequence,
                    request_input_lease: args.input,
                    client_instance_id: args.client_instance_id.clone(),
                },
                &args.idempotency_key,
            )
            .await
            .context(DaemonClientSnafu)?;
        println!(
            "session_id={} read_only={} input_lease_id={} input_lease_expires_unix_ms={}",
            response.session_id,
            response.read_only,
            response.input_lease_id,
            response.input_lease_expires_unix_ms,
        );
        Ok(())
    }

    async fn events(
        &self,
        client: &DaemonClient,
        args: &SessionEventsArgs,
    ) -> Result<(), CliError> {
        let page = client
            .session_events(&args.session_id, args.after_sequence, args.maximum_records)
            .await
            .context(DaemonClientSnafu)?;
        for event in page.records {
            println!(
                "session_id={} sequence={} timestamp_unix_ms={} kind={} payload={}",
                event.session_id,
                event.sequence,
                event.timestamp_unix_ms,
                event.event_kind,
                String::from_utf8_lossy(&event.payload),
            );
        }
        println!(
            "durable_cursor={} truncated_before_cursor={}",
            page.end.durable_cursor, page.end.truncated_before_cursor
        );
        Ok(())
    }

    fn write_create(record: erebor_runtime_ipc::v1::SessionCreateResponse) {
        println!(
            "session_id={} state={} generation={} retry_expires_unix_ms={}",
            record.session_id,
            record.state,
            record.generation,
            record.retry_guarantee_expires_unix_ms,
        );
    }

    fn write_record(record: SessionRecord) {
        println!(
            "session_id={} state={} generation={} owner_uid={} runner_id={} recovery={} retention_hold={} failure={}",
            record.session_id,
            record.state,
            record.generation,
            record.owner_uid,
            record.runner_id,
            record.runner_recovery,
            record.retention_hold,
            record.failure,
        );
    }
}

impl GenericSessionRequestArgs {
    fn to_request(&self) -> SessionCreateRequest {
        SessionCreateRequest {
            runner_id: self.runner.as_str().to_owned(),
            command: self.command.clone(),
            workspace: self.workspace.display().to_string(),
            policy_set_digest: self.policy_set_digest.clone().unwrap_or_default(),
            package_digest: self.package_digest.clone().unwrap_or_default(),
            installation_digest: self.installation_digest.clone().unwrap_or_default(),
            adapter_digest: self.adapter_digest.clone().unwrap_or_default(),
            daemon_failure_mode: self.failure_mode.clone(),
            requested_loss_grace_seconds: self.loss_grace_seconds,
            environment: self
                .environment
                .iter()
                .map(|(key, value)| SessionEnvironmentEntry {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect(),
            secret_references: self.secret_references.clone(),
            container_image_digest: String::new(),
            tty: self.tty,
            detached: self.detached,
        }
    }
}

impl OptionalGenericSessionRequestArgs {
    fn has_generic_identity(&self) -> bool {
        self.workspace.is_some()
            || self.package_digest.is_some()
            || self.installation_digest.is_some()
            || self.adapter_digest.is_some()
            || self.policy_set_digest.is_some()
            || !self.environment.is_empty()
            || !self.secret_references.is_empty()
            || self.tty
            || self.detached
    }

    fn to_generic_request(&self) -> Result<SessionCreateRequest, CliError> {
        let missing = [
            ("--runner", self.runner.is_some()),
            ("--workspace", self.workspace.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, present)| (!present).then_some(name))
        .collect::<Vec<_>>();
        if !missing.is_empty() {
            return InvalidSessionCommandSnafu {
                reason: format!("generic run requires {}", missing.join(", ")),
            }
            .fail();
        }
        let (Some(runner), Some(workspace)) = (self.runner, self.workspace.as_ref()) else {
            return InvalidSessionCommandSnafu {
                reason: String::from("generic run identities changed during validation"),
            }
            .fail();
        };
        Ok(SessionCreateRequest {
            runner_id: runner.as_str().to_owned(),
            command: self.command.clone(),
            workspace: workspace.display().to_string(),
            policy_set_digest: self.policy_set_digest.clone().unwrap_or_default(),
            package_digest: self.package_digest.clone().unwrap_or_default(),
            installation_digest: self.installation_digest.clone().unwrap_or_default(),
            adapter_digest: self.adapter_digest.clone().unwrap_or_default(),
            daemon_failure_mode: self.failure_mode.clone(),
            requested_loss_grace_seconds: self.loss_grace_seconds,
            environment: self
                .environment
                .iter()
                .map(|(key, value)| SessionEnvironmentEntry {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect(),
            secret_references: self.secret_references.clone(),
            container_image_digest: String::new(),
            tty: self.tty,
            detached: self.detached,
        })
    }
}

struct SessionPlanBuilder<'a> {
    config: &'a RuntimeConfig,
    config_path: &'a std::path::PathBuf,
}

impl<'a> SessionPlanBuilder<'a> {
    const fn new(config: &'a RuntimeConfig, config_path: &'a std::path::PathBuf) -> Self {
        Self {
            config,
            config_path,
        }
    }

    fn run(&self, args: &SessionRunArgs) -> Result<SessionRunPlan, CliError> {
        let runner = args.request.runner.ok_or_else(|| {
            InvalidSessionCommandSnafu {
                reason: String::from("temporary Codex run requires --runner"),
            }
            .build()
        })?;
        let mut plan = SessionRunPlan::from_config(
            self.config,
            runner.into(),
            SessionId::new(format!("session-{}", std::process::id())),
            args.request.command.clone(),
        )
        .context(InvalidConfigSnafu)?;
        plan.set_config_path(self.config_path.clone());
        Ok(plan)
    }
}

#[cfg(test)]
mod tests;
