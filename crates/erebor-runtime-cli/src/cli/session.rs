use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

use erebor_runtime_client::DaemonClient;
use erebor_runtime_ipc::v1::{
    CodexAppServerAttachRequest, CodexAppServerInputCloseRequest, CodexAppServerInputRequest,
    CodexRunRequest, SessionAttachRequest, SessionCreateRequest, SessionEnvironmentEntry,
    SessionInputLeaseReleaseRequest, SessionInputLeaseRenewRequest, SessionInputRequest,
    SessionPruneRequest, SessionRecord,
};
use snafu::ResultExt;
use uuid::Uuid;

use crate::error::{CliError, DaemonClientSnafu, DaemonRuntimeSnafu, InvalidSessionCommandSnafu};

mod args;
mod interactive;

use args::{
    GenericSessionCreateArgs, GenericSessionRequestArgs, SessionAliasArgs, SessionAliasCommand,
    SessionAttachArgs, SessionCommand, SessionEventsArgs, SessionLogsArgs, SessionRunArgs,
};
use interactive::{
    InteractiveInput, InteractiveTerminal, StructuredJsonlEvent, StructuredJsonlInput,
};

pub(super) use args::{CodexRunArgs, SessionArgs};

pub(super) struct SessionCommandOwner<'a> {
    args: &'a SessionArgs,
}

impl<'a> SessionCommandOwner<'a> {
    pub(super) const fn new(args: &'a SessionArgs) -> Self {
        Self { args }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        runtime.block_on(self.execute_daemon())
    }

    pub(super) fn execute_codex_run(args: &CodexRunArgs) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        runtime.block_on(Self::run_codex_alias(&DaemonClient::local(), args))
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
            SessionCommand::Alias(args) => self.aliases(&client, args).await?,
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
        let request = args.request.to_request();
        let key = args.idempotency_key.as_str();
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
            let client_instance_id = format!("erebor-cli-{}", std::process::id());
            Self::follow_attached(
                client,
                &created.session_id,
                args.request.tty,
                key,
                &client_instance_id,
            )
            .await?;
        }
        Ok(())
    }

    async fn run_codex_alias(client: &DaemonClient, args: &CodexRunArgs) -> Result<(), CliError> {
        let app_server = args.alias == "codex-app-server";
        let workspace = args.workspace.clone().unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_error| std::path::PathBuf::from("."))
        });
        let key = format!("codex-run-{}", Uuid::new_v4());
        let created = client
            .codex_run(
                CodexRunRequest {
                    alias: args.alias.clone(),
                    workspace: workspace.display().to_string(),
                    policy_set_reference: args.policy.clone(),
                    daemon_failure_mode: args.failure_mode.clone(),
                    requested_loss_grace_seconds: args.loss_grace_seconds,
                    tty: !app_server,
                    detached: args.detached,
                },
                &key,
            )
            .await
            .context(DaemonClientSnafu)?;
        if !app_server {
            Self::write_create(created.clone());
        }
        let started = client
            .session_start(&created.session_id, &format!("{key}:start"))
            .await
            .context(DaemonClientSnafu)?;
        if !app_server {
            Self::write_record(started);
        }
        if !args.detached {
            let client_instance_id = format!("erebor-cli-{}", std::process::id());
            if app_server {
                Self::follow_codex_app_server(
                    client,
                    &created.session_id,
                    &key,
                    &client_instance_id,
                )
                .await?;
            } else {
                Self::follow_attached(client, &created.session_id, true, &key, &client_instance_id)
                    .await?;
            }
        }
        Ok(())
    }

    async fn follow_codex_app_server(
        client: &DaemonClient,
        session_id: &str,
        key: &str,
        client_instance_id: &str,
    ) -> Result<(), CliError> {
        let attachment = client
            .codex_app_server_attach(
                CodexAppServerAttachRequest {
                    session_id: session_id.to_owned(),
                    client_instance_id: client_instance_id.to_owned(),
                },
                &format!("{key}:app-server-attach"),
            )
            .await
            .context(DaemonClientSnafu)?;
        if attachment.read_only {
            return InvalidSessionCommandSnafu {
                reason: String::from(
                    "Codex App Server attachment did not receive its structured input lease",
                ),
            }
            .fail();
        }
        let input = StructuredJsonlInput::open();
        let mut stdout_cursor = 0;
        let mut stderr_cursor = 0;
        let mut renew_at = Instant::now() + Duration::from_secs(10);
        let mut renewal = 0_u64;
        let mut interrupt_sent = false;
        let mut input_closed = false;
        let interrupt = tokio::signal::ctrl_c();
        tokio::pin!(interrupt);
        loop {
            while !input_closed {
                let Some(event) = input.try_event() else {
                    break;
                };
                match event {
                    StructuredJsonlEvent::Frame(jsonl_frame) => {
                        let expected_bytes =
                            u32::try_from(jsonl_frame.len()).map_err(|_error| {
                                CliError::InvalidSessionCommand {
                                    reason: String::from(
                                        "Codex App Server input exceeds the client protocol limit",
                                    ),
                                    location: snafu::Location::default(),
                                }
                            })?;
                        let response = client
                            .codex_app_server_input(CodexAppServerInputRequest {
                                session_id: attachment.session_id.clone(),
                                input_lease_id: attachment.input_lease_id.clone(),
                                client_instance_id: client_instance_id.to_owned(),
                                jsonl_frame,
                            })
                            .await
                            .context(DaemonClientSnafu)?;
                        if response.session_id != attachment.session_id {
                            return InvalidSessionCommandSnafu {
                                reason: String::from(
                                    "daemon acknowledged a different Codex App Server session",
                                ),
                            }
                            .fail();
                        }
                        if response.synthetic_jsonl_response.is_empty() {
                            if response.accepted_bytes != expected_bytes {
                                return InvalidSessionCommandSnafu {
                                    reason: String::from("daemon did not acknowledge the exact Codex App Server frame"),
                                }
                                .fail();
                            }
                        } else {
                            if response.accepted_bytes != 0 {
                                return InvalidSessionCommandSnafu {
                                    reason: String::from(
                                        "daemon both denied and forwarded a Codex App Server frame",
                                    ),
                                }
                                .fail();
                            }
                            io::stdout()
                                .lock()
                                .write_all(&response.synthetic_jsonl_response)
                                .context(crate::error::WriteSessionOutputSnafu)?;
                            io::stdout()
                                .lock()
                                .flush()
                                .context(crate::error::WriteSessionOutputSnafu)?;
                        }
                    }
                    StructuredJsonlEvent::Closed => {
                        let response = client
                            .codex_app_server_input_close(CodexAppServerInputCloseRequest {
                                session_id: attachment.session_id.clone(),
                                input_lease_id: attachment.input_lease_id.clone(),
                                client_instance_id: client_instance_id.to_owned(),
                            })
                            .await
                            .context(DaemonClientSnafu)?;
                        if response.session_id != attachment.session_id || !response.closed {
                            return InvalidSessionCommandSnafu {
                                reason: String::from(
                                    "daemon did not acknowledge Codex App Server input EOF",
                                ),
                            }
                            .fail();
                        }
                        input_closed = true;
                    }
                    StructuredJsonlEvent::Failed(source) => {
                        return Err(CliError::Terminal {
                            source: source.into(),
                            location: snafu::Location::default(),
                        });
                    }
                }
            }
            if Instant::now() >= renew_at {
                renewal = renewal.saturating_add(1);
                client
                    .session_input_lease_renew(
                        SessionInputLeaseRenewRequest {
                            session_id: attachment.session_id.clone(),
                            input_lease_id: attachment.input_lease_id.clone(),
                            client_instance_id: client_instance_id.to_owned(),
                        },
                        &format!("{key}:app-server-lease-renew-{renewal}"),
                    )
                    .await
                    .context(DaemonClientSnafu)?;
                renew_at = Instant::now() + Duration::from_secs(10);
            }
            stdout_cursor = Self::write_stream_page(
                client
                    .session_logs(&attachment.session_id, "stdout", stdout_cursor, 256)
                    .await
                    .context(DaemonClientSnafu)?,
            )?;
            stderr_cursor = Self::write_stream_page_to_stderr(
                client
                    .session_logs(&attachment.session_id, "stderr", stderr_cursor, 256)
                    .await
                    .context(DaemonClientSnafu)?,
            )?;
            let record = client
                .session_inspect(&attachment.session_id)
                .await
                .context(DaemonClientSnafu)?;
            if matches!(
                record.state.as_str(),
                "succeeded" | "failed" | "interrupted" | "removed"
            ) {
                Self::release_codex_app_server_lease(
                    client,
                    &attachment,
                    client_instance_id,
                    &format!("{key}:app-server-finished"),
                )
                .await?;
                return Ok(());
            }
            if interrupt_sent {
                tokio::time::sleep(Duration::from_millis(100)).await;
            } else {
                tokio::select! {
                    _ = &mut interrupt => {
                        client
                            .session_kill(
                                &attachment.session_id,
                                "interrupt",
                                &format!("{key}:app-server-interrupt"),
                            )
                            .await
                            .context(DaemonClientSnafu)?;
                        interrupt_sent = true;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        }
    }

    async fn follow_attached(
        client: &DaemonClient,
        session_id: &str,
        request_input_lease: bool,
        key: &str,
        client_instance_id: &str,
    ) -> Result<(), CliError> {
        let attachment = client
            .session_attach(
                SessionAttachRequest {
                    session_id: session_id.to_owned(),
                    after_output_sequence: 0,
                    request_input_lease,
                    client_instance_id: client_instance_id.to_owned(),
                },
                &format!("{key}:attach"),
            )
            .await
            .context(DaemonClientSnafu)?;
        Self::follow_attachment(
            client,
            attachment,
            0,
            request_input_lease,
            key,
            client_instance_id,
        )
        .await
    }

    async fn follow_attachment(
        client: &DaemonClient,
        attachment: erebor_runtime_ipc::v1::SessionAttachResponse,
        after_output_sequence: u64,
        request_input_lease: bool,
        key: &str,
        client_instance_id: &str,
    ) -> Result<(), CliError> {
        println!(
            "session_id={} read_only={} input_lease_id={} input_lease_expires_unix_ms={}",
            attachment.session_id,
            attachment.read_only,
            attachment.input_lease_id,
            attachment.input_lease_expires_unix_ms,
        );
        if request_input_lease && attachment.read_only {
            return InvalidSessionCommandSnafu {
                reason: String::from("interactive attachment did not receive an input lease"),
            }
            .fail();
        }
        let terminal = request_input_lease
            .then(InteractiveTerminal::open)
            .transpose()?;
        let mut stdout_cursor = after_output_sequence;
        let mut stderr_cursor = after_output_sequence;
        let mut renew_at = Instant::now() + Duration::from_secs(10);
        let mut renewal = 0_u64;
        let mut interrupt_sent = false;
        let interrupt = tokio::signal::ctrl_c();
        tokio::pin!(interrupt);
        loop {
            if let Some(terminal) = terminal.as_ref() {
                while let Some(input) = terminal.try_input() {
                    match input {
                        InteractiveInput::Bytes(data) => {
                            let expected_bytes = u32::try_from(data.len()).map_err(|_error| {
                                CliError::InvalidSessionCommand {
                                    reason: String::from(
                                        "interactive input exceeds the client protocol limit",
                                    ),
                                    location: snafu::Location::default(),
                                }
                            })?;
                            let response = client
                                .session_input(SessionInputRequest {
                                    session_id: attachment.session_id.clone(),
                                    input_lease_id: attachment.input_lease_id.clone(),
                                    client_instance_id: client_instance_id.to_owned(),
                                    data,
                                })
                                .await
                                .context(DaemonClientSnafu)?;
                            if response.session_id != attachment.session_id
                                || response.accepted_bytes != expected_bytes
                            {
                                return InvalidSessionCommandSnafu {
                                    reason: String::from(
                                        "daemon did not acknowledge the exact interactive input write",
                                    ),
                                }
                                .fail();
                            }
                        }
                        InteractiveInput::Detach | InteractiveInput::Closed => {
                            Self::release_input_lease(
                                client,
                                &attachment,
                                client_instance_id,
                                &format!("{key}:detach"),
                            )
                            .await?;
                            return Ok(());
                        }
                        InteractiveInput::Failed(source) => {
                            return Err(CliError::Terminal {
                                source,
                                location: snafu::Location::default(),
                            });
                        }
                    }
                }
                if Instant::now() >= renew_at {
                    renewal = renewal.saturating_add(1);
                    client
                        .session_input_lease_renew(
                            SessionInputLeaseRenewRequest {
                                session_id: attachment.session_id.clone(),
                                input_lease_id: attachment.input_lease_id.clone(),
                                client_instance_id: client_instance_id.to_owned(),
                            },
                            &format!("{key}:lease-renew-{renewal}"),
                        )
                        .await
                        .context(DaemonClientSnafu)?;
                    renew_at = Instant::now() + Duration::from_secs(10);
                }
            }
            stdout_cursor = Self::write_stream_page(
                client
                    .session_logs(&attachment.session_id, "stdout", stdout_cursor, 256)
                    .await
                    .context(DaemonClientSnafu)?,
            )?;
            stderr_cursor = Self::write_stream_page(
                client
                    .session_logs(&attachment.session_id, "stderr", stderr_cursor, 256)
                    .await
                    .context(DaemonClientSnafu)?,
            )?;
            let record = client
                .session_inspect(&attachment.session_id)
                .await
                .context(DaemonClientSnafu)?;
            if matches!(
                record.state.as_str(),
                "succeeded" | "failed" | "interrupted" | "removed"
            ) {
                Self::write_record(record);
                return Ok(());
            }
            if terminal.is_some() || interrupt_sent {
                tokio::time::sleep(Duration::from_millis(100)).await;
            } else {
                tokio::select! {
                    _ = &mut interrupt => {
                        client
                            .session_kill(
                                &attachment.session_id,
                                "interrupt",
                                &format!("{key}:interrupt"),
                            )
                            .await
                            .context(DaemonClientSnafu)?;
                        interrupt_sent = true;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        }
    }

    async fn release_input_lease(
        client: &DaemonClient,
        attachment: &erebor_runtime_ipc::v1::SessionAttachResponse,
        client_instance_id: &str,
        idempotency_key: &str,
    ) -> Result<(), CliError> {
        client
            .session_input_lease_release(
                SessionInputLeaseReleaseRequest {
                    session_id: attachment.session_id.clone(),
                    input_lease_id: attachment.input_lease_id.clone(),
                    client_instance_id: client_instance_id.to_owned(),
                },
                idempotency_key,
            )
            .await
            .context(DaemonClientSnafu)?;
        Ok(())
    }

    async fn release_codex_app_server_lease(
        client: &DaemonClient,
        attachment: &erebor_runtime_ipc::v1::CodexAppServerAttachResponse,
        client_instance_id: &str,
        idempotency_key: &str,
    ) -> Result<(), CliError> {
        client
            .session_input_lease_release(
                SessionInputLeaseReleaseRequest {
                    session_id: attachment.session_id.clone(),
                    input_lease_id: attachment.input_lease_id.clone(),
                    client_instance_id: client_instance_id.to_owned(),
                },
                idempotency_key,
            )
            .await
            .context(DaemonClientSnafu)?;
        Ok(())
    }

    fn write_stream_page(page: erebor_runtime_client::SessionLogPage) -> Result<u64, CliError> {
        let mut output = io::stdout().lock();
        for record in page.records {
            output
                .write_all(&record.data)
                .context(crate::error::WriteSessionOutputSnafu)?;
        }
        output
            .flush()
            .context(crate::error::WriteSessionOutputSnafu)?;
        Ok(page.end.durable_cursor)
    }

    fn write_stream_page_to_stderr(
        page: erebor_runtime_client::SessionLogPage,
    ) -> Result<u64, CliError> {
        let mut output = io::stderr().lock();
        for record in page.records {
            output
                .write_all(&record.data)
                .context(crate::error::WriteSessionOutputSnafu)?;
        }
        output
            .flush()
            .context(crate::error::WriteSessionOutputSnafu)?;
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
        Self::follow_attachment(
            client,
            response,
            args.after_output_sequence,
            args.input,
            &args.idempotency_key,
            &args.client_instance_id,
        )
        .await
    }

    async fn aliases(
        &self,
        client: &DaemonClient,
        args: &SessionAliasArgs,
    ) -> Result<(), CliError> {
        match &args.command {
            SessionAliasCommand::Set(args) => {
                let alias = client
                    .session_alias_set(&args.alias, &args.session_id, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?;
                println!("alias={} session_id={}", alias.alias, alias.session_id);
            }
            SessionAliasCommand::Remove(args) => {
                let alias = client
                    .session_alias_remove(&args.alias, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?;
                println!("alias={} session_id={}", alias.alias, alias.session_id);
            }
            SessionAliasCommand::List => {
                for alias in client
                    .session_alias_list()
                    .await
                    .context(DaemonClientSnafu)?
                    .aliases
                {
                    println!("alias={} session_id={}", alias.alias, alias.session_id);
                }
            }
        }
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

#[cfg(test)]
mod tests;
