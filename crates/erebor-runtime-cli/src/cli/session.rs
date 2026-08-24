use std::{
    collections::BTreeMap,
    io::{self, Write},
    time::{Duration, Instant},
};

use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, ContentArrangement, Table};
use erebor_runtime_client::DaemonClient;
use erebor_runtime_core::TerminalSize;
use erebor_runtime_ipc::v1::{
    CallerHomeFilesystemSource, CodexAppServerAttachRequest, CodexAppServerInputCloseRequest,
    CodexAppServerInputRequest, CodexRunRequest, ContextDeliveryReceiveRequest,
    ContextDeliveryRejectRequest, ContextGraphActivity, ContextGraphResponse,
    ContextScopeGraphNode, SessionAttachRequest, SessionCreateRequest, SessionEnvironmentEntry,
    SessionInputLeaseReleaseRequest, SessionInputLeaseRenewRequest, SessionInputRequest,
    SessionPruneRequest, SessionRecord, SessionTerminalResizeRequest,
};
use snafu::ResultExt;
use uuid::Uuid;

use crate::error::{CliError, DaemonClientSnafu, DaemonRuntimeSnafu, InvalidSessionCommandSnafu};

mod args;
mod interactive;

use args::{
    GenericSessionCreateArgs, GenericSessionRequestArgs, SessionAliasArgs, SessionAliasCommand,
    SessionAttachArgs, SessionCommand, SessionContextArgs, SessionContextCommand,
    SessionContextGraphArgs, SessionEventsArgs, SessionLogsArgs, SessionRunArgs,
};
use interactive::{
    InteractiveInput, InteractiveTerminal, StructuredJsonlEvent, StructuredJsonlInput,
};

const APP_SERVER_INPUT_BATCH_SIZE: usize = 32;

pub(super) use args::{CodexRunArgs, SessionArgs};

pub(super) struct SessionCommandOwner<'a> {
    args: &'a SessionArgs,
    client: &'a DaemonClient,
}

struct ContextGraphTree {
    children: BTreeMap<String, Vec<usize>>,
    activity_children: BTreeMap<(String, String), Vec<usize>>,
    activities: BTreeMap<String, Vec<ContextGraphActivity>>,
}

impl ContextGraphTree {
    fn new(nodes: &[ContextScopeGraphNode], graph_activities: Vec<ContextGraphActivity>) -> Self {
        let mut activities = BTreeMap::<String, Vec<ContextGraphActivity>>::new();
        for activity in graph_activities {
            activities
                .entry(activity.scope.clone())
                .or_default()
                .push(activity);
        }
        let mut children = BTreeMap::<String, Vec<usize>>::new();
        let mut activity_children = BTreeMap::<(String, String), Vec<usize>>::new();
        for (index, node) in nodes.iter().enumerate() {
            if node.parent_scope.is_empty() {
                continue;
            }
            let source_tool = node.source_tool_use_id.as_str();
            let parent_has_source_tool = !source_tool.is_empty()
                && activities
                    .get(&node.parent_scope)
                    .is_some_and(|parent_activities| {
                        parent_activities
                            .iter()
                            .any(|activity| activity.tool_use_id == source_tool)
                    });
            if parent_has_source_tool {
                activity_children
                    .entry((node.parent_scope.clone(), source_tool.to_owned()))
                    .or_default()
                    .push(index);
            } else {
                children
                    .entry(node.parent_scope.clone())
                    .or_default()
                    .push(index);
            }
        }
        for indexes in children.values_mut() {
            indexes.sort_by(|left, right| nodes[*left].scope.cmp(&nodes[*right].scope));
        }
        for indexes in activity_children.values_mut() {
            indexes.sort_by(|left, right| nodes[*left].scope.cmp(&nodes[*right].scope));
        }
        Self {
            children,
            activity_children,
            activities,
        }
    }
}

impl<'a> SessionCommandOwner<'a> {
    pub(super) const fn new(args: &'a SessionArgs, client: &'a DaemonClient) -> Self {
        Self { args, client }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        runtime.block_on(self.execute_daemon())
    }

    pub(super) fn execute_codex_run(
        client: &DaemonClient,
        args: &CodexRunArgs,
    ) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        runtime.block_on(Self::run_codex_agent(client, args))
    }

    async fn execute_daemon(&self) -> Result<(), CliError> {
        match &self.args.command {
            SessionCommand::Create(args) => self.create(self.client, args).await?,
            SessionCommand::Run(args) => self.run_generic(self.client, args).await?,
            SessionCommand::Start(args) => Self::write_record(
                self.client
                    .session_start(&args.session_id, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Ps => {
                let records = self
                    .client
                    .session_list()
                    .await
                    .context(DaemonClientSnafu)?
                    .sessions;
                Self::write_records(&records);
            }
            SessionCommand::Inspect(args) => Self::write_record(
                self.client
                    .session_inspect(&args.session_id)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Logs(args) => self.logs(self.client, args).await?,
            SessionCommand::Attach(args) => self.attach(self.client, args).await?,
            SessionCommand::Events(args) => self.events(self.client, args).await?,
            SessionCommand::Stop(args) => Self::write_record(
                self.client
                    .session_stop(&args.session_id, args.grace_seconds, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Kill(args) => Self::write_record(
                self.client
                    .session_kill(&args.session_id, &args.signal, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Wait(args) => Self::write_record(
                self.client
                    .session_wait(&args.session_id, args.after_generation)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Remove(args) => Self::write_record(
                self.client
                    .session_remove(&args.session_id, args.force, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            SessionCommand::Prune(args) => {
                let result = self
                    .client
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
            SessionCommand::Alias(args) => self.aliases(self.client, args).await?,
            SessionCommand::Context(args) => self.context_deliveries(self.client, args).await?,
        }
        Ok(())
    }

    async fn create(
        &self,
        client: &DaemonClient,
        args: &GenericSessionCreateArgs,
    ) -> Result<(), CliError> {
        let mut request = args.request.to_request()?;
        Self::set_initial_terminal_size(&mut request, false)?;
        let response = client
            .session_create(request, &args.idempotency_key)
            .await
            .context(DaemonClientSnafu)?;
        Self::write_create(response);
        Ok(())
    }

    fn set_initial_terminal_size(
        request: &mut SessionCreateRequest,
        require_terminal: bool,
    ) -> Result<(), CliError> {
        if !request.tty {
            return Ok(());
        }
        let terminal_size = if require_terminal {
            InteractiveTerminal::current_size()?
        } else {
            InteractiveTerminal::current_size_or_default()?
        };
        request.terminal_rows = u32::from(terminal_size.rows());
        request.terminal_columns = u32::from(terminal_size.columns());
        Ok(())
    }

    async fn run_generic(
        &self,
        client: &DaemonClient,
        args: &SessionRunArgs,
    ) -> Result<(), CliError> {
        let mut request = args.request.to_request()?;
        let static_association = !request.agent_name.is_empty();
        Self::set_initial_terminal_size(&mut request, !args.request.detached)?;
        let key = args.idempotency_key.as_str();
        let created = client
            .session_create(request, key)
            .await
            .context(DaemonClientSnafu)?;
        Self::write_create(created.clone());
        if static_association {
            return Ok(());
        }
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

    async fn run_codex_agent(client: &DaemonClient, args: &CodexRunArgs) -> Result<(), CliError> {
        let app_server = args.app_server;
        let workspace = args.workspace.clone().unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_error| std::path::PathBuf::from("."))
        });
        let key = format!("codex-run-{}", Uuid::new_v4());
        let terminal_size = if app_server {
            None
        } else if args.detached {
            Some(InteractiveTerminal::current_size_or_default()?)
        } else {
            Some(InteractiveTerminal::current_size()?)
        };
        let created = client
            .codex_run(
                CodexRunRequest {
                    agent_name: args.agent_name.clone(),
                    workspace: workspace.display().to_string(),
                    policy_set_name: args.policy.clone(),
                    daemon_failure_mode: args.failure_mode.clone(),
                    requested_loss_grace_seconds: args.loss_grace_seconds,
                    tty: !app_server,
                    detached: args.detached,
                    terminal_rows: terminal_size.map_or(0, |size| u32::from(size.rows())),
                    terminal_columns: terminal_size.map_or(0, |size| u32::from(size.columns())),
                    app_server,
                    environment: std::env::var("PATH")
                        .ok()
                        .filter(|path| !path.is_empty())
                        .map(|path| {
                            vec![SessionEnvironmentEntry {
                                key: String::from("PATH"),
                                value: path,
                            }]
                        })
                        .unwrap_or_default(),
                    caller_home_sources: args
                        .caller_home_sources
                        .iter()
                        .map(Self::caller_home_source)
                        .collect(),
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
        let terminal = matches!(
            started.state.as_str(),
            "succeeded" | "failed" | "interrupted" | "removed"
        );
        if !app_server {
            Self::write_record(started);
        }
        if !args.detached {
            let client_instance_id = format!("erebor-cli-{}", std::process::id());
            if app_server {
                if terminal {
                    let mut stdout_cursor = 0;
                    let mut stderr_cursor = 0;
                    Self::drain_codex_app_server_logs(
                        client,
                        &created.session_id,
                        &mut stdout_cursor,
                        &mut stderr_cursor,
                    )
                    .await?;
                    return Ok(());
                }
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
            .await;
        let attachment = match attachment {
            Ok(attachment) => attachment,
            Err(source) => {
                let mut stdout_cursor = 0;
                let mut stderr_cursor = 0;
                if Self::drain_if_codex_app_server_terminal(
                    client,
                    session_id,
                    &mut stdout_cursor,
                    &mut stderr_cursor,
                )
                .await?
                {
                    return Ok(());
                }
                return Err(source).context(DaemonClientSnafu);
            }
        };
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
            for _ in 0..APP_SERVER_INPUT_BATCH_SIZE {
                if interrupt_sent || input_closed {
                    break;
                }
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
                            .await;
                        if response.is_err()
                            && Self::drain_if_codex_app_server_terminal(
                                client,
                                &attachment.session_id,
                                &mut stdout_cursor,
                                &mut stderr_cursor,
                            )
                            .await?
                        {
                            return Ok(());
                        }
                        let response = response.context(DaemonClientSnafu)?;
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
                            .await;
                        if response.is_err()
                            && Self::drain_if_codex_app_server_terminal(
                                client,
                                &attachment.session_id,
                                &mut stdout_cursor,
                                &mut stderr_cursor,
                            )
                            .await?
                        {
                            return Ok(());
                        }
                        let response = response.context(DaemonClientSnafu)?;
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
                            source,
                            location: snafu::Location::default(),
                        });
                    }
                }
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
                Self::drain_codex_app_server_logs(
                    client,
                    &attachment.session_id,
                    &mut stdout_cursor,
                    &mut stderr_cursor,
                )
                .await?;
                return Ok(());
            }
            if Instant::now() >= renew_at {
                renewal = renewal.saturating_add(1);
                let renewal_result = client
                    .session_input_lease_renew(
                        SessionInputLeaseRenewRequest {
                            session_id: attachment.session_id.clone(),
                            input_lease_id: attachment.input_lease_id.clone(),
                            client_instance_id: client_instance_id.to_owned(),
                        },
                        &format!("{key}:app-server-lease-renew-{renewal}"),
                    )
                    .await;
                if renewal_result.is_err()
                    && matches!(
                        client
                            .session_inspect(&attachment.session_id)
                            .await
                            .context(DaemonClientSnafu)?
                            .state
                            .as_str(),
                        "succeeded" | "failed" | "interrupted" | "removed"
                    )
                {
                    Self::drain_codex_app_server_logs(
                        client,
                        &attachment.session_id,
                        &mut stdout_cursor,
                        &mut stderr_cursor,
                    )
                    .await?;
                    return Ok(());
                }
                renewal_result.context(DaemonClientSnafu)?;
                renew_at = Instant::now() + Duration::from_secs(10);
            }
            tokio::select! {
                _ = &mut interrupt, if !interrupt_sent => {
                    client
                        .session_stop(
                            &attachment.session_id,
                            2,
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

    async fn drain_codex_app_server_logs(
        client: &DaemonClient,
        session_id: &str,
        stdout_cursor: &mut u64,
        stderr_cursor: &mut u64,
    ) -> Result<(), CliError> {
        loop {
            let previous = *stdout_cursor;
            *stdout_cursor = Self::write_stream_page(
                client
                    .session_logs(session_id, "stdout", previous, 256)
                    .await
                    .context(DaemonClientSnafu)?,
            )?;
            if *stdout_cursor == previous {
                break;
            }
        }
        loop {
            let previous = *stderr_cursor;
            *stderr_cursor = Self::write_stream_page_to_stderr(
                client
                    .session_logs(session_id, "stderr", previous, 256)
                    .await
                    .context(DaemonClientSnafu)?,
            )?;
            if *stderr_cursor == previous {
                break;
            }
        }
        Ok(())
    }

    async fn drain_if_codex_app_server_terminal(
        client: &DaemonClient,
        session_id: &str,
        stdout_cursor: &mut u64,
        stderr_cursor: &mut u64,
    ) -> Result<bool, CliError> {
        let record = client
            .session_inspect(session_id)
            .await
            .context(DaemonClientSnafu)?;
        if !matches!(
            record.state.as_str(),
            "succeeded" | "failed" | "interrupted" | "removed"
        ) {
            return Ok(false);
        }
        Self::drain_codex_app_server_logs(client, session_id, stdout_cursor, stderr_cursor).await?;
        Ok(true)
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
        let mut terminal_size = None;
        if let Some(size) = terminal
            .as_ref()
            .map(InteractiveTerminal::size)
            .transpose()?
        {
            Self::resize_terminal(client, &attachment, client_instance_id, size).await?;
            terminal_size = Some(size);
        }
        let mut stdout_cursor = after_output_sequence;
        let mut stderr_cursor = after_output_sequence;
        let mut renew_at = Instant::now() + Duration::from_secs(10);
        let mut renewal = 0_u64;
        let mut interrupt_sent = false;
        let interrupt = tokio::signal::ctrl_c();
        tokio::pin!(interrupt);
        loop {
            if let Some(terminal) = terminal.as_ref() {
                let size = terminal.size()?;
                if terminal_size != Some(size) {
                    Self::resize_terminal(client, &attachment, client_instance_id, size).await?;
                    terminal_size = Some(size);
                }
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

    async fn resize_terminal(
        client: &DaemonClient,
        attachment: &erebor_runtime_ipc::v1::SessionAttachResponse,
        client_instance_id: &str,
        terminal_size: TerminalSize,
    ) -> Result<(), CliError> {
        let response = client
            .session_terminal_resize(SessionTerminalResizeRequest {
                session_id: attachment.session_id.clone(),
                input_lease_id: attachment.input_lease_id.clone(),
                client_instance_id: client_instance_id.to_owned(),
                rows: u32::from(terminal_size.rows()),
                columns: u32::from(terminal_size.columns()),
            })
            .await
            .context(DaemonClientSnafu)?;
        if response.session_id != attachment.session_id
            || response.rows != u32::from(terminal_size.rows())
            || response.columns != u32::from(terminal_size.columns())
        {
            return InvalidSessionCommandSnafu {
                reason: String::from("daemon did not acknowledge the exact terminal resize"),
            }
            .fail();
        }
        Ok(())
    }

    fn write_stream_page(page: erebor_runtime_client::SessionLogPage) -> Result<u64, CliError> {
        Self::require_complete_stream_page(&page)?;
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
        Self::require_complete_stream_page(&page)?;
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

    fn require_complete_stream_page(
        page: &erebor_runtime_client::SessionLogPage,
    ) -> Result<(), CliError> {
        if page.end.truncated_before_cursor {
            return InvalidSessionCommandSnafu {
                reason: format!(
                    "{} output rotated before the attachment consumed it",
                    page.end.stream
                ),
            }
            .fail();
        }
        Ok(())
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

    async fn context_deliveries(
        &self,
        client: &DaemonClient,
        args: &SessionContextArgs,
    ) -> Result<(), CliError> {
        match &args.command {
            SessionContextCommand::Graph(args) => self.context_graph(client, args).await?,
            SessionContextCommand::Inbox(args) => {
                let deliveries = client
                    .context_delivery_inbox(&args.parent_session_id)
                    .await
                    .context(DaemonClientSnafu)?
                    .deliveries;
                let mut table = Self::table();
                table.set_header([
                    "PARENT SCOPE",
                    "CHILD SCOPE",
                    "DELIVERY",
                    "CHILD PIN",
                    "PARENT PIN",
                ]);
                for delivery in deliveries {
                    table.add_row([
                        delivery.receiver_scope,
                        delivery.child_scope,
                        delivery.delivery_path,
                        delivery.delivery_commit,
                        delivery.expected_parent_head,
                    ]);
                }
                println!("{table}");
            }
            SessionContextCommand::Receive(args) => {
                let decision = client
                    .context_delivery_receive(
                        ContextDeliveryReceiveRequest {
                            parent_session_id: args.parent_session_id.clone(),
                            delivery_path: args.delivery_path.clone(),
                            delivery_commit: args.delivery_commit.clone(),
                            expected_parent_head: args.expected_parent_head.clone(),
                        },
                        &args.idempotency_key,
                    )
                    .await
                    .context(DaemonClientSnafu)?;
                println!(
                    "parent_head={} receipt_path={} rejected={}",
                    decision.parent_head, decision.receipt_path, decision.rejected
                );
            }
            SessionContextCommand::Reject(args) => {
                let decision = client
                    .context_delivery_reject(
                        ContextDeliveryRejectRequest {
                            parent_session_id: args.decision.parent_session_id.clone(),
                            delivery_path: args.decision.delivery_path.clone(),
                            delivery_commit: args.decision.delivery_commit.clone(),
                            expected_parent_head: args.decision.expected_parent_head.clone(),
                            reason: args.reason.clone(),
                        },
                        &args.decision.idempotency_key,
                    )
                    .await
                    .context(DaemonClientSnafu)?;
                println!(
                    "parent_head={} receipt_path={} rejected={}",
                    decision.parent_head, decision.receipt_path, decision.rejected
                );
            }
        }
        Ok(())
    }

    async fn context_graph(
        &self,
        client: &DaemonClient,
        args: &SessionContextGraphArgs,
    ) -> Result<(), CliError> {
        let graph = client
            .context_graph(&args.session_id)
            .await
            .context(DaemonClientSnafu)?;
        Self::write_context_graph(graph);
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
        let mut table = Self::table();
        table.set_header(["ID", "STATE", "GENERATION", "RETRY EXPIRES (MS)"]);
        table.add_row([
            record.session_id,
            record.state,
            record.generation.to_string(),
            record.retry_guarantee_expires_unix_ms.to_string(),
        ]);
        println!("{table}");
    }

    fn write_record(record: SessionRecord) {
        Self::write_records(&[record]);
    }

    fn write_records(records: &[SessionRecord]) {
        let mut table = Self::table();
        table.set_header([
            "ID",
            "STATE",
            "GEN",
            "OWNER",
            "API",
            "KIND",
            "AGENT",
            "POLICYSET",
            "SURFACES",
            "RUNNER",
            "RETAINED",
            "FAILURE",
        ]);
        for record in records {
            table.add_row([
                Self::short_id(&record.session_id),
                record.state.clone(),
                record.generation.to_string(),
                record.owner_uid.to_string(),
                Self::empty_as_dash(&record.api_version),
                Self::empty_as_dash(&record.kind),
                Self::empty_as_dash(&record.agent_name),
                Self::empty_as_dash(&record.policy_set_name),
                if record.surface_names.is_empty() {
                    String::from("-")
                } else {
                    record.surface_names.join(",")
                },
                record.runner_id.clone(),
                record.retention_hold.to_string(),
                if record.failure.is_empty() {
                    String::from("-")
                } else {
                    record.failure.clone()
                },
            ]);
        }
        println!("{table}");
    }

    fn empty_as_dash(value: &str) -> String {
        if value.is_empty() {
            String::from("-")
        } else {
            value.to_owned()
        }
    }

    fn write_context_graph(graph: ContextGraphResponse) {
        for line in Self::context_graph_lines(graph) {
            println!("{line}");
        }
    }

    fn context_graph_lines(graph: ContextGraphResponse) -> Vec<String> {
        let ContextGraphResponse {
            root_scope,
            nodes,
            activities: graph_activities,
        } = graph;
        let Some(root_index) = nodes.iter().position(|node| node.scope == root_scope) else {
            return vec![String::from(
                "Context DAG is unavailable: daemon response has no root node",
            )];
        };
        let tree = ContextGraphTree::new(&nodes, graph_activities);
        let session = root_scope
            .strip_prefix("refs/scopes/")
            .and_then(|scope| scope.split_once('/'))
            .map_or(root_scope.as_str(), |(session, _rest)| session);
        let mut lines = vec![format!("CONTEXT DAG  {}", Self::short_id(session))];
        Self::write_context_graph_node(&nodes, &tree, root_index, "", true, &mut lines);
        lines
    }

    fn write_context_graph_node(
        nodes: &[ContextScopeGraphNode],
        tree: &ContextGraphTree,
        index: usize,
        prefix: &str,
        is_last: bool,
        lines: &mut Vec<String>,
    ) {
        let node = &nodes[index];
        let is_root = node.parent_scope.is_empty();
        let branch = if is_root {
            "●"
        } else if is_last {
            "└─●"
        } else {
            "├─●"
        };
        let label = Self::short_scope(&node.scope);
        let mut detail = format!("HEAD {}", Self::short_id(&node.head_commit));
        if !node.fork_parent_commit.is_empty() {
            detail.push_str(&format!(
                "  FROM {}",
                Self::short_id(&node.fork_parent_commit)
            ));
        }
        if !node.execution_binding.is_empty() {
            detail.push_str(&format!("  {}", node.execution_binding));
        }
        if !node.source_identity.is_empty() {
            detail.push_str(&format!("  {}", node.source_identity));
        }
        lines.push(format!("{prefix}{branch} {label}  {detail}"));
        let scope_activities = tree
            .activities
            .get(&node.scope)
            .map_or(&[][..], Vec::as_slice);
        let child_indexes = tree
            .children
            .get(&node.scope)
            .map_or(&[][..], Vec::as_slice);
        let entry_count = scope_activities.len() + child_indexes.len();
        if entry_count == 0 {
            return;
        }
        let child_prefix = if is_root {
            String::new()
        } else if is_last {
            format!("{prefix}   ")
        } else {
            format!("{prefix}│  ")
        };
        for (offset, activity) in scope_activities.iter().enumerate() {
            let entry_is_last = offset + 1 == entry_count;
            let branch = if entry_is_last { "└─" } else { "├─" };
            lines.push(format!("{child_prefix}{branch} {}", activity.summary));
            if activity.tool_use_id.is_empty() {
                continue;
            }
            let anchored_children = tree
                .activity_children
                .get(&(node.scope.clone(), activity.tool_use_id.clone()))
                .map_or(&[][..], Vec::as_slice);
            let activity_prefix = if entry_is_last {
                format!("{child_prefix}   ")
            } else {
                format!("{child_prefix}│  ")
            };
            for (child_offset, child_index) in anchored_children.iter().enumerate() {
                Self::write_context_graph_node(
                    nodes,
                    tree,
                    *child_index,
                    &activity_prefix,
                    child_offset + 1 == anchored_children.len(),
                    lines,
                );
            }
        }
        for (offset, child_index) in child_indexes.iter().enumerate() {
            Self::write_context_graph_node(
                nodes,
                tree,
                *child_index,
                &child_prefix,
                scope_activities.len() + offset + 1 == entry_count,
                lines,
            );
        }
    }

    fn table() -> Table {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic);
        table
    }

    fn short_id(value: &str) -> String {
        value
            .strip_prefix("session-")
            .unwrap_or(value)
            .chars()
            .take(12)
            .collect()
    }

    fn short_scope(scope: &str) -> String {
        let Some((_session, leaf)) = scope
            .strip_prefix("refs/scopes/")
            .and_then(|scope| scope.split_once('/'))
        else {
            return Self::short_id(scope);
        };
        if leaf == "root" {
            return String::from("root");
        }
        let Some(identifier) = leaf.strip_prefix("scope/") else {
            return Self::short_id(leaf);
        };
        if let Some(hash) = identifier.strip_prefix("codex-operation-") {
            return format!("codex-operation-{}", Self::short_id(hash));
        }
        Self::short_id(identifier)
    }

    fn caller_home_source(source: &args::CallerHomeSourceArg) -> CallerHomeFilesystemSource {
        CallerHomeFilesystemSource {
            relative_path: source.relative_path.clone(),
            kind: source.kind.clone(),
            access: source.access.clone(),
        }
    }
}

impl GenericSessionRequestArgs {
    fn is_static_association(&self) -> Result<bool, CliError> {
        let static_association =
            self.agent.is_some() || self.policy.is_some() || !self.surfaces.is_empty();
        if static_association {
            if self.agent.is_none() || self.policy.is_none() {
                return InvalidSessionCommandSnafu {
                    reason: String::from(
                        "a static Session association requires both --agent and --policy",
                    ),
                }
                .fail();
            }
            if self.runner.is_some()
                || self.workspace.is_some()
                || !self.command.is_empty()
                || self.failure_mode.is_some()
                || self.loss_grace_seconds.is_some()
                || !self.environment.is_empty()
                || !self.caller_home_sources.is_empty()
                || !self.secret_references.is_empty()
                || self.tty
                || self.detached
            {
                return InvalidSessionCommandSnafu {
                    reason: String::from(
                        "a static Session association accepts only --agent, --policy, and optional --surface",
                    ),
                }
                .fail();
            }
            return Ok(true);
        }
        if self.runner.is_none() || self.workspace.is_none() || self.command.is_empty() {
            return InvalidSessionCommandSnafu {
                reason: String::from(
                    "a generic Session requires --runner, --workspace, and a command",
                ),
            }
            .fail();
        }
        Ok(false)
    }

    fn to_request(&self) -> Result<SessionCreateRequest, CliError> {
        let static_association = self.is_static_association()?;
        Ok(SessionCreateRequest {
            runner_id: self
                .runner
                .as_ref()
                .map_or_else(String::new, |runner| runner.as_str().to_owned()),
            command: self.command.clone(),
            workspace: self
                .workspace
                .as_ref()
                .map_or_else(String::new, |workspace| workspace.display().to_string()),
            daemon_failure_mode: if static_association {
                String::new()
            } else {
                self.failure_mode
                    .clone()
                    .unwrap_or_else(|| String::from("terminate"))
            },
            requested_loss_grace_seconds: if static_association {
                0
            } else {
                self.loss_grace_seconds.unwrap_or(2)
            },
            environment: self
                .environment
                .iter()
                .map(|(key, value)| SessionEnvironmentEntry {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect(),
            secret_references: self.secret_references.clone(),
            tty: self.tty,
            detached: self.detached,
            terminal_rows: 0,
            terminal_columns: 0,
            agent_name: self.agent.clone().unwrap_or_default(),
            policy_set_name: self.policy.clone().unwrap_or_default(),
            surface_names: self.surfaces.clone(),
            caller_home_sources: self
                .caller_home_sources
                .iter()
                .map(SessionCommandOwner::caller_home_source)
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests;
