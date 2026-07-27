use std::{
    collections::BTreeMap,
    io::{self, Write},
    time::{Duration, Instant},
};

use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, ContentArrangement, Table};
use erebor_runtime_client::DaemonClient;
use erebor_runtime_core::TerminalSize;
use erebor_runtime_ipc::v1::{
    CodexAppServerAttachRequest, CodexAppServerInputCloseRequest, CodexAppServerInputRequest,
    CodexRunRequest, ContextDeliveryReceiveRequest, ContextDeliveryRejectRequest,
    ContextGraphActivity, ContextGraphResponse, ContextScopeGraphNode, SessionAttachRequest,
    SessionCreateRequest, SessionEnvironmentEntry, SessionInputLeaseReleaseRequest,
    SessionInputLeaseRenewRequest, SessionInputRequest, SessionPruneRequest, SessionRecord,
    SessionTerminalResizeRequest,
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
        let mut request = args.request.to_request();
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
        let mut request = args.request.to_request();
        Self::set_initial_terminal_size(&mut request, !args.request.detached)?;
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
            "ID", "STATE", "GEN", "OWNER", "RUNNER", "RETAINED", "FAILURE",
        ]);
        for record in records {
            table.add_row([
                Self::short_id(&record.session_id),
                record.state.clone(),
                record.generation.to_string(),
                record.owner_uid.to_string(),
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
}

impl GenericSessionRequestArgs {
    fn to_request(&self) -> SessionCreateRequest {
        SessionCreateRequest {
            runner_id: self.runner.as_str().to_owned(),
            command: self.command.clone(),
            workspace: self.workspace.display().to_string(),
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
            tty: self.tty,
            detached: self.detached,
            terminal_rows: 0,
            terminal_columns: 0,
        }
    }
}

#[cfg(test)]
mod tests;
