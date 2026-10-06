use clap::{Args, Subcommand};
use erebor_runtime_client::DaemonClient;
use snafu::ResultExt;

use crate::{
    cli::parse_non_empty_string,
    error::{CliError, DaemonClientSnafu, DaemonRuntimeSnafu},
};

#[derive(Debug, Args)]
pub(super) struct SurfaceArgs {
    #[command(subcommand)]
    command: SurfaceCommand,
}

impl SurfaceArgs {
    pub(super) fn display(&self) -> String {
        match &self.command {
            SurfaceCommand::Create(args) => format!("surface create {}", args.name),
            SurfaceCommand::List => String::from("surface ls"),
            SurfaceCommand::Inspect(args) => format!("surface inspect {}", args.name),
        }
    }
}

#[derive(Debug, Subcommand)]
enum SurfaceCommand {
    /// Create one immutable independently configured Surface record.
    Create(SurfaceCreateArgs),
    /// List independent Surface records visible to the caller.
    #[command(alias = "ls")]
    List,
    /// Show one independent Surface record selected by name.
    Inspect(SurfaceNameArgs),
}

#[derive(Debug, Args)]
struct SurfaceCreateArgs {
    /// Immutable owner-scoped Surface name.
    #[arg(value_parser = parse_non_empty_string)]
    name: String,
    /// Registered Surface type. Phase 5.2 accepts browser_cdp only.
    #[arg(long = "type", value_parser = parse_non_empty_string)]
    surface_type: String,
    /// Stable key reused only after an uncertain create result.
    #[arg(long, value_parser = parse_non_empty_string)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct SurfaceNameArgs {
    #[arg(value_parser = parse_non_empty_string)]
    name: String,
}

pub(super) struct SurfaceCommandOwner<'a> {
    args: &'a SurfaceArgs,
    client: &'a DaemonClient,
}

impl<'a> SurfaceCommandOwner<'a> {
    pub(super) const fn new(args: &'a SurfaceArgs, client: &'a DaemonClient) -> Self {
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

    async fn execute_daemon(&self) -> Result<(), CliError> {
        match &self.args.command {
            SurfaceCommand::Create(args) => {
                let surface = self
                    .client
                    .surface_create(&args.name, &args.surface_type, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?;
                Self::write_surface(&surface.name, &surface.surface_type);
            }
            SurfaceCommand::List => {
                for surface in self
                    .client
                    .surface_list()
                    .await
                    .context(DaemonClientSnafu)?
                    .surfaces
                {
                    Self::write_surface(&surface.name, &surface.surface_type);
                }
            }
            SurfaceCommand::Inspect(args) => {
                let surface = self
                    .client
                    .surface_inspect(&args.name)
                    .await
                    .context(DaemonClientSnafu)?;
                Self::write_surface(&surface.name, &surface.surface_type);
            }
        }
        Ok(())
    }

    fn write_surface(name: &str, surface_type: &str) {
        println!("surface={name} type={surface_type}");
    }
}
