use std::path::PathBuf;

use araphor_data::{PackageBundleV1, PackageRequestV1, PackageResponseV1};
use clap::{Args, Subcommand};
use snafu::{OptionExt as _, ResultExt as _};

use super::args::{Prepared, SelectionArgs};
use super::error::{
    ClientSnafu, EncodeSnafu, InterruptedSnafu, InvalidSnafu, PackageSnafu, ProtocolSnafu, Result,
};
use super::{wire, CommandRun};

#[derive(Debug, Args)]
pub(crate) struct PackageArgs {
    #[arg(long, global = true)]
    scope: Option<String>,
    #[command(flatten)]
    selection: SelectionArgs,
    #[command(subcommand)]
    operation: PackageCommand,
}

#[derive(Debug, Subcommand)]
enum PackageCommand {
    /// Read the digest used in Control package trust pins.
    Digest { path: PathBuf },
    /// Admit a built JSON file or directory and activate its SQL exports.
    Install {
        path: PathBuf,
        #[arg(long)]
        parameters: Option<String>,
    },
    /// Read descriptors, dependencies, coverage, and readiness.
    Inspect { package: String },
    /// Query typed outputs from a current or historical result.
    Query {
        package: String,
        export: String,
        sql: String,
        #[arg(long)]
        result_id: Option<String>,
    },
    /// Evaluate active exports with an explicit retry identity.
    Run {
        package: String,
        #[arg(long)]
        export: Option<String>,
        #[arg(long)]
        evaluation_id: String,
        #[arg(long)]
        parameters: Option<String>,
    },
    /// Prepare and activate a new built revision.
    Update { path: PathBuf },
    /// Activate an admitted historical revision.
    Rollback { package: String, revision: String },
    /// Stop execution and retain referenced history.
    Remove { package: String },
    /// Run declared fixtures through the admitted evaluator.
    Test {
        package: String,
        #[arg(long)]
        fixture: Option<String>,
    },
}

impl PackageArgs {
    pub(super) fn prepare(&self) -> Result<Prepared> {
        if let PackageCommand::Digest { path } = &self.operation {
            if self.scope.is_some() || self.selection.selected() {
                return InvalidSnafu {
                    field: "digest does not accept a scope or input selection",
                }
                .fail();
            }
            let digest = PackageBundleV1::read(path)
                .context(PackageSnafu)?
                .digest()
                .context(PackageSnafu)?;
            return Ok(Prepared::PackageDigest(digest));
        }
        let scope_id = self
            .scope
            .clone()
            .filter(|scope| !scope.is_empty())
            .context(InvalidSnafu {
                field: "package scope is required",
            })?;
        let operation = match &self.operation {
            PackageCommand::Install { path, parameters } => PackageRequestV1::Install {
                scope_id,
                bundle: PackageBundleV1::read(path).context(PackageSnafu)?,
                parameters: Self::parameters(parameters)?,
            },
            PackageCommand::Inspect { package } => PackageRequestV1::Inspect {
                scope_id,
                package_id: package.clone(),
            },
            PackageCommand::Query {
                package,
                export,
                sql,
                result_id,
            } => PackageRequestV1::Query {
                scope_id,
                package_id: package.clone(),
                export: export.clone(),
                sql: sql.clone(),
                result_id: result_id.clone(),
            },
            PackageCommand::Run {
                package,
                export,
                evaluation_id,
                parameters,
            } => PackageRequestV1::Run {
                scope_id,
                package_id: package.clone(),
                export: export.clone(),
                evaluation_id: evaluation_id.clone(),
                parameters: Self::parameters(parameters)?,
            },
            PackageCommand::Update { path } => PackageRequestV1::Update {
                scope_id,
                bundle: PackageBundleV1::read(path).context(PackageSnafu)?,
            },
            PackageCommand::Rollback { package, revision } => PackageRequestV1::Rollback {
                scope_id,
                package_id: package.clone(),
                revision: revision.clone(),
            },
            PackageCommand::Remove { package } => PackageRequestV1::Remove {
                scope_id,
                package_id: package.clone(),
            },
            PackageCommand::Test { package, fixture } => PackageRequestV1::Test {
                scope_id,
                package_id: package.clone(),
                fixture: fixture.clone(),
            },
            PackageCommand::Digest { .. } => unreachable!("digest is a local operation"),
        };
        Ok(Prepared::Package(wire::PackageOperationRequest {
            definition_json: serde_json::to_vec(&operation).context(EncodeSnafu)?,
            selection: Some((&self.selection).try_into()?),
        }))
    }

    fn parameters(value: &Option<String>) -> Result<Option<serde_json::Value>> {
        value
            .as_deref()
            .map(|value| {
                serde_json::from_str(value).map_err(|_| {
                    InvalidSnafu {
                        field: "package parameter JSON",
                    }
                    .build()
                })
            })
            .transpose()
    }
}

impl CommandRun {
    pub(super) async fn package(&mut self, request: wire::PackageOperationRequest) -> Result<()> {
        let response = tokio::select! {
            _ = self.signal.as_mut() => return InterruptedSnafu.fail(),
            result = self.client.package_operation(request) => result.context(ClientSnafu)?,
        };
        let response: PackageResponseV1 =
            serde_json::from_slice(&response.result_json).map_err(|_| {
                ProtocolSnafu {
                    field: "package result JSON",
                }
                .build()
            })?;
        let bytes = self.output.package(response)?;
        self.output.write(&bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser as _;

    #[test]
    fn package_cli_incomplete_commands() {
        for args in [
            vec!["araphor", "package"],
            vec!["araphor", "package", "install"],
            vec!["araphor", "package", "run", "denials"],
            vec!["araphor", "package", "rollback", "denials"],
            vec!["araphor", "package", "inspect", "denials", "--unknown"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn package_cli_shared_contract() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "araphor",
            "package",
            "run",
            "denials",
            "--scope",
            "team",
            "--evaluation-id",
            "retry-1",
            "--parameters",
            "{\"threshold\":3}",
        ])?;
        let Command::Investigate(command) = cli.command else {
            return Err("package command absent".into());
        };
        let Prepared::Package(request) = command.prepare()? else {
            return Err("package request absent".into());
        };
        let operation: PackageRequestV1 = serde_json::from_slice(&request.definition_json)?;
        assert!(
            matches!(operation, PackageRequestV1::Run { scope_id, package_id, evaluation_id, .. }
            if scope_id == "team" && package_id == "denials" && evaluation_id == "retry-1")
        );
        let cli = Cli::try_parse_from(["araphor", "package", "inspect", "denials"])?;
        let Command::Investigate(command) = cli.command else {
            return Err("package command absent".into());
        };
        assert!(command.prepare().is_err());
        Ok(())
    }
}
