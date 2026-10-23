use std::path::PathBuf;

use araphor_data::{PackageBundleV1, PackageRequestV1, PackageResponseV1};
use clap::{Args, Subcommand};
use snafu::ResultExt as _;

use super::args::Prepared;
use super::error::{ClientSnafu, InterruptedSnafu, PackageSnafu, ProtocolSnafu, Result};
use super::{wire, CommandRun};

#[derive(Debug, Args)]
pub(crate) struct DefinitionArgs {
    #[command(subcommand)]
    operation: DefinitionCommand,
}

#[derive(Debug, Subcommand)]
enum DefinitionCommand {
    /// Capture local source files and admit the definition without starting it.
    Admit { path: PathBuf },
    /// Read an admitted definition and its exact image references.
    Inspect {
        name: String,
        #[arg(long)]
        revision: Option<String>,
    },
}

impl DefinitionArgs {
    pub(super) fn prepare(&self) -> Result<Prepared> {
        let operation = match &self.operation {
            DefinitionCommand::Admit { path } => PackageRequestV1::AdmitDefinition {
                definition: araphor_discovery_definition::Definition::read(path)
                    .map_err(araphor_data::Error::from)
                    .context(PackageSnafu)?,
            },
            DefinitionCommand::Inspect { name, revision } => PackageRequestV1::InspectDefinition {
                name: name.clone(),
                revision: revision.clone(),
            },
        };
        Ok(Prepared::Package(wire::PackageOperationRequest {
            definition: operation.encode().context(PackageSnafu)?,
            selection: None,
        }))
    }
}

#[derive(Debug, Args)]
pub(crate) struct ImageArgs {
    #[command(subcommand)]
    operation: ImageCommand,
}

#[derive(Debug, Subcommand)]
enum ImageCommand {
    /// Read the digest used in Control package trust pins.
    Digest { path: PathBuf },
    /// Retain a local OCI layout or archive for the authenticated tenant.
    Install { path: PathBuf },
    /// Remove installed access to one exact image. Retain admitted programs and history.
    Uninstall {
        package: String,
        #[arg(long)]
        revision: String,
        #[arg(long)]
        digest: String,
    },
    /// Run saved fixtures from one exact retained image.
    Test {
        package: String,
        #[arg(long)]
        revision: String,
        #[arg(long, requires = "artifact_revision")]
        artifact: Option<String>,
        #[arg(long, requires = "artifact")]
        artifact_revision: Option<String>,
        #[arg(long)]
        fixture: Option<String>,
    },
    /// Read retained image descriptors and artifact identities.
    Inspect {
        package: String,
        #[arg(long)]
        revision: Option<String>,
    },
}

impl ImageArgs {
    pub(super) fn prepare(&self) -> Result<Prepared> {
        let operation = match &self.operation {
            ImageCommand::Digest { path } => {
                let digest = PackageBundleV1::read(path)
                    .map_err(araphor_data::Error::from)
                    .context(PackageSnafu)?
                    .digest()
                    .map_err(araphor_data::Error::from)
                    .context(PackageSnafu)?;
                return Ok(Prepared::PackageDigest(digest));
            }
            ImageCommand::Install { path } => PackageRequestV1::InstallImage {
                bundle: PackageBundleV1::read(path)
                    .map_err(araphor_data::Error::from)
                    .context(PackageSnafu)?,
            },
            ImageCommand::Uninstall {
                package,
                revision,
                digest,
            } => {
                let image = araphor_discovery_definition::ImagePin {
                    image: araphor_data::PackageRefV1 {
                        package_id: package.clone(),
                        revision: revision.clone(),
                    },
                    digest: digest.clone(),
                };
                image
                    .validate()
                    .map_err(araphor_data::Error::from)
                    .context(PackageSnafu)?;
                PackageRequestV1::UninstallImage { image }
            }
            ImageCommand::Test {
                package,
                revision,
                artifact,
                artifact_revision,
                fixture,
            } => PackageRequestV1::TestImage {
                image: araphor_data::PackageRefV1 {
                    package_id: package.clone(),
                    revision: revision.clone(),
                },
                artifact: artifact.as_ref().zip(artifact_revision.as_ref()).map(
                    |(package, revision)| araphor_data::PackageRefV1 {
                        package_id: package.clone(),
                        revision: revision.clone(),
                    },
                ),
                fixture: fixture.clone(),
            },
            ImageCommand::Inspect { package, revision } => PackageRequestV1::InspectImage {
                package_id: package.clone(),
                revision: revision.clone(),
            },
        };
        Ok(Prepared::Package(wire::PackageOperationRequest {
            definition: operation.encode().context(PackageSnafu)?,
            selection: None,
        }))
    }
}

#[derive(Debug, Args)]
pub(crate) struct InstanceArgs {
    #[command(subcommand)]
    operation: InstanceCommand,
}

#[derive(Debug, Args)]
struct InstanceLifecycle {
    instance: String,
    #[arg(long)]
    lifecycle: u64,
}

#[derive(Debug, Subcommand)]
enum InstanceCommand {
    /// Admit one stopped instance from an exact saved definition.
    Admit {
        instance: String,
        #[arg(long)]
        definition: String,
        #[arg(long)]
        revision: String,
    },
    /// Start the saved instance and retain its execution grant.
    Start(InstanceLifecycle),
    /// Stop and join the saved instance. Retain its history.
    Stop(InstanceLifecycle),
    /// Run one finite step with the saved execution grant.
    Run {
        #[command(flatten)]
        target: InstanceLifecycle,
        evaluation: String,
        #[arg(long)]
        rebuild: bool,
    },
    /// Replace the grant of an exact stopped and joined instance.
    Renew(InstanceLifecycle),
    /// Evaluate an exact definition and replace the instance on success.
    Update {
        #[command(flatten)]
        target: InstanceLifecycle,
        #[arg(long)]
        definition: String,
        #[arg(long)]
        revision: String,
        #[arg(long)]
        rebuild: bool,
    },
    /// Evaluate an exact retained generation and replace the instance on success.
    Rollback {
        #[command(flatten)]
        target: InstanceLifecycle,
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        rebuild: bool,
    },
    /// Stop and remove the exact instance lifecycle. Retain its history.
    Remove(InstanceLifecycle),
    /// Admit a fresh stopped instance after an explicit removal.
    Recreate {
        #[command(flatten)]
        target: InstanceLifecycle,
        #[arg(long)]
        definition: String,
        #[arg(long)]
        revision: String,
    },
    /// Read current lifecycle, progress, and readiness without running the instance.
    Inspect { instance: String },
    /// List original successful receipts without running the instance.
    History { instance: String },
    /// Read every output, evidence link, reason, and checkpoint of an exact retained call.
    Read { instance: String, result: String },
    /// Run one local SELECT over an exact result or the current selected output.
    #[command(allow_missing_positional = true)]
    Query {
        instance: String,
        result: Option<String>,
        sql: String,
    },
}

impl InstanceArgs {
    pub(super) fn prepare(&self) -> Result<Prepared> {
        let operation = match &self.operation {
            InstanceCommand::Admit {
                instance,
                definition,
                revision,
            } => PackageRequestV1::AdmitInstance {
                instance_id: instance.clone(),
                definition_name: definition.clone(),
                definition_revision: revision.clone(),
            },
            InstanceCommand::Start(target) => PackageRequestV1::StartInstance {
                instance_id: target.instance.clone(),
                expected_lifecycle: target.lifecycle,
            },
            InstanceCommand::Stop(target) => PackageRequestV1::StopInstance {
                instance_id: target.instance.clone(),
                expected_lifecycle: target.lifecycle,
            },
            InstanceCommand::Run {
                target,
                evaluation,
                rebuild,
            } => PackageRequestV1::RunInstance {
                instance_id: target.instance.clone(),
                expected_lifecycle: target.lifecycle,
                evaluation_id: evaluation.clone(),
                rebuild: *rebuild,
            },
            InstanceCommand::Renew(target) => PackageRequestV1::RenewInstance {
                instance_id: target.instance.clone(),
                expected_lifecycle: target.lifecycle,
            },
            InstanceCommand::Update {
                target,
                definition,
                revision,
                rebuild,
            } => PackageRequestV1::UpdateInstance {
                instance_id: target.instance.clone(),
                expected_lifecycle: target.lifecycle,
                definition_name: definition.clone(),
                definition_revision: revision.clone(),
                rebuild: *rebuild,
            },
            InstanceCommand::Rollback {
                target,
                generation,
                rebuild,
            } => PackageRequestV1::RollbackInstance {
                instance_id: target.instance.clone(),
                expected_lifecycle: target.lifecycle,
                generation: *generation,
                rebuild: *rebuild,
            },
            InstanceCommand::Remove(target) => PackageRequestV1::RemoveInstance {
                instance_id: target.instance.clone(),
                expected_lifecycle: target.lifecycle,
            },
            InstanceCommand::Recreate {
                target,
                definition,
                revision,
            } => PackageRequestV1::RecreateInstance {
                instance_id: target.instance.clone(),
                expected_lifecycle: target.lifecycle,
                definition_name: definition.clone(),
                definition_revision: revision.clone(),
            },
            InstanceCommand::Inspect { instance } => PackageRequestV1::InspectInstance {
                instance_id: instance.clone(),
            },
            InstanceCommand::History { instance } => PackageRequestV1::InspectInstanceHistory {
                instance_id: instance.clone(),
            },
            InstanceCommand::Read { instance, result } => PackageRequestV1::ReadInstanceResult {
                instance_id: instance.clone(),
                result_id: result.clone(),
            },
            InstanceCommand::Query {
                instance,
                result,
                sql,
            } => PackageRequestV1::QueryInstanceResult {
                instance_id: instance.clone(),
                result_id: result.clone(),
                sql: sql.clone(),
            },
        };
        Ok(Prepared::Package(wire::PackageOperationRequest {
            definition: operation.encode().context(PackageSnafu)?,
            selection: None,
        }))
    }
}

impl CommandRun {
    pub(super) async fn package(&mut self, request: wire::PackageOperationRequest) -> Result<()> {
        let response = tokio::select! {
            _ = self.signal.as_mut() => return InterruptedSnafu.fail(),
            result = self.client.package_operation(request) => result.context(ClientSnafu)?,
        };
        let response: PackageResponseV1 =
            PackageResponseV1::from_bytes(&response.result).map_err(|_| {
                ProtocolSnafu {
                    field: "binary package response",
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
    fn definition_cli_contract() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for args in [
            vec!["araphor", "definition"],
            vec!["araphor", "definition", "admit"],
            vec!["araphor", "definition", "start", "counts"],
            vec![
                "araphor",
                "definition",
                "inspect",
                "counts",
                "--scope",
                "team",
            ],
            vec![
                "araphor",
                "definition",
                "inspect",
                "counts",
                "--node",
                "node-a",
            ],
            vec!["araphor", "definition", "inspect", "counts", "--unknown"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        let cli = Cli::try_parse_from([
            "araphor",
            "definition",
            "inspect",
            "counts",
            "--revision",
            "exact",
        ])?;
        let Command::Investigate(command) = cli.command else {
            return Err("definition command absent".into());
        };
        assert_eq!(command.to_string(), "definition");
        let Prepared::Package(request) = command.prepare()? else {
            return Err("definition request absent".into());
        };
        assert!(request.selection.is_none());
        assert!(matches!(PackageRequestV1::from_bytes(&request.definition)?,
            PackageRequestV1::InspectDefinition { name, revision }
                if name == "counts" && revision.as_deref() == Some("exact")));
        Ok(())
    }

    #[test]
    fn definition_cli_captures_source() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for (kind, text) in [
            ("sql", "SELECT 1"),
            ("prql", "from events"),
            ("call", "SELECT source_cursor AS value FROM events"),
        ] {
            let file = crate::cli::test_support::TempJsonFile::write("")?;
            let path = file.path().with_extension("yaml");
            let source = file.path().with_extension("source");
            let filename = source
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .ok_or("source filename absent")?;
            let program = if kind == "call" {
                format!("call:\n  package: fixture\n  revision: r1\n  export: count\n  inputs:\n    source:\n      file: {filename}\n  parameters:\n    increment: 2\n  output: result\n")
            } else {
                format!("{kind}:\n  file: {filename}\n")
            };
            std::fs::write(&source, text)?;
            std::fs::write(&path, format!("name: counts-{kind}\ndescription: Count retained events.\nlabels:\n  owner: analysis\n  team: security\n{program}"))?;
            let cli = Cli::try_parse_from([
                std::ffi::OsStr::new("araphor"),
                std::ffi::OsStr::new("definition"),
                std::ffi::OsStr::new("admit"),
                path.as_os_str(),
            ])?;
            let Command::Investigate(command) = cli.command else {
                return Err("definition command absent".into());
            };
            let Prepared::Package(request) = command.prepare()? else {
                return Err("definition request absent".into());
            };
            std::fs::write(&source, "changed")?;
            std::fs::remove_file(&source)?;
            std::fs::remove_file(&path)?;
            let PackageRequestV1::AdmitDefinition { definition } =
                PackageRequestV1::from_bytes(&request.definition)?
            else {
                return Err("definition admission absent".into());
            };
            assert_eq!(definition.name, format!("counts-{kind}"));
            assert_eq!(definition.description, "Count retained events.");
            assert_eq!(
                definition.labels,
                std::collections::BTreeMap::from([
                    ("owner".into(), "analysis".into()),
                    ("team".into(), "security".into()),
                ])
            );
            let captured = definition.program.source().inline()?;
            if kind == "call" {
                assert!(matches!(
                    &definition.program,
                    araphor_discovery_definition::Program::Sql { .. }
                ));
                for fragment in [
                    "fixture",
                    "r1",
                    "count",
                    "source_cursor",
                    "increment",
                    "result",
                ] {
                    assert!(captured.contains(fragment), "{captured}");
                }
                assert!(!captured.contains("changed"));
            } else {
                assert_eq!(captured, text);
                assert_eq!(
                    matches!(
                        &definition.program,
                        araphor_discovery_definition::Program::Prql { .. }
                    ),
                    kind == "prql"
                );
            }
            assert!(request.selection.is_none());
        }
        Ok(())
    }

    #[test]
    fn image_cli_incomplete_commands() {
        for args in [
            vec!["araphor", "image"],
            vec!["araphor", "image", "digest"],
            vec!["araphor", "image", "install"],
            vec!["araphor", "image", "inspect"],
            vec!["araphor", "image", "inspect", "example", "--revision"],
            vec!["araphor", "image", "run", "example"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn image_cli_tenant_scope() {
        for flag in [
            "--scope",
            "--parameters",
            "--node",
            "--cluster",
            "--container",
            "--target",
        ] {
            for operation in ["digest", "install", "inspect"] {
                assert!(Cli::try_parse_from([
                    "araphor", "image", operation, "example", flag, "value",
                ])
                .is_err());
            }
        }
    }

    #[test]
    fn image_cli_shared_contract() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for revision in [None, Some("2")] {
            let mut args = vec!["araphor", "image", "inspect", "example"];
            if let Some(revision) = revision {
                args.extend(["--revision", revision]);
            }
            let cli = Cli::try_parse_from(args)?;
            let Command::Investigate(command) = cli.command else {
                return Err("image command absent".into());
            };
            assert_eq!(command.to_string(), "image");
            let Prepared::Package(request) = command.prepare()? else {
                return Err("image request absent".into());
            };
            assert!(request.selection.is_none());
            assert!(matches!(
                PackageRequestV1::from_bytes(&request.definition)?,
                PackageRequestV1::InspectImage { package_id, revision: actual }
                    if package_id == "example" && actual.as_deref() == revision
            ));
        }
        Ok(())
    }

    #[test]
    fn image_cli_archive_request() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bundle = araphor_analysis::Package::discovery_bundle()?;
        let path =
            std::env::temp_dir().join(format!("araphor-image-{}.oci.tar", uuid::Uuid::new_v4()));
        std::fs::write(&path, bundle.encode()?)?;
        let result = (|| -> std::result::Result<(), Box<dyn std::error::Error>> {
            for operation in ["digest", "install"] {
                let cli = Cli::try_parse_from([
                    std::ffi::OsStr::new("araphor"),
                    std::ffi::OsStr::new("image"),
                    std::ffi::OsStr::new(operation),
                    path.as_os_str(),
                ])?;
                let Command::Investigate(command) = cli.command else {
                    return Err("image command absent".into());
                };
                match command.prepare()? {
                    Prepared::PackageDigest(digest) => assert_eq!(digest, bundle.digest()?),
                    Prepared::Package(request) => {
                        assert!(request.selection.is_none());
                        let PackageRequestV1::InstallImage { bundle: actual } =
                            PackageRequestV1::from_bytes(&request.definition)?
                        else {
                            return Err("image install absent".into());
                        };
                        assert_eq!(actual.artifacts, bundle.artifacts);
                        assert_eq!(actual.digest()?, bundle.digest()?);
                    }
                    _ => return Err("image operation changed".into()),
                }
            }
            Ok(())
        })();
        std::fs::remove_file(path)?;
        result
    }

    #[test]
    fn instance_cli_is_readonly() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for args in [
            vec!["araphor", "instance"],
            vec!["araphor", "instance", "inspect"],
            vec!["araphor", "instance", "query", "counts"],
            vec!["araphor", "instance", "start", "counts"],
            vec!["araphor", "instance", "read", "counts"],
            vec!["araphor", "instance", "history"],
            vec!["araphor", "instance", "history", "counts", "--follow"],
            vec!["araphor", "instance", "read", "counts", "saved", "--follow"],
            vec!["araphor", "instance", "inspect", "counts", "--unknown"],
            vec![
                "araphor",
                "instance",
                "inspect",
                "counts",
                "--revision",
                "r1",
            ],
            vec![
                "araphor", "instance", "query", "counts", "result", "SELECT 1", "--follow",
            ],
            vec![
                "araphor", "instance", "inspect", "counts", "--node", "node-a",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        for args in [
            vec!["araphor", "instance", "inspect", "counts"],
            vec!["araphor", "instance", "history", "counts"],
            vec!["araphor", "instance", "read", "counts", "saved"],
            vec![
                "araphor",
                "instance",
                "query",
                "counts",
                "SELECT value FROM selected",
            ],
            vec![
                "araphor",
                "instance",
                "query",
                "counts",
                "saved",
                "SELECT value FROM rows",
            ],
        ] {
            let latest = args.len() == 5 && args[2] == "query";
            let cli = Cli::try_parse_from(args)?;
            let Command::Investigate(command) = cli.command else {
                return Err("instance command absent".into());
            };
            assert_eq!(command.to_string(), "instance");
            let Prepared::Package(request) = command.prepare()? else {
                return Err("instance request absent".into());
            };
            assert!(request.selection.is_none());
            let operation = PackageRequestV1::from_bytes(&request.definition)?;
            assert_eq!(operation.action(), araphor_data::PackageActionV1::Inspect);
            match operation {
                PackageRequestV1::InspectInstance { instance_id }
                | PackageRequestV1::InspectInstanceHistory { instance_id } => {
                    assert_eq!(instance_id, "counts")
                }
                PackageRequestV1::ReadInstanceResult {
                    instance_id,
                    result_id,
                } => {
                    assert_eq!(instance_id, "counts");
                    assert_eq!(result_id, "saved");
                }
                PackageRequestV1::QueryInstanceResult {
                    instance_id,
                    result_id,
                    sql,
                } => {
                    assert_eq!(instance_id, "counts");
                    assert_eq!(result_id.as_deref(), (!latest).then_some("saved"));
                    assert_eq!(
                        sql,
                        if latest {
                            "SELECT value FROM selected"
                        } else {
                            "SELECT value FROM rows"
                        }
                    );
                }
                _ => return Err("instance operation changed".into()),
            }
        }
        Ok(())
    }

    #[test]
    fn instance_admission_is_explicit() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let revision = format!("sha256:{}", "1".repeat(64));
        let args = [
            "araphor",
            "instance",
            "admit",
            "counts",
            "--definition",
            "count-events",
            "--revision",
            revision.as_str(),
        ];
        let cli = Cli::try_parse_from(args)?;
        let Command::Investigate(command) = cli.command else {
            return Err("instance command".into());
        };
        let Prepared::Package(request) = command.prepare()? else {
            return Err("instance request".into());
        };
        assert!(request.selection.is_none());
        assert!(matches!(
            PackageRequestV1::from_bytes(&request.definition)?,
            PackageRequestV1::AdmitInstance {
                instance_id,
                definition_name,
                definition_revision,
            } if instance_id == "counts"
                && definition_name == "count-events"
                && definition_revision == revision
        ));
        for args in [
            vec!["araphor", "instance", "admit"],
            vec!["araphor", "instance", "admit", "counts"],
            vec![
                "araphor",
                "instance",
                "admit",
                "counts",
                "--definition",
                "count-events",
            ],
            vec![
                "araphor",
                "instance",
                "admit",
                "counts",
                "--revision",
                &revision,
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        for option in ["--follow", "--run", "--force", "--scope", "--lifecycle"] {
            let mut invalid = args.to_vec();
            invalid.push(option);
            assert!(Cli::try_parse_from(invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn lifecycle_cli_is_explicit() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for (operation, tail, expected) in [
            (
                "start",
                vec![],
                serde_json::json!({"operation":"start_instance","instance_id":"counts","expected_lifecycle":17}),
            ),
            (
                "stop",
                vec![],
                serde_json::json!({"operation":"stop_instance","instance_id":"counts","expected_lifecycle":17}),
            ),
            (
                "run",
                vec!["once", "--rebuild"],
                serde_json::json!({"operation":"run_instance","instance_id":"counts","expected_lifecycle":17,"evaluation_id":"once","rebuild":true}),
            ),
            (
                "renew",
                vec![],
                serde_json::json!({"operation":"renew_instance","instance_id":"counts","expected_lifecycle":17}),
            ),
            (
                "update",
                vec![
                    "--definition",
                    "count-events",
                    "--revision",
                    "exact",
                    "--rebuild",
                ],
                serde_json::json!({"operation":"update_instance","instance_id":"counts","expected_lifecycle":17,"definition_name":"count-events","definition_revision":"exact","rebuild":true}),
            ),
            (
                "rollback",
                vec!["--generation", "11", "--rebuild"],
                serde_json::json!({"operation":"rollback_instance","instance_id":"counts","expected_lifecycle":17,"generation":11,"rebuild":true}),
            ),
        ] {
            let mut args = vec![
                "araphor",
                "instance",
                operation,
                "counts",
                "--lifecycle",
                "17",
            ];
            args.extend(tail.clone());
            let cli = Cli::try_parse_from(&args)?;
            let Command::Investigate(command) = cli.command else {
                return Err("instance command".into());
            };
            let Prepared::Package(request) = command.prepare()? else {
                return Err("instance request".into());
            };
            assert!(request.selection.is_none());
            let decoded = PackageRequestV1::from_bytes(&request.definition)?;
            assert_eq!(serde_json::to_value(decoded)?, expected);
            for option in ["--force", "--owner", "--grant", "--follow", "--scope"] {
                let mut invalid = args.clone();
                invalid.push(option);
                assert!(Cli::try_parse_from(invalid).is_err());
            }
            let mut missing = vec!["araphor", "instance", operation, "counts"];
            missing.extend(tail);
            assert!(Cli::try_parse_from(missing).is_err());
        }
        for args in [
            vec!["araphor", "instance", "run", "counts", "--lifecycle", "17"],
            vec![
                "araphor",
                "instance",
                "update",
                "counts",
                "--lifecycle",
                "17",
                "--definition",
                "count-events",
            ],
            vec![
                "araphor",
                "instance",
                "rollback",
                "counts",
                "--lifecycle",
                "17",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        Ok(())
    }

    #[test]
    fn legacy_package_cli_is_rejected() {
        for args in [
            vec!["araphor", "package"],
            vec!["araphor", "package", "install"],
            vec!["araphor", "package", "run", "denials"],
            vec!["araphor", "package", "rollback", "denials"],
            vec!["araphor", "package", "inspect", "denials", "--unknown"],
            vec!["araphor", "package", "digest", "image.oci.tar"],
            vec![
                "araphor", "package", "inspect", "denials", "--scope", "team",
            ],
            vec![
                "araphor",
                "package",
                "run",
                "denials",
                "--scope",
                "team",
                "--evaluation-id",
                "retry-1",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn image_test_cli() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for name in [None, Some("equal")] {
            let mut args = vec!["araphor", "image", "test", "fixture", "--revision", "exact"];
            if let Some(name) = name {
                args.extend(["--fixture", name]);
            }
            let cli = Cli::try_parse_from(args)?;
            assert!(cli.validate_route().is_ok());
            let Command::Investigate(command) = cli.command else {
                return Err("image command".into());
            };
            let Prepared::Package(request) = command.prepare()? else {
                return Err("image request".into());
            };
            assert!(request.selection.is_none());
            assert!(matches!(PackageRequestV1::from_bytes(&request.definition)?,
                PackageRequestV1::TestImage { image, artifact, fixture } if image.package_id == "fixture" && image.revision == "exact" && artifact.is_none() && fixture.as_deref() == name));
        }
        for args in [
            vec!["araphor", "image", "test", "fixture"],
            vec!["araphor", "image", "test", "fixture", "--revision"],
            vec![
                "araphor",
                "image",
                "test",
                "fixture",
                "--revision",
                "exact",
                "--fixture",
            ],
            vec![
                "araphor",
                "image",
                "test",
                "fixture",
                "--revision",
                "exact",
                "--revision",
                "other",
            ],
            vec![
                "araphor",
                "image",
                "test",
                "fixture",
                "--revision",
                "exact",
                "--unknown",
            ],
            vec![
                "araphor",
                "image",
                "test",
                "fixture",
                "--revision",
                "exact",
                "--scope",
                "team",
            ],
            vec![
                "araphor",
                "image",
                "test",
                "fixture",
                "--revision",
                "exact",
                "--node",
                "node-a",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        Ok(())
    }

    #[test]
    fn image_test_selects_artifact() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "araphor",
            "image",
            "test",
            "container",
            "--revision",
            "image-exact",
            "--artifact",
            "child",
            "--artifact-revision",
            "child-exact",
            "--fixture",
            "equal",
        ])?;
        let Command::Investigate(command) = cli.command else {
            return Err("image command".into());
        };
        let Prepared::Package(request) = command.prepare()? else {
            return Err("image request".into());
        };
        assert!(request.selection.is_none());
        assert!(matches!(PackageRequestV1::from_bytes(&request.definition)?,
            PackageRequestV1::TestImage { image, artifact: Some(artifact), fixture }
                if image.package_id == "container" && image.revision == "image-exact"
                    && artifact.package_id == "child" && artifact.revision == "child-exact"
                    && fixture.as_deref() == Some("equal")));
        for tail in [
            vec!["--artifact", "child"],
            vec!["--artifact-revision", "child-exact"],
            vec!["--artifact", "child", "--artifact-revision"],
            vec![
                "--artifact",
                "child",
                "--artifact-revision",
                "child-exact",
                "--artifact",
                "other",
            ],
        ] {
            let mut args = vec![
                "araphor",
                "image",
                "test",
                "container",
                "--revision",
                "image-exact",
            ];
            args.extend(tail);
            assert!(Cli::try_parse_from(args).is_err());
        }
        Ok(())
    }
    #[test]
    fn removal_cli_is_explicit() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let digest = format!("sha256:{}", "1".repeat(64));
        let revision = format!("sha256:{}", "2".repeat(64));
        for args in [
            vec!["araphor", "image", "uninstall", "example"],
            vec![
                "araphor",
                "image",
                "uninstall",
                "example",
                "--revision",
                "1",
            ],
            vec![
                "araphor",
                "image",
                "uninstall",
                "example",
                "--revision",
                "1",
                "--digest",
                "invalid",
            ],
            vec!["araphor", "instance", "remove", "counts"],
            vec![
                "araphor",
                "instance",
                "remove",
                "counts",
                "--lifecycle",
                "-1",
            ],
            vec![
                "araphor",
                "instance",
                "recreate",
                "counts",
                "--lifecycle",
                "19",
                "--definition",
                "counts",
            ],
            vec![
                "araphor",
                "instance",
                "remove",
                "counts",
                "--lifecycle",
                "17",
                "--force",
            ],
        ] {
            match Cli::try_parse_from(args) {
                Err(_) => {}
                Ok(cli) => {
                    let Command::Investigate(command) = cli.command else {
                        return Err("removal command absent".into());
                    };
                    assert!(command.prepare().is_err());
                }
            }
        }
        for (args, expected) in [
            (
                vec![
                    "araphor",
                    "image",
                    "uninstall",
                    "example",
                    "--revision",
                    "1",
                    "--digest",
                    &digest,
                ],
                serde_json::json!({"operation":"uninstall_image", "image":{"image":{"package_id":"example", "revision":"1"}, "digest":digest}}),
            ),
            (
                vec![
                    "araphor",
                    "instance",
                    "remove",
                    "counts",
                    "--lifecycle",
                    "17",
                ],
                serde_json::json!({"operation":"remove_instance", "instance_id":"counts", "expected_lifecycle":17}),
            ),
            (
                vec![
                    "araphor",
                    "instance",
                    "recreate",
                    "counts",
                    "--lifecycle",
                    "19",
                    "--definition",
                    "counts",
                    "--revision",
                    &revision,
                ],
                serde_json::json!({"operation":"recreate_instance", "instance_id":"counts", "expected_lifecycle":19, "definition_name":"counts", "definition_revision":revision}),
            ),
        ] {
            let cli = Cli::try_parse_from(args)?;
            let Command::Investigate(command) = cli.command else {
                return Err("removal command absent".into());
            };
            let Prepared::Package(request) = command.prepare()? else {
                return Err("removal request absent".into());
            };
            assert!(request.selection.is_none());
            assert_eq!(
                serde_json::to_value(PackageRequestV1::from_bytes(&request.definition)?)?,
                expected
            );
        }
        Ok(())
    }
}
