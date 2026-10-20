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
}
