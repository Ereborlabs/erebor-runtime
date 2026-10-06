use std::{
    fmt,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use clap::{Args, Subcommand, ValueEnum};
use erebor_runtime_client::AraphorProfile;
use erebor_runtime_ipc::araphor as wire;
use uuid::Uuid;

use super::error::{AraphorCommandError as Error, Result};

#[derive(Debug, Args)]
pub(crate) struct ConnectionArgs {
    /// JSON profile for the TLS endpoint, tenant, and service credential file.
    #[arg(long, global = true)]
    pub(super) profile: Option<PathBuf>,
    /// Override the profile's HTTPS endpoint. The tenant and credentials stay unchanged.
    #[arg(long, global = true)]
    pub(super) endpoint: Option<String>,
    /// Select table or JSONL output. Follow defaults to table. Other defaults depend on stdout.
    #[arg(long, global = true, value_enum)]
    pub(super) output: Option<OutputMode>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AraphorCommand {
    /// List query relations, recipe source, or retained policy targets.
    Catalog(CatalogArgs),
    /// Evaluate one SQL statement, or follow its committed results.
    Sql(SqlArgs),
    /// Submit and watch one finite trace, or resume a read-only viewer.
    Trace(TraceArgs),
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("catalog_kind").args(["relation", "recipes", "targets"]).multiple(false)))]
pub(crate) struct CatalogArgs {
    #[arg(long)]
    relation: Option<String>,
    #[arg(long)]
    recipes: bool,
    #[arg(long)]
    targets: bool,
    #[command(flatten)]
    selection: SelectionArgs,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(super) enum OutputMode {
    Table,
    Jsonl,
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("statement").args(["sql", "file"]).required(true).multiple(false)))]
pub(crate) struct SqlArgs {
    /// One SQL statement. Use --file - to read stdin.
    sql: Option<String>,
    #[arg(short = 'f', long)]
    file: Option<PathBuf>,
    #[command(flatten)]
    selection: SelectionArgs,
    #[arg(long)]
    follow: bool,
    #[arg(long, requires = "follow")]
    duration: Option<Span>,
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("source").args(["file", "expression", "recipe"]).multiple(false)))]
pub(crate) struct TraceArgs {
    #[arg(long, conflicts_with = "resume")]
    file: Option<PathBuf>,
    #[arg(long, conflicts_with = "resume")]
    expression: Option<String>,
    #[arg(long, conflicts_with = "resume")]
    recipe: Option<String>,
    #[command(flatten)]
    selection: SelectionArgs,
    #[arg(long, conflicts_with = "resume")]
    duration: Option<Span>,
    /// Read retained output. This command does not submit or cancel execution.
    #[arg(long)]
    resume: Option<Uuid>,
}

#[derive(Debug, Args)]
struct SelectionArgs {
    #[arg(long)]
    target: Option<String>,
    #[arg(long)]
    cluster: Option<String>,
    #[arg(long)]
    container: Option<String>,
    #[arg(long = "node")]
    nodes: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
struct Span(Duration);

impl FromStr for Span {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (number, scale) = if let Some(value) = value.strip_suffix('s') {
            (value, 1)
        } else if let Some(value) = value.strip_suffix('m') {
            (value, 60)
        } else {
            return Err("duration must use integer seconds or minutes".into());
        };
        let seconds = number
            .parse::<u64>()
            .ok()
            .and_then(|value| value.checked_mul(scale))
            .filter(|value| *value > 0 && value.checked_mul(1_000_000_000).is_some())
            .ok_or_else(|| "duration is empty, zero, or too large".to_owned())?;
        Ok(Self(Duration::from_secs(seconds)))
    }
}

pub(super) enum Prepared {
    Sql {
        request: wire::QueryRequest,
        duration: Option<Duration>,
    },
    Trace {
        request: Option<wire::SubmitTraceRequest>,
        trace_id: Vec<u8>,
    },
}

impl AraphorCommand {
    pub(super) fn prepare(&self) -> Result<Prepared> {
        match self {
            AraphorCommand::Catalog(args) => args.prepare(),
            AraphorCommand::Sql(args) => {
                let bytes =
                    SourceInput::read(args.file.as_deref(), args.sql.as_deref(), 16 * 1024)?;
                let sql =
                    String::from_utf8(bytes).map_err(|_| SourceInput::invalid("SQL UTF-8"))?;
                let duration = args.duration.map(|span| span.0);
                Ok(Prepared::Sql {
                    request: wire::QueryRequest {
                        sql,
                        parameters: Vec::new(),
                        selection: Some((&args.selection).try_into()?),
                        follow: args.follow,
                        bookmark: Vec::new(),
                        duration_ns: duration.map(|value| value.as_nanos() as u64),
                    },
                    duration,
                })
            }
            AraphorCommand::Trace(args) => {
                if let Some(id) = args.resume {
                    if args.selection.selected() || args.duration.is_some() || id.is_nil() {
                        return Err(SourceInput::invalid(
                            "resume cannot select new targets, source, or duration",
                        ));
                    }
                    return Ok(Prepared::Trace {
                        request: None,
                        trace_id: id.as_bytes().to_vec(),
                    });
                }
                let selection = wire::InputSelection::try_from(&args.selection)?;
                if selection.target.is_empty() {
                    return Err(SourceInput::invalid("trace target is required"));
                }
                let source = match (&args.file, &args.expression, &args.recipe) {
                    (Some(path), None, None) => wire::submit_trace_request::Source::Script(
                        SourceInput::read(Some(path), None, 64 * 1024)?,
                    ),
                    (None, Some(source), None) => wire::submit_trace_request::Source::Script(
                        SourceInput::read(None, Some(source), 64 * 1024)?,
                    ),
                    (None, None, Some(recipe))
                        if !recipe.trim().is_empty() && recipe.len() <= 128 =>
                    {
                        wire::submit_trace_request::Source::Recipe(recipe.clone())
                    }
                    _ => return Err(SourceInput::invalid("trace requires exactly one source")),
                };
                let seconds = args.duration.map_or(30, |span| span.0.as_secs());
                if !(1..=300).contains(&seconds) {
                    return Err(SourceInput::invalid(
                        "trace duration must be 1 to 300 seconds",
                    ));
                }
                let trace_id = Uuid::new_v4().as_bytes().to_vec();
                Ok(Prepared::Trace {
                    request: Some(wire::SubmitTraceRequest {
                        idempotency_key: trace_id.clone(),
                        selection: Some(selection),
                        source: Some(source),
                        collection_seconds: seconds as u32,
                        finding_reference: String::new(),
                    }),
                    trace_id,
                })
            }
        }
    }
}

impl fmt::Display for AraphorCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Catalog(_) => "catalog",
            Self::Sql(_) => "sql",
            Self::Trace(_) => "trace",
        })
    }
}

impl ConnectionArgs {
    pub(crate) fn selected(&self) -> bool {
        self.profile.is_some() || self.endpoint.is_some() || self.output.is_some()
    }

    pub(super) fn connection(&self) -> Result<AraphorProfile> {
        let path = self
            .profile
            .clone()
            .or_else(|| std::env::var_os("ARAPHOR_PROFILE").map(PathBuf::from))
            .or_else(|| {
                std::env::var_os("XDG_CONFIG_HOME")
                    .map(|path| PathBuf::from(path).join("araphor/client.json"))
            })
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|path| PathBuf::from(path).join(".config/araphor/client.json"))
            })
            .ok_or_else(|| SourceInput::invalid("configure --profile or ARAPHOR_PROFILE"))?;
        let mut profile = AraphorProfile::read(&path).map_err(|source| Error::Client {
            source,
            location: snafu::Location::default(),
        })?;
        if let Some(endpoint) = &self.endpoint {
            profile.endpoint = endpoint.clone();
        }
        Ok(profile)
    }
}

impl CatalogArgs {
    fn prepare(&self) -> Result<Prepared> {
        let mut parameters = Vec::new();
        let sql = if let Some(relation) = &self.relation {
            if relation.is_empty()
                || relation.len() > 128
                || !relation
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err(SourceInput::invalid("catalog relation name"));
            }
            parameters.push(wire::QueryValue {
                kind: Some(wire::query_value::Kind::Text(relation.clone())),
            });
            "SELECT * FROM catalog WHERE relation = $1 ORDER BY ordinal"
        } else if self.recipes {
            "SELECT * FROM trace_recipes ORDER BY recipe"
        } else if self.targets {
            "SELECT * FROM targets ORDER BY node_id, binding_id"
        } else {
            "SELECT relation, MAX(owner) AS owner, MAX(readiness) AS readiness, MAX(description) AS description, COUNT(*) AS fields FROM catalog GROUP BY relation ORDER BY relation"
        };
        Ok(Prepared::Sql {
            request: wire::QueryRequest {
                sql: sql.into(),
                parameters,
                selection: Some((&self.selection).try_into()?),
                ..Default::default()
            },
            duration: None,
        })
    }
}

impl SelectionArgs {
    fn selected(&self) -> bool {
        self.target.is_some()
            || self.cluster.is_some()
            || self.container.is_some()
            || !self.nodes.is_empty()
    }
}

impl TryFrom<&SelectionArgs> for wire::InputSelection {
    type Error = Error;

    fn try_from(selection: &SelectionArgs) -> Result<Self> {
        for value in selection
            .target
            .iter()
            .chain(selection.cluster.iter())
            .chain(selection.container.iter())
            .chain(selection.nodes.iter())
        {
            if value.trim().is_empty() || value.len() > 1024 || value.contains('\0') {
                return Err(SourceInput::invalid(
                    "selection is empty or exceeds its bound",
                ));
            }
        }
        if selection.nodes.len() > 64 {
            return Err(SourceInput::invalid("too many node selectors"));
        }
        Ok(Self {
            target: selection.target.clone().unwrap_or_default(),
            cluster: selection.cluster.clone().unwrap_or_default(),
            container: selection.container.clone().unwrap_or_default(),
            node_ids: selection.nodes.clone(),
        })
    }
}

struct SourceInput;

impl SourceInput {
    fn read(path: Option<&Path>, inline: Option<&str>, limit: usize) -> Result<Vec<u8>> {
        let bytes = match (path, inline) {
            (None, Some(value)) => {
                if value.len() > limit {
                    return Err(Self::invalid("source byte limit"));
                }
                value.as_bytes().to_vec()
            }
            (Some(path), None) => {
                let mut bytes = Vec::new();
                if path == Path::new("-") {
                    io::stdin().take(limit as u64 + 1).read_to_end(&mut bytes)
                } else {
                    File::open(path)
                        .and_then(|file| file.take(limit as u64 + 1).read_to_end(&mut bytes))
                }
                .map_err(|source| Error::Input {
                    source,
                    location: snafu::Location::default(),
                })?;
                bytes
            }
            _ => {
                return Err(Self::invalid(
                    "exactly one source argument or file is required",
                ));
            }
        };
        if bytes.len() > limit
            || bytes.contains(&0)
            || std::str::from_utf8(&bytes).is_err()
            || bytes.iter().all(u8::is_ascii_whitespace)
        {
            return Err(Self::invalid(
                "source is empty, invalid UTF-8, contains NUL, or exceeds its bound",
            ));
        }
        Ok(bytes)
    }

    fn invalid(field: &'static str) -> Error {
        Error::Invalid {
            field,
            location: snafu::Location::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;

    fn prepare(cli: Cli) -> Result<Prepared> {
        let Command::Investigate(command) = cli.command else {
            return Err(SourceInput::invalid("test command"));
        };
        command.prepare()
    }

    #[test]
    fn observability_cli_arguments() {
        for args in [
            vec!["araphor", "sql"],
            vec!["araphor", "sql", "SELECT 1", "--file", "query.sql"],
            vec!["araphor", "sql", "SELECT 1", "--duration", "10s"],
            vec![
                "araphor",
                "trace",
                "--file",
                "a.bt",
                "--expression",
                "BEGIN {}",
            ],
            vec![
                "araphor",
                "trace",
                "--resume",
                "10000000-0000-0000-0000-000000000001",
                "--recipe",
                "failed-opens@1",
            ],
            vec!["araphor", "sql", "SELECT 1", "--token", "secret"],
            vec!["araphor", "catalog", "--recipes", "--targets"],
            vec!["araphor", "catalog", "--relation", "events", "--recipes"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(Cli::try_parse_from([
            "araphor",
            "sql",
            "--file",
            "-",
            "--follow",
            "--duration",
            "1m"
        ])
        .is_ok());
    }

    #[test]
    fn observability_cli_selectors() -> Result<()> {
        let args = Cli::try_parse_from([
            "araphor",
            "sql",
            "SELECT 1",
            "--target",
            "pod/payments/api",
            "--cluster",
            "prod",
            "--container",
            "worker",
            "--node",
            "node-a",
            "--node",
            "node-b",
        ])
        .map_err(|_| SourceInput::invalid("test args"))?;
        let Prepared::Sql { request, .. } = prepare(args)? else {
            return Err(SourceInput::invalid("test query"));
        };
        assert_eq!(
            request.selection,
            Some(wire::InputSelection {
                target: "pod/payments/api".into(),
                cluster: "prod".into(),
                container: "worker".into(),
                node_ids: vec!["node-a".into(), "node-b".into()],
            })
        );
        let oversized = "x".repeat(1025);
        for flag in ["--target", "--cluster", "--container", "--node"] {
            for invalid in ["", " ", "\0", oversized.as_str()] {
                let args = Cli::try_parse_from(["araphor", "sql", "SELECT 1", flag, invalid])
                    .map_err(|_| SourceInput::invalid("test args"))?;
                assert!(prepare(args).is_err());
            }
        }
        let mut selection = SelectionArgs {
            target: None,
            cluster: None,
            container: None,
            nodes: vec!["node-a".into(); 64],
        };
        assert!(wire::InputSelection::try_from(&selection).is_ok());
        selection.nodes.push("node-b".into());
        assert!(wire::InputSelection::try_from(&selection).is_err());
        Ok(())
    }

    #[test]
    fn observability_cli_catalog() -> Result<()> {
        for (args, expected) in [
            (vec!["araphor", "catalog"], "GROUP BY relation"),
            (
                vec!["araphor", "catalog", "--recipes"],
                "FROM trace_recipes",
            ),
            (
                vec!["araphor", "catalog", "--targets", "--node", "node-a"],
                "FROM targets",
            ),
            (
                vec!["araphor", "catalog", "--relation", "events"],
                "relation = $1",
            ),
        ] {
            let args = Cli::try_parse_from(args).map_err(|_| SourceInput::invalid("test args"))?;
            let Prepared::Sql { request, duration } = prepare(args)? else {
                return Err(SourceInput::invalid("catalog query"));
            };
            assert!(request.sql.contains(expected));
            assert!(!request.follow);
            assert!(duration.is_none());
            if expected == "relation = $1" {
                assert_eq!(request.parameters.len(), 1);
                assert_eq!(
                    request.parameters[0].kind,
                    Some(wire::query_value::Kind::Text("events".into()))
                );
            }
            if expected == "FROM targets" {
                assert_eq!(
                    request.selection.map(|value| value.node_ids),
                    Some(vec!["node-a".into()])
                );
            }
        }
        let args = Cli::try_parse_from(["araphor", "catalog", "--relation", "events'; SELECT 1"])
            .map_err(|_| SourceInput::invalid("test args"))?;
        assert!(prepare(args).is_err());
        Ok(())
    }

    #[test]
    fn observability_cli_readonly_resume() -> Result<()> {
        let args = Cli::try_parse_from([
            "araphor",
            "trace",
            "--resume",
            "10000000-0000-0000-0000-000000000001",
        ])
        .map_err(|_| SourceInput::invalid("test args"))?;
        assert!(matches!(
            prepare(args)?,
            Prepared::Trace { request: None, .. }
        ));
        let args = Cli::try_parse_from([
            "araphor",
            "trace",
            "--resume",
            "10000000-0000-0000-0000-000000000001",
            "--target",
            "pod/ns/name",
        ])
        .map_err(|_| SourceInput::invalid("test args"))?;
        assert!(prepare(args).is_err());
        Ok(())
    }

    #[test]
    fn observability_cli_fixed_source() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let file = crate::cli::test_support::TempJsonFile::write("BEGIN { exit(); }")?;
        let args = Cli::try_parse_from([
            "araphor",
            "trace",
            "--file",
            file.path()
                .to_str()
                .ok_or_else(|| SourceInput::invalid("test path"))?,
            "--target",
            "pod/ns/name",
        ])
        .map_err(|_| SourceInput::invalid("test args"))?;
        let Prepared::Trace {
            request: Some(request),
            trace_id,
        } = prepare(args)?
        else {
            return Err(SourceInput::invalid("test trace").into());
        };
        std::fs::write(file.path(), "BEGIN { printf(\"changed\"); }")?;
        assert_eq!(request.idempotency_key, trace_id);
        assert_eq!(
            request.source,
            Some(wire::submit_trace_request::Source::Script(
                b"BEGIN { exit(); }".to_vec()
            ))
        );
        assert!(SourceInput::read(None, Some("\0"), 1).is_err());
        assert!(SourceInput::read(None, Some("  "), 2).is_err());
        Ok(())
    }
}
