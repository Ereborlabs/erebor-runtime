use std::{ffi::OsString, path::PathBuf};

use erebor_runtime_daemon::{DaemonControlService, DaemonPaths};
use erebor_runtime_error::ErrorExt;
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};

enum LaunchMode {
    Run(DaemonPaths),
    Help,
}

#[derive(Default)]
struct PathOverrides {
    config: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
    log_dir: Option<PathBuf>,
    state_dir: Option<PathBuf>,
}

impl PathOverrides {
    fn apply(self) -> DaemonPaths {
        let mut paths = DaemonPaths::system();
        if let Some(path) = self.config {
            paths.set_config_path(path);
        }
        if let Some(path) = self.runtime_dir {
            paths.set_runtime_dir(path);
        }
        if let Some(path) = self.log_dir {
            paths.set_log_dir(path);
        }
        if let Some(path) = self.state_dir {
            paths.set_state_dir(path);
        }
        paths
    }
}

#[tokio::main]
async fn main() {
    let mode = match parse_launch_mode(std::env::args_os().skip(1)) {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("{message}\n\n{}", usage());
            std::process::exit(2);
        }
    };
    let LaunchMode::Run(paths) = mode else {
        println!("{}", usage());
        return;
    };
    let service = match DaemonControlService::start_with_paths(paths).await {
        Ok(service) => service,
        Err(error) => {
            init_foreground_logging();
            erebor_runtime_telemetry::error!(error; "erebord failed before daemon logging initialized");
            eprintln!("{}", error.output_msg());
            std::process::exit(1);
        }
    };
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            init_foreground_logging();
            erebor_runtime_telemetry::error!(error; "erebord could not register SIGTERM handling");
            eprintln!("erebord could not register SIGTERM handling: {error}");
            std::process::exit(1);
        }
    };
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(signal) => signal,
        Err(error) => {
            init_foreground_logging();
            erebor_runtime_telemetry::error!(error; "erebord could not register SIGINT handling");
            eprintln!("erebord could not register SIGINT handling: {error}");
            std::process::exit(1);
        }
    };
    let result = tokio::select! {
        result = service.serve() => result,
        _received = terminate.recv() => Ok(()),
        _received = interrupt.recv() => Ok(()),
    };
    if result.is_err() {
        std::process::exit(1);
    }
}

fn parse_launch_mode(arguments: impl IntoIterator<Item = OsString>) -> Result<LaunchMode, String> {
    let mut arguments = arguments.into_iter();
    let mut overrides = PathOverrides::default();
    while let Some(argument) = arguments.next() {
        if argument == "--help" || argument == "-h" {
            if let Some(extra) = arguments.next() {
                return Err(format!(
                    "erebord does not accept extra argument `{}` after --help",
                    extra.to_string_lossy()
                ));
            }
            return Ok(LaunchMode::Help);
        }
        match argument.to_str() {
            Some("--config") => {
                set_path_override(&mut overrides.config, "--config", &mut arguments)?
            }
            Some("--runtime-dir") => {
                set_path_override(&mut overrides.runtime_dir, "--runtime-dir", &mut arguments)?
            }
            Some("--log-dir") => {
                set_path_override(&mut overrides.log_dir, "--log-dir", &mut arguments)?;
            }
            Some("--state-dir") => {
                set_path_override(&mut overrides.state_dir, "--state-dir", &mut arguments)?;
            }
            _ => {
                return Err(format!(
                    "erebord does not accept `{}`",
                    argument.to_string_lossy()
                ));
            }
        }
    }
    Ok(LaunchMode::Run(overrides.apply()))
}

fn set_path_override(
    target: &mut Option<PathBuf>,
    option: &str,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("erebord accepts {option} only once"));
    }
    let path = arguments
        .next()
        .filter(|path| !path.to_string_lossy().starts_with('-'))
        .map(PathBuf::from)
        .ok_or_else(|| format!("{option} requires a path"))?;
    *target = Some(path);
    Ok(())
}

fn usage() -> &'static str {
    "Usage: erebord [OPTIONS]\n\nRun the privileged local Erebor daemon control service.\n\nOptions:\n  --config <PATH>       Root-owned daemon configuration (default: /etc/erebor/erebord.json)\n  --runtime-dir <PATH>  Socket and lock directory (default: /run/erebor)\n  --log-dir <PATH>      Daemon log directory (default: /var/log/erebor)\n  --state-dir <PATH>    Daemon persistent-state directory (default: /var/lib/erebor)\n  -h, --help            Print this help\n\nEach option overrides only its named local path. They do not add a remote endpoint, context, or daemon-selection model."
}

fn init_foreground_logging() {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    let _result = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::Path};

    use super::{parse_launch_mode, LaunchMode};

    #[test]
    fn defaults_to_installed_system_paths() -> Result<(), String> {
        let paths = run_paths(parse_launch_mode(Vec::new())?)?;
        assert_eq!(paths.config_path(), Path::new("/etc/erebor/erebord.json"));
        assert_eq!(paths.socket_path(), Path::new("/run/erebor/daemon.sock"));
        assert_eq!(paths.log_path(), Path::new("/var/log/erebor/daemon.jsonl"));
        assert_eq!(
            paths.idempotency_path(),
            Path::new("/var/lib/erebor/daemon/control-idempotency")
        );
        Ok(())
    }

    #[test]
    fn accepts_independent_local_path_overrides() -> Result<(), String> {
        let paths = run_paths(parse_launch_mode([
            OsString::from("--config"),
            OsString::from("/tmp/erebor-phase1/etc/erebord.json"),
            OsString::from("--runtime-dir"),
            OsString::from("/tmp/erebor-phase1/run"),
            OsString::from("--log-dir"),
            OsString::from("/tmp/erebor-phase1/log"),
            OsString::from("--state-dir"),
            OsString::from("/tmp/erebor-phase1/lib"),
        ])?)?;
        assert_eq!(
            paths.config_path(),
            Path::new("/tmp/erebor-phase1/etc/erebord.json")
        );
        assert_eq!(
            paths.socket_path(),
            Path::new("/tmp/erebor-phase1/run/daemon.sock")
        );
        assert_eq!(
            paths.log_path(),
            Path::new("/tmp/erebor-phase1/log/daemon.jsonl")
        );
        assert_eq!(
            paths.idempotency_path(),
            Path::new("/tmp/erebor-phase1/lib/daemon/control-idempotency")
        );
        Ok(())
    }

    #[test]
    fn rejects_missing_duplicate_or_unknown_options() {
        assert!(parse_launch_mode([OsString::from("--config")]).is_err());
        assert!(parse_launch_mode([
            OsString::from("--config"),
            OsString::from("--runtime-dir"),
            OsString::from("/tmp/erebor-phase1/run"),
        ])
        .is_err());
        assert!(parse_launch_mode([
            OsString::from("--log-dir"),
            OsString::from("/tmp/a"),
            OsString::from("--log-dir"),
            OsString::from("/tmp/b"),
        ])
        .is_err());
        assert!(parse_launch_mode([OsString::from("--unsupported")]).is_err());
    }

    fn run_paths(mode: LaunchMode) -> DaemonPathsResult {
        match mode {
            LaunchMode::Run(paths) => Ok(paths),
            LaunchMode::Help => Err(String::from("expected daemon paths, found help")),
        }
    }

    type DaemonPathsResult = Result<erebor_runtime_daemon::DaemonPaths, String>;
}
