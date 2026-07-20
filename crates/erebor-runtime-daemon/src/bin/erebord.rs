use std::{ffi::OsString, path::PathBuf};

use erebor_runtime_daemon::DaemonControlService;
use erebor_runtime_error::ErrorExt;
use tracing_subscriber::{filter::LevelFilter, EnvFilter};

enum LaunchMode {
    System,
    Development { root: PathBuf },
    Help,
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
    if matches!(mode, LaunchMode::Help) {
        println!("{}", usage());
        return;
    }
    let service = match mode {
        LaunchMode::System => DaemonControlService::start_system().await,
        LaunchMode::Development { root } => DaemonControlService::start_development(root).await,
        LaunchMode::Help => unreachable!("help mode returned before daemon startup"),
    };
    let service = match service {
        Ok(service) => service,
        Err(error) => {
            init_foreground_logging();
            erebor_runtime_telemetry::error!(error; "erebord failed before daemon logging initialized");
            eprintln!("{}", error.output_msg());
            std::process::exit(1);
        }
    };
    if service.serve().await.is_err() {
        std::process::exit(1);
    }
}

fn parse_launch_mode(arguments: impl IntoIterator<Item = OsString>) -> Result<LaunchMode, String> {
    let mut arguments = arguments.into_iter();
    let Some(argument) = arguments.next() else {
        return Ok(LaunchMode::System);
    };
    if argument == "--help" || argument == "-h" {
        return no_extra_arguments(arguments).map(|()| LaunchMode::Help);
    }
    if argument == "--development-root" {
        let root = arguments
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| String::from("--development-root requires a directory"))?;
        return no_extra_arguments(arguments).map(|()| LaunchMode::Development { root });
    }
    Err(format!(
        "erebord does not accept `{}`",
        argument.to_string_lossy()
    ))
}

fn no_extra_arguments(arguments: impl IntoIterator<Item = OsString>) -> Result<(), String> {
    if let Some(argument) = arguments.into_iter().next() {
        Err(format!(
            "erebord does not accept extra argument `{}`",
            argument.to_string_lossy()
        ))
    } else {
        Ok(())
    }
}

fn usage() -> &'static str {
    "Usage: erebord [--development-root <directory>]\n\nRun the privileged local Erebor daemon control service.\n\n--development-root stores all daemon paths below a disposable local directory for the documented hands-on walkthrough. It still requires root and exposes only a local Unix socket."
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
    use std::{ffi::OsString, path::PathBuf};

    use super::{parse_launch_mode, LaunchMode};

    #[test]
    fn defaults_to_system_paths() {
        assert!(matches!(
            parse_launch_mode(Vec::new()),
            Ok(LaunchMode::System)
        ));
    }

    #[test]
    fn accepts_one_development_root() {
        let root = PathBuf::from("/tmp/erebor-development");
        let mode = parse_launch_mode(vec![
            OsString::from("--development-root"),
            root.clone().into_os_string(),
        ]);
        assert!(matches!(mode, Ok(LaunchMode::Development { root: actual }) if actual == root));
    }

    #[test]
    fn rejects_missing_or_extra_development_arguments() {
        assert!(parse_launch_mode(vec![OsString::from("--development-root")]).is_err());
        assert!(parse_launch_mode(vec![
            OsString::from("--development-root"),
            OsString::from("/tmp/erebor-development"),
            OsString::from("unexpected"),
        ])
        .is_err());
    }
}
