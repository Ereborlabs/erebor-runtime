use std::{env, error::Error, path::PathBuf, process::Command};

#[test]
#[ignore = "requires Linux and passwordless sudo"]
fn temporary_path_phase_one_daemon_control_plane() -> Result<(), Box<dyn Error>> {
    let repository = repository_root()?;
    let target = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository.join("target"));
    let erebord = target.join("debug/erebord");
    let erebor = target.join("debug/erebor");
    if !erebord.is_file() || !erebor.is_file() {
        return Err(format!(
            "build erebord and erebor before this privileged control-plane test: `{}` and `{}`",
            erebord.display(),
            erebor.display()
        )
        .into());
    }

    let output = Command::new("sudo")
        .arg("-n")
        .arg("env")
        .arg(format!("EREBOR_PHASE1_EREBORD={}", erebord.display()))
        .arg(format!("EREBOR_PHASE1_EREBOR={}", erebor.display()))
        .arg("bash")
        .arg(repository.join(".github/scripts/privileged-daemon-control-plane.sh"))
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "temporary-path privileged daemon control-plane probe failed (status {}):\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
    .into())
}

fn repository_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .ok_or_else(|| {
            format!(
                "could not derive repository root from `{}`",
                manifest.display()
            )
            .into()
        })
}
