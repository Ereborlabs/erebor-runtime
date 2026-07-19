use std::{env, error::Error, path::PathBuf, process::Command};

#[test]
#[ignore = "requires Ubuntu 24.04, PID 1 systemd, cgroup v2, and passwordless sudo"]
fn installed_phase_one_daemon_control_plane() -> Result<(), Box<dyn Error>> {
    let repository = repository_root()?;
    let target = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository.join("target"));
    let erebord = target.join("debug/erebord");
    let erebor = target.join("debug/erebor");
    if !erebord.is_file() || !erebor.is_file() {
        return Err(format!(
            "build erebord and erebor before this installed-product test: `{}` and `{}`",
            erebord.display(),
            erebor.display()
        )
        .into());
    }

    let output = Command::new("sudo")
        .args(["-n", "env"])
        .env("EREBOR_PHASE1_REPOSITORY", &repository)
        .env("EREBOR_PHASE1_EREBORD", &erebord)
        .env("EREBOR_PHASE1_EREBOR", &erebor)
        .arg(repository.join(".github/scripts/privileged-daemon-control-plane.sh"))
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "privileged daemon control-plane probe failed (status {}):\nstdout:\n{}\nstderr:\n{}",
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
