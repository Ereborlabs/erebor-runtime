use std::{
    env,
    error::Error,
    path::Path,
    process::{Command, Output},
    thread,
    time::Duration,
};

#[test]
#[ignore = "requires Linux, Docker, and privileged containers"]
fn daemon_control_plane_and_codex_context_dag_run_in_systemd_container(
) -> Result<(), Box<dyn Error>> {
    run_systemd_probe(
        ["/usr/local/lib/erebor/daemon-systemd-control-plane.sh"],
        None,
    )
}

#[test]
#[ignore = "requires Linux, Docker, privileged containers, and EREBOR_REAL_CODEX_RELEASE"]
fn real_codex_tui_runs_as_a_governed_session_in_systemd_container() -> Result<(), Box<dyn Error>> {
    let release = env::var("EREBOR_REAL_CODEX_RELEASE")?;
    let release = Path::new(&release);
    if !release.join("bin/codex").is_file() {
        return Err(format!(
            "EREBOR_REAL_CODEX_RELEASE must contain bin/codex: {}",
            release.display()
        )
        .into());
    }
    run_systemd_probe(
        ["/usr/local/lib/erebor/daemon-systemd-control-plane.sh"],
        Some(release),
    )
}

fn run_systemd_probe<const N: usize>(
    arguments: [&str; N],
    codex_release: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    if env::consts::OS != "linux" {
        return Err("the daemon systemd-container probe requires Linux".into());
    }

    let image = env::var("EREBOR_DAEMON_SYSTEMD_IMAGE")
        .unwrap_or_else(|_| "erebor-daemon-systemd:local".to_owned());
    let container = SystemdContainer::start(&image, codex_release)?;
    let output = container.exec(arguments)?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "daemon systemd-container probe failed (status {}):\nstdout:\n{}\nstderr:\n{}\ncontainer logs:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        container.logs(),
    )
    .into())
}

struct SystemdContainer {
    id: String,
}

impl SystemdContainer {
    fn start(image: &str, codex_release: Option<&Path>) -> Result<Self, Box<dyn Error>> {
        let mut command = Command::new("docker");
        command.args([
            "run",
            "--detach",
            "--rm",
            "--privileged",
            "--cgroupns=private",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            // The daemon's intrinsic filesystem Surface creates an
            // OverlayFS view. Docker's own root OverlayFS cannot host a
            // nested writable OverlayFS upper/work pair, so this
            // privileged test gives daemon state a valid independent
            // backing filesystem. Production chooses its daemon state
            // filesystem; this is test-fixture storage only.
            "--tmpfs",
            "/var/lib/erebor",
        ]);
        if let Some(release) = codex_release {
            command.args(["--env", "EREBOR_SKIP_FIXTURE_CODEX_PROBE=1"]);
            command.args([
                "--mount",
                &format!(
                    "type=bind,src={},dst=/opt/erebor-real-codex-release,readonly",
                    release.display()
                ),
            ]);
        }
        let output = command.arg(image).output()?;
        if !output.status.success() {
            return Err(format!(
                "could not start privileged systemd container from `{image}` (status {}):\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )
            .into());
        }

        let container = Self {
            id: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        };
        container.await_systemd()?;
        Ok(container)
    }

    fn await_systemd(&self) -> Result<(), Box<dyn Error>> {
        for _ in 0..100 {
            let output = self.exec(["systemctl", "show", "--property=Version", "--value"])?;
            if output.status.success() && !output.stdout.is_empty() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(format!(
            "systemd did not become ready in container `{}`:\n{}",
            self.id,
            self.logs(),
        )
        .into())
    }

    fn exec<const N: usize>(&self, arguments: [&str; N]) -> Result<Output, Box<dyn Error>> {
        Ok(Command::new("docker")
            .arg("exec")
            .arg(&self.id)
            .args(arguments)
            .output()?)
    }

    fn logs(&self) -> String {
        Command::new("docker")
            .arg("logs")
            .arg(&self.id)
            .output()
            .map(|output| {
                format!(
                    "stdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                )
            })
            .unwrap_or_else(|error| format!("could not read Docker logs: {error}"))
    }
}

impl Drop for SystemdContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "--force", self.id.as_str()])
            .status();
    }
}
