use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Case {
    Backend,
    BackendLifecycle,
    OwnedCapture,
}

#[derive(Parser)]
#[command(about = "Qualify diagnostic capture on a disposable host")]
struct Cli {
    #[arg(long, value_enum, default_value = "backend")]
    case: Case,
    #[arg(long, requires = "sha256", required_if_eq("case", "backend"))]
    executable: Option<PathBuf>,
    #[arg(long, requires = "executable", required_if_eq("case", "backend"))]
    sha256: Option<String>,
    #[arg(long)]
    output_directory: PathBuf,
    #[arg(long)]
    retained_pin_root: Option<PathBuf>,
    #[arg(long, conflicts_with = "retained_pin_root")]
    parent_fixture: bool,
    #[arg(long, conflicts_with_all = ["parent_fixture", "retained_pin_root"])]
    pod_cgroup: Option<PathBuf>,
}

impl Cli {
    fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let owner = mithril_e2e::ObservabilityQualification::new(self.output_directory);
        if self.case == Case::OwnedCapture {
            if self.executable.is_some()
                || self.sha256.is_some()
                || self.retained_pin_root.is_some()
                || self.parent_fixture
                || self.pod_cgroup.is_some()
            {
                return Err("owned-capture does not accept physical-backend options".into());
            }
            return owner.owned_capture();
        }
        if self.case == Case::BackendLifecycle {
            if self.executable.is_some()
                || self.sha256.is_some()
                || self.retained_pin_root.is_some()
                || self.pod_cgroup.is_some()
            {
                return Err("backend-lifecycle does not accept physical-backend options".into());
            }
            return if self.parent_fixture {
                owner.lifecycle_child()
            } else {
                owner.backend_lifecycle()
            };
        }
        let executable = self.executable.ok_or("backend requires --executable")?;
        let digest: [u8; 32] = hex::decode(self.sha256.ok_or("backend requires --sha256")?)?
            .try_into()
            .map_err(|_| "expected a 32-byte executable digest")?;
        if let Some(cgroup) = self.pod_cgroup {
            owner.pod_recipes(executable, digest, &cgroup)
        } else if self.parent_fixture {
            owner.parent_fixture(executable, digest)
        } else {
            owner.backend(executable, digest, self.retained_pin_root)
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Cli::parse().run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_backend_cli() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "test",
            "--case",
            "backend-lifecycle",
            "--output-directory",
            "/tmp/proof",
        ])?;
        assert_eq!(cli.case, Case::BackendLifecycle);
        assert!(cli.executable.is_none());
        for args in [
            vec![
                "test",
                "--case",
                "backend",
                "--output-directory",
                "/tmp/proof",
            ],
            vec![
                "test",
                "--case",
                "unknown",
                "--output-directory",
                "/tmp/proof",
            ],
            vec![
                "test",
                "--case",
                "backend-lifecycle",
                "--sha256",
                "00",
                "--output-directory",
                "/tmp/proof",
            ],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        }
        assert!(
            Cli::try_parse_from(["test", "--output-directory", "/tmp/proof"])?
                .run()
                .is_err()
        );
        let cli = Cli::try_parse_from([
            "test",
            "--case",
            "backend-lifecycle",
            "--retained-pin-root",
            "/sys/fs/bpf/unused",
            "--output-directory",
            "/tmp/proof",
        ])?;
        assert!(cli.run().is_err());
        Ok(())
    }

    #[test]
    fn observability_owned_cli() -> Result<(), Box<dyn std::error::Error>> {
        let args = [
            "test",
            "--case",
            "owned-capture",
            "--output-directory",
            "/tmp/proof",
        ];
        let cli = Cli::try_parse_from(args)?;
        assert_eq!(cli.case, Case::OwnedCapture);
        assert!(cli.executable.is_none());
        for options in [
            vec!["--parent-fixture"],
            vec!["--retained-pin-root", "/sys/fs/bpf/unused"],
            vec!["--pod-cgroup", "/sys/fs/cgroup/unused"],
            vec!["--executable", "/unused/bpftrace", "--sha256", "00"],
        ] {
            let cli = Cli::try_parse_from(args.into_iter().chain(options))?;
            assert!(cli.run().is_err());
        }
        Ok(())
    }
}
