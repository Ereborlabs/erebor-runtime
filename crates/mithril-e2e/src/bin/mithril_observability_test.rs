use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(about = "Qualify diagnostic capture on a disposable host")]
struct Cli {
    #[arg(long)]
    executable: PathBuf,
    #[arg(long)]
    sha256: String,
    #[arg(long)]
    output_directory: PathBuf,
    #[arg(long)]
    retained_pin_root: Option<PathBuf>,
    #[arg(long, conflicts_with = "retained_pin_root")]
    parent_fixture: bool,
    #[arg(long, conflicts_with_all = ["parent_fixture", "retained_pin_root"])]
    pod_cgroup: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let digest: [u8; 32] = hex::decode(&cli.sha256)?
        .try_into()
        .map_err(|_| "expected a 32-byte executable digest")?;
    let owner = mithril_e2e::ObservabilityQualification::new(cli.output_directory);
    if let Some(cgroup) = cli.pod_cgroup {
        owner.pod_recipes(cli.executable, digest, &cgroup)
    } else if cli.parent_fixture {
        owner.parent_fixture(cli.executable, digest)
    } else {
        owner.backend(cli.executable, digest, cli.retained_pin_root)
    }
}
