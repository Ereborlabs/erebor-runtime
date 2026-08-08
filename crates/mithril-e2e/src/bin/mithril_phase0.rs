use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use mithril_e2e::{BenchmarkModeV1, Phase0Runner, Result};

#[derive(Parser)]
#[command(about = "Run Mithril Phase 0 qualification checks")]
struct Cli {
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Verify {
        #[arg(long)]
        output: PathBuf,
    },
    SourceCheck,
    Probe {
        #[arg(long)]
        output_directory: PathBuf,
    },
    Benchmark {
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum)]
        mode: BenchmarkMode,
        #[arg(long, default_value_t = 100_000)]
        warmup_iterations: u64,
        #[arg(long, default_value_t = 1_000_000)]
        measured_iterations: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum BenchmarkMode {
    Baseline,
    Protected,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let runner = Phase0Runner::new(cli.repo_root);
    match cli.command {
        Command::Verify { output } => {
            let bundle = runner.verify()?;
            runner.write_json(&output, &bundle)
        }
        Command::SourceCheck => runner.verify_checked_sources(),
        Command::Probe { output_directory } => {
            let bundle = runner.probe(&output_directory)?;
            runner.write_json(&output_directory.join("capability-probe.json"), &bundle)
        }
        Command::Benchmark {
            target,
            output,
            mode,
            warmup_iterations,
            measured_iterations,
        } => {
            let mode = match mode {
                BenchmarkMode::Baseline => BenchmarkModeV1::Baseline,
                BenchmarkMode::Protected => BenchmarkModeV1::Protected,
            };
            let bundle = runner.benchmark(mode, &target, warmup_iterations, measured_iterations)?;
            runner.write_json(&output, &bundle)
        }
    }
}
