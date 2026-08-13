use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use mithril_e2e::{BenchmarkModeV1, KernelQualificationRunner, Result};

#[derive(Parser)]
#[command(about = "Run Mithril kernel qualification checks")]
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
    PhysicalProbe {
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long)]
        bpf_object: Option<PathBuf>,
    },
    RecordPhysicalQualification {
        #[arg(long)]
        physical_probe: PathBuf,
        #[arg(long)]
        baseline_benchmark: PathBuf,
        #[arg(long)]
        protected_benchmark: PathBuf,
        #[arg(long)]
        probe_binary: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Benchmark {
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum)]
        mode: BenchmarkMode,
        #[arg(long)]
        bpf_object: Option<PathBuf>,
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
    let runner = KernelQualificationRunner::new(cli.repo_root);
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
        Command::PhysicalProbe {
            output_directory,
            bpf_object,
        } => {
            let bundle =
                runner.physical_file_open_probe(&output_directory, bpf_object.as_deref())?;
            runner.write_json(
                &output_directory.join("physical-file-open-probe.json"),
                &bundle,
            )
        }
        Command::RecordPhysicalQualification {
            physical_probe,
            baseline_benchmark,
            protected_benchmark,
            probe_binary,
            output,
        } => runner.record_physical_qualification(
            &physical_probe,
            &baseline_benchmark,
            &protected_benchmark,
            &probe_binary,
            &output,
        ),
        Command::Benchmark {
            target,
            output,
            mode,
            warmup_iterations,
            measured_iterations,
            bpf_object,
        } => {
            let mode = match mode {
                BenchmarkMode::Baseline => BenchmarkModeV1::Baseline,
                BenchmarkMode::Protected => BenchmarkModeV1::Protected,
            };
            let bundle = runner.benchmark(
                mode,
                &target,
                warmup_iterations,
                measured_iterations,
                bpf_object.as_deref(),
            )?;
            runner.write_json(&output, &bundle)
        }
    }?;
    println!("Mithril kernel qualification command completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Cli, Command};

    #[test]
    fn physical_record_command_requires_all_evidence_paths() -> std::result::Result<(), clap::Error>
    {
        let cli = Cli::try_parse_from([
            "mithril-kernel-qualification",
            "record-physical-qualification",
            "--physical-probe",
            "physical.json",
            "--baseline-benchmark",
            "baseline.json",
            "--protected-benchmark",
            "protected.json",
            "--probe-binary",
            "probe",
            "--output",
            "record.json",
        ])?;
        assert!(matches!(
            cli.command,
            Command::RecordPhysicalQualification { .. }
        ));
        assert!(Cli::try_parse_from([
            "mithril-kernel-qualification",
            "record-physical-qualification",
            "--physical-probe",
            "physical.json",
            "--baseline-benchmark",
            "baseline.json",
            "--protected-benchmark",
            "protected.json",
            "--output",
            "record.json",
        ])
        .is_err());
        Ok(())
    }
}
