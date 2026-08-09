use std::fs::File;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use serde::Serialize;
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::{DigestV1, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LatencyDistributionV1 {
    pub unit: &'static str,
    pub sample_count: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub maximum: u64,
    pub raw_samples_sha256: String,
    pub raw_samples_ns: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OpenBenchmarkRecordV1 {
    pub operation: &'static str,
    pub concurrency: u32,
    pub warmup_iterations: u64,
    pub measured_iterations: u64,
    pub elapsed_ns: u64,
    pub operations_per_second: f64,
    pub distribution: LatencyDistributionV1,
}

pub struct OpenBenchmark;

impl OpenBenchmark {
    pub fn run(
        path: &Path,
        warmup_iterations: u64,
        measured_iterations: u64,
        concurrency: u32,
    ) -> Result<OpenBenchmarkRecordV1> {
        ensure!(
            measured_iterations > 0 && concurrency > 0,
            InvalidInputSnafu {
                path: path.to_path_buf(),
                reason: "measured iterations and concurrency must be nonzero"
            }
        );
        ensure!(
            path.is_file(),
            InvalidInputSnafu {
                path: path.to_path_buf(),
                reason: "open benchmark target must be a regular file"
            }
        );

        for _ in 0..warmup_iterations {
            File::open(path).context(IoSnafu {
                path: path.to_path_buf(),
            })?;
        }
        let started = Instant::now();
        let mut workers = Vec::with_capacity(concurrency as usize);
        for worker in 0..concurrency {
            let path = path.to_path_buf();
            let worker_measured = share(measured_iterations, concurrency, worker);
            workers.push(thread::spawn(move || {
                measure_worker(&path, worker_measured)
            }));
        }
        let mut samples = Vec::with_capacity(measured_iterations as usize);
        for worker in workers {
            let result = worker.join().map_err(|_| {
                InvalidInputSnafu {
                    path: path.to_path_buf(),
                    reason: "open benchmark worker panicked",
                }
                .build()
            })?;
            samples.extend(result?);
        }
        let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let operations_per_second =
            measured_iterations as f64 * 1_000_000_000.0 / elapsed_ns.max(1) as f64;
        let distribution = LatencyDistributionV1::from_samples(samples);
        Ok(OpenBenchmarkRecordV1 {
            operation: "OPEN",
            concurrency,
            warmup_iterations,
            measured_iterations,
            elapsed_ns,
            operations_per_second,
            distribution,
        })
    }
}

impl LatencyDistributionV1 {
    fn from_samples(raw_samples_ns: Vec<u64>) -> Self {
        let mut sorted = raw_samples_ns.clone();
        sorted.sort_unstable();
        let mut bytes = Vec::with_capacity(raw_samples_ns.len() * size_of::<u64>());
        for sample in &raw_samples_ns {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        Self {
            unit: "NANOSECONDS",
            sample_count: raw_samples_ns.len() as u64,
            p50: percentile(&sorted, 50),
            p95: percentile(&sorted, 95),
            p99: percentile(&sorted, 99),
            maximum: sorted.last().copied().unwrap_or_default(),
            raw_samples_sha256: DigestV1::of(bytes).to_hex(),
            raw_samples_ns,
        }
    }
}

fn share(total: u64, workers: u32, worker: u32) -> u64 {
    total / u64::from(workers) + u64::from(worker < (total % u64::from(workers)) as u32)
}

fn measure_worker(path: &PathBuf, measured: u64) -> Result<Vec<u64>> {
    let mut samples = Vec::with_capacity(measured as usize);
    for _ in 0..measured {
        let started = Instant::now();
        File::open(path).context(IoSnafu { path: path.clone() })?;
        samples.push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    Ok(samples)
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    sorted[(sorted.len() - 1) * percentile / 100]
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use snafu::ResultExt as _;

    use super::OpenBenchmark;
    use crate::error::IoSnafu;

    #[test]
    fn benchmark_records_every_open_sample_at_requested_concurrency() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: PathBuf::from("temporary benchmark directory"),
        })?;
        let target = directory.path().join("target");
        fs::write(&target, b"safe fixture").context(IoSnafu {
            path: target.clone(),
        })?;
        let record = OpenBenchmark::run(&target, 9, 101, 4)?;
        assert_eq!(record.distribution.sample_count, 101);
        assert_eq!(record.distribution.raw_samples_ns.len(), 101);
        assert!(record.distribution.p50 <= record.distribution.p95);
        assert!(record.distribution.p95 <= record.distribution.p99);
        assert!(record.operations_per_second > 0.0);
        Ok(())
    }
}
