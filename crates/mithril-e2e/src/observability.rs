use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::fd::{AsFd as _, FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use erebor_interceptor::diagnostic::{DiagnosticBackend, DiagnosticMode, DiagnosticResult};
use erebor_interceptor::{KernelHostConfig, KernelHostOwner};
use serde::{Deserialize, Serialize};

type ProofResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn kubernetes_cgroup_path(path: &Path) -> bool {
    ["/sys/fs/cgroup/kubepods", "/sys/fs/cgroup/kubepods.slice"]
        .iter()
        .any(|root| {
            path.strip_prefix(root).is_ok_and(|relative| {
                relative.components().count() >= 2
                    && relative
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_)))
            })
        })
}

#[derive(Serialize)]
struct CaseResult {
    name: &'static str,
    result: DiagnosticResult,
    frames: Vec<erebor_interceptor::diagnostic::DiagnosticFrame>,
    observed_program_ids: BTreeSet<u64>,
    observed_map_ids: BTreeSet<u64>,
    map_memlock_bytes: BTreeMap<u64, Option<u64>>,
    kernel_runtime: BTreeMap<u32, KernelRunTime>,
    cleanup_verified: bool,
    enforcement_manifest_unchanged: bool,
}

#[derive(Serialize)]
struct KernelRunTime {
    run_time_ns: u64,
    run_count: u64,
    recursion_misses: u64,
}

struct KernelRuntimeStats {
    _lease: OwnedFd,
}

impl KernelRuntimeStats {
    #[allow(unsafe_code)]
    fn open() -> ProofResult<Self> {
        // SAFETY: The syscall has no pointer inputs and returns a new owned descriptor.
        let fd = unsafe {
            libbpf_rs::libbpf_sys::bpf_enable_stats(libbpf_rs::libbpf_sys::BPF_STATS_RUN_TIME)
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: This owner closes the successful syscall descriptor once.
        Ok(Self {
            _lease: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }
}

impl CaseResult {
    fn verify(&self) -> ProofResult<()> {
        let diagnostics: Vec<_> = self
            .frames
            .iter()
            .filter(|frame| frame.stderr)
            .flat_map(|frame| frame.bytes.iter().copied())
            .collect();
        let diagnostics = String::from_utf8_lossy(&diagnostics);
        if self.name == "probe-limit" && !diagnostics.contains("exceeds") {
            return Err("probe-limit: the backend did not report its probe ceiling".into());
        }
        if self.name == "unsafe-helper" && !diagnostics.contains("unsafe") {
            return Err("unsafe-helper: the backend did not reject the unsafe function".into());
        }
        if self.name == "histogram"
            && !self.frames.iter().any(|frame| {
                serde_json::from_slice::<serde_json::Value>(&frame.bytes)
                    .is_ok_and(|value| value["type"] == "hist")
            })
        {
            return Err("histogram: final histogram output is missing".into());
        }
        if self.name == "partial-attach"
            && (self.result.exit_code == Some(0)
                || self.result.attach_notification_ms.is_some()
                || self.observed_program_ids.len() < 2)
        {
            return Err("partial-attach: failure after partial loading was not observed".into());
        }
        if !self.cleanup_verified
            || !self.enforcement_manifest_unchanged
            || self.result.cleanup_verified == Some(false)
        {
            return Err(format!("{}: resource cleanup failed", self.name).into());
        }
        if self.name == "parse-error" {
            let output: Vec<_> = self
                .frames
                .iter()
                .flat_map(|frame| frame.bytes.iter().copied())
                .collect();
            if !String::from_utf8_lossy(&output)
                .contains("ERROR: unexpected end of file, expected {")
            {
                return Err("parse-error: compiler did not reach source parsing".into());
            }
        }
        if self.name == "compile-valid"
            && (self.result.exit_code != Some(0) || !self.observed_program_ids.is_empty())
        {
            return Err("compile-valid: compilation failed or loaded a program".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ResourceSnapshot {
    programs: BTreeSet<u64>,
    maps: BTreeSet<u64>,
    links: BTreeSet<u64>,
}

impl ResourceSnapshot {
    fn read() -> ProofResult<Self> {
        if !rustix::process::geteuid().is_root() {
            return Err("BPF inventory requires root".into());
        }
        Ok(Self {
            programs: libbpf_rs::query::ProgInfoIter::default()
                .map(|item| u64::from(item.id))
                .collect(),
            maps: libbpf_rs::query::MapInfoIter::default()
                .map(|item| u64::from(item.id))
                .collect(),
            links: libbpf_rs::query::LinkInfoIter::default()
                .map(|item| u64::from(item.id))
                .collect(),
        })
    }
}

pub struct ObservabilityQualification {
    output: PathBuf,
}

impl ObservabilityQualification {
    pub fn new(output: PathBuf) -> Self {
        Self { output }
    }

    pub fn pod_recipes(
        &self,
        executable: PathBuf,
        digest: [u8; 32],
        cgroup: &Path,
    ) -> ProofResult<()> {
        use mithril_control::{TraceFrameKindV1, TraceFrameV1, TraceRecipeV1};
        use std::os::unix::fs::MetadataExt as _;
        fs::create_dir(&self.output)?;
        if !kubernetes_cgroup_path(cgroup) || !cgroup.is_dir() {
            return Err("the recipe target is not a Kubernetes cgroup".into());
        }
        let held = fs::File::open(cgroup)?;
        let cgroup_id = held.metadata()?.ino();
        let baseline = ResourceSnapshot::read()?;
        let backend = DiagnosticBackend::new(executable, digest)?;
        let mut results = Vec::new();
        for recipe in [TraceRecipeV1::SyscallErrors, TraceRecipeV1::FailedOpens] {
            for pod in ["foreign", "target"] {
                let capture = backend.start(
                    &recipe.manifest()?.source.bytes,
                    cgroup_id,
                    DiagnosticMode::Capture,
                    Duration::from_secs(3),
                )?;
                let mut frames = Vec::new();
                let deadline = Instant::now() + Duration::from_secs(12);
                let mut ready = false;
                while Instant::now() < deadline && !capture.is_finished() {
                    for frame in capture.frames().try_iter() {
                        ready |=
                            frame.stderr && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n";
                        frames.push(frame);
                    }
                    if ready {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !ready {
                    return Err("recipe attachment did not become ready".into());
                }
                if fs::metadata(cgroup)?.ino() != cgroup_id {
                    return Err("Pod cgroup changed before probe".into());
                }
                let probe = Command::new("/usr/local/bin/k3s")
                    .args([
                        "kubectl",
                        "-n",
                        "araphor-observability-qualification",
                        "exec",
                        pod,
                        "--",
                        "/bin/cat",
                        "/araphor-observability-missing-file",
                    ])
                    .output()?;
                if probe.status.code() != Some(1) {
                    return Err("Pod did not report the expected failed open".into());
                }
                while !capture.is_finished() {
                    frames.extend(capture.frames().try_iter());
                    std::thread::sleep(Duration::from_millis(10));
                }
                frames.extend(capture.frames().try_iter());
                let terminal = capture.finish()?;
                let measurements: Vec<_> = frames
                    .iter()
                    .flat_map(|frame| {
                        recipe
                            .measurements(&TraceFrameV1 {
                                execution_id: [1; 16],
                                sequence: frame.sequence,
                                kind: if frame.stderr {
                                    TraceFrameKindV1::Diagnostic
                                } else {
                                    TraceFrameKindV1::Data
                                },
                                bytes: frame.bytes.clone(),
                            })
                            .unwrap_or_default()
                    })
                    .collect();
                let expected = if pod == "foreign" {
                    measurements.is_empty()
                } else {
                    measurements
                        .iter()
                        .any(|row| row.errno == -libc::ENOENT as i64 && row.count > 0)
                };
                results.push(serde_json::json!({ "recipe": recipe, "probe_pod": pod,
                    "cgroup": cgroup, "cgroup_id": cgroup_id, "frames": frames,
                    "measurements": measurements, "terminal": terminal }));
                fs::write(
                    self.output.join("pod-recipes.json"),
                    serde_json::to_vec_pretty(&results)?,
                )?;
                if !expected
                    || terminal.forced_kill
                    || terminal.output_incomplete
                    || terminal.cleanup_verified != Some(true)
                {
                    return Err(format!(
                        "recipe attribution or cleanup failed: {recipe:?} {pod}: {terminal:?}"
                    )
                    .into());
                }
                let cleanup_deadline = Instant::now() + Duration::from_secs(2);
                while ResourceSnapshot::read()? != baseline && Instant::now() < cleanup_deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                if ResourceSnapshot::read()? != baseline {
                    return Err("recipe changed the BPF resource baseline".into());
                }
            }
        }
        Ok(())
    }

    pub fn backend(
        &self,
        executable: PathBuf,
        digest: [u8; 32],
        retained_pin_root: Option<PathBuf>,
    ) -> ProofResult<()> {
        fs::create_dir(&self.output)?;
        let _runtime_stats = KernelRuntimeStats::open()?;
        let directory = tempfile::tempdir()?;
        let pin_root = retained_pin_root.unwrap_or_else(|| {
            PathBuf::from(format!(
                "/sys/fs/bpf/araphor-observability-{}",
                uuid::Uuid::new_v4()
            ))
        });
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let host = KernelHostOwner::new(KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            directory.path().join("lease"),
            Some(pin_root),
            boot.trim(),
            1,
        ))
        .start()?;
        let result = self.backend_cases(&host, executable, digest);
        let cleanup = host.decommission();
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error.into()),
            (Err(error), Err(cleanup)) => {
                Err(format!("{error}; enforcement cleanup also failed: {cleanup}").into())
            }
        }
    }

    fn backend_cases(
        &self,
        host: &erebor_interceptor::KernelHost,
        executable: PathBuf,
        digest: [u8; 32],
    ) -> ProofResult<()> {
        let backend = DiagnosticBackend::new(executable, digest)?;
        let baseline = ResourceSnapshot::read()?;
        Self::missing_btf()?;
        if ResourceSnapshot::read()? != baseline {
            return Err("missing BTF changed live resources".into());
        }
        self.write("missing-btf.json", &true)?;
        self.write("baseline.json", &baseline)?;
        self.write("enforcement-manifest.json", host.manifest())?;
        let cases = [
            (
                "compile-timeout",
                "BEGIN { @x = count(); }",
                DiagnosticMode::Compile,
                false,
            ),
            (
                "oversize-output",
                "BEGIN { printf(\"%1048577d\\n\", 1); exit(); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "raw-output",
                "iter:task { printf(\"not-json\\n\"); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "probe-limit",
                "tracepoint:syscalls:sys_enter_* { @x = count(); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "unsafe-helper",
                "BEGIN { system(\"true\"); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "compile-valid",
                "BEGIN { @x = count(); }",
                DiagnosticMode::Compile,
                false,
            ),
            (
                "parse-error",
                "this is not bpftrace",
                DiagnosticMode::Compile,
                false,
            ),
            (
                "unsupported-hook",
                "kprobe:araphor_missing_hook_5f6d { @x = count(); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "quiet",
                include_str!("../fixtures/observability/quiet.bt"),
                DiagnosticMode::Capture,
                true,
            ),
            (
                "histogram",
                include_str!("../fixtures/observability/histogram.bt"),
                DiagnosticMode::Capture,
                true,
            ),
            (
                "graceful",
                "interval:s:1 { @x = count(); exit(); }",
                DiagnosticMode::Capture,
                false,
            ),
            (
                "partial-attach",
                include_str!("../fixtures/observability/partial-attach.bt"),
                DiagnosticMode::Capture,
                false,
            ),
            (
                "deadline",
                include_str!("../fixtures/observability/quiet.bt"),
                DiagnosticMode::Capture,
                false,
            ),
            (
                "forced-kill",
                include_str!("../fixtures/observability/quiet.bt"),
                DiagnosticMode::Capture,
                true,
            ),
            (
                "syscall-errors",
                include_str!("../fixtures/observability/syscall-errors.bt"),
                DiagnosticMode::Capture,
                false,
            ),
            (
                "failed-opens",
                include_str!("../fixtures/observability/failed-opens.bt"),
                DiagnosticMode::Capture,
                false,
            ),
        ];
        let mut results = Vec::new();
        for (name, source, mode, cancel) in cases {
            let capture = backend.start(
                source.as_bytes(),
                1,
                mode,
                Duration::from_secs(if cancel { 3 } else { 1 }),
            )?;
            let start = Instant::now();
            let mut frames = Vec::new();
            let mut observed_program_ids = BTreeSet::new();
            let mut observed_map_ids = BTreeSet::new();
            let mut map_memlock_bytes = BTreeMap::new();
            let mut kernel_runtime = BTreeMap::new();
            let mut stopped = false;
            while !capture.is_finished() {
                frames.extend(capture.frames().try_iter());
                let live = ResourceSnapshot::read()?;
                observed_program_ids.extend(live.programs.difference(&baseline.programs).copied());
                observed_map_ids.extend(live.maps.difference(&baseline.maps).copied());
                for program in libbpf_rs::query::ProgInfoIter::default()
                    .filter(|program| observed_program_ids.contains(&u64::from(program.id)))
                {
                    kernel_runtime.insert(
                        program.id,
                        KernelRunTime {
                            run_time_ns: program.run_time_ns,
                            run_count: program.run_cnt,
                            recursion_misses: program.recursion_misses,
                        },
                    );
                }
                for id in live.maps.difference(&baseline.maps) {
                    let memory = libbpf_rs::MapHandle::from_map_id(*id as u32)
                        .ok()
                        .and_then(|map| libbpf_rs::MapFdInfo::from_fd(map.as_fd()).ok())
                        .and_then(|info| info.memlock);
                    map_memlock_bytes.insert(*id, memory);
                }
                if !stopped
                    && ((name == "forced-kill" && !observed_program_ids.is_empty())
                        || (name == "compile-timeout" && capture.process_id().is_some()))
                {
                    let pid = capture
                        .process_id()
                        .and_then(|pid| rustix::process::Pid::from_raw(pid as i32))
                        .ok_or("diagnostic process disappeared")?;
                    let fd =
                        rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
                    rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::STOP)?;
                    if name == "forced-kill" {
                        capture.cancel();
                    }
                    stopped = true;
                }
                if cancel && start.elapsed() > Duration::from_secs(2) {
                    capture.cancel();
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            frames.extend(capture.frames().try_iter());
            let result = capture.finish()?;
            host.verify_live_manifest()?;
            let after = ResourceSnapshot::read()?;
            let record = CaseResult {
                name,
                result,
                frames,
                observed_program_ids,
                observed_map_ids,
                map_memlock_bytes,
                kernel_runtime,
                cleanup_verified: after == baseline,
                enforcement_manifest_unchanged: true,
            };
            self.write(&format!("{name}.json"), &record)?;
            record.verify()?;
            if name == "compile-timeout"
                && (!record.result.forced_kill
                    || record.result.stop
                        != erebor_interceptor::diagnostic::DiagnosticStop::Deadline)
            {
                return Err("compile-timeout: preparation did not stop at its deadline".into());
            }
            if name == "oversize-output"
                && record.result.stop != erebor_interceptor::diagnostic::DiagnosticStop::OutputLimit
            {
                return Err("oversize-output: frame limit was not reached".into());
            }
            if name == "raw-output"
                && !record
                    .frames
                    .iter()
                    .any(|frame| frame.bytes == b"not-json\n")
            {
                return Err("raw-output: backend output was not preserved".into());
            }
            if matches!(name, "probe-limit" | "unsafe-helper") && record.result.exit_code == Some(0)
            {
                return Err(format!("{name}: backend accepted prohibited source").into());
            }
            if name == "forced-kill" && !record.result.forced_kill {
                return Err("forced-kill: the supervisor did not kill the stopped child".into());
            }
            if name == "deadline"
                && record.result.stop != erebor_interceptor::diagnostic::DiagnosticStop::Deadline
            {
                return Err("deadline: the collection lease did not expire".into());
            }
            if !record.cleanup_verified {
                return Err(format!("{name}: BPF resource inventory changed after cleanup").into());
            }
            if cancel && record.observed_program_ids.is_empty() {
                return Err(format!("{name}: no diagnostic program was observed").into());
            }
            if name == "graceful" && record.result.exit_code != Some(0) {
                return Err("graceful bpftrace fixture failed".into());
            }
            results.push(record);
        }
        self.write("backend-results.json", &results)?;
        self.parent_death(host, &baseline, digest)?;
        Ok(())
    }

    pub fn parent_fixture(&self, executable: PathBuf, digest: [u8; 32]) -> ProofResult<()> {
        fs::create_dir(&self.output)?;
        let capture = DiagnosticBackend::new(executable, digest)?.start(
            include_bytes!("../fixtures/observability/quiet.bt"),
            1,
            DiagnosticMode::Capture,
            Duration::from_secs(30),
        )?;
        let started = Instant::now();
        while capture.process_id().is_none()
            && !capture.is_finished()
            && started.elapsed() < Duration::from_secs(5)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.write(
            "pid.json",
            &capture
                .process_id()
                .ok_or("parent fixture could not spawn bpftrace")?,
        )?;
        let _frames: Vec<_> = capture.frames().iter().collect();
        capture.finish()?;
        Ok(())
    }

    fn parent_death(
        &self,
        host: &erebor_interceptor::KernelHost,
        baseline: &ResourceSnapshot,
        digest: [u8; 32],
    ) -> ProofResult<()> {
        let path = self.output.join("parent-fixture");
        let mut fixture = QualificationChild(
            Command::new(std::env::current_exe()?)
                .arg("--parent-fixture")
                .args([
                    "--executable",
                    "/usr/bin/bpftrace",
                    "--sha256",
                    &hex::encode(digest),
                ])
                .arg("--output-directory")
                .arg(&path)
                .spawn()?,
        );
        let started = Instant::now();
        let mut observed = BTreeSet::new();
        while started.elapsed() < Duration::from_secs(5) {
            let live = ResourceSnapshot::read()?;
            observed.extend(live.programs.difference(&baseline.programs).copied());
            if path.join("pid.json").is_file()
                && !observed.is_empty()
                && started.elapsed() >= Duration::from_secs(1)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        fixture.0.kill()?;
        fixture.0.wait()?;
        let cleanup_started = Instant::now();
        loop {
            if ResourceSnapshot::read()? == *baseline {
                break;
            }
            if cleanup_started.elapsed() >= Duration::from_secs(5) {
                return Err("parent death left BPF resources".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if observed.is_empty() {
            return Err("parent-death fixture never loaded a diagnostic program".into());
        }
        host.verify_live_manifest()?;
        self.write("parent-death-program-ids.json", &observed)?;
        Ok(())
    }

    fn write(&self, name: &str, value: &impl Serialize) -> ProofResult<()> {
        fs::write(
            self.output.join(Path::new(name)),
            serde_json::to_vec_pretty(value)?,
        )?;
        Ok(())
    }

    fn missing_btf() -> ProofResult<()> {
        let directory = tempfile::tempdir()?;
        let missing = directory.path().join("missing.btf");
        let owner = KernelHostOwner::new(KernelHostConfig::identity(
            &missing,
            directory.path().join("lease"),
            None,
            "qualification",
            1,
        ));
        match owner.preflight() {
            Err(erebor_interceptor::Error::InvalidConfiguration { path, reason, .. })
                if path == missing && reason == "runtime BTF is not a regular file" =>
            {
                Ok(())
            }
            _ => Err("missing BTF did not fail before attachment".into()),
        }
    }
}

struct QualificationChild(std::process::Child);

impl Drop for QualificationChild {
    fn drop(&mut self) {
        let _kill = self.0.kill();
        let _wait = self.0.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_target_latency_fixture_needs_no_protected_file_writes() -> ProofResult<()> {
        let status = Command::new("python3")
            .arg("-c")
            .arg(
                r#"
import builtins, ctypes, errno, os, pathlib, sys, time
source = pathlib.Path(sys.argv[1]).read_text()
names = []
class Libc:
    def prctl(self, operation, value, *args):
        names.append(ctypes.string_at(value).decode())
        return 0
ctypes.CDLL = lambda *args, **kwargs: Libc()
def denied(*args, **kwargs):
    raise PermissionError(errno.EACCES, 'protected file operation')
builtins.open = denied
os.open = denied
os.rename = denied
os.path.exists = lambda path: True
time.sleep = lambda delay: None
sys.argv = ['observability.py', '/work']
exec(compile(source, 'observability.py', 'exec'))
assert len(names) == 10 and all(name.startswith(f'tr{i}:') for i, name in enumerate(names)), names
"#,
            )
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/process/observability.py"))
            .status()?;
        assert!(status.success());
        Ok(())
    }

    #[test]
    fn observability_target_accepts_the_k3s_systemd_cgroup_layout() {
        assert!(kubernetes_cgroup_path(Path::new("/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod123.slice/cri-containerd-456.scope")));
        assert!(kubernetes_cgroup_path(Path::new(
            "/sys/fs/cgroup/kubepods/besteffort/pod123/456"
        )));
        assert!(!kubernetes_cgroup_path(Path::new(
            "/sys/fs/cgroup/kubepods-other/456"
        )));
        assert!(!kubernetes_cgroup_path(Path::new(
            "/sys/fs/cgroup/system.slice/456"
        )));
    }

    #[test]
    fn observability_backend_missing_btf_rejects_before_attach() -> ProofResult<()> {
        ObservabilityQualification::missing_btf()
    }

    #[test]
    fn observability_backend_root_refusal_is_not_a_parse_proof() {
        let record = CaseResult {
            name: "parse-error",
            result: DiagnosticResult {
                process_id: 1,
                stop: erebor_interceptor::diagnostic::DiagnosticStop::Exited,
                exit_code: Some(1),
                forced_kill: false,
                output_incomplete: false,
                emitted_frames: 1,
                retained_bytes: 0,
                elapsed_ms: 1,
                attach_notification_ms: None,
                program_ids: BTreeSet::new(),
                map_ids: BTreeSet::new(),
                cleanup_verified: None,
                peak_rss_kib: None,
            },
            frames: vec![erebor_interceptor::diagnostic::DiagnosticFrame {
                sequence: 1,
                stderr: true,
                bytes: b"ERROR: bpftrace currently only supports running as the root user.\n"
                    .to_vec(),
            }],
            observed_program_ids: BTreeSet::new(),
            observed_map_ids: BTreeSet::new(),
            map_memlock_bytes: BTreeMap::new(),
            kernel_runtime: BTreeMap::new(),
            cleanup_verified: true,
            enforcement_manifest_unchanged: true,
        };
        assert!(record.verify().is_err());
    }
}
