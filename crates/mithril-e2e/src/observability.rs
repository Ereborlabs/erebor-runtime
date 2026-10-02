use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::fd::{AsFd as _, FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use erebor_interceptor::diagnostic::{
    DiagnosticBackend, DiagnosticFrame, DiagnosticMode, DiagnosticResult, DiagnosticStop,
    PREPARATION_LIMIT,
};
use erebor_interceptor::{KernelHostConfig, KernelHostOwner};
use serde::{Deserialize, Serialize};

mod lifecycle;

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
    observed_link_ids: BTreeSet<u64>,
    hash_entries: BTreeMap<u64, u32>,
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
    fn attached(frame: &DiagnosticFrame) -> bool {
        frame.stderr && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
    }

    fn verify(&self) -> ProofResult<()> {
        if self.hash_entries.values().any(|entries| *entries > 4096)
            || (matches!(self.name, "syscall-errors" | "failed-opens")
                && self.hash_entries.is_empty())
        {
            return Err(format!(
                "{}: the diagnostic map-key ceiling is not proved",
                self.name
            )
            .into());
        }
        let diagnostics: Vec<_> = self
            .frames
            .iter()
            .filter(|frame| frame.stderr)
            .flat_map(|frame| frame.bytes.iter().copied())
            .collect();
        let diagnostics = String::from_utf8_lossy(&diagnostics);
        if matches!(
            self.name,
            "quiet"
                | "histogram"
                | "graceful"
                | "deadline"
                | "forced-kill"
                | "syscall-errors"
                | "failed-opens"
        ) {
            if self.result.attach_notification_ms.is_none()
                || !self.frames.iter().any(Self::attached)
                || self.observed_program_ids.is_empty()
            {
                return Err(
                    format!("{}: qualified capture readiness is missing", self.name).into(),
                );
            }
            let stop = match self.name {
                "quiet" | "histogram" | "forced-kill" => DiagnosticStop::Cancelled,
                "graceful" => DiagnosticStop::Exited,
                _ => DiagnosticStop::Deadline,
            };
            if self.result.stop != stop
                || if self.name == "forced-kill" {
                    !self.result.forced_kill
                        || !self.result.output_incomplete
                        || self.result.exit_code.is_some()
                } else {
                    self.result.forced_kill
                        || self.result.output_incomplete
                        || self.result.exit_code != Some(0)
                }
            {
                return Err(
                    format!("{}: capture did not reach its expected result", self.name).into(),
                );
            }
        }
        if matches!(
            self.name,
            "parse-error" | "probe-limit" | "unsafe-helper" | "unsupported-hook" | "partial-attach"
        ) && (self.result.stop != DiagnosticStop::Exited
            || self.result.exit_code.is_none_or(|code| code == 0)
            || self.result.forced_kill
            || self.result.output_incomplete
            || self.result.attach_notification_ms.is_some()
            || self.frames.iter().any(Self::attached))
        {
            return Err(format!("{}: the expected backend rejection is missing", self.name).into());
        }
        if self.name == "unsupported-hook"
            && !diagnostics.contains("Error attaching probe: 'kprobe:araphor_missing_hook_5f6d'")
        {
            return Err("unsupported-hook: the selected hook did not fail attachment".into());
        }
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
            && (self.result.stop != DiagnosticStop::Exited
                || self.result.exit_code != Some(0)
                || self.result.forced_kill
                || self.result.output_incomplete
                || self.result.attach_notification_ms.is_some()
                || !self.observed_program_ids.is_empty()
                || !self.observed_map_ids.is_empty()
                || !self.observed_link_ids.is_empty())
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
                        ready |= CaseResult::attached(&frame);
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
        let backend = DiagnosticBackend::new(executable.clone(), digest)?;
        let baseline = ResourceSnapshot::read()?;
        Self::missing_btf()?;
        if ResourceSnapshot::read()? != baseline {
            return Err("missing BTF changed live resources".into());
        }
        self.write(
            "missing-btf.json",
            &serde_json::json!({
                "owner": "KernelHostOwner",
                "stage": "preflight",
                "missing_runtime_btf_rejected": true,
            }),
        )?;
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
                Duration::from_secs(if cancel || name == "graceful" { 3 } else { 1 }),
            )?;
            let mut attached = None;
            let mut frames = Vec::new();
            let mut observed_program_ids = BTreeSet::new();
            let mut observed_map_ids = BTreeSet::new();
            let mut observed_link_ids = BTreeSet::new();
            let mut hash_entries = BTreeMap::new();
            let mut map_memlock_bytes = BTreeMap::new();
            let mut kernel_runtime = BTreeMap::new();
            let mut stopped = false;
            while !capture.is_finished() {
                for frame in capture.frames().try_iter() {
                    if attached.is_none() && CaseResult::attached(&frame) {
                        attached = Some(Instant::now());
                    }
                    frames.push(frame);
                }
                let live = ResourceSnapshot::read()?;
                observed_program_ids.extend(live.programs.difference(&baseline.programs).copied());
                observed_map_ids.extend(live.maps.difference(&baseline.maps).copied());
                observed_link_ids.extend(live.links.difference(&baseline.links).copied());
                for map in libbpf_rs::query::MapInfoIter::default().filter(|map| {
                    observed_map_ids.contains(&u64::from(map.id)) && map.ty.is_hash_map()
                }) {
                    hash_entries.insert(u64::from(map.id), map.max_entries);
                }
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
                    && ((name == "forced-kill"
                        && attached.is_some()
                        && !observed_program_ids.is_empty())
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
                if cancel && attached.is_some_and(|time| time.elapsed() > Duration::from_secs(2)) {
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
                observed_link_ids,
                hash_entries,
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
            if !record.cleanup_verified {
                return Err(format!("{name}: BPF resource inventory changed after cleanup").into());
            }
            results.push(record);
        }
        self.write("backend-results.json", &results)?;
        self.parent_death(host, &baseline, &executable, digest)?;
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
        while !capture.is_finished()
            && started.elapsed() < PREPARATION_LIMIT + Duration::from_secs(2)
        {
            for frame in capture.frames().try_iter() {
                if CaseResult::attached(&frame) {
                    self.write(
                        "pid.json",
                        &capture
                            .process_id()
                            .ok_or("parent fixture exited before readiness")?,
                    )?;
                    self.write("ready-pending.json", &frame)?;
                    fs::rename(
                        self.output.join("ready-pending.json"),
                        self.output.join("ready.json"),
                    )?;
                    capture.frames().iter().for_each(drop);
                    return Err(format!(
                        "parent fixture ended before parent death: {:?}",
                        capture.finish()?
                    )
                    .into());
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err("parent fixture did not report qualified attachment readiness".into())
    }

    fn parent_death(
        &self,
        host: &erebor_interceptor::KernelHost,
        baseline: &ResourceSnapshot,
        executable: &Path,
        digest: [u8; 32],
    ) -> ProofResult<()> {
        let path = self.output.join("parent-fixture");
        if path.exists() {
            return Err("parent fixture output already exists".into());
        }
        let mut fixture = QualificationChild(
            Command::new(std::env::current_exe()?)
                .arg("--parent-fixture")
                .arg("--executable")
                .arg(executable)
                .args(["--sha256", &hex::encode(digest)])
                .arg("--output-directory")
                .arg(&path)
                .spawn()?,
        );
        let started = Instant::now();
        let mut observed = ResourceSnapshot {
            programs: BTreeSet::new(),
            maps: BTreeSet::new(),
            links: BTreeSet::new(),
        };
        let mut ready = false;
        while started.elapsed() < PREPARATION_LIMIT + Duration::from_secs(2) {
            if fixture.0.try_wait()?.is_some() {
                return Err("parent fixture exited before qualified readiness".into());
            }
            let live = ResourceSnapshot::read()?;
            observed
                .programs
                .extend(live.programs.difference(&baseline.programs).copied());
            observed
                .maps
                .extend(live.maps.difference(&baseline.maps).copied());
            observed
                .links
                .extend(live.links.difference(&baseline.links).copied());
            if Self::parent_ready(&path, &live, baseline)? {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !ready {
            return Err("parent fixture did not reach qualified attachment readiness".into());
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
        host.verify_live_manifest()?;
        self.write("parent-death-program-ids.json", &observed.programs)?;
        self.write("parent-death-map-ids.json", &observed.maps)?;
        self.write("parent-death-link-ids.json", &observed.links)?;
        Ok(())
    }

    fn parent_ready(
        path: &Path,
        live: &ResourceSnapshot,
        baseline: &ResourceSnapshot,
    ) -> ProofResult<bool> {
        let bytes = match fs::read(path.join("ready.json")) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if !CaseResult::attached(&serde_json::from_slice::<DiagnosticFrame>(&bytes)?) {
            return Err("parent fixture readiness is not an attachment notification".into());
        }
        Ok(live
            .programs
            .difference(&baseline.programs)
            .next()
            .is_some())
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

    fn capture_case(name: &'static str) -> CaseResult {
        let mut frames = vec![DiagnosticFrame {
            sequence: 1,
            stderr: true,
            bytes: b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n".to_vec(),
        }];
        if name == "histogram" {
            frames.push(DiagnosticFrame {
                sequence: 2,
                stderr: false,
                bytes: b"{\"type\":\"hist\",\"data\":{}}\n".to_vec(),
            });
        }
        CaseResult {
            name,
            result: DiagnosticResult {
                process_id: 1,
                stop: match name {
                    "quiet" | "histogram" | "forced-kill" => DiagnosticStop::Cancelled,
                    "graceful" => DiagnosticStop::Exited,
                    _ => DiagnosticStop::Deadline,
                },
                exit_code: (name != "forced-kill").then_some(0),
                forced_kill: name == "forced-kill",
                output_incomplete: name == "forced-kill",
                emitted_frames: frames.len() as u64,
                retained_bytes: frames.iter().map(|frame| frame.bytes.len()).sum(),
                elapsed_ms: 3_000,
                attach_notification_ms: Some(100),
                program_ids: BTreeSet::from([11]),
                map_ids: BTreeSet::from([12]),
                cleanup_verified: Some(true),
                peak_rss_kib: None,
            },
            frames,
            observed_program_ids: BTreeSet::from([11]),
            observed_map_ids: BTreeSet::from([12]),
            observed_link_ids: BTreeSet::new(),
            hash_entries: BTreeMap::from([(12, 4096)]),
            map_memlock_bytes: BTreeMap::new(),
            kernel_runtime: BTreeMap::new(),
            cleanup_verified: true,
            enforcement_manifest_unchanged: true,
        }
    }

    #[test]
    fn observability_backend_capture_readiness() -> ProofResult<()> {
        for name in [
            "quiet",
            "histogram",
            "graceful",
            "deadline",
            "forced-kill",
            "syscall-errors",
            "failed-opens",
        ] {
            let mut record = capture_case(name);
            record.verify()?;
            record.result.attach_notification_ms = None;
            assert!(record.verify().is_err(), "{name}: missing notification");
            record.result.attach_notification_ms = Some(100);
            record.frames[0].stderr = false;
            assert!(record.verify().is_err(), "{name}: stdout marker");
            record.frames[0].stderr = true;
            for bytes in [
                b"Attaching 1 probe...\n".as_slice(),
                b"__BPFTRACE_NOTIFY_PROBES_ATTACHED extra\n".as_slice(),
            ] {
                record.frames[0].bytes = bytes.to_vec();
                assert!(record.verify().is_err(), "{name}: wrong marker");
            }
            record.frames[0].bytes = b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n".to_vec();
            record.observed_program_ids.clear();
            assert!(record.verify().is_err(), "{name}: no observed program");
        }
        Ok(())
    }

    #[test]
    fn observability_backend_map_capacity() -> ProofResult<()> {
        let mut record = capture_case("syscall-errors");
        record.verify()?;
        record.hash_entries.insert(12, 4097);
        assert!(record.verify().is_err());
        record.hash_entries.clear();
        assert!(record.verify().is_err());
        Ok(())
    }

    #[test]
    fn observability_backend_capture_outcome() -> ProofResult<()> {
        for name in [
            "quiet",
            "histogram",
            "graceful",
            "deadline",
            "forced-kill",
            "syscall-errors",
            "failed-opens",
        ] {
            let mut record = capture_case(name);
            record.verify()?;
            let stop = record.result.stop;
            record.result.stop = DiagnosticStop::PreparationDeadline;
            assert!(record.verify().is_err(), "{name}: preparation failure");
            record.result.stop = stop;
            record.result.output_incomplete = !record.result.output_incomplete;
            assert!(record.verify().is_err(), "{name}: output completeness");
            record.result.output_incomplete = !record.result.output_incomplete;
            record.result.forced_kill = !record.result.forced_kill;
            assert!(record.verify().is_err(), "{name}: wrong termination");
            record.result.forced_kill = !record.result.forced_kill;
            record.result.exit_code = Some(1);
            assert!(record.verify().is_err(), "{name}: unsuccessful capture");
        }
        Ok(())
    }

    #[test]
    fn observability_backend_hook_rejection() -> ProofResult<()> {
        let mut record = capture_case("quiet");
        record.name = "unsupported-hook";
        record.result.stop = DiagnosticStop::Exited;
        record.result.exit_code = Some(1);
        record.result.attach_notification_ms = None;
        record.frames[0].bytes =
            b"ERROR: Error attaching probe: 'kprobe:araphor_missing_hook_5f6d'\n".to_vec();
        record.verify()?;
        record.result.exit_code = Some(0);
        assert!(record.verify().is_err());
        record.result.exit_code = None;
        assert!(record.verify().is_err());
        record.result.exit_code = Some(1);
        record.result.stop = DiagnosticStop::Deadline;
        assert!(record.verify().is_err());
        record.result.stop = DiagnosticStop::Exited;
        record.result.attach_notification_ms = Some(100);
        assert!(record.verify().is_err());
        record.result.attach_notification_ms = None;
        for bytes in [
            b"ERROR: bpftrace currently only supports running as the root user.\n".as_slice(),
            b"ERROR: Error attaching probe: 'kprobe:another_hook'\n".as_slice(),
            b"WARNING: araphor_missing_hook_5f6d is not traceable\n".as_slice(),
        ] {
            record.frames[0].bytes = bytes.to_vec();
            assert!(record.verify().is_err());
        }
        Ok(())
    }

    #[test]
    fn observability_backend_compile_resources() -> ProofResult<()> {
        let mut record = capture_case("graceful");
        record.name = "compile-valid";
        record.result.attach_notification_ms = None;
        record.frames.clear();
        record.observed_program_ids.clear();
        record.observed_map_ids.clear();
        record.hash_entries.clear();
        record.verify()?;
        record.observed_link_ids.insert(13);
        assert!(record.verify().is_err());
        assert_eq!(
            serde_json::to_value(&record)?["observed_link_ids"],
            serde_json::json!([13]),
        );
        record.observed_link_ids.clear();
        record.observed_map_ids.insert(12);
        assert!(record.verify().is_err());
        Ok(())
    }

    #[test]
    fn observability_backend_parent_readiness() -> ProofResult<()> {
        let directory = tempfile::tempdir()?;
        let baseline = ResourceSnapshot {
            programs: BTreeSet::from([1]),
            maps: BTreeSet::new(),
            links: BTreeSet::new(),
        };
        let mut live = baseline.clone();
        live.programs.insert(2);
        fs::write(directory.path().join("pid.json"), b"123")?;
        assert!(!ObservabilityQualification::parent_ready(
            directory.path(),
            &live,
            &baseline,
        )?);
        let mut frame = capture_case("quiet").frames.remove(0);
        let path = directory.path().join("ready.json");
        fs::write(&path, serde_json::to_vec(&frame)?)?;
        assert!(!ObservabilityQualification::parent_ready(
            directory.path(),
            &baseline,
            &baseline,
        )?);
        assert!(ObservabilityQualification::parent_ready(
            directory.path(),
            &live,
            &baseline,
        )?);
        frame.stderr = false;
        fs::write(&path, serde_json::to_vec(&frame)?)?;
        assert!(
            ObservabilityQualification::parent_ready(directory.path(), &live, &baseline,).is_err()
        );
        frame.stderr = true;
        frame.bytes = b"Attaching 1 probe...\n".to_vec();
        fs::write(&path, serde_json::to_vec(&frame)?)?;
        assert!(
            ObservabilityQualification::parent_ready(directory.path(), &live, &baseline,).is_err()
        );
        Ok(())
    }

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
        assert!(kubernetes_cgroup_path(Path::new(
            "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod123.slice/cri-containerd-456.scope"
        )));
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
            observed_link_ids: BTreeSet::new(),
            hash_entries: BTreeMap::new(),
            map_memlock_bytes: BTreeMap::new(),
            kernel_runtime: BTreeMap::new(),
            cleanup_verified: true,
            enforcement_manifest_unchanged: true,
        };
        assert!(record.verify().is_err());
    }
}
