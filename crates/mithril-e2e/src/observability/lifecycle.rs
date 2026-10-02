use super::*;
use erebor_interceptor::diagnostic::{DiagnosticCapture, DiagnosticStop, MAX_OUTPUT_BYTES};
use serde_json::json;

const ATTACHED: &[u8] = b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n";

impl ObservabilityQualification {
    pub fn backend_lifecycle(&self) -> ProofResult<()> {
        fs::create_dir(&self.output)?;
        let cases = [
            ("parse-error", DiagnosticMode::Compile, "printf 'ERROR: unexpected end of file, expected {\\n' >&2; exit 1", DiagnosticStop::Exited),
            ("unsupported-hook", DiagnosticMode::Capture, "printf 'ERROR: missing hook\\n' >&2; exit 1", DiagnosticStop::Exited),
            ("quiet", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; exec sleep 60", DiagnosticStop::Cancelled),
            ("histogram", DiagnosticMode::Capture, r#"trap 'printf "%s\n" "{\"type\":\"hist\",\"data\":{}}"; exit 0' INT; printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\n' >&2; while :; do sleep 1; done"#, DiagnosticStop::Cancelled),
            ("raw-output", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; printf 'not-json\\n'", DiagnosticStop::Exited),
            ("oversize-output", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; head -c 1048577 /dev/zero", DiagnosticStop::OutputLimit),
            ("graceful", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2", DiagnosticStop::Exited),
            ("deadline", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; exec sleep 60", DiagnosticStop::Deadline),
            ("forced-kill", DiagnosticMode::Capture, "trap '' INT; printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; exec sleep 60", DiagnosticStop::Cancelled),
            ("compile-timeout", DiagnosticMode::Compile, "exec sleep 60", DiagnosticStop::Deadline),
            ("preparation-timeout", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n'; exec sleep 60", DiagnosticStop::PreparationDeadline),
            ("slow-consumer", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; while :; do printf 'output\\n'; done", DiagnosticStop::ConsumerSlow),
        ];
        let mut results = Vec::new();
        for (name, mode, script, expected) in cases {
            let capture = Self::fixture_capture(script, mode, Duration::from_millis(500))?;
            let mut frames = Vec::new();
            let mut stopped = false;
            let deadline = Instant::now() + Duration::from_secs(20);
            while !capture.is_finished() && Instant::now() < deadline {
                if name != "slow-consumer" {
                    frames.extend(capture.frames().try_iter());
                }
                let ready = frames
                    .iter()
                    .any(|frame| frame.stderr && frame.bytes == ATTACHED);
                if !stopped && name == "compile-timeout" {
                    if let Some(pid) = capture
                        .process_id()
                        .and_then(|pid| rustix::process::Pid::from_raw(pid as i32))
                    {
                        let fd =
                            rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
                        rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::STOP)?;
                        stopped = true;
                    }
                } else if !stopped && ready && matches!(name, "quiet" | "histogram" | "forced-kill")
                {
                    capture.cancel();
                    stopped = true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !capture.is_finished() {
                return Err(format!("{name}: supervisor did not finish").into());
            }
            frames.extend(capture.frames().try_iter());
            let result = capture.finish()?;
            let reaped = !Path::new(&format!("/proc/{}", result.process_id)).exists();
            let readiness = mode == DiagnosticMode::Capture
                && !matches!(name, "unsupported-hook" | "preparation-timeout");
            let record = json!({
                "name": name,
                "result": result,
                "frames": frames,
                "process_reaped": reaped,
                "kernel_cleanup_verified": null,
                "enforcement_manifest_unchanged": null,
            });
            self.write(&format!("{name}.json"), &record)?;
            if result.stop != expected
                || !reaped
                || result.attach_notification_ms.is_some() != readiness
                || result.cleanup_verified.is_some()
                || !result.program_ids.is_empty()
                || !result.map_ids.is_empty()
                || result.retained_bytes > MAX_OUTPUT_BYTES
                || frames
                    .iter()
                    .enumerate()
                    .any(|(index, frame)| frame.sequence != index as u64 + 1)
            {
                return Err(format!("{name}: incorrect lifecycle result: {result:?}").into());
            }
            if matches!(name, "forced-kill" | "compile-timeout") && !result.forced_kill {
                return Err(format!("{name}: forced cleanup did not run").into());
            }
            if matches!(name, "parse-error" | "unsupported-hook") && result.exit_code != Some(1) {
                return Err(format!("{name}: expected source failure").into());
            }
            if matches!(name, "graceful" | "raw-output" | "histogram")
                && result.exit_code != Some(0)
            {
                return Err(format!("{name}: expected graceful exit").into());
            }
            if name == "histogram"
                && !frames.iter().any(|frame| {
                    serde_json::from_slice::<serde_json::Value>(&frame.bytes)
                        .is_ok_and(|value| value["type"] == "hist")
                })
            {
                return Err("histogram: final output was lost".into());
            }
            if name == "raw-output" && !frames.iter().any(|frame| frame.bytes == b"not-json\n") {
                return Err("raw-output: bytes were not preserved".into());
            }
            results.push(record);
        }
        let parent = self.lifecycle_parent()?;
        self.write("result.json", &json!({
            "schema_version": 1,
            "case": "backend-lifecycle",
            "result": "PASS",
            "proof_boundary": "Production supervision with external-process doubles. Attachment notifications are simulated. No BPF attachment, kernel cleanup, or enforcement proof.",
            "cases": results,
            "parent_death": parent,
            "physical": false,
            "performance_claim": false,
        }))
    }

    fn fixture_capture(
        script: &str,
        mode: DiagnosticMode,
        collection: Duration,
    ) -> ProofResult<DiagnosticCapture> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &format!("cat >/dev/null; {script}")]);
        Ok(DiagnosticBackend::start_fixture(command, mode, collection)?)
    }

    pub fn lifecycle_child(&self) -> ProofResult<()> {
        fs::create_dir(&self.output)?;
        let capture = Self::fixture_capture(
            "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; exec sleep 60",
            DiagnosticMode::Capture,
            Duration::from_secs(30),
        )?;
        let frame = capture.frames().recv_timeout(Duration::from_secs(2))?;
        if !frame.stderr || frame.bytes != ATTACHED {
            return Err("parent fixture did not reach simulated attachment".into());
        }
        self.write(
            "pid.json",
            &capture
                .process_id()
                .ok_or("fixture exited before readiness")?,
        )?;
        let _frames: Vec<_> = capture.frames().iter().collect();
        capture.finish()?;
        Ok(())
    }

    fn lifecycle_parent(&self) -> ProofResult<serde_json::Value> {
        let path = self.output.join("parent-fixture");
        let mut command = Command::new(std::env::current_exe()?);
        if cfg!(test) {
            command
                .args([
                    "--exact",
                    "observability::lifecycle::tests::observability_backend_child",
                    "--ignored",
                ])
                .env("ARAPHOR_DIAGNOSTIC_FIXTURE", &path);
        } else {
            command
                .args([
                    "--case",
                    "backend-lifecycle",
                    "--parent-fixture",
                    "--output-directory",
                ])
                .arg(&path);
        }
        let mut parent = QualificationChild(command.spawn()?);
        let deadline = Instant::now() + Duration::from_secs(3);
        let pid: u32 = loop {
            if let Some(pid) = fs::read(path.join("pid.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            {
                break pid;
            }
            if Instant::now() >= deadline {
                return Err("parent fixture did not report its child identity".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        parent.0.kill()?;
        parent.0.wait()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match fs::read_to_string(format!("/proc/{pid}/status")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Ok(status)
                    if status
                        .lines()
                        .any(|line| line.starts_with("State:") && line.contains("Z (zombie)")) =>
                {
                    break
                }
                _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                _ => return Err("diagnostic child survived parent death".into()),
            }
        }
        Ok(
            json!({"process_id": pid, "child_stopped": true, "terminal_missing": true, "kernel_cleanup_verified": null}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_backend_lifecycle() -> ProofResult<()> {
        let directory = tempfile::tempdir()?;
        let owner = ObservabilityQualification::new(directory.path().join("result"));
        owner.backend_lifecycle()?;
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(owner.output.join("result.json"))?)?;
        assert_eq!(receipt["result"], "PASS");
        assert_eq!(receipt["cases"].as_array().map(Vec::len), Some(12));
        assert_eq!(receipt["physical"], false);
        assert!(owner.backend_lifecycle().is_err());
        Ok(())
    }

    #[test]
    #[ignore = "subprocess fixture for the parent-death check"]
    fn observability_backend_child() -> ProofResult<()> {
        let path =
            std::env::var_os("ARAPHOR_DIAGNOSTIC_FIXTURE").ok_or("missing fixture directory")?;
        ObservabilityQualification::new(PathBuf::from(path)).lifecycle_child()
    }
}
