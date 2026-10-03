use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use sha2::{Digest as _, Sha256};

use super::ProofResult;
use crate::process::ProcessFixture;

const ATTACH_MARKER: &[u8] = b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n";
const ATTACH_LIMIT: Duration = Duration::from_secs(15);
const COLLECTION: Duration = Duration::from_secs(5);
const DRAIN_LIMIT: Duration = Duration::from_secs(5);
const OUTPUT_LIMIT: u64 = 16 * 1024 * 1024;
const ENVIRONMENT: [(&str, &str); 9] = [
    ("PATH", "/usr/bin:/bin"),
    ("LANG", "C"),
    ("DEBUGINFOD_URLS", ""),
    ("__BPFTRACE_NOTIFY_PROBES_ATTACHED", "1"),
    ("BPFTRACE_MAX_MAP_KEYS", "4096"),
    ("BPFTRACE_MAX_PROBES", "16"),
    ("BPFTRACE_MAX_BPF_PROGS", "16"),
    ("BPFTRACE_PERF_RB_PAGES", "8"),
    ("BPFTRACE_MAX_CAT_BYTES", "1024"),
];

pub(crate) struct PlainCapture {
    child: ProcessFixture,
    pidfd: OwnedFd,
    output: PathBuf,
    executable: PathBuf,
    executable_sha256: String,
    source_sha256: String,
    cgroup_id: u64,
    started: Instant,
    attached: Option<Instant>,
    signalled: Option<Instant>,
    status: Option<ExitStatus>,
    forced_kill: bool,
}

impl PlainCapture {
    pub(crate) fn start(
        executable: &Path,
        source: &[u8],
        cgroup_id: u64,
        output: &Path,
    ) -> ProofResult<Self> {
        if !executable.is_absolute()
            || !fs::symlink_metadata(executable)?.file_type().is_file()
            || fs::metadata(executable)?.permissions().mode() & 0o111 == 0
            || !output.is_absolute()
            || source.is_empty()
            || source.len() > 64 * 1024
            || source.contains(&0)
            || cgroup_id == 0
        {
            return Err(
                "plain capture requires an executable, bounded source and exact cgroup".into(),
            );
        }
        let source_text = std::str::from_utf8(source)?;
        let executable_sha256 = format!("{:x}", Sha256::digest(fs::read(executable)?));
        let source_sha256 = format!("{:x}", Sha256::digest(source));
        DirBuilder::new().mode(0o700).create(output)?;
        fs::write(output.join("source.bt"), source)?;
        let stdout = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output.join("stdout.jsonl"))?;
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output.join("stderr.log"))?;
        let started = Instant::now();
        let child = Self::command(executable, source_text, cgroup_id)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()?;
        let child = ProcessFixture::new(child, executable);
        let pid = Pid::from_raw(i32::try_from(child.id())?).ok_or("invalid plain capture PID")?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())?;
        let mut capture = Self {
            child,
            pidfd,
            output: output.to_owned(),
            executable: executable.to_owned(),
            executable_sha256,
            source_sha256,
            cgroup_id,
            started,
            attached: None,
            signalled: None,
            status: None,
            forced_kill: false,
        };
        loop {
            capture.status = capture.child.try_wait()?;
            if capture.status.is_some() {
                return capture.fail("plain bpftrace exited before attachment");
            }
            if !capture.output_bounded()? {
                return capture.fail("plain bpftrace exceeded the output limit before attachment");
            }
            if capture.started.elapsed() >= ATTACH_LIMIT {
                return capture.fail("plain bpftrace did not attach within 15 seconds");
            }
            match Self::markers(&capture.read_output("stderr.log")?) {
                0 => {}
                1 => {
                    capture.attached = Some(Instant::now());
                    return Ok(capture);
                }
                _ => return capture.fail("plain bpftrace emitted duplicate attachment markers"),
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub(crate) fn poll(&mut self) -> ProofResult<bool> {
        if !self.output_bounded()? {
            return self.fail("plain bpftrace exceeded the output limit");
        }
        if let Some(status) = self.child.try_wait()? {
            self.status = Some(status);
            if self.signalled.is_none() {
                return self.fail("plain bpftrace exited before the collection deadline");
            }
            if !status.success() {
                return self.fail("plain bpftrace did not exit successfully after SIGINT");
            }
            return Ok(true);
        }
        let attached = self.attached.ok_or("plain attachment is absent")?;
        let now = Instant::now();
        if self.signalled.is_none() && now >= attached + COLLECTION {
            if let Err(source) = pidfd_send_signal(&self.pidfd, Signal::INT) {
                return self.fail(&format!("plain bpftrace SIGINT failed: {source}"));
            }
            self.signalled = Some(Instant::now());
        }
        if self
            .signalled
            .is_some_and(|signalled| now >= signalled + DRAIN_LIMIT)
        {
            return self.fail("plain bpftrace did not drain within five seconds");
        }
        Ok(false)
    }

    pub(crate) fn finish(&mut self) -> ProofResult<serde_json::Value> {
        while !self.poll()? {
            std::thread::sleep(Duration::from_millis(10));
        }
        let receipt = self.receipt("Deadline")?;
        if receipt["attach_notifications"] != 1
            || receipt["stdout_utf8"] != true
            || receipt["stderr_utf8"] != true
        {
            return Err("plain bpftrace output or attachment proof is invalid".into());
        }
        Ok(receipt)
    }

    fn command(executable: &Path, source: &str, cgroup_id: u64) -> Command {
        let mut command = Command::new(executable);
        command.env_clear().current_dir("/");
        for (key, value) in ENVIRONMENT {
            command.env(key, value);
        }
        command.args([
            "-B",
            "none",
            "-f",
            "json",
            "-e",
            source,
            &cgroup_id.to_string(),
        ]);
        command
    }

    fn markers(bytes: &[u8]) -> usize {
        bytes
            .split_inclusive(|byte| *byte == b'\n')
            .filter(|line| *line == ATTACH_MARKER)
            .count()
    }

    fn output_bounded(&self) -> ProofResult<bool> {
        let stdout = fs::metadata(self.output.join("stdout.jsonl"))?.len();
        let stderr = fs::metadata(self.output.join("stderr.log"))?.len();
        Ok(stdout.saturating_add(stderr) <= OUTPUT_LIMIT)
    }

    fn read_output(&self, name: &str) -> ProofResult<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(self.output.join(name))?
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn receipt(&self, stop: &str) -> ProofResult<serde_json::Value> {
        let stdout = self.read_output("stdout.jsonl")?;
        let stderr = self.read_output("stderr.log")?;
        let environment = ENVIRONMENT
            .into_iter()
            .map(|(key, value)| (key.to_owned(), serde_json::Value::from(value)))
            .collect::<serde_json::Map<_, _>>();
        let receipt = serde_json::json!({
            "schema_version": 1,
            "mode": "plain",
            "executable": self.executable,
            "executable_sha256": self.executable_sha256,
            "source_sha256": self.source_sha256,
            "source_path": self.output.join("source.bt"),
            "cgroup_id": self.cgroup_id,
            "environment": environment,
            "process_id": self.child.id(),
            "stop": stop,
            "elapsed_ms": self.started.elapsed().as_millis(),
            "attach_notification_ms": self.attached.map(|value| value.duration_since(self.started).as_millis()),
            "collection_ms": self.attached.zip(self.signalled).map(|(attached, signalled)| signalled.duration_since(attached).as_millis()),
            "attach_notifications": Self::markers(&stderr),
            "exit_code": self.status.and_then(|status| status.code()),
            "exit_signal": self.status.and_then(|status| status.signal()),
            "forced_kill": self.forced_kill,
            "stdout_path": self.output.join("stdout.jsonl"),
            "stderr_path": self.output.join("stderr.log"),
            "stdout_utf8": std::str::from_utf8(&stdout).is_ok(),
            "stderr_utf8": std::str::from_utf8(&stderr).is_ok(),
            "stdout": String::from_utf8_lossy(&stdout),
            "stderr": String::from_utf8_lossy(&stderr),
        });
        fs::write(
            self.output.join("receipt.json"),
            serde_json::to_vec_pretty(&receipt)?,
        )?;
        Ok(receipt)
    }

    fn fail<T>(&mut self, reason: &str) -> ProofResult<T> {
        if self.status.is_none() {
            self.forced_kill = true;
            match pidfd_send_signal(&self.pidfd, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(source) => {
                    let _ = self.receipt(reason);
                    return Err(format!("{reason}; kill failed: {source}").into());
                }
            }
            match self
                .child
                .wait_exit("plain bpftrace forced cleanup", DRAIN_LIMIT)
            {
                Ok(status) => self.status = Some(status),
                Err(source) => {
                    let _ = self.receipt(reason);
                    return Err(format!("{reason}; reap failed: {source}").into());
                }
            }
        }
        self.receipt(reason)?;
        Err(reason.into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsStr;
    use std::path::Path;

    use super::{PlainCapture, ATTACH_MARKER, ENVIRONMENT};

    #[test]
    fn plain_command_is_direct() {
        let source = "tracepoint:syscalls:sys_exit_openat { @errors[args.ret] = count(); }\n";
        let command = PlainCapture::command(Path::new("/usr/bin/bpftrace"), source, 42);
        assert_eq!(command.get_program(), OsStr::new("/usr/bin/bpftrace"));
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["-B", "none", "-f", "json", "-e", source, "42"]
                .map(OsStr::new)
                .to_vec()
        );
        assert_eq!(
            command.get_envs().collect::<BTreeMap<_, _>>(),
            ENVIRONMENT
                .into_iter()
                .map(|(key, value)| (OsStr::new(key), Some(OsStr::new(value))))
                .collect::<BTreeMap<_, _>>()
        );
    }

    #[test]
    fn plain_marker_requires_attachment() {
        assert_eq!(PlainCapture::markers(ATTACH_MARKER), 1);
        assert_eq!(
            PlainCapture::markers(b"Attaching 2 probes...\n{\"type\":\"attached_probes\"}\n"),
            0
        );
        assert_eq!(
            PlainCapture::markers(b"__BPFTRACE_NOTIFY_PROBES_ATTACHED"),
            0
        );
        assert_eq!(
            PlainCapture::markers(b"prefix __BPFTRACE_NOTIFY_PROBES_ATTACHED\n"),
            0
        );
        assert_eq!(
            PlainCapture::markers(b"__BPFTRACE_NOTIFY_PROBES_ATTACHED suffix\n"),
            0
        );
        assert_eq!(PlainCapture::markers(&ATTACH_MARKER.repeat(2)), 2);
    }
}
