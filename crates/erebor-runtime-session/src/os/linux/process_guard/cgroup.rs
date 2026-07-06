use std::{env, fs, fs::OpenOptions, io::Write, path::Path};

use super::sys::Pid;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct CgroupJoinReport {
    pub(super) requested: bool,
    pub(super) cgroup_v2: bool,
    pub(super) dir: Option<String>,
    pub(super) joined: usize,
    pub(super) failed: usize,
    pub(super) reason: Option<String>,
}

pub(super) fn join_configured_cgroup(pids: &[Pid]) -> CgroupJoinReport {
    let Ok(dir) = env::var("EREBOR_GUARD_CGROUP_DIR") else {
        return CgroupJoinReport::default();
    };
    if dir.is_empty() {
        return CgroupJoinReport::default();
    }

    let mut report = CgroupJoinReport {
        requested: true,
        cgroup_v2: Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        dir: Some(dir.clone()),
        ..CgroupJoinReport::default()
    };

    if !report.cgroup_v2 {
        report.failed = pids.len();
        report.reason = Some(String::from("cgroup v2 is not mounted"));
        return report;
    }

    if let Err(error) = fs::create_dir_all(&dir) {
        report.failed = pids.len();
        report.reason = Some(format!("failed to create cgroup directory: {error}"));
        return report;
    }

    let procs = Path::new(&dir).join("cgroup.procs");
    for pid in pids {
        match OpenOptions::new().write(true).open(&procs) {
            Ok(mut file) => {
                if writeln!(file, "{pid}").is_ok() {
                    report.joined += 1;
                } else {
                    report.failed += 1;
                }
            }
            Err(error) => {
                report.failed += 1;
                if report.reason.is_none() {
                    report.reason = Some(format!("failed to open cgroup.procs: {error}"));
                }
            }
        }
    }

    report
}

pub(super) fn write_capability_report(
    mode: &str,
    root_pid: Pid,
    attached: usize,
    failed_attach: usize,
    cgroup: &CgroupJoinReport,
) {
    eprintln!(
        "erebor linux process guard capability: mode={} root_pid={} ptrace=enabled recursive_attach={} attached={} failed_attach={} yama_ptrace_scope={} cgroup_v2={} cgroup_requested={} cgroup_dir={} cgroup_joined={} cgroup_failed={} cgroup_reason={} residual_risks=preexisting_fds,preexisting_sockets,network_not_enforced",
        mode,
        root_pid,
        if failed_attach == 0 { "complete" } else { "partial" },
        attached,
        failed_attach,
        yama_ptrace_scope(),
        cgroup.cgroup_v2,
        cgroup.requested,
        cgroup.dir.as_deref().unwrap_or("none"),
        cgroup.joined,
        cgroup.failed,
        cgroup.reason.as_deref().unwrap_or("none")
    );
}

fn yama_ptrace_scope() -> String {
    fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| String::from("unknown"))
}

#[cfg(test)]
mod tests {
    use super::CgroupJoinReport;

    #[test]
    fn cgroup_report_defaults_to_not_requested() {
        let report = CgroupJoinReport::default();

        assert!(!report.requested);
        assert!(!report.cgroup_v2);
        assert_eq!(report.joined, 0);
        assert_eq!(report.failed, 0);
    }
}
