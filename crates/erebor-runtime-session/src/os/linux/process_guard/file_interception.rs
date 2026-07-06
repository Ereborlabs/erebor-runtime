use std::{
    env, fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use super::{
    broker::GuardBrokerEnvironment,
    ipc,
    memory::{read_cstring, read_pointer},
    proc_parent_pid,
    sys::{Pid, UserRegsStruct},
    MAX_STRING,
};

const SYS_OPEN: u64 = 2;
const SYS_OPENAT: u64 = 257;
const SYS_OPENAT2: u64 = 437;
const AT_FDCWD: i64 = -100;

const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_PATH: u64 = 0o10000000;
const O_TMPFILE: u64 = 0o20000000;

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileSyscallRequest {
    operation: ipc::FileOperationKind,
    path: String,
    cwd: String,
    resolved_identity: Option<ipc::FileIdentity>,
}

pub(super) fn should_deny_file_syscall(pid: Pid, regs: &UserRegsStruct) -> bool {
    let Some(request) = file_request_from_syscall(pid, regs) else {
        return false;
    };
    if !GuardBrokerEnvironment::operation_enabled(request.operation.as_str()) {
        return false;
    }

    match broker_decision_for_file(pid, &request) {
        Ok(decision) => should_deny_broker_decision(&request, &decision),
        Err(reason) => {
            eprintln!("erebor linux process guard: broker file decision failed: {reason}");
            true
        }
    }
}

fn should_deny_broker_decision(
    request: &FileSyscallRequest,
    decision: &ipc::InterceptionDecision,
) -> bool {
    match decision.kind {
        ipc::InterceptionDecisionKind::Allow => false,
        ipc::InterceptionDecisionKind::Deny => {
            eprintln!(
                "erebor linux process guard: denied {}: {}: {}",
                request.operation.as_str(),
                request.path,
                decision.reason
            );
            true
        }
        ipc::InterceptionDecisionKind::RequireApproval => {
            eprintln!(
                "erebor linux process guard: verification required for {}, denied fail-closed: {}: {}",
                request.operation.as_str(),
                request.path,
                decision.reason
            );
            true
        }
        ipc::InterceptionDecisionKind::Mediate | ipc::InterceptionDecisionKind::Unknown => {
            eprintln!(
                "erebor linux process guard: unsupported file decision for {}, denied fail-closed: {}",
                request.operation.as_str(),
                request.path
            );
            true
        }
    }
}

fn broker_decision_for_file(
    pid: Pid,
    request: &FileSyscallRequest,
) -> Result<ipc::InterceptionDecision, String> {
    let endpoint = GuardBrokerEnvironment::endpoint()?
        .ok_or_else(|| String::from("runtime interception endpoint is not configured"))?;
    let hello = GuardBrokerEnvironment::hello()?;
    let mut connection = ipc::RuntimeInterceptionConnection::connect(&endpoint, hello)?;
    connection.request_decision(&interception_request_from_file(pid, request))
}

fn interception_request_from_file(
    pid: Pid,
    request: &FileSyscallRequest,
) -> ipc::InterceptionRequest {
    let timestamp = GuardBrokerEnvironment::current_unix_timestamp();
    ipc::InterceptionRequest {
        request_id: timestamp,
        actor_id: env::var("EREBOR_ACTOR_ID").unwrap_or_else(|_| String::from("agent")),
        source: ipc::InterceptionSource::Ptrace,
        pid: i64::from(pid),
        ppid: proc_parent_pid(pid).map_or(0, i64::from),
        executable: String::new(),
        argv: Vec::new(),
        cwd: request.cwd.clone(),
        matched_handler_id: String::new(),
        timestamp: format!("unix:{timestamp}"),
        operation: request.operation.interception_operation(),
        file: Some(ipc::FileOperation {
            kind: request.operation,
            path: request.path.clone(),
            resolved_identity: request.resolved_identity,
        }),
    }
}

fn file_request_from_syscall(pid: Pid, regs: &UserRegsStruct) -> Option<FileSyscallRequest> {
    let syscall = OpenSyscall::from_regs(pid, regs)?;
    let raw_path = read_cstring(pid, syscall.path_address, MAX_STRING);
    if raw_path.is_empty() {
        return None;
    }
    let cwd = GuardBrokerEnvironment::proc_cwd(pid);
    let path = resolve_request_path(pid, syscall.dirfd, &cwd, &raw_path);
    let resolved_identity = resolved_identity(pid, &path);

    Some(FileSyscallRequest {
        operation: classify_open_flags(syscall.flags),
        path,
        cwd,
        resolved_identity,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OpenSyscall {
    path_address: u64,
    dirfd: Option<i64>,
    flags: u64,
}

impl OpenSyscall {
    fn from_regs(pid: Pid, regs: &UserRegsStruct) -> Option<Self> {
        match regs.orig_rax {
            SYS_OPEN => Some(Self {
                path_address: regs.rdi,
                dirfd: None,
                flags: regs.rsi,
            }),
            SYS_OPENAT => Some(Self {
                path_address: regs.rsi,
                dirfd: Some(regs.rdi as i64),
                flags: regs.rdx,
            }),
            SYS_OPENAT2 => Some(Self {
                path_address: regs.rsi,
                dirfd: Some(regs.rdi as i64),
                flags: read_pointer(pid, regs.rdx).unwrap_or(0),
            }),
            _ => None,
        }
    }
}

pub(super) fn classify_open_flags(flags: u64) -> ipc::FileOperationKind {
    if flags & O_PATH == O_PATH {
        return ipc::FileOperationKind::Open;
    }
    if flags & (O_CREAT | O_TRUNC | O_APPEND | O_TMPFILE) != 0 {
        return ipc::FileOperationKind::Mutation;
    }
    match flags & O_ACCMODE {
        O_WRONLY | O_RDWR => ipc::FileOperationKind::Mutation,
        _ => ipc::FileOperationKind::Read,
    }
}

fn resolve_request_path(pid: Pid, dirfd: Option<i64>, cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        return path.to_owned();
    }
    if let Some(dirfd) = dirfd.filter(|dirfd| *dirfd != AT_FDCWD) {
        if let Some(base) = fd_path(pid, dirfd) {
            return join_path(&base, path);
        }
    }
    join_path(cwd, path)
}

fn fd_path(pid: Pid, dirfd: i64) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/fd/{dirfd}"))
        .ok()
        .map(|path| path.display().to_string())
}

fn join_path(base: &str, path: &str) -> String {
    if base.is_empty() || base == "." {
        path.to_owned()
    } else if base.ends_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

fn resolved_identity(pid: Pid, path: &str) -> Option<ipc::FileIdentity> {
    let metadata_path = tracee_metadata_path(pid, path);
    let metadata = fs::metadata(metadata_path).ok()?;
    Some(ipc::FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn tracee_metadata_path(pid: Pid, path: &str) -> PathBuf {
    if path.starts_with('/') {
        Path::new("/proc")
            .join(pid.to_string())
            .join("root")
            .join(path.trim_start_matches('/'))
    } else {
        PathBuf::from(path)
    }
}

#[cfg(test)]
mod tests {
    use super::super::ipc;
    use super::{
        classify_open_flags, join_path, resolve_request_path, O_APPEND, O_CREAT, O_PATH, O_RDWR,
        O_TRUNC, O_WRONLY,
    };

    #[test]
    fn classifies_open_flags_for_file_operations() {
        assert_eq!(classify_open_flags(0), ipc::FileOperationKind::Read);
        assert_eq!(classify_open_flags(O_PATH), ipc::FileOperationKind::Open);
        assert_eq!(
            classify_open_flags(O_WRONLY),
            ipc::FileOperationKind::Mutation
        );
        assert_eq!(
            classify_open_flags(O_RDWR),
            ipc::FileOperationKind::Mutation
        );
        assert_eq!(
            classify_open_flags(O_CREAT),
            ipc::FileOperationKind::Mutation
        );
        assert_eq!(
            classify_open_flags(O_TRUNC),
            ipc::FileOperationKind::Mutation
        );
        assert_eq!(
            classify_open_flags(O_APPEND),
            ipc::FileOperationKind::Mutation
        );
    }

    #[test]
    fn joins_relative_paths_without_canonicalizing() {
        assert_eq!(join_path("/workspace", "a/../b"), "/workspace/a/../b");
        assert_eq!(join_path("/workspace/", "file.txt"), "/workspace/file.txt");
        assert_eq!(join_path("", "file.txt"), "file.txt");
    }

    #[test]
    fn resolves_at_fdcwd_relative_paths_against_cwd() {
        assert_eq!(
            resolve_request_path(0, Some(-100), "/workspace", "secret.txt"),
            "/workspace/secret.txt"
        );
        assert_eq!(
            resolve_request_path(0, None, "/workspace", "/etc/passwd"),
            "/etc/passwd"
        );
    }
}
