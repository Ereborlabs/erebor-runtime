#![allow(unsafe_code)]

#[path = "process_guard/interception.rs"]
mod interception;

use std::{
    collections::HashMap,
    env,
    ffi::{CStr, CString},
    fs::{self, OpenOptions},
    io::Write,
    os::{
        raw::{c_char, c_int, c_long, c_uint, c_ulong, c_void},
        unix::ffi::OsStringExt,
    },
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Erebor's Linux process guard currently supports x86_64 Linux only");

const MAX_RULES: usize = 64;
const MAX_ARGV: usize = 32;
const MAX_TEXT: usize = 4096;
const MAX_STRING: usize = 512;

const PTRACE_TRACEME: c_uint = 0;
const PTRACE_PEEKDATA: c_uint = 2;
const PTRACE_GETREGS: c_uint = 12;
const PTRACE_SETREGS: c_uint = 13;
const PTRACE_ATTACH: c_uint = 16;
const PTRACE_DETACH: c_uint = 17;
const PTRACE_SYSCALL: c_uint = 24;
const PTRACE_SETOPTIONS: c_uint = 0x4200;
const PTRACE_GETEVENTMSG: c_uint = 0x4201;

const PTRACE_O_TRACESYSGOOD: c_ulong = 1;
const PTRACE_O_TRACEFORK: c_ulong = 1 << 1;
const PTRACE_O_TRACEVFORK: c_ulong = 1 << 2;
const PTRACE_O_TRACECLONE: c_ulong = 1 << 3;
const PTRACE_O_TRACEEXEC: c_ulong = 1 << 4;
const PTRACE_O_TRACEEXIT: c_ulong = 1 << 6;

const PTRACE_EVENT_FORK: u32 = 1;
const PTRACE_EVENT_VFORK: u32 = 2;
const PTRACE_EVENT_CLONE: u32 = 3;
const PTRACE_EVENT_EXEC: u32 = 4;
const PTRACE_EVENT_EXIT: u32 = 6;
const PTRACE_EVENT_STOP: u32 = 128;

const SYS_EXECVE: u64 = 59;
const SYS_EXECVEAT: u64 = 322;

const SIGSTOP: c_int = 19;
const SIGTRAP: c_int = 5;
const EINTR: c_int = 4;
const ENOENT: c_int = 2;
const EPERM: c_int = 1;
const ESRCH: c_int = 3;
const WAIT_ALL_TRACED: c_int = 0x4000_0000;

type Pid = c_int;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserRegsStruct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
}

#[derive(Clone, Debug)]
struct ProcessRule {
    token: String,
    reason: String,
    rule_id: String,
    decision: ProcessRuleDecision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessRuleDecision {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditCommandLogLevel {
    All,
    Signal,
    NonAllow,
}

#[derive(Clone, Debug, Default)]
struct PidState {
    in_syscall: bool,
    denied_pending: bool,
}

struct TraceContext {
    rules: Vec<ProcessRule>,
    states: HashMap<Pid, PidState>,
    audit_seq: u64,
    root_pid: Pid,
    live_traces: usize,
}

unsafe extern "C" {
    fn ptrace(request: c_uint, pid: Pid, address: *mut c_void, data: *mut c_void) -> c_long;
    fn waitpid(pid: Pid, status: *mut c_int, options: c_int) -> Pid;
    fn fork() -> Pid;
    fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int;
    fn raise(signal: c_int) -> c_int;
    fn _exit(status: c_int) -> !;
    fn strerror(error: c_int) -> *mut c_char;
    fn __errno_location() -> *mut c_int;
}

fn main() {
    if let Some(status) = interception::try_handle_configured_interception() {
        process::exit(status);
    }

    let rules = parse_rules();

    if let Some(root_pid) = adopt_pid_from_env() {
        process::exit(adopt_existing_process_tree(root_pid, rules));
    }

    let command = match command_args() {
        Ok(command) => command,
        Err(error) => die(&error),
    };
    process::exit(launch_new_process_tree(command, rules));
}

fn launch_new_process_tree(command: Vec<CString>, rules: Vec<ProcessRule>) -> i32 {
    let child = unsafe { fork() };
    if child < 0 {
        die(&format!("fork failed: {}", errno_message(errno())));
    }

    if child == 0 {
        child_exec(command);
    }

    let mut context = TraceContext {
        rules,
        states: HashMap::from([(child, PidState::default())]),
        audit_seq: 0,
        root_pid: child,
        live_traces: 1,
    };

    wait_for_initial_stop(child);
    set_trace_options(child);
    let cgroup = join_configured_cgroup(&[child]);
    write_capability_report("relaunch", child, 1, 0, &cgroup);
    continue_trace(child, 0);

    trace_loop(&mut context)
}

fn adopt_existing_process_tree(root_pid: Pid, rules: Vec<ProcessRule>) -> i32 {
    let candidate_pids = process_tree_pids(root_pid);
    let mut context = TraceContext {
        rules,
        states: HashMap::new(),
        audit_seq: 0,
        root_pid,
        live_traces: 0,
    };
    let mut failed = Vec::new();

    for pid in candidate_pids {
        match attach_existing_pid(pid) {
            Ok(()) => {
                context.states.insert(pid, PidState::default());
                context.live_traces += 1;
            }
            Err(reason) => {
                failed.push((pid, reason));
            }
        }
    }

    let attached_pids = context.states.keys().copied().collect::<Vec<_>>();
    let cgroup = join_configured_cgroup(&attached_pids);
    write_capability_report(
        "adopt",
        root_pid,
        attached_pids.len(),
        failed.len(),
        &cgroup,
    );

    for (pid, reason) in &failed {
        eprintln!(
            "erebor linux process guard residual risk: failed_attach_pid={} reason={}",
            pid, reason
        );
    }

    if !context.states.contains_key(&root_pid) {
        for pid in attached_pids {
            detach_trace(pid);
        }
        return 126;
    }

    for pid in context.states.keys().copied().collect::<Vec<_>>() {
        continue_trace(pid, 0);
    }

    trace_loop(&mut context)
}

fn adopt_pid_from_env() -> Option<Pid> {
    let Ok(value) = env::var("EREBOR_GUARD_ADOPT_PID") else {
        return None;
    };
    let Ok(pid) = value.parse::<Pid>() else {
        die("EREBOR_GUARD_ADOPT_PID must be a positive process id");
    };
    if pid <= 0 {
        die("EREBOR_GUARD_ADOPT_PID must be a positive process id");
    }

    Some(pid)
}

fn attach_existing_pid(pid: Pid) -> Result<(), String> {
    let result = unsafe {
        ptrace(
            PTRACE_ATTACH,
            pid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result != 0 {
        return Err(errno_message(errno()));
    }

    wait_for_attached_stop(pid)?;
    if let Err(reason) = try_set_trace_options(pid) {
        detach_trace(pid);
        Err(reason)
    } else {
        Ok(())
    }
}

fn wait_for_attached_stop(pid: Pid) -> Result<(), String> {
    loop {
        let mut status = 0;
        let waited = unsafe { waitpid(pid, &mut status, 0) };
        if waited < 0 {
            let error = errno();
            if error == EINTR {
                continue;
            }
            return Err(format!("waitpid failed: {}", errno_message(error)));
        }
        if waited == pid && wait_stopped(status) {
            return Ok(());
        }
        if wait_exited(status) || wait_signaled(status) {
            return Err(String::from("process exited before attachment completed"));
        }
    }
}

fn command_args() -> Result<Vec<CString>, String> {
    let mut args = Vec::new();
    for arg in env::args_os().skip(1) {
        let bytes = arg.into_vec();
        let c_string =
            CString::new(bytes).map_err(|_| String::from("session command contains a NUL byte"))?;
        args.push(c_string);
    }

    if args.is_empty() {
        Err(String::from("missing session command"))
    } else {
        Ok(args)
    }
}

fn child_exec(command: Vec<CString>) -> ! {
    let mut argv = command
        .iter()
        .map(|argument| argument.as_ptr())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null());

    if unsafe {
        ptrace(
            PTRACE_TRACEME,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } != 0
    {
        die(&format!(
            "PTRACE_TRACEME failed: {}",
            errno_message(errno())
        ));
    }
    unsafe {
        raise(SIGSTOP);
        execvp(command[0].as_ptr(), argv.as_ptr());
    }

    let error = errno();
    eprintln!(
        "erebor linux process guard: failed to exec {}: {}",
        command[0].to_string_lossy(),
        errno_message(error)
    );
    unsafe {
        _exit(if error == ENOENT { 127 } else { 126 });
    }
}

fn wait_for_initial_stop(child: Pid) {
    let mut status = 0;
    let waited = unsafe { waitpid(child, &mut status, 0) };
    if waited < 0 {
        die(&format!(
            "initial waitpid failed: {}",
            errno_message(errno())
        ));
    }
    if !wait_stopped(status) {
        die("child did not stop for tracing");
    }
}

fn trace_loop(context: &mut TraceContext) -> i32 {
    let mut root_status = 1;

    while context.live_traces > 0 {
        let mut status = 0;
        let pid = unsafe { waitpid(-1, &mut status, WAIT_ALL_TRACED) };
        if pid < 0 {
            let error = errno();
            if error == EINTR {
                continue;
            }
            die(&format!("waitpid failed: {}", errno_message(error)));
        }

        if wait_exited(status) || wait_signaled(status) {
            if pid == context.root_pid {
                root_status = if wait_exited(status) {
                    wait_exit_status(status)
                } else {
                    128 + wait_term_signal(status)
                };
            }
            context.states.remove(&pid);
            context.live_traces = context.live_traces.saturating_sub(1);
            continue;
        }

        if !wait_stopped(status) {
            continue_trace(pid, 0);
            continue;
        }

        let stop_signal = wait_stop_signal(status);
        let event = ptrace_event(status);

        if matches!(
            event,
            PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK | PTRACE_EVENT_CLONE
        ) {
            let mut new_pid: c_ulong = 0;
            let result = unsafe {
                ptrace(
                    PTRACE_GETEVENTMSG,
                    pid,
                    std::ptr::null_mut(),
                    &mut new_pid as *mut c_ulong as *mut c_void,
                )
            };
            if result == 0 && new_pid != 0 {
                context.states.entry(new_pid as Pid).or_default();
                context.live_traces += 1;
            }
            continue_trace(pid, 0);
            continue;
        }

        if matches!(
            event,
            PTRACE_EVENT_EXEC | PTRACE_EVENT_EXIT | PTRACE_EVENT_STOP
        ) {
            continue_trace(pid, 0);
            continue;
        }

        if stop_signal == (SIGTRAP | 0x80) {
            handle_syscall_stop(context, pid);
            continue_trace(pid, 0);
            continue;
        }

        if stop_signal == SIGSTOP || stop_signal == SIGTRAP {
            continue_trace(pid, 0);
        } else {
            continue_trace(pid, stop_signal);
        }
    }

    root_status
}

fn handle_syscall_stop(context: &mut TraceContext, pid: Pid) {
    let mut regs = UserRegsStruct::default();
    let get_result = unsafe {
        ptrace(
            PTRACE_GETREGS,
            pid,
            std::ptr::null_mut(),
            &mut regs as *mut UserRegsStruct as *mut c_void,
        )
    };
    if get_result != 0 {
        return;
    }

    let entering_syscall = match context.states.get_mut(&pid) {
        Some(state) => {
            if state.in_syscall {
                false
            } else {
                state.in_syscall = true;
                true
            }
        }
        None => return,
    };

    if entering_syscall {
        if regs.orig_rax == SYS_EXECVE || regs.orig_rax == SYS_EXECVEAT {
            let deny = should_deny_exec(context, pid, &regs, regs.orig_rax == SYS_EXECVEAT);
            if deny {
                regs.orig_rax = (-1i64) as u64;
                regs.rax = (-(EPERM as i64)) as u64;
                if let Some(state) = context.states.get_mut(&pid) {
                    state.denied_pending = true;
                }
                set_regs(pid, &regs);
            }
        }
    } else if let Some(state) = context.states.get_mut(&pid) {
        if state.denied_pending {
            regs.rax = (-(EPERM as i64)) as u64;
            state.denied_pending = false;
            set_regs(pid, &regs);
        }
        state.in_syscall = false;
    }
}

fn should_deny_exec(
    context: &mut TraceContext,
    pid: Pid,
    regs: &UserRegsStruct,
    is_execveat: bool,
) -> bool {
    let path_address = if is_execveat { regs.rsi } else { regs.rdi };
    let argv_address = if is_execveat { regs.rdx } else { regs.rsi };
    let path = read_cstring(pid, path_address, MAX_STRING);
    let argv = read_argv(pid, argv_address);
    let text = command_text(&path, &argv);
    let rule = context
        .rules
        .iter()
        .find(|rule| text.contains(&rule.token))
        .cloned();

    context.audit_seq += 1;
    write_audit(context.audit_seq, pid, &path, &argv, &text, rule.as_ref());

    if let Some(rule) = rule {
        match rule.decision {
            ProcessRuleDecision::Allow => {}
            ProcessRuleDecision::Deny => {
                eprintln!(
                    "erebor linux process guard: denied exec: {}: {}",
                    text, rule.reason
                );
            }
            ProcessRuleDecision::RequireApproval => {
                eprintln!(
                    "erebor linux process guard: verification required for exec, denied fail-closed: {}: {}",
                    text, rule.reason
                );
            }
        }
        !matches!(rule.decision, ProcessRuleDecision::Allow)
    } else {
        false
    }
}

fn set_trace_options(pid: Pid) {
    if let Err(reason) = try_set_trace_options(pid) {
        die(&reason);
    }
}

fn try_set_trace_options(pid: Pid) -> Result<(), String> {
    let options = PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACEVFORK
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEEXEC
        | PTRACE_O_TRACEEXIT;
    let result = unsafe {
        ptrace(
            PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut(),
            options as usize as *mut c_void,
        )
    };
    if result != 0 {
        Err(format!(
            "failed to set ptrace options for pid {}: {}",
            pid,
            errno_message(errno())
        ))
    } else {
        Ok(())
    }
}

fn continue_trace(pid: Pid, signal_to_deliver: c_int) {
    let result = unsafe {
        ptrace(
            PTRACE_SYSCALL,
            pid,
            std::ptr::null_mut(),
            signal_to_deliver as isize as *mut c_void,
        )
    };
    if result != 0 && errno() != ESRCH {
        eprintln!(
            "erebor linux process guard: failed to continue pid {}: {}",
            pid,
            errno_message(errno())
        );
    }
}

fn set_regs(pid: Pid, regs: &UserRegsStruct) {
    unsafe {
        ptrace(
            PTRACE_SETREGS,
            pid,
            std::ptr::null_mut(),
            regs as *const UserRegsStruct as *mut c_void,
        );
    }
}

fn detach_trace(pid: Pid) {
    let result = unsafe {
        ptrace(
            PTRACE_DETACH,
            pid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result != 0 && errno() != ESRCH {
        eprintln!(
            "erebor linux process guard: failed to detach pid {}: {}",
            pid,
            errno_message(errno())
        );
    }
}

fn process_tree_pids(root_pid: Pid) -> Vec<Pid> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return vec![root_pid];
    };
    let mut parent_by_pid = HashMap::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<Pid>() else {
            continue;
        };
        if let Some(ppid) = proc_parent_pid(pid) {
            parent_by_pid.insert(pid, ppid);
        }
    }

    let mut tree = vec![root_pid];
    let mut changed = true;
    while changed {
        changed = false;
        for (pid, ppid) in &parent_by_pid {
            if tree.contains(pid) || !tree.contains(ppid) {
                continue;
            }
            tree.push(*pid);
            changed = true;
        }
    }

    tree.sort_unstable();
    tree.retain(|pid| *pid != root_pid);
    tree.insert(0, root_pid);
    tree
}

fn proc_parent_pid(pid: Pid) -> Option<Pid> {
    let source = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_parent_pid_from_stat(&source)
}

fn parse_parent_pid_from_stat(source: &str) -> Option<Pid> {
    let (_command, rest) = source.rsplit_once(')')?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CgroupJoinReport {
    requested: bool,
    cgroup_v2: bool,
    dir: Option<String>,
    joined: usize,
    failed: usize,
    reason: Option<String>,
}

fn join_configured_cgroup(pids: &[Pid]) -> CgroupJoinReport {
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

fn write_capability_report(
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

fn read_argv(pid: Pid, argv_address: u64) -> Vec<String> {
    if argv_address == 0 {
        return Vec::new();
    }

    let mut argv = Vec::new();
    for index in 0..MAX_ARGV {
        let pointer_address = argv_address + (index * std::mem::size_of::<u64>()) as u64;
        let Some(pointer) = read_pointer(pid, pointer_address) else {
            break;
        };
        if pointer == 0 {
            break;
        }
        let argument = read_cstring(pid, pointer, 256);
        if argument.is_empty() {
            break;
        }
        argv.push(argument);
    }
    argv
}

fn read_pointer(pid: Pid, address: u64) -> Option<u64> {
    ptrace_peek(pid, address).map(|value| value as u64)
}

fn read_cstring(pid: Pid, address: u64, size: usize) -> String {
    if address == 0 || size == 0 {
        return String::new();
    }

    let mut bytes = Vec::new();
    let word_size = std::mem::size_of::<c_long>();
    while bytes.len() + 1 < size {
        let Some(word) = ptrace_peek(pid, address + bytes.len() as u64) else {
            break;
        };
        for byte in word.to_ne_bytes() {
            if bytes.len() + 1 >= size {
                break;
            }
            if byte == 0 {
                return String::from_utf8_lossy(&bytes).to_string();
            }
            bytes.push(byte);
        }
        if word_size == 0 {
            break;
        }
    }

    String::from_utf8_lossy(&bytes).to_string()
}

fn ptrace_peek(pid: Pid, address: u64) -> Option<c_long> {
    set_errno(0);
    let value = unsafe {
        ptrace(
            PTRACE_PEEKDATA,
            pid,
            address as usize as *mut c_void,
            std::ptr::null_mut(),
        )
    };
    if errno() == 0 {
        Some(value)
    } else {
        None
    }
}

fn command_text(path: &str, argv: &[String]) -> String {
    let mut text = String::new();
    text.push_str(path);
    for argument in argv {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(argument);
        if text.len() >= MAX_TEXT {
            text.truncate(MAX_TEXT);
            break;
        }
    }
    text
}

fn should_write_process_audit(path: &str, argv: &[String], rule: Option<&ProcessRule>) -> bool {
    if rule.is_some_and(|rule| rule.decision != ProcessRuleDecision::Allow) {
        return true;
    }

    match audit_command_log_level() {
        AuditCommandLogLevel::All => true,
        AuditCommandLogLevel::NonAllow => false,
        AuditCommandLogLevel::Signal => !matches_debug_command(path, argv),
    }
}

fn audit_command_log_level() -> AuditCommandLogLevel {
    match env::var("EREBOR_GUARD_AUDIT_TERMINAL_LEVEL")
        .unwrap_or_else(|_| String::from("signal"))
        .as_str()
    {
        "all" => AuditCommandLogLevel::All,
        "non_allow" => AuditCommandLogLevel::NonAllow,
        _ => AuditCommandLogLevel::Signal,
    }
}

fn matches_debug_command(path: &str, argv: &[String]) -> bool {
    let debug_commands = audit_debug_commands();
    if debug_commands.is_empty() {
        return false;
    }

    let mut tokens = Vec::new();
    tokens.push(path);
    if let Some(first) = argv.first() {
        tokens.push(first);
    }

    tokens.iter().any(|token| {
        debug_commands
            .iter()
            .any(|debug_command| command_token_matches(token, debug_command))
    })
}

fn audit_debug_commands() -> Vec<String> {
    match env::var("EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS") {
        Ok(source) => source
            .lines()
            .map(str::trim)
            .filter(|command| !command.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Err(_) => vec![String::from("sleep")],
    }
}

fn command_token_matches(token: &str, debug_command: &str) -> bool {
    token == debug_command
        || basename(token) == debug_command
        || basename(debug_command) == token
        || basename(token) == basename(debug_command)
}

fn basename(value: &str) -> &str {
    value
        .rsplit_once('/')
        .map_or(value, |(_prefix, basename)| basename)
}

fn parse_rules() -> Vec<ProcessRule> {
    let source = env::var("EREBOR_GUARD_RULES")
        .or_else(|_| env::var("EREBOR_GUARD_DENY_RULES"))
        .unwrap_or_default();
    parse_rules_from_source(&source)
}

fn parse_rules_from_source(source: &str) -> Vec<ProcessRule> {
    source
        .lines()
        .take(MAX_RULES)
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let token = fields.next().unwrap_or_default();
            if token.is_empty() {
                return None;
            }
            Some(ProcessRule {
                token: token.to_owned(),
                reason: fields
                    .next()
                    .filter(|reason| !reason.is_empty())
                    .unwrap_or("process execution denied by Erebor policy")
                    .to_owned(),
                rule_id: fields
                    .next()
                    .filter(|rule_id| !rule_id.is_empty())
                    .unwrap_or("erebor-linux-process-guard")
                    .to_owned(),
                decision: ProcessRuleDecision::from_guard_env(fields.next()),
            })
        })
        .collect()
}

fn write_audit(
    sequence: u64,
    pid: Pid,
    path: &str,
    argv: &[String],
    text: &str,
    rule: Option<&ProcessRule>,
) {
    let audit_path = match env::var("EREBOR_GUARD_AUDIT_JSONL") {
        Ok(path) if !path.is_empty() => path,
        _ => return,
    };
    if !should_write_process_audit(path, argv, rule) {
        return;
    }

    let Ok(mut file) = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&audit_path)
    else {
        eprintln!(
            "erebor linux process guard: failed to open audit log {}: {}",
            audit_path,
            errno_message(errno())
        );
        return;
    };

    let session_id =
        env::var("EREBOR_SESSION_ID").unwrap_or_else(|_| String::from("unknown-session"));
    let actor_id = env::var("EREBOR_ACTOR_ID").unwrap_or_else(|_| String::from("agent"));
    let tty = env::var("EREBOR_TERMINAL_TTY").unwrap_or_else(|_| String::from("false"));
    let cwd = env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("<unknown>"))
        .display()
        .to_string();
    let event_id = format!("{session_id}-process-exec-{pid}-{sequence}");
    let policy_decision = rule.map_or("allow", |rule| rule.decision.policy_decision_type());
    let final_decision = rule.map_or("allow", |rule| rule.decision.final_decision_type());
    let risk = match rule.map(|rule| rule.decision) {
        Some(ProcessRuleDecision::Allow) => "low",
        Some(ProcessRuleDecision::Deny | ProcessRuleDecision::RequireApproval) => "high",
        None => "medium",
    };
    let reason = rule.map_or("agent-issued process execution attempt", |rule| {
        rule.reason.as_str()
    });
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    let _ = write!(
        file,
        "{{\"event\":{{\"id\":{},\"session_id\":{},\"actor\":{{\"id\":{},\"kind\":\"agent\"}},\"surface\":\"terminal\",\"action\":\"process_exec\",\"target\":{{\"label\":{},\"uri\":null}},\"payload\":{{\"kind\":\"agent_process_exec_attempt\",\"terminal\":{{\"surface\":\"terminal\",\"tty\":{},\"interception_path\":\"linux_ptrace\"}},\"working_directory\":{},\"parent_process\":\"linux-process-guard\",\"argv_summary\":{},\"command\":[",
        json_string(&event_id),
        json_string(&session_id),
        json_string(&actor_id),
        json_string(path),
        if tty == "true" { "true" } else { "false" },
        json_string(&cwd),
        json_string(text)
    );
    for (index, argument) in argv.iter().enumerate() {
        if index > 0 {
            let _ = write!(file, ",");
        }
        let _ = write!(file, "{}", json_string(argument));
    }
    let _ = write!(
        file,
        "]}},\"risk\":{{\"level\":\"{}\",\"reasons\":[{}]}},\"timestamp\":\"unix:{}\"}},\"policy_decision\":{{\"type\":\"{}\"",
        risk,
        json_string(reason),
        timestamp,
        policy_decision
    );
    if let Some(rule) = rule {
        let _ = write!(
            file,
            ",\"reason\":{},\"rule_id\":{}",
            json_string(&rule.reason),
            json_string(&rule.rule_id)
        );
        if rule.decision == ProcessRuleDecision::RequireApproval {
            let _ = write!(file, ",\"approval_id\":null");
        }
    }
    let _ = write!(
        file,
        "}},\"final_decision\":{{\"type\":\"{}\"",
        final_decision
    );
    if let Some(rule) = rule {
        let final_reason = match rule.decision {
            ProcessRuleDecision::Allow => rule.reason.as_str(),
            ProcessRuleDecision::Deny => rule.reason.as_str(),
            ProcessRuleDecision::RequireApproval => {
                "process execution requires verification but no terminal approval provider is available"
            }
        };
        let _ = write!(
            file,
            ",\"reason\":{},\"rule_id\":{}",
            json_string(final_reason),
            json_string(&rule.rule_id)
        );
    }
    let _ = writeln!(file, "}}}}");
}

impl ProcessRuleDecision {
    fn from_guard_env(value: Option<&str>) -> Self {
        match value.unwrap_or_default() {
            "allow" => Self::Allow,
            "require_approval" | "require_verification" => Self::RequireApproval,
            _ => Self::Deny,
        }
    }

    const fn policy_decision_type(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireApproval => "require_approval",
        }
    }

    const fn final_decision_type(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny | Self::RequireApproval => "deny",
        }
    }
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character < ' ' => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn wait_exited(status: c_int) -> bool {
    status & 0x7f == 0
}

fn wait_exit_status(status: c_int) -> c_int {
    (status >> 8) & 0xff
}

fn wait_signaled(status: c_int) -> bool {
    let term_signal = status & 0x7f;
    term_signal != 0 && term_signal != 0x7f
}

fn wait_term_signal(status: c_int) -> c_int {
    status & 0x7f
}

fn wait_stopped(status: c_int) -> bool {
    status & 0xff == 0x7f
}

fn wait_stop_signal(status: c_int) -> c_int {
    (status >> 8) & 0xff
}

fn ptrace_event(status: c_int) -> u32 {
    (status as u32) >> 16
}

fn errno() -> c_int {
    unsafe { *__errno_location() }
}

fn set_errno(value: c_int) {
    unsafe {
        *__errno_location() = value;
    }
}

fn errno_message(error: c_int) -> String {
    let pointer = unsafe { strerror(error) };
    if pointer.is_null() {
        format!("errno {error}")
    } else {
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .to_string()
    }
}

fn die(message: &str) -> ! {
    eprintln!("erebor linux process guard: {message}");
    process::exit(127);
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::{
        command_text, json_string, parse_parent_pid_from_stat, parse_rules_from_source,
        ptrace_event, should_write_process_audit, wait_exit_status, wait_exited, wait_signaled,
        wait_stop_signal, wait_stopped, wait_term_signal, CgroupJoinReport, ProcessRule,
        ProcessRuleDecision, MAX_RULES, MAX_TEXT, PTRACE_EVENT_CLONE, SIGTRAP,
    };

    #[test]
    fn parses_deny_rules_from_guard_environment_format() {
        let rules = parse_rules_from_source(
            "/tmp/erebor/shims/google-chrome\tmanaged shim\tallow-shim\tallow\nremote-debugging-port\traw CDP is denied\tdeny-raw-cdp\nchromium\t\t\n\n",
        );

        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].token, "/tmp/erebor/shims/google-chrome");
        assert_eq!(rules[0].reason, "managed shim");
        assert_eq!(rules[0].rule_id, "allow-shim");
        assert_eq!(rules[0].decision, ProcessRuleDecision::Allow);
        assert_eq!(rules[1].token, "remote-debugging-port");
        assert_eq!(rules[1].reason, "raw CDP is denied");
        assert_eq!(rules[1].rule_id, "deny-raw-cdp");
        assert_eq!(rules[1].decision, ProcessRuleDecision::Deny);
        assert_eq!(rules[2].token, "chromium");
        assert_eq!(rules[2].reason, "process execution denied by Erebor policy");
        assert_eq!(rules[2].rule_id, "erebor-linux-process-guard");
        assert_eq!(rules[2].decision, ProcessRuleDecision::Deny);
    }

    #[test]
    fn generated_shim_allow_rule_wins_before_raw_cdp_deny() {
        let rules = parse_rules_from_source(
            "/tmp/erebor/shims/google-chrome\tmanaged shim\tallow-shim\tallow\nremote-debugging-port\traw CDP is denied\tdeny-raw-cdp\tdeny\n",
        );
        let command_text =
            "/bin/sh sh -c exec \"$0\" \"$@\" /tmp/erebor/shims/google-chrome --remote-debugging-port=1000";
        let matched = rules
            .iter()
            .find(|rule| command_text.contains(&rule.token))
            .expect("expected shim allow rule to match first");

        assert_eq!(matched.rule_id, "allow-shim");
        assert_eq!(matched.decision, ProcessRuleDecision::Allow);
    }

    #[test]
    fn parses_verification_rules_from_guard_environment_format() {
        let rules = parse_rules_from_source(
            "git push\tgit push needs verification\tverify-git-push\trequire_approval\n",
        );

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].token, "git push");
        assert_eq!(rules[0].reason, "git push needs verification");
        assert_eq!(rules[0].rule_id, "verify-git-push");
        assert_eq!(rules[0].decision, ProcessRuleDecision::RequireApproval);
    }

    #[test]
    fn ignores_empty_rule_tokens_and_caps_rule_count() {
        let source = (0..(MAX_RULES + 5))
            .map(|index| format!("token-{index}\treason-{index}\trule-{index}"))
            .chain([String::from("\tmissing token\tmissing-token")])
            .collect::<Vec<_>>()
            .join("\n");

        let rules = parse_rules_from_source(&source);

        assert_eq!(rules.len(), MAX_RULES);
        assert_eq!(rules[0].token, "token-0");
        assert_eq!(
            rules[MAX_RULES - 1].rule_id,
            format!("rule-{}", MAX_RULES - 1)
        );
    }

    #[test]
    fn command_text_preserves_path_and_arguments_with_spaces() {
        let text = command_text(
            "/bin/sh",
            &[
                String::from("sh"),
                String::from("-lc"),
                String::from("echo hello world"),
            ],
        );

        assert_eq!(text, "/bin/sh sh -lc echo hello world");
    }

    #[test]
    fn command_text_is_bounded() {
        let text = command_text("/bin/echo", &[String::from("x".repeat(MAX_TEXT * 2))]);

        assert_eq!(text.len(), MAX_TEXT);
        assert!(text.starts_with("/bin/echo "));
    }

    #[test]
    fn default_audit_filter_suppresses_allowed_sleep() {
        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_LEVEL");
        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS");

        assert!(!should_write_process_audit(
            "/usr/bin/sleep",
            &[String::from("sleep"), String::from("0.25")],
            None,
        ));
    }

    #[test]
    fn all_audit_level_logs_allowed_sleep() {
        env::set_var("EREBOR_GUARD_AUDIT_TERMINAL_LEVEL", "all");
        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS");

        assert!(should_write_process_audit(
            "/usr/bin/sleep",
            &[String::from("sleep"), String::from("0.25")],
            None,
        ));

        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_LEVEL");
    }

    #[test]
    fn audit_filter_always_logs_denied_sleep() {
        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_LEVEL");
        env::remove_var("EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS");
        let rule = ProcessRule {
            token: String::from("sleep"),
            reason: String::from("sleep denied"),
            rule_id: String::from("deny-sleep"),
            decision: ProcessRuleDecision::Deny,
        };

        assert!(should_write_process_audit(
            "/usr/bin/sleep",
            &[String::from("sleep"), String::from("0.25")],
            Some(&rule),
        ));
    }

    #[test]
    fn json_string_escapes_audit_values() {
        assert_eq!(
            json_string("quote\" slash\\ newline\n tab\t"),
            "\"quote\\\" slash\\\\ newline\\n tab\\t\""
        );
    }

    #[test]
    fn wait_status_helpers_do_not_treat_stops_as_signals() {
        let stopped = (SIGTRAP << 8) | 0x7f;

        assert!(wait_stopped(stopped));
        assert!(!wait_signaled(stopped));
        assert!(!wait_exited(stopped));
        assert_eq!(wait_stop_signal(stopped), SIGTRAP);
    }

    #[test]
    fn wait_status_helpers_decode_exit_and_signal_statuses() {
        let exited = 42 << 8;
        let signaled = 9;

        assert!(wait_exited(exited));
        assert_eq!(wait_exit_status(exited), 42);
        assert!(wait_signaled(signaled));
        assert_eq!(wait_term_signal(signaled), 9);
    }

    #[test]
    fn ptrace_event_decodes_high_status_bits() {
        let status = (PTRACE_EVENT_CLONE as i32) << 16;

        assert_eq!(ptrace_event(status), PTRACE_EVENT_CLONE);
    }

    #[test]
    fn parses_parent_pid_from_proc_stat_with_spaces_in_command() {
        let stat = "1234 (agent worker) S 4321 1 1 0 -1 4194560 0 0 0 0";

        assert_eq!(parse_parent_pid_from_stat(stat), Some(4321));
    }

    #[test]
    fn cgroup_report_defaults_to_not_requested() {
        let report = CgroupJoinReport::default();

        assert!(!report.requested);
        assert!(!report.cgroup_v2);
        assert_eq!(report.joined, 0);
        assert_eq!(report.failed, 0);
    }
}
