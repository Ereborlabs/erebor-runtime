#![allow(unsafe_code)]

#[path = "process_guard/audit.rs"]
mod audit;
#[path = "process_guard/broker.rs"]
mod broker;
#[path = "process_guard/cgroup.rs"]
mod cgroup;
#[path = "process_guard/file_interception.rs"]
mod file_interception;
#[path = "process_guard/interception.rs"]
mod interception;
#[path = "../../../../erebor-runtime-ipc/src/standalone/mod.rs"]
mod ipc;
#[path = "process_guard/memory.rs"]
mod memory;
#[path = "process_guard/rules.rs"]
mod rules;
#[path = "process_guard/status.rs"]
mod status;
#[path = "process_guard/sys.rs"]
mod sys;
#[path = "process_guard/trace.rs"]
mod trace;

use std::{collections::HashMap, env, ffi::CString, fs, os::unix::ffi::OsStringExt, process};

use cgroup::{join_configured_cgroup, write_capability_report};
use rules::{parse_rules, ProcessRule};
use status::{wait_exited, wait_signaled, wait_stopped};
use sys::{LinuxSys, Pid, EINTR, ENOENT, SIGSTOP};
use trace::TraceLoop;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Erebor's Linux process guard currently supports x86_64 Linux only");

const MAX_ARGV: usize = 32;
const MAX_STRING: usize = 512;

fn main() {
    if let Some(status) = interception::ShimInterception::try_handle_configured_interception() {
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
    let child = LinuxSys::fork();
    if child < 0 {
        die(&format!(
            "fork failed: {}",
            LinuxSys::errno_message(LinuxSys::errno())
        ));
    }

    if child == 0 {
        child_exec(command);
    }

    let mut trace_loop = TraceLoop::new(child, rules);
    trace_loop.track(child);

    wait_for_initial_stop(child);
    set_trace_options(child);
    let cgroup = join_configured_cgroup(&[child]);
    write_capability_report("relaunch", child, 1, 0, &cgroup);
    LinuxSys::continue_trace(child, 0);

    trace_loop.run()
}

fn adopt_existing_process_tree(root_pid: Pid, rules: Vec<ProcessRule>) -> i32 {
    let candidate_pids = process_tree_pids(root_pid);
    let mut trace_loop = TraceLoop::new(root_pid, rules);
    let mut failed = Vec::new();

    for pid in candidate_pids {
        match attach_existing_pid(pid) {
            Ok(()) => {
                trace_loop.track(pid);
            }
            Err(reason) => {
                failed.push((pid, reason));
            }
        }
    }

    let attached_pids = trace_loop.tracked_pids();
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

    if !trace_loop.contains(root_pid) {
        for pid in attached_pids {
            LinuxSys::detach_trace(pid);
        }
        return 126;
    }

    for pid in trace_loop.tracked_pids() {
        LinuxSys::continue_trace(pid, 0);
    }

    trace_loop.run()
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
    LinuxSys::attach(pid)?;

    wait_for_attached_stop(pid)?;
    if let Err(reason) = LinuxSys::set_trace_options(pid) {
        LinuxSys::detach_trace(pid);
        Err(reason)
    } else {
        Ok(())
    }
}

fn wait_for_attached_stop(pid: Pid) -> Result<(), String> {
    loop {
        let mut status = 0;
        let waited = LinuxSys::waitpid(pid, &mut status, 0);
        if waited < 0 {
            let error = LinuxSys::errno();
            if error == EINTR {
                continue;
            }
            return Err(format!(
                "waitpid failed: {}",
                LinuxSys::errno_message(error)
            ));
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

    if let Err(reason) = LinuxSys::trace_me() {
        die(&reason);
    }
    LinuxSys::raise(SIGSTOP);
    LinuxSys::execvp(command[0].as_ptr(), argv.as_ptr());

    let error = LinuxSys::errno();
    eprintln!(
        "erebor linux process guard: failed to exec {}: {}",
        command[0].to_string_lossy(),
        LinuxSys::errno_message(error)
    );
    LinuxSys::exit(if error == ENOENT { 127 } else { 126 });
}

fn wait_for_initial_stop(child: Pid) {
    let mut status = 0;
    let waited = LinuxSys::waitpid(child, &mut status, 0);
    if waited < 0 {
        die(&format!(
            "initial waitpid failed: {}",
            LinuxSys::errno_message(LinuxSys::errno())
        ));
    }
    if !wait_stopped(status) {
        die("child did not stop for tracing");
    }
}

fn set_trace_options(pid: Pid) {
    if let Err(reason) = LinuxSys::set_trace_options(pid) {
        die(&reason);
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

fn die(message: &str) -> ! {
    eprintln!("erebor linux process guard: {message}");
    process::exit(127);
}

#[cfg(test)]
mod tests {
    use super::parse_parent_pid_from_stat;

    #[test]
    fn parses_parent_pid_from_proc_stat_with_spaces_in_command() {
        let stat = "1234 (agent worker) S 4321 1 1 0 -1 4194560 0 0 0 0";

        assert_eq!(parse_parent_pid_from_stat(stat), Some(4321));
    }
}
