use std::{
    collections::{HashMap, HashSet},
    os::raw::c_ulong,
};

use super::{
    audit::write_process_audit,
    broker::GuardBrokerEnvironment,
    die,
    exec_observer::GuardExecObserver,
    file_interception, ipc,
    memory::{read_argv, read_cstring},
    observer_protocol::GuardObserverStatus,
    rules::{command_text, ProcessRule, ProcessRuleDecision},
    status::{
        ptrace_event, wait_exit_status, wait_exited, wait_signaled, wait_stop_signal, wait_stopped,
        wait_term_signal,
    },
    sys::{
        LinuxSys, Pid, UserRegsStruct, EINTR, EPERM, PTRACE_EVENT_CLONE, PTRACE_EVENT_EXEC,
        PTRACE_EVENT_EXIT, PTRACE_EVENT_FORK, PTRACE_EVENT_STOP, PTRACE_EVENT_VFORK,
        PTRACE_GETEVENTMSG, PTRACE_GETREGS, SIGKILL, SIGSTOP, SIGTRAP, SYS_EXECVE, SYS_EXECVEAT,
        WAIT_ALL_TRACED,
    },
};

#[derive(Clone, Debug, Default)]
struct PidState {
    in_syscall: bool,
    denied_pending: bool,
    exec_history: Vec<String>,
}

pub(super) struct TraceLoop {
    rules: Vec<ProcessRule>,
    states: HashMap<Pid, PidState>,
    audit_seq: u64,
    root_pid: Pid,
    live_traces: usize,
    exec_observer: Option<GuardExecObserver>,
    observed_hook_pids: HashSet<Pid>,
    held_effect_pids: HashSet<Pid>,
    observer_barrier_rejected: bool,
}

impl TraceLoop {
    pub(super) fn new(
        root_pid: Pid,
        rules: Vec<ProcessRule>,
        exec_observer: Option<GuardExecObserver>,
    ) -> Self {
        Self {
            rules,
            states: HashMap::new(),
            audit_seq: 0,
            root_pid,
            live_traces: 0,
            exec_observer,
            observed_hook_pids: HashSet::new(),
            held_effect_pids: HashSet::new(),
            observer_barrier_rejected: false,
        }
    }

    pub(super) fn track(&mut self, pid: Pid) {
        if self.states.insert(pid, PidState::default()).is_none() {
            self.live_traces += 1;
        }
    }

    pub(super) fn contains(&self, pid: Pid) -> bool {
        self.states.contains_key(&pid)
    }

    pub(super) fn tracked_pids(&self) -> Vec<Pid> {
        self.states.keys().copied().collect()
    }

    pub(super) fn run(&mut self) -> i32 {
        let mut root_status = 1;

        while self.live_traces > 0 {
            let mut status = 0;
            let pid = LinuxSys::waitpid(-1, &mut status, WAIT_ALL_TRACED);
            if pid < 0 {
                let error = LinuxSys::errno();
                if error == EINTR {
                    continue;
                }
                die(&format!(
                    "waitpid failed: {}",
                    LinuxSys::errno_message(error)
                ));
            }

            if wait_exited(status) || wait_signaled(status) {
                self.observe_exit(pid, wait_exited(status) && wait_exit_status(status) == 0);
                if pid == self.root_pid {
                    root_status = if wait_exited(status) {
                        wait_exit_status(status)
                    } else {
                        128 + wait_term_signal(status)
                    };
                }
                self.states.remove(&pid);
                self.live_traces = self.live_traces.saturating_sub(1);
                self.release_held_effects();
                continue;
            }

            if !wait_stopped(status) {
                LinuxSys::continue_trace(pid, 0);
                continue;
            }

            let stop_signal = wait_stop_signal(status);
            let event = ptrace_event(status);

            if matches!(
                event,
                PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK | PTRACE_EVENT_CLONE
            ) {
                let mut new_pid: c_ulong = 0;
                let result = LinuxSys::ptrace(
                    PTRACE_GETEVENTMSG,
                    pid,
                    std::ptr::null_mut(),
                    &mut new_pid as *mut c_ulong as *mut std::ffi::c_void,
                );
                if result == 0 && new_pid != 0 {
                    let history = self
                        .states
                        .get(&pid)
                        .map_or_else(Vec::new, |state| state.exec_history.clone());
                    self.track_with_history(new_pid as Pid, history);
                    self.observe_fork(pid, new_pid as Pid);
                }
                LinuxSys::continue_trace(pid, 0);
                continue;
            }

            if event == PTRACE_EVENT_EXEC {
                self.observe_exec(pid);
                LinuxSys::continue_trace(pid, 0);
                continue;
            }

            if matches!(event, PTRACE_EVENT_EXIT | PTRACE_EVENT_STOP) {
                LinuxSys::continue_trace(pid, 0);
                continue;
            }

            if stop_signal == (SIGTRAP | 0x80) {
                if self.handle_syscall_stop(pid) {
                    LinuxSys::continue_trace(pid, 0);
                }
                continue;
            }

            if stop_signal == SIGSTOP || stop_signal == SIGTRAP {
                LinuxSys::continue_trace(pid, 0);
            } else {
                LinuxSys::continue_trace(pid, stop_signal);
            }
        }

        root_status
    }

    fn track_with_history(&mut self, pid: Pid, exec_history: Vec<String>) {
        if self
            .states
            .insert(
                pid,
                PidState {
                    exec_history,
                    ..PidState::default()
                },
            )
            .is_none()
        {
            self.live_traces += 1;
        }
    }

    fn observe_exec(&mut self, pid: Pid) {
        let Some(observer) = self.exec_observer.as_mut() else {
            return;
        };
        let executable = match std::fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(path) => path.display().to_string(),
            Err(error) => {
                eprintln!("erebor linux process guard: failed to inspect exec {pid}: {error}");
                LinuxSys::kill(pid, SIGKILL);
                return;
            }
        };
        let Some(state) = self.states.get_mut(&pid) else {
            LinuxSys::kill(pid, SIGKILL);
            return;
        };
        state.exec_history.push(executable);
        match observer.observe_exec(pid, state.exec_history.clone()) {
            Ok(GuardObserverStatus::Ignore) => {}
            Ok(GuardObserverStatus::Track) => {
                self.observed_hook_pids.insert(pid);
            }
            Ok(GuardObserverStatus::Reject) => {
                self.observer_barrier_rejected = true;
                LinuxSys::kill(pid, SIGKILL);
            }
            Err(reason) => {
                eprintln!("erebor linux process guard: guarded exec observation failed: {reason}");
                self.observer_barrier_rejected = true;
                LinuxSys::kill(pid, SIGKILL);
            }
        }
    }

    fn observe_fork(&mut self, parent_pid: Pid, child_pid: Pid) {
        let Some(observer) = self.exec_observer.as_mut() else {
            return;
        };
        match observer.observe_fork(parent_pid, child_pid) {
            Ok(GuardObserverStatus::Ignore | GuardObserverStatus::Track) => {}
            Ok(GuardObserverStatus::Reject) => self.observer_barrier_rejected = true,
            Err(reason) => {
                eprintln!("erebor linux process guard: guarded fork observation failed: {reason}");
                self.observer_barrier_rejected = true;
            }
        }
    }

    fn observe_exit(&mut self, pid: Pid, succeeded: bool) {
        let tracked_hook = self.observed_hook_pids.remove(&pid);
        let Some(observer) = self.exec_observer.as_mut() else {
            return;
        };
        match observer.observe_exit(pid, succeeded) {
            Ok(GuardObserverStatus::Track) if tracked_hook && succeeded => {}
            Ok(GuardObserverStatus::Track) => self.observer_barrier_rejected = true,
            Ok(GuardObserverStatus::Ignore) if !tracked_hook => {}
            Ok(GuardObserverStatus::Ignore | GuardObserverStatus::Reject) => {
                self.observer_barrier_rejected = true;
            }
            Err(reason) => {
                eprintln!("erebor linux process guard: guarded exit observation failed: {reason}");
                self.observer_barrier_rejected = true;
            }
        }
    }

    fn handle_syscall_stop(&mut self, pid: Pid) -> bool {
        let mut regs = UserRegsStruct::default();
        let get_result = LinuxSys::ptrace(
            PTRACE_GETREGS,
            pid,
            std::ptr::null_mut(),
            &mut regs as *mut UserRegsStruct as *mut std::ffi::c_void,
        );
        if get_result != 0 {
            return true;
        }

        let entering_syscall = match self.states.get_mut(&pid) {
            Some(state) => {
                if state.in_syscall {
                    false
                } else {
                    state.in_syscall = true;
                    true
                }
            }
            None => return true,
        };

        if entering_syscall {
            if self.should_hold_effect_for_hook_exit(pid, &regs) {
                self.held_effect_pids.insert(pid);
                return false;
            }
            let deny_requested = file_interception::should_deny_file_syscall(pid, &regs)
                || (GuardBrokerEnvironment::operation_enabled("process_exec")
                    && (regs.orig_rax == SYS_EXECVE || regs.orig_rax == SYS_EXECVEAT)
                    && self.should_deny_exec(pid, &regs, regs.orig_rax == SYS_EXECVEAT));
            if deny_requested {
                Self::deny_syscall(pid, &mut regs, &mut self.states);
            }
        } else if let Some(state) = self.states.get_mut(&pid) {
            if state.denied_pending {
                regs.rax = (-(EPERM as i64)) as u64;
                state.denied_pending = false;
                LinuxSys::set_regs(pid, &regs);
            }
            state.in_syscall = false;
        }
        true
    }

    fn should_hold_effect_for_hook_exit(&self, pid: Pid, regs: &UserRegsStruct) -> bool {
        !self.observed_hook_pids.is_empty()
            && !self.observed_hook_pids.contains(&pid)
            && self.is_intercepted_effect(pid, regs)
    }

    fn is_intercepted_effect(&self, pid: Pid, regs: &UserRegsStruct) -> bool {
        file_interception::is_intercepted_file_syscall(pid, regs)
            || (GuardBrokerEnvironment::operation_enabled("process_exec")
                && (regs.orig_rax == SYS_EXECVE || regs.orig_rax == SYS_EXECVEAT))
    }

    fn release_held_effects(&mut self) {
        if !self.observed_hook_pids.is_empty() {
            return;
        }
        let held_pids = self.held_effect_pids.drain().collect::<Vec<_>>();
        for pid in held_pids {
            let mut regs = UserRegsStruct::default();
            let get_result = LinuxSys::ptrace(
                PTRACE_GETREGS,
                pid,
                std::ptr::null_mut(),
                &mut regs as *mut UserRegsStruct as *mut std::ffi::c_void,
            );
            if get_result != 0 || !self.states.contains_key(&pid) {
                continue;
            }
            let deny_requested = self.observer_barrier_rejected
                || file_interception::should_deny_file_syscall(pid, &regs)
                || (GuardBrokerEnvironment::operation_enabled("process_exec")
                    && (regs.orig_rax == SYS_EXECVE || regs.orig_rax == SYS_EXECVEAT)
                    && self.should_deny_exec(pid, &regs, regs.orig_rax == SYS_EXECVEAT));
            if deny_requested {
                Self::deny_syscall(pid, &mut regs, &mut self.states);
            }
            LinuxSys::continue_trace(pid, 0);
        }
    }

    fn deny_syscall(pid: Pid, regs: &mut UserRegsStruct, states: &mut HashMap<Pid, PidState>) {
        regs.orig_rax = (-1i64) as u64;
        regs.rax = (-(EPERM as i64)) as u64;
        if let Some(state) = states.get_mut(&pid) {
            state.denied_pending = true;
        }
        LinuxSys::set_regs(pid, regs);
    }

    fn should_deny_exec(&mut self, pid: Pid, regs: &UserRegsStruct, is_execveat: bool) -> bool {
        let path_address = if is_execveat { regs.rsi } else { regs.rdi };
        let argv_address = if is_execveat { regs.rdx } else { regs.rsi };
        let path = read_cstring(pid, path_address, super::MAX_STRING);
        let argv = read_argv(pid, argv_address);
        let text = command_text(&path, &argv);
        let rule = match self.broker_rule_for_exec(pid, &path, &argv) {
            Ok(Some(rule)) => Some(rule),
            Ok(None) => self
                .rules
                .iter()
                .find(|rule| text.contains(&rule.token))
                .cloned(),
            Err(reason) => {
                eprintln!(
                    "erebor linux process guard: broker process_exec decision failed: {reason}"
                );
                Some(ProcessRule {
                    token: text.clone(),
                    reason,
                    rule_id: String::from(
                        "erebor-runtime-interception-broker-process-exec-fail-closed",
                    ),
                    decision: ProcessRuleDecision::Deny,
                })
            }
        };

        self.audit_seq += 1;
        write_process_audit(self.audit_seq, pid, &path, &argv, &text, rule.as_ref());

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

    fn broker_rule_for_exec(
        &self,
        pid: Pid,
        path: &str,
        argv: &[String],
    ) -> Result<Option<ProcessRule>, String> {
        let Some(endpoint) = GuardBrokerEnvironment::endpoint()? else {
            return Ok(None);
        };
        let hello = GuardBrokerEnvironment::hello()?;
        let mut connection = ipc::RuntimeInterceptionConnection::connect(&endpoint, hello)?;
        let request = GuardBrokerEnvironment::process_exec_request(pid, path, argv);
        connection
            .request_decision(&request)
            .map(|decision| Some(Self::process_rule_from_broker_decision(&decision)))
    }

    fn process_rule_from_broker_decision(decision: &ipc::InterceptionDecision) -> ProcessRule {
        let (decision_kind, default_reason) = match decision.kind {
            ipc::InterceptionDecisionKind::Allow => (
                ProcessRuleDecision::Allow,
                "process execution allowed by routed surface",
            ),
            ipc::InterceptionDecisionKind::Deny => (
                ProcessRuleDecision::Deny,
                "process execution denied by routed surface",
            ),
            ipc::InterceptionDecisionKind::RequireApproval => (
                ProcessRuleDecision::RequireApproval,
                "process execution requires approval from routed surface",
            ),
            ipc::InterceptionDecisionKind::Mediate | ipc::InterceptionDecisionKind::Unknown => (
                ProcessRuleDecision::Deny,
                "routed surface returned unsupported process execution decision",
            ),
        };
        ProcessRule {
            token: String::new(),
            reason: if decision.reason.is_empty() {
                String::from(default_reason)
            } else {
                decision.reason.clone()
            },
            rule_id: if decision.rule_id.is_empty() {
                String::from("erebor-routed-process-exec")
            } else {
                decision.rule_id.clone()
            },
            decision: decision_kind,
        }
    }
}
