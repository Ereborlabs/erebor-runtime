use std::{
    ffi::CStr,
    os::raw::{c_char, c_int, c_long, c_uint, c_ulong, c_void},
};

pub(super) const PTRACE_PEEKDATA: c_uint = 2;
pub(super) const PTRACE_GETREGS: c_uint = 12;
pub(super) const PTRACE_SETREGS: c_uint = 13;
pub(super) const PTRACE_SYSCALL: c_uint = 24;
pub(super) const PTRACE_GETEVENTMSG: c_uint = 0x4201;

pub(super) const PTRACE_EVENT_FORK: u32 = 1;
pub(super) const PTRACE_EVENT_VFORK: u32 = 2;
pub(super) const PTRACE_EVENT_CLONE: u32 = 3;
pub(super) const PTRACE_EVENT_EXEC: u32 = 4;
pub(super) const PTRACE_EVENT_EXIT: u32 = 6;
pub(super) const PTRACE_EVENT_STOP: u32 = 128;

pub(super) const SYS_EXECVE: u64 = 59;
pub(super) const SYS_EXECVEAT: u64 = 322;

pub(super) const SIGSTOP: c_int = 19;
pub(super) const SIGTRAP: c_int = 5;
pub(super) const SIGKILL: c_int = 9;
pub(super) const EINTR: c_int = 4;
pub(super) const ENOENT: c_int = 2;
pub(super) const EPERM: c_int = 1;
pub(super) const WAIT_ALL_TRACED: c_int = 0x4000_0000;

const PTRACE_TRACEME: c_uint = 0;
const PTRACE_ATTACH: c_uint = 16;
const PTRACE_DETACH: c_uint = 17;
const PTRACE_SETOPTIONS: c_uint = 0x4200;

const PTRACE_O_TRACESYSGOOD: c_ulong = 1;
const PTRACE_O_TRACEFORK: c_ulong = 1 << 1;
const PTRACE_O_TRACEVFORK: c_ulong = 1 << 2;
const PTRACE_O_TRACECLONE: c_ulong = 1 << 3;
const PTRACE_O_TRACEEXEC: c_ulong = 1 << 4;
const PTRACE_O_TRACEEXIT: c_ulong = 1 << 6;
const PTRACE_O_EXITKILL: c_ulong = 1 << 20;

const ESRCH: c_int = 3;

pub(super) type Pid = c_int;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct UserRegsStruct {
    pub(super) r15: u64,
    pub(super) r14: u64,
    pub(super) r13: u64,
    pub(super) r12: u64,
    pub(super) rbp: u64,
    pub(super) rbx: u64,
    pub(super) r11: u64,
    pub(super) r10: u64,
    pub(super) r9: u64,
    pub(super) r8: u64,
    pub(super) rax: u64,
    pub(super) rcx: u64,
    pub(super) rdx: u64,
    pub(super) rsi: u64,
    pub(super) rdi: u64,
    pub(super) orig_rax: u64,
    pub(super) rip: u64,
    pub(super) cs: u64,
    pub(super) eflags: u64,
    pub(super) rsp: u64,
    pub(super) ss: u64,
    pub(super) fs_base: u64,
    pub(super) gs_base: u64,
    pub(super) ds: u64,
    pub(super) es: u64,
    pub(super) fs: u64,
    pub(super) gs: u64,
}

unsafe extern "C" {
    fn ptrace(request: c_uint, pid: Pid, address: *mut c_void, data: *mut c_void) -> c_long;
    fn waitpid(pid: Pid, status: *mut c_int, options: c_int) -> Pid;
    fn fork() -> Pid;
    fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int;
    fn raise(signal: c_int) -> c_int;
    fn kill(pid: Pid, signal: c_int) -> c_int;
    fn setgroups(size: usize, list: *const c_uint) -> c_int;
    fn setresgid(real: c_uint, effective: c_uint, saved: c_uint) -> c_int;
    fn setresuid(real: c_uint, effective: c_uint, saved: c_uint) -> c_int;
    fn setrlimit(resource: c_uint, limits: *const RLimit) -> c_int;
    fn umask(mask: c_uint) -> c_uint;
    fn mount(
        source: *const c_char,
        target: *const c_char,
        filesystem_type: *const c_char,
        flags: c_ulong,
        data: *const c_void,
    ) -> c_int;
    fn unshare(flags: c_int) -> c_int;
    fn prctl(option: c_int, argument: c_ulong, ...) -> c_int;
    fn _exit(status: c_int) -> !;
    fn strerror(error: c_int) -> *mut c_char;
    fn __errno_location() -> *mut c_int;
}

#[repr(C)]
struct RLimit {
    current: u64,
    maximum: u64,
}

pub(super) struct LinuxSys;

impl LinuxSys {
    pub(super) fn prepare_child_pid_namespace() -> Result<(), String> {
        const CLONE_NEWPID: c_int = 0x2000_0000;
        if unsafe { unshare(CLONE_NEWPID) } != 0 {
            return Err(format!(
                "failed to create the private session pid namespace: {}",
                Self::errno_message(Self::errno())
            ));
        }
        Ok(())
    }

    pub(super) fn prepare_private_workload_namespace() -> Result<(), String> {
        const CLONE_NEWNS: c_int = 0x0002_0000;
        const MS_NOSUID: c_ulong = 2;
        const MS_NODEV: c_ulong = 4;
        const MS_NOEXEC: c_ulong = 8;
        if unsafe { unshare(CLONE_NEWNS) } != 0 {
            return Err(format!(
                "failed to isolate the workload mount namespace: {}",
                Self::errno_message(Self::errno())
            ));
        }
        let source = c"proc";
        let target = c"/proc";
        let filesystem_type = c"proc";
        if unsafe {
            mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem_type.as_ptr(),
                MS_NOSUID | MS_NODEV | MS_NOEXEC,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(format!(
                "failed to mount the private session proc view: {}",
                Self::errno_message(Self::errno())
            ));
        }
        Self::lock_privileges()
    }

    pub(super) fn lock_privileges() -> Result<(), String> {
        const PR_SET_NO_NEW_PRIVS: c_int = 38;
        if unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(format!(
                "failed to set no_new_privs: {}",
                Self::errno_message(Self::errno())
            ));
        }
        Ok(())
    }

    pub(super) fn fork() -> Pid {
        unsafe { fork() }
    }

    pub(super) fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
        unsafe { execvp(file, argv) }
    }

    pub(super) fn raise(signal: c_int) -> c_int {
        unsafe { raise(signal) }
    }

    pub(super) fn kill(pid: Pid, signal: c_int) {
        let _result = unsafe { kill(pid, signal) };
    }

    pub(super) fn apply_workload_constraints(
        mask: c_uint,
        maximum_open_files: u64,
        maximum_processes: u64,
        maximum_core_bytes: u64,
    ) -> Result<(), String> {
        const RLIMIT_CORE: c_uint = 4;
        const RLIMIT_NPROC: c_uint = 6;
        const RLIMIT_NOFILE: c_uint = 7;
        unsafe {
            umask(mask);
        }
        for (resource, maximum, name) in [
            (RLIMIT_NOFILE, maximum_open_files, "RLIMIT_NOFILE"),
            (RLIMIT_NPROC, maximum_processes, "RLIMIT_NPROC"),
            (RLIMIT_CORE, maximum_core_bytes, "RLIMIT_CORE"),
        ] {
            let limits = RLimit {
                current: maximum,
                maximum,
            };
            if unsafe { setrlimit(resource, &limits) } != 0 {
                return Err(format!(
                    "setrlimit {name} failed: {}",
                    Self::errno_message(Self::errno())
                ));
            }
        }
        Ok(())
    }

    pub(super) fn drop_privileges(
        uid: c_uint,
        gid: c_uint,
        supplementary_groups: &[c_uint],
    ) -> Result<(), String> {
        if unsafe { setgroups(supplementary_groups.len(), supplementary_groups.as_ptr()) } != 0 {
            return Err(format!(
                "setgroups failed: {}",
                Self::errno_message(Self::errno())
            ));
        }
        if unsafe { setresgid(gid, gid, gid) } != 0 {
            return Err(format!(
                "setresgid failed: {}",
                Self::errno_message(Self::errno())
            ));
        }
        if unsafe { setresuid(uid, uid, uid) } != 0 {
            return Err(format!(
                "setresuid failed: {}",
                Self::errno_message(Self::errno())
            ));
        }
        Ok(())
    }

    pub(super) fn exit(status: c_int) -> ! {
        unsafe { _exit(status) }
    }

    pub(super) fn waitpid(pid: Pid, status: &mut c_int, options: c_int) -> Pid {
        unsafe { waitpid(pid, status, options) }
    }

    pub(super) fn ptrace(
        request: c_uint,
        pid: Pid,
        address: *mut c_void,
        data: *mut c_void,
    ) -> c_long {
        unsafe { ptrace(request, pid, address, data) }
    }

    pub(super) fn trace_me() -> Result<(), String> {
        if Self::ptrace(
            PTRACE_TRACEME,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) != 0
        {
            Err(format!(
                "PTRACE_TRACEME failed: {}",
                Self::errno_message(Self::errno())
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn attach(pid: Pid) -> Result<(), String> {
        let result = Self::ptrace(
            PTRACE_ATTACH,
            pid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if result != 0 {
            Err(Self::errno_message(Self::errno()))
        } else {
            Ok(())
        }
    }

    pub(super) fn set_trace_options(pid: Pid) -> Result<(), String> {
        let options = PTRACE_O_TRACESYSGOOD
            | PTRACE_O_TRACEFORK
            | PTRACE_O_TRACEVFORK
            | PTRACE_O_TRACECLONE
            | PTRACE_O_TRACEEXEC
            | PTRACE_O_TRACEEXIT
            | PTRACE_O_EXITKILL;
        let result = Self::ptrace(
            PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut(),
            options as usize as *mut c_void,
        );
        if result != 0 {
            Err(format!(
                "failed to set ptrace options for pid {}: {}",
                pid,
                Self::errno_message(Self::errno())
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn continue_trace(pid: Pid, signal_to_deliver: c_int) {
        let result = Self::ptrace(
            PTRACE_SYSCALL,
            pid,
            std::ptr::null_mut(),
            signal_to_deliver as isize as *mut c_void,
        );
        if result != 0 && Self::errno() != ESRCH {
            eprintln!(
                "erebor linux process guard: failed to continue pid {}: {}",
                pid,
                Self::errno_message(Self::errno())
            );
        }
    }

    pub(super) fn set_regs(pid: Pid, regs: &UserRegsStruct) {
        Self::ptrace(
            PTRACE_SETREGS,
            pid,
            std::ptr::null_mut(),
            regs as *const UserRegsStruct as *mut c_void,
        );
    }

    pub(super) fn detach_trace(pid: Pid) {
        let result = Self::ptrace(
            PTRACE_DETACH,
            pid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if result != 0 && Self::errno() != ESRCH {
            eprintln!(
                "erebor linux process guard: failed to detach pid {}: {}",
                pid,
                Self::errno_message(Self::errno())
            );
        }
    }

    pub(super) fn peek_data(pid: Pid, address: u64) -> Option<c_long> {
        Self::set_errno(0);
        let value = Self::ptrace(
            PTRACE_PEEKDATA,
            pid,
            address as usize as *mut c_void,
            std::ptr::null_mut(),
        );
        if Self::errno() == 0 {
            Some(value)
        } else {
            None
        }
    }

    pub(super) fn errno() -> c_int {
        unsafe { *__errno_location() }
    }

    fn set_errno(value: c_int) {
        unsafe {
            *__errno_location() = value;
        }
    }

    pub(super) fn errno_message(error: c_int) -> String {
        let pointer = unsafe { strerror(error) };
        if pointer.is_null() {
            format!("errno {error}")
        } else {
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .to_string()
        }
    }
}
