#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Seek as _, SeekFrom};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

const AT_RECURSIVE: libc::c_int = 0x8000;
const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
const OPEN_TREE_CLONE: libc::c_uint = 0x0000_0001;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

pub(super) fn exec_path(path: &Path, use_execveat: bool) -> io::Result<()> {
    let path = path_c_string(path)?;
    let arguments = [
        c"sh".as_ptr(),
        c"-c".as_ptr(),
        c"exit 0".as_ptr(),
        std::ptr::null(),
    ];
    let environment = [std::ptr::null::<libc::c_char>()];

    fork_and_wait(|| {
        if use_execveat {
            // SAFETY: every pointer references a retained NUL-terminated value.
            unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    arguments.as_ptr(),
                    environment.as_ptr(),
                    0,
                );
            }
        } else {
            // SAFETY: every pointer references a retained NUL-terminated value.
            unsafe {
                libc::execve(path.as_ptr(), arguments.as_ptr(), environment.as_ptr());
            }
        }
        last_errno()
    })
}

pub(super) fn exec_fd(fd: RawFd, from_non_leader: bool) -> io::Result<()> {
    let arguments = [
        c"sh".as_ptr(),
        c"-c".as_ptr(),
        c"exit 0".as_ptr(),
        std::ptr::null(),
    ];
    let environment = [std::ptr::null::<libc::c_char>()];

    if !from_non_leader {
        return fork_and_wait(|| {
            // SAFETY: fd and the retained argument vectors remain valid after fork.
            unsafe {
                libc::fexecve(fd, arguments.as_ptr(), environment.as_ptr());
            }
            last_errno()
        });
    }

    let call = ThreadExecCall {
        fd,
        arguments: arguments.as_ptr(),
        environment: environment.as_ptr(),
    };
    fork_and_wait(|| {
        let mut thread = unsafe { zeroed::<libc::pthread_t>() };
        // SAFETY: the new process has one thread. `call` stays live until join.
        let created = unsafe {
            libc::pthread_create(
                &mut thread,
                std::ptr::null(),
                exec_fd_thread,
                (&call as *const ThreadExecCall).cast_mut().cast(),
            )
        };
        if created != 0 {
            return created;
        }
        let mut result = std::ptr::null_mut();
        // SAFETY: thread is the successful pthread_create result.
        let joined = unsafe { libc::pthread_join(thread, &mut result) };
        if joined == 0 {
            result.addr() as libc::c_int
        } else {
            joined
        }
    })
}

struct ThreadExecCall {
    fd: RawFd,
    arguments: *const *const libc::c_char,
    environment: *const *const libc::c_char,
}

extern "C" fn exec_fd_thread(argument: *mut libc::c_void) -> *mut libc::c_void {
    // SAFETY: argument points to ThreadExecCall retained by the joining thread.
    let call = unsafe { &*argument.cast::<ThreadExecCall>() };
    // SAFETY: all fields remain valid until this function returns or exec succeeds.
    unsafe {
        libc::fexecve(call.fd, call.arguments, call.environment);
    }
    std::ptr::without_provenance_mut(last_errno() as usize)
}

pub(super) fn memfd_copy(source: &Path) -> io::Result<File> {
    // SAFETY: name is a valid NUL-terminated string.
    let fd = unsafe { libc::memfd_create(c"mithril-exec-fixture".as_ptr(), libc::MFD_EXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is newly owned by this process.
    let mut target = unsafe { File::from_raw_fd(fd) };
    let mut input = File::open(source)?;
    io::copy(&mut input, &mut target)?;
    target.seek(SeekFrom::Start(0))?;
    Ok(target)
}

pub(super) fn make_mapping_exec(mapping: &memmap2::Mmap) -> io::Result<()> {
    // SAFETY: a zero-offset Mmap owns this page-aligned range for its lifetime.
    syscall_result(unsafe {
        libc::mprotect(
            mapping.as_ptr().cast_mut().cast(),
            mapping.len(),
            libc::PROT_READ | libc::PROT_EXEC,
        ) as libc::c_long
    })
}

pub(super) fn map_anonymous(protection: libc::c_int) -> io::Result<()> {
    // SAFETY: mmap receives no user pointer or file descriptor, and returns a new mapping.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            1,
            protection,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if address == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: address is the live mapping returned above.
    syscall_result(unsafe { libc::munmap(address, 1) }.into())
}

pub(super) fn pkey_mprotect_anonymous(protection: libc::c_int) -> io::Result<()> {
    let mut mapping = memmap2::MmapMut::map_anon(1)?;
    // SAFETY: mapping owns the aligned range, and protection key zero is always allocated.
    syscall_result(unsafe {
        libc::syscall(
            libc::SYS_pkey_mprotect,
            mapping.as_mut_ptr(),
            mapping.len(),
            protection,
            0,
        )
    })
}

pub(super) fn receive_file_from_actor(path: &Path) -> io::Result<File> {
    let path = path_c_string(path)?;
    let (receiver, sender) = UnixDatagram::pair()?;

    // SAFETY: no borrowed Rust state is modified by the child before _exit.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        drop(receiver);
        // SAFETY: path is retained and flags do not require a mode argument.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            // SAFETY: child exits without running inherited destructors.
            unsafe { libc::_exit(last_errno()) };
        }
        let sent = send_fd(sender.as_raw_fd(), fd);
        // SAFETY: fd belongs to the child and is no longer needed.
        unsafe { libc::close(fd) };
        // SAFETY: child exits without running inherited destructors.
        unsafe {
            libc::_exit(
                sent.err()
                    .and_then(|error| error.raw_os_error())
                    .unwrap_or(0),
            )
        };
    }
    drop(sender);
    let received = receive_file_descriptor(receiver.as_raw_fd());
    let child_result = wait_child(child);
    child_result?;
    let received = received?;
    if !received.payload_received || received.control_truncated {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SCM_RIGHTS control fixture did not receive a complete descriptor",
        ));
    }
    received.file.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "SCM_RIGHTS message contains no file descriptor",
        )
    })
}

pub(super) fn send_fd(socket: RawFd, fd: RawFd) -> io::Result<()> {
    let mut control = [0_usize; 4];
    let mut byte = 1_u8;
    let mut io = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    // SAFETY: the zeroed header is filled with valid pointers and lengths below.
    let mut message = unsafe { zeroed::<libc::msghdr>() };
    message.msg_iov = &mut io;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of::<[usize; 4]>();
    // SAFETY: message owns enough aligned ancillary storage for one descriptor.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SCM_RIGHTS control buffer is too small",
            ));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as _) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), fd);
        if libc::sendmsg(socket, &message, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(super) struct ReceivedFileDescriptor {
    pub(super) payload_received: bool,
    pub(super) control_truncated: bool,
    pub(super) file: Option<File>,
}

pub(super) fn receive_file_descriptor(socket: RawFd) -> io::Result<ReceivedFileDescriptor> {
    let mut control = [0_usize; 4];
    let mut byte = 0_u8;
    let mut io = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    // SAFETY: the zeroed header is filled with valid pointers and lengths below.
    let mut message = unsafe { zeroed::<libc::msghdr>() };
    message.msg_iov = &mut io;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of::<[usize; 4]>();
    // SAFETY: every pointer in message points to live writable storage.
    let received = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    if received != 1 || byte != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SCM_RIGHTS message contains the wrong payload",
        ));
    }
    // SAFETY: recvmsg initialized ancillary headers within control.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    let fd = if header.is_null() {
        None
    } else {
        let expected_length = unsafe { libc::CMSG_LEN(size_of::<libc::c_int>() as _) } as usize;
        if unsafe { (*header).cmsg_level } != libc::SOL_SOCKET
            || unsafe { (*header).cmsg_type } != libc::SCM_RIGHTS
            || unsafe { (*header).cmsg_len } != expected_length
            // SAFETY: header is the first valid header in message.
            || !unsafe { libc::CMSG_NXTHDR(&message, header) }.is_null()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SCM_RIGHTS message contains invalid descriptor control data",
            ));
        }
        // SAFETY: the checked SCM_RIGHTS header contains one c_int descriptor.
        Some(unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>()) })
    };
    // SAFETY: recvmsg installed every descriptor in the checked SCM_RIGHTS header.
    let file = fd.map(|fd| unsafe { File::from_raw_fd(fd) });

    // Linux reports a security_file_receive rejection through MSG_CTRUNC.
    // recvmsg can still return the ordinary payload and does not return EACCES.
    Ok(ReceivedFileDescriptor {
        payload_received: true,
        control_truncated: message.msg_flags & libc::MSG_CTRUNC != 0,
        file,
    })
}

pub(super) fn open_mount_tree(path: &Path) -> io::Result<File> {
    let path = path_c_string(path)?;
    // SAFETY: path is NUL-terminated and flags are valid open_tree flags.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            path.as_ptr(),
            OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: fd is a newly owned open_tree descriptor.
        Ok(unsafe { File::from_raw_fd(fd as RawFd) })
    }
}

pub(super) fn move_mount(tree: RawFd, target: &Path) -> io::Result<()> {
    let target = path_c_string(target)?;
    // SAFETY: both strings and the detached mount descriptor remain valid.
    syscall_result(unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree,
            c"".as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    })
}

pub(super) fn set_mount_read_only(path: &Path) -> io::Result<()> {
    let path = path_c_string(path)?;
    let attributes = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: path and the complete mount_attr value remain valid for the call.
    syscall_result(unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            path.as_ptr(),
            AT_RECURSIVE,
            &attributes,
            size_of::<MountAttr>(),
        )
    })
}

pub(super) fn make_mount_shared(path: &Path) -> io::Result<()> {
    let path = path_c_string(path)?;
    // SAFETY: only target and propagation flags are used for this mount call.
    let result = unsafe {
        libc::mount(
            std::ptr::null(),
            path.as_ptr(),
            std::ptr::null(),
            libc::MS_SHARED | libc::MS_REC,
            std::ptr::null(),
        )
    };
    syscall_result(result.into())
}

fn fork_and_wait(child_call: impl FnOnce() -> libc::c_int) -> io::Result<()> {
    // SAFETY: the child executes only the supplied syscall path and then _exit.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        let result = child_call();
        // SAFETY: this branch is the disposable fork child.
        unsafe { libc::_exit(result) };
    }
    wait_child(child)
}

fn wait_child(child: libc::pid_t) -> io::Result<()> {
    let mut status = 0;
    // SAFETY: child is a live PID and status is writable storage.
    if unsafe { libc::waitpid(child, &mut status, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code))
        }
    } else {
        Err(io::Error::other("execution fixture terminated by signal"))
    }
}

fn syscall_result(result: libc::c_long) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn path_c_string(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn last_errno() -> libc::c_int {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}
