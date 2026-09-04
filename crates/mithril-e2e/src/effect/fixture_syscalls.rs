#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Seek as _, SeekFrom};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::atomic::{fence, Ordering};

const AT_RECURSIVE: libc::c_int = 0x8000;
const FSCONFIG_SET_STRING: libc::c_uint = 1;
const FSCONFIG_CMD_RECONFIGURE: libc::c_uint = 7;
const FSPICK_CLOEXEC: libc::c_uint = 0x0000_0001;
const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
const OPEN_TREE_CLONE: libc::c_uint = 0x0000_0001;
const IORING_SETUP_R_DISABLED: u32 = 1 << 6;
const IORING_SETUP_SQPOLL: u32 = 1 << 1;
const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
const IORING_FEAT_SINGLE_MMAP: u32 = 1;
const IORING_REGISTER_RESTRICTIONS: libc::c_uint = 11;
const IORING_REGISTER_ENABLE_RINGS: libc::c_uint = 12;
const IORING_RESTRICTION_REGISTER_OP: u16 = 0;
const IORING_RESTRICTION_SQE_OP: u16 = 1;
const IORING_RESTRICTION_SQE_FLAGS_ALLOWED: u16 = 2;
const IORING_OP_READ: u8 = 22;
const IORING_OP_WRITE: u8 = 23;
const IOSQE_ASYNC: u8 = 1 << 4;
const IORING_ENTER_GETEVENTS: libc::c_uint = 1;
const IORING_OFF_SQ_RING: libc::off_t = 0;
const IORING_OFF_CQ_RING: libc::off_t = 0x0800_0000;
const IORING_OFF_SQES: libc::off_t = 0x1000_0000;

pub(super) enum ForkResult {
    Parent(libc::pid_t),
    Child,
}

pub(super) fn fork_process() -> io::Result<ForkResult> {
    // SAFETY: the caller uses the child only for a bounded fixture command loop.
    let process = unsafe { libc::fork() };
    if process < 0 {
        Err(io::Error::last_os_error())
    } else if process == 0 {
        Ok(ForkResult::Child)
    } else {
        Ok(ForkResult::Parent(process))
    }
}

pub(super) fn exit_process(code: libc::c_int) -> ! {
    // SAFETY: this is called only in the isolated fork child.
    unsafe { libc::_exit(code) }
}

pub(super) fn wait_process(process: libc::pid_t) -> io::Result<()> {
    wait_child(process)
}

pub(super) fn forked_write_one(fd: RawFd, byte: u8) -> io::Result<()> {
    fork_and_wait(|| {
        // SAFETY: fd is live in the fork child and byte is retained for this call.
        let written = unsafe { libc::write(fd, std::ptr::from_ref(&byte).cast(), 1) };
        match written {
            1 => 0,
            value if value < 0 => last_errno(),
            _ => libc::EIO,
        }
    })
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoSqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoCqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: IoSqringOffsets,
    cq_off: IoCqringOffsets,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoUringRestriction {
    opcode: u16,
    operation: u8,
    reserved: u8,
    reserved2: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoUringSqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    offset: u64,
    address: u64,
    length: u32,
    rw_flags: u32,
    user_data: u64,
    buffer_index: u16,
    personality: u16,
    splice_fd_in: i32,
    address3: u64,
    padding: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoUringCqe {
    user_data: u64,
    result: i32,
    flags: u32,
}

struct MappedRegion {
    address: *mut libc::c_void,
    length: usize,
}

impl MappedRegion {
    fn new(fd: RawFd, length: usize, offset: libc::off_t) -> io::Result<Self> {
        // SAFETY: the kernel owns the io_uring mapping and validates the offset.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                offset,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { address, length })
    }

    fn pointer<T>(&self, offset: u32) -> io::Result<*mut T> {
        let offset = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "io_uring offset overflow"))?;
        if offset
            .checked_add(size_of::<T>())
            .is_none_or(|end| end > self.length)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "io_uring offset exceeds its mapping",
            ));
        }
        Ok(self.address.cast::<u8>().wrapping_add(offset).cast())
    }
}

impl Drop for MappedRegion {
    fn drop(&mut self) {
        // SAFETY: this object owns the exact successful mmap range.
        unsafe {
            libc::munmap(self.address, self.length);
        }
    }
}

const _: () = assert!(size_of::<IoUringSqe>() == 64);
const _: () = assert!(size_of::<IoUringCqe>() == 16);
const _: () = assert!(size_of::<IoUringRestriction>() == 16);

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

pub(super) fn io_uring_read_one(fd: RawFd, expected: u8) -> io::Result<()> {
    let mut parameters = IoUringParams {
        flags: IORING_SETUP_R_DISABLED | IORING_SETUP_SINGLE_ISSUER,
        ..IoUringParams::default()
    };
    // SAFETY: parameters points to the exact Linux io_uring_params layout.
    let ring_fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 2_u32, &raw mut parameters) };
    if ring_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: io_uring_setup returned a new owned descriptor.
    let ring = unsafe { File::from_raw_fd(ring_fd as RawFd) };
    let restrictions = [
        IoUringRestriction {
            opcode: IORING_RESTRICTION_REGISTER_OP,
            operation: IORING_REGISTER_ENABLE_RINGS as u8,
            reserved: 0,
            reserved2: [0; 3],
        },
        IoUringRestriction {
            opcode: IORING_RESTRICTION_SQE_OP,
            operation: IORING_OP_READ,
            reserved: 0,
            reserved2: [0; 3],
        },
        IoUringRestriction {
            opcode: IORING_RESTRICTION_SQE_OP,
            operation: IORING_OP_WRITE,
            reserved: 0,
            reserved2: [0; 3],
        },
        IoUringRestriction {
            opcode: IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
            operation: IOSQE_ASYNC,
            reserved: 0,
            reserved2: [0; 3],
        },
    ];
    // SAFETY: the restriction array uses the exact Linux UAPI layout.
    syscall_result(unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            ring.as_raw_fd(),
            IORING_REGISTER_RESTRICTIONS,
            restrictions.as_ptr(),
            restrictions.len(),
        )
    })?;
    // SAFETY: ENABLE_RINGS takes no argument array.
    syscall_result(unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            ring.as_raw_fd(),
            IORING_REGISTER_ENABLE_RINGS,
            std::ptr::null::<libc::c_void>(),
            0_u32,
        )
    })?;

    let sq_length = usize::try_from(parameters.sq_off.array)
        .ok()
        .and_then(|offset| {
            usize::try_from(parameters.sq_entries)
                .ok()
                .and_then(|entries| entries.checked_mul(size_of::<u32>()))
                .and_then(|array| offset.checked_add(array))
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid SQ ring size"))?;
    let cq_length = usize::try_from(parameters.cq_off.cqes)
        .ok()
        .and_then(|offset| {
            usize::try_from(parameters.cq_entries)
                .ok()
                .and_then(|entries| entries.checked_mul(size_of::<IoUringCqe>()))
                .and_then(|cqes| offset.checked_add(cqes))
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid CQ ring size"))?;
    let sq_mapping_length = if parameters.features & IORING_FEAT_SINGLE_MMAP != 0 {
        sq_length.max(cq_length)
    } else {
        sq_length
    };
    let sq_mapping = MappedRegion::new(ring.as_raw_fd(), sq_mapping_length, IORING_OFF_SQ_RING)?;
    let cq_mapping = if parameters.features & IORING_FEAT_SINGLE_MMAP != 0 {
        None
    } else {
        Some(MappedRegion::new(
            ring.as_raw_fd(),
            cq_length,
            IORING_OFF_CQ_RING,
        )?)
    };
    let cq_mapping = cq_mapping.as_ref().unwrap_or(&sq_mapping);
    let sqe_length = usize::try_from(parameters.sq_entries)
        .ok()
        .and_then(|entries| entries.checked_mul(size_of::<IoUringSqe>()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid SQE size"))?;
    let sqes = MappedRegion::new(ring.as_raw_fd(), sqe_length, IORING_OFF_SQES)?;

    let sq_head = sq_mapping.pointer::<u32>(parameters.sq_off.head)?;
    let sq_tail = sq_mapping.pointer::<u32>(parameters.sq_off.tail)?;
    let sq_mask = sq_mapping.pointer::<u32>(parameters.sq_off.ring_mask)?;
    let sq_array = sq_mapping.pointer::<u32>(parameters.sq_off.array)?;
    let cq_head = cq_mapping.pointer::<u32>(parameters.cq_off.head)?;
    let cq_tail = cq_mapping.pointer::<u32>(parameters.cq_off.tail)?;
    let cq_mask = cq_mapping.pointer::<u32>(parameters.cq_off.ring_mask)?;
    let cqes = cq_mapping.pointer::<IoUringCqe>(parameters.cq_off.cqes)?;
    let mut byte = 0xa5_u8;
    // SAFETY: all pointers and indices were validated against kernel-provided mappings.
    unsafe {
        let head = sq_head.read_volatile();
        let tail = sq_tail.read_volatile();
        let mask = sq_mask.read_volatile();
        if tail.wrapping_sub(head) >= parameters.sq_entries {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "io_uring SQ is full",
            ));
        }
        let index = tail & mask;
        let entry = sqes.pointer::<IoUringSqe>(
            index
                .checked_mul(u32::try_from(size_of::<IoUringSqe>()).unwrap_or(u32::MAX))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SQE offset overflow"))?,
        )?;
        entry.write(IoUringSqe {
            opcode: IORING_OP_READ,
            flags: IOSQE_ASYNC,
            fd,
            address: (&raw mut byte).addr() as u64,
            length: 1,
            user_data: 0x4d49_5448_5249_4c01,
            ..IoUringSqe::default()
        });
        sq_array
            .add(usize::try_from(index).unwrap_or(usize::MAX))
            .write(index);
        fence(Ordering::Release);
        sq_tail.write_volatile(tail.wrapping_add(1));
    }
    // SAFETY: the ring mappings and SQE stay live until one completion arrives.
    syscall_result(unsafe {
        libc::syscall(
            libc::SYS_io_uring_enter,
            ring.as_raw_fd(),
            1_u32,
            1_u32,
            IORING_ENTER_GETEVENTS,
            std::ptr::null::<libc::sigset_t>(),
            0_usize,
        )
    })?;
    fence(Ordering::Acquire);
    // SAFETY: completion pointers are inside the validated CQ mapping.
    let result = unsafe {
        let head = cq_head.read_volatile();
        let tail = cq_tail.read_volatile();
        if head == tail {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "io_uring returned without the requested completion",
            ));
        }
        let index = head & cq_mask.read_volatile();
        let completion = cqes
            .add(usize::try_from(index).unwrap_or(usize::MAX))
            .read();
        cq_head.write_volatile(head.wrapping_add(1));
        completion.result
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(-result));
    }
    if result != 1 || byte != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "io_uring read did not return the exact expected byte",
        ));
    }
    Ok(())
}

pub(super) fn io_uring_sqpoll_setup() -> io::Result<()> {
    let mut parameters = IoUringParams {
        flags: IORING_SETUP_R_DISABLED | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_SQPOLL,
        ..IoUringParams::default()
    };
    // SAFETY: parameters points to the exact Linux io_uring_params layout.
    let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 2_u32, &raw mut parameters) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful setup result is a new descriptor.
    unsafe {
        libc::close(fd as RawFd);
    }
    Ok(())
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

pub(super) fn open_detached_mount_file(tree: RawFd, path: &Path) -> io::Result<()> {
    let path = path_c_string(path)?;
    // SAFETY: tree and path identify a live detached mount and a bounded relative path.
    let fd = unsafe { libc::openat(tree, path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut byte = [0_u8; 1];
    std::io::Read::read_exact(&mut file, &mut byte)
}

pub(super) fn reconfigure_mount(path: &Path) -> io::Result<()> {
    let path = path_c_string(path)?;
    // SAFETY: path is NUL-terminated and FSPICK_CLOEXEC is a valid fspick flag.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_fspick,
            libc::AT_FDCWD,
            path.as_ptr(),
            FSPICK_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fspick returned a new owned filesystem-context descriptor.
    let context = unsafe { File::from_raw_fd(fd as RawFd) };
    // SAFETY: the filesystem context and static NUL-terminated strings remain valid.
    syscall_result(unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            FSCONFIG_SET_STRING,
            c"size".as_ptr(),
            c"4194304".as_ptr(),
            0,
        )
    })?;
    // SAFETY: CMD_RECONFIGURE consumes the completed options on the live context.
    syscall_result(unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            FSCONFIG_CMD_RECONFIGURE,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<libc::c_void>(),
            0,
        )
    })
}

pub(super) fn set_mount_read_only(path: &Path) -> io::Result<()> {
    set_mount_readonly_state(path, true)
}

pub(super) fn set_mount_read_write(path: &Path) -> io::Result<()> {
    set_mount_readonly_state(path, false)
}

fn set_mount_readonly_state(path: &Path, read_only: bool) -> io::Result<()> {
    let path = path_c_string(path)?;
    let attributes = MountAttr {
        attr_set: if read_only { MOUNT_ATTR_RDONLY } else { 0 },
        attr_clr: if read_only { 0 } else { MOUNT_ATTR_RDONLY },
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
