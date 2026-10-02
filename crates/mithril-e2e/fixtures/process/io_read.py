import contextlib
import ctypes
import mmap
import os
import struct
import sys


if os.uname().machine not in ("aarch64", "x86_64"):
    raise RuntimeError(f"unsupported architecture: {os.uname().machine}")

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]


class SqOffsets(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in
                ("head", "tail", "ring_mask", "ring_entries", "flags", "dropped", "array", "reserved")]
    _fields_ += [("user_addr", ctypes.c_uint64)]


class CqOffsets(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in
                ("head", "tail", "ring_mask", "ring_entries", "overflow", "cqes", "flags", "reserved")]
    _fields_ += [("user_addr", ctypes.c_uint64)]


class Params(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in
                ("sq_entries", "cq_entries", "flags", "sq_thread_cpu", "sq_thread_idle", "features", "wq_fd")]
    _fields_ += [("reserved", ctypes.c_uint32 * 3), ("sq_off", SqOffsets), ("cq_off", CqOffsets)]


class Restriction(ctypes.Structure):
    _fields_ = [("opcode", ctypes.c_uint16), ("operation", ctypes.c_uint8),
                ("reserved", ctypes.c_uint8), ("reserved2", ctypes.c_uint32 * 3)]


class Sqe(ctypes.Structure):
    _fields_ = [
        ("opcode", ctypes.c_uint8), ("flags", ctypes.c_uint8), ("ioprio", ctypes.c_uint16),
        ("fd", ctypes.c_int32), ("offset", ctypes.c_uint64), ("address", ctypes.c_uint64),
        ("length", ctypes.c_uint32), ("rw_flags", ctypes.c_uint32), ("user_data", ctypes.c_uint64),
        ("buffer_index", ctypes.c_uint16), ("personality", ctypes.c_uint16),
        ("splice_fd", ctypes.c_int32), ("address3", ctypes.c_uint64), ("padding", ctypes.c_uint64),
    ]


class Cqe(ctypes.Structure):
    _fields_ = [("user_data", ctypes.c_uint64), ("result", ctypes.c_int32), ("flags", ctypes.c_uint32)]


assert ctypes.sizeof(Params) == 120
assert ctypes.sizeof(Restriction) == 16
assert ctypes.sizeof(Sqe) == 64
assert ctypes.sizeof(Cqe) == 16


class Ring:
    def __init__(self, resources):
        params = Params(flags=(1 << 6) | (1 << 12))
        self.fd = self.call(425, 2, ctypes.byref(params))
        resources.callback(os.close, self.fd)
        self.params = params
        restrictions = (Restriction * 4)(
            Restriction(opcode=0, operation=12),
            Restriction(opcode=1, operation=22),
            Restriction(opcode=1, operation=23),
            Restriction(opcode=2, operation=16),
        )
        self.call(427, self.fd, 11, ctypes.byref(restrictions), len(restrictions))
        self.call(427, self.fd, 12, ctypes.c_void_p(), 0)
        sq_size = params.sq_off.array + params.sq_entries * ctypes.sizeof(ctypes.c_uint32)
        cq_size = params.cq_off.cqes + params.cq_entries * ctypes.sizeof(Cqe)

        def mapping(length, offset):
            return resources.enter_context(mmap.mmap(
                self.fd, length, flags=mmap.MAP_SHARED | mmap.MAP_POPULATE,
                prot=mmap.PROT_READ | mmap.PROT_WRITE, offset=offset,
            ))

        self.sq = mapping(max(sq_size, cq_size) if params.features & 1 else sq_size, 0)
        self.cq = self.sq if params.features & 1 else mapping(cq_size, 0x08000000)
        self.entries = mapping(params.sq_entries * ctypes.sizeof(Sqe), 0x10000000)

    @staticmethod
    def call(number, *args):
        result = libc.syscall(number, *args)
        if result < 0:
            raise OSError(ctypes.get_errno(), f"syscall({number})")
        return result

    @staticmethod
    def word(mapping, offset):
        return struct.unpack_from("=I", mapping, offset)[0]

    def read(self, descriptor, expected):
        sq = self.params.sq_off
        head = self.word(self.sq, sq.head)
        tail = self.word(self.sq, sq.tail)
        if (tail - head) & 0xffffffff >= self.params.sq_entries:
            raise RuntimeError("io_uring SQ is full")
        index = tail & self.word(self.sq, sq.ring_mask)
        byte = ctypes.c_ubyte(0xa5)
        entry = Sqe(opcode=22, flags=16, fd=descriptor, address=ctypes.addressof(byte),
                    length=1, user_data=0x4d49544852494c01)
        start = index * ctypes.sizeof(Sqe)
        self.entries[start:start + ctypes.sizeof(Sqe)] = bytes(entry)
        struct.pack_into("=I", self.sq, sq.array + index * 4, index)
        struct.pack_into("=I", self.sq, sq.tail, (tail + 1) & 0xffffffff)
        self.call(426, self.fd, 1, 1, 1, ctypes.c_void_p(), 0)
        cq = self.params.cq_off
        head = self.word(self.cq, cq.head)
        if head == self.word(self.cq, cq.tail):
            raise RuntimeError("io_uring returned no completion")
        index = head & self.word(self.cq, cq.ring_mask)
        start = cq.cqes + index * ctypes.sizeof(Cqe)
        completion = Cqe.from_buffer_copy(self.cq[start:start + ctypes.sizeof(Cqe)])
        struct.pack_into("=I", self.cq, cq.head, (head + 1) & 0xffffffff)
        if completion.user_data != entry.user_data:
            raise RuntimeError("io_uring returned another request")
        if completion.result < 0:
            raise OSError(-completion.result, "io_uring read")
        if completion.result != 1 or byte.value != expected:
            raise RuntimeError(f"unexpected read: count={completion.result}, byte={byte.value}")


os.makedirs("/tmp", exist_ok=True)
with contextlib.ExitStack() as resources:
    descriptors = []
    for path, content in [("/tmp/mithril-descriptor-secret", b"restricted\n"),
                          ("/tmp/mithril-descriptor-allowed", b"benign\n")]:
        with open(path, "wb") as output:
            output.write(content)
        descriptor = os.open(path, os.O_RDONLY)
        resources.callback(os.close, descriptor)
        descriptors.append((descriptor, content[0]))
    print("native-fixture-ready", flush=True)
    for command in sys.stdin.buffer:
        if command == b"stop\n":
            break
        if command != b"act\n":
            raise RuntimeError(f"unknown command: {command!r}")
        results = []
        for descriptor, expected in descriptors:
            try:
                with contextlib.ExitStack() as ring_files:
                    Ring(ring_files).read(descriptor, expected)
                results.append(0)
            except OSError as failure:
                results.append(failure.errno)
        name = ctypes.create_string_buffer(("uring-" + "-".join(map(str, results))).encode("ascii"))
        if libc.prctl(15, ctypes.addressof(name), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")
