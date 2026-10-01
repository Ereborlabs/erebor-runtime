import ctypes
import socket
import sys


class UnixPeer:
    def __init__(self, mode):
        self.mode = mode
        self.stream = None
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                                   ctypes.c_ulong, ctypes.c_ulong]

    def name(self, value):
        name = ctypes.create_string_buffer(value.encode("ascii"))
        if self.libc.prctl(15, ctypes.addressof(name), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")

    def prepare(self):
        if self.stream is not None:
            raise RuntimeError("socket is already prepared")
        self.stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.stream.settimeout(5)
        if self.mode == "server":
            self.stream.bind("\0mithril-stream")
            self.stream.listen(1)
        self.name("unix-ready")

    def exchange(self):
        if self.stream is None:
            raise RuntimeError("socket is not prepared")
        if self.mode == "server":
            with self.stream.accept()[0] as stream:
                stream.settimeout(5)
                if stream.recv(1) != b"\x01":
                    raise RuntimeError("incorrect request byte")
                stream.sendall(b"\x02")
        else:
            self.stream.connect("\0mithril-stream")
            self.stream.sendall(b"\x01")
            if self.stream.recv(1) != b"\x02":
                raise RuntimeError("incorrect response byte")
        self.name("unix-ok")

    def run(self):
        try:
            print("native-fixture-ready", flush=True)
            for command in sys.stdin:
                if command == "prepare\n":
                    self.prepare()
                elif command == "exchange\n":
                    self.exchange()
                elif command == "release\n":
                    break
                else:
                    raise RuntimeError(f"unexpected command: {command!r}")
        finally:
            if self.stream is not None:
                self.stream.close()


mode = sys.argv[2]
if mode not in ("client", "server"):
    raise ValueError(f"unexpected mode: {mode}")
UnixPeer(mode).run()
