import errno
import socket
import sys


def tcp(address):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        connection.connect(address)


def require_denied(name, action):
    try:
        action()
    except OSError as failure:
        if failure.errno == errno.EACCES:
            return
        raise RuntimeError(f"{name} failed with errno {failure.errno}") from failure
    raise RuntimeError(f"{name} was allowed")


print("native-fixture-ready", flush=True)
sys.stdin.buffer.readline()
for name, action in [
    ("TCP DNS", lambda: tcp(("127.0.0.1", 53))),
    ("TCP DoT", lambda: tcp(("127.0.0.53", 853))),
    ("TCP DoH", lambda: tcp(("127.0.0.53", 443))),
]:
    require_denied(name, action)
