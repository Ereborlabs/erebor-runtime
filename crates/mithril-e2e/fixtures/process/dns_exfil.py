import errno
import socket
import sys


def tcp(address):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        connection.connect(address)


def udp(address, connected):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        if connected:
            connection.connect(address)
            connection.send(b"dns")
        else:
            connection.sendto(b"dns", address)


def require_denied(name, action):
    try:
        action()
    except OSError as failure:
        if failure.errno == errno.EACCES:
            return
        raise RuntimeError(f"{name} failed with errno {failure.errno}") from failure
    raise RuntimeError(f"{name} was allowed")


print("native-fixture-ready", flush=True)
mode = sys.stdin.buffer.readline().strip()
actions = {
    b"run": [
        ("TCP DNS", lambda: tcp(("127.0.0.1", 53))),
        ("TCP DoT", lambda: tcp(("127.0.0.53", 853))),
        ("TCP DoH", lambda: tcp(("127.0.0.53", 443))),
    ],
    b"udp": [
        ("UDP DNS", lambda: udp(("127.0.0.1", 53), False)),
        ("UDP external DNS", lambda: udp(("8.8.8.8", 53), True)),
        ("UDP alternate resolver", lambda: udp(("127.0.0.53", 5353), False)),
    ],
}
for name, action in actions[mode]:
    require_denied(name, action)
