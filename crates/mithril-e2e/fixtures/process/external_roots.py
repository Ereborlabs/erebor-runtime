import shutil
import subprocess
import sys
from pathlib import Path


work = Path(sys.argv[1])
if len(sys.argv) == 2:
    exe = Path(sys.executable).resolve()
    target = work / "bin/python-external"
    (work / "bin").mkdir(exist_ok=True)
    shutil.copy2(exe, target)
    report = subprocess.run(
        ["/lib64/ld-linux-x86-64.so.2", "--list", exe],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    lib = work / "lib"
    lib.mkdir()
    for line in report.splitlines():
        parts = line.split(" => ", 1)
        if len(parts) == 2:
            source = Path(parts[1].split()[0])
            if source.is_file():
                shutil.copy2(source, lib / source.name)
    subprocess.run([target, "-c", ""], check=True)
print("native-fixture-ready", flush=True)
if sys.stdin.readline() not in ("stop\n", ""):
    raise RuntimeError("expected stop")
