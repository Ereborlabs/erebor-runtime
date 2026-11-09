import json
import pathlib
import queue
import random
import subprocess
import threading
import time

root = pathlib.Path('/home/navid/go/src/github.com/Ereborlabs/erebor-runtime')
out = root / 'output/storage-engine-baseline-20261108'
binary = out / 'versioned-direct-scan'
report = out / 'gdb-combined-report.json'
log = (out / 'gdb-combined-stacks.jsonl').open('w')
started = time.monotonic()
process = subprocess.Popen(
    ['gdb', '-nx', '-nh', '--quiet', '--interpreter=mi2', '--args',
     str(binary), str(report), 'combined'],
    cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT, text=True, bufsize=1)
lines = queue.Queue()
state = {'stopped': False, 'exited': False}
token = 0

def record(kind, value):
    log.write(json.dumps({'seconds': time.monotonic() - started,
                          'kind': kind, 'value': value}) + '\n')
    log.flush()

def reader():
    for line in process.stdout:
        lines.put(line.rstrip('\n'))
    lines.put(None)

threading.Thread(target=reader, daemon=True).start()

def receive(timeout=10):
    line = lines.get(timeout=timeout)
    if line is None:
        raise EOFError('GDB closed its output')
    record('gdb', line)
    if line.startswith('*stopped'):
        state['stopped'] = True
        if 'reason="exited' in line:
            state['exited'] = True
    if line.startswith('=thread-group-exited'):
        state['exited'] = True
    return line

def command(value):
    global token
    token += 1
    prefix = str(token)
    record('command', value)
    process.stdin.write(prefix + value + '\n')
    process.stdin.flush()
    while True:
        line = receive()
        if line.startswith(prefix + '^'):
            if line.startswith(prefix + '^error'):
                raise RuntimeError(line)
            return line

record('configuration', {'binary': str(binary), 'report': str(report),
       'mode': 'combined', 'seed': 1937, 'interval_seconds': [0.001, 0.003],
       'interpretation': 'perturbed wall-position stacks; excluded from acceptance'})
try:
    for option in ['mi-async on', 'pagination off', 'confirm off',
                   'disable-randomization off', 'debuginfod enabled off',
                   'auto-load python-scripts off']:
        command('-gdb-set ' + option)
    command('-exec-run')
    rng = random.Random(1937)
    samples = 0
    while not state['exited']:
        deadline = time.monotonic() + rng.uniform(0.001, 0.003)
        while time.monotonic() < deadline and not state['exited']:
            try:
                receive(max(0.001, deadline - time.monotonic()))
            except queue.Empty:
                break
        if state['exited']:
            break
        if time.monotonic() - started > 60:
            raise TimeoutError('Diagnostic wall limit reached')
        state['stopped'] = False
        command('-exec-interrupt --all')
        while not state['stopped'] and not state['exited']:
            receive()
        if state['exited']:
            break
        record('sample', samples)
        command('-thread-info')
        command('-stack-list-frames --thread 1 0 40')
        if samples == 0:
            command('-interpreter-exec console "thread apply all bt 6"')
        samples += 1
        state['stopped'] = False
        command('-exec-continue --all')
    record('completed', {'samples': samples, 'report_exists': report.exists()})
except Exception as error:
    record('error', repr(error))
    print(type(error).__name__ + ': ' + str(error), flush=True)
    raise
finally:
    if process.poll() is None:
        try:
            command('-gdb-exit')
            process.wait(timeout=5)
        except Exception:
            process.kill()
            process.wait()
    log.close()
print('GDB diagnostic complete: ' + str(samples) + ' samples', flush=True)
