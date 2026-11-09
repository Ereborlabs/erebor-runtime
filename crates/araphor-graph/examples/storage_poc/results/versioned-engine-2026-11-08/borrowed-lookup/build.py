import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import time

root = pathlib.Path.cwd()
out = pathlib.Path('output/storage-engine-baseline-20261108')
label = 'b197824fa+borrow-key'
command = ['cargo', 'build', '--release', '--manifest-path',
           'crates/araphor-graph/examples/storage_poc/neon-bench/Cargo.toml',
           '--config', '/tmp/araphor-storage-release-override.toml', '--offline']
variables = dict(CARGO_TARGET_DIR=str(root / 'target'), CARGO_INCREMENTAL='0',
                 CARGO_BUILD_JOBS='4', POC_SOURCE_REVISION=label)
record = dict(command=command, environment=variables, started_unix_s=time.time())
with (out / 'borrow-key-build.log').open('w') as log:
    process = subprocess.run(command, env=dict(os.environ, **variables),
                             stdout=log, stderr=subprocess.STDOUT)
record.update(exit_code=process.returncode, finished_unix_s=time.time())
(out / 'borrow-key-build.json').write_text(json.dumps(record, indent=2) + '\n')
print('build', process.returncode, flush=True)
assert process.returncode == 0
binary = out / 'versioned-borrow-keys'
assert not binary.exists()
shutil.copy2(root / 'target/release/storage_poc', binary)
patch = subprocess.check_output(['git', '-C', 'lsm-tree', 'diff', '--binary'])
(out / 'borrow-key.patch').write_bytes(patch)
before = out / 'versioned-consume-staging'
before_hash = hashlib.sha256(before.read_bytes()).hexdigest()
assert before_hash == 'b37a851d1e14bd94e86e2333dd88e39feeb340aa8ded5eacb1551c4a0e9d00f9'
manifest = dict(
    root_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    fjall_commit=subprocess.check_output(['git', '-C', 'fjall', 'rev-parse', 'HEAD'], text=True).strip(),
    lsm_tree_base=subprocess.check_output(['git', '-C', 'lsm-tree', 'rev-parse', 'HEAD'], text=True).strip(),
    lsm_tree_patch='borrow-key.patch', patch_sha256=hashlib.sha256(patch).hexdigest(),
    binary=str(binary), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
    before_binary=str(before), before_binary_sha256=before_hash, source_label=label,
    build_command=command, build_environment=variables,
    before_bytes=before.stat().st_size, after_bytes=binary.stat().st_size)
(out / 'borrow-key-binary.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2), flush=True)
