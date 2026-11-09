import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import time

root = pathlib.Path.cwd()
out = pathlib.Path('output/storage-engine-baseline-20261108')
label = '34cfabd63+cursor-buffer'
command = ['cargo', 'build', '--release', '--manifest-path',
           'crates/araphor-graph/examples/storage_poc/neon-bench/Cargo.toml',
           '--config', '/tmp/araphor-storage-release-override.toml', '--offline']
variables = dict(CARGO_TARGET_DIR=str(root / 'target'), CARGO_INCREMENTAL='0',
                 CARGO_BUILD_JOBS='4', POC_SOURCE_REVISION=label)
record = dict(command=command, environment=variables, started_unix_s=time.time())
with (out / 'cursor-buffer-build.log').open('w') as log:
    process = subprocess.run(command, env=dict(os.environ, **variables),
                             stdout=log, stderr=subprocess.STDOUT)
record.update(exit_code=process.returncode, finished_unix_s=time.time())
(out / 'cursor-buffer-build.json').write_text(json.dumps(record, indent=2) + '\n')
print('build', process.returncode, flush=True)
assert process.returncode == 0
binary = out / 'versioned-cursor-buffer'
assert not binary.exists()
shutil.copy2(root / 'target/release/storage_poc', binary)
patch = subprocess.check_output(['git', '-C', 'fjall', 'diff', '--binary'])
(out / 'cursor-buffer.patch').write_bytes(patch)
before = out / 'versioned-header-group'
before_hash = hashlib.sha256(before.read_bytes()).hexdigest()
assert before_hash == '514e2ea0e7d7335ce824832f49fb6277ecab81bfece1af8236be0bd650f96533'
manifest = dict(
    root_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    fjall_base=subprocess.check_output(['git', '-C', 'fjall', 'rev-parse', 'HEAD'], text=True).strip(),
    lsm_tree_commit=subprocess.check_output(['git', '-C', 'lsm-tree', 'rev-parse', 'HEAD'], text=True).strip(),
    fjall_patch='cursor-buffer.patch', patch_sha256=hashlib.sha256(patch).hexdigest(),
    binary=str(binary), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
    before_binary=str(before), before_binary_sha256=before_hash, source_label=label,
    build_command=command, build_environment=variables,
    before_bytes=before.stat().st_size, after_bytes=binary.stat().st_size)
(out / 'cursor-buffer-binary.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2), flush=True)
