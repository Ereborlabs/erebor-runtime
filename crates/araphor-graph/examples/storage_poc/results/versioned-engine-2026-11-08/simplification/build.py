import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import time

root = pathlib.Path.cwd()
out = root / 'output/storage-engine-simplify-20261109'
source = {tree: subprocess.check_output(['git', '-C', tree, 'rev-parse', 'HEAD'], text=True).strip()
          for tree in ['fjall', 'lsm-tree']}
for tree in source:
    assert not subprocess.check_output(['git', '-C', tree, 'status', '--porcelain'], text=True)
label = 'fjall-' + source['fjall'][:12]
command = ['cargo', 'build', '--release', '--manifest-path',
           'crates/araphor-graph/examples/storage_poc/neon-bench/Cargo.toml',
           '--config', '/tmp/araphor-storage-release-override.toml', '--offline']
variables = dict(CARGO_TARGET_DIR=str(root / 'target'), CARGO_INCREMENTAL='0',
                 CARGO_BUILD_JOBS='4', POC_SOURCE_REVISION=label)
record = dict(command=command, environment=variables, source=source, started=time.time())
with (out / 'build.log').open('x') as log:
    result = subprocess.run(command, env=dict(os.environ, **variables),
                            stdout=log, stderr=subprocess.STDOUT)
record.update(exit_code=result.returncode, finished=time.time())
(out / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
assert result.returncode == 0
binary = out / 'versioned-simplified'
assert not binary.exists()
shutil.copy2(root / 'target/release/storage_poc', binary)
before = json.loads((out / 'before.json').read_text())
assert hashlib.sha256(pathlib.Path(before['binary']).read_bytes()).hexdigest() == before['binary_sha256']
manifest = dict(source=source, source_label=label, binary=str(binary.relative_to(root)),
                binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                binary_bytes=binary.stat().st_size, before=before,
                build_command=command, build_environment=variables)
(out / 'binary.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2), flush=True)
