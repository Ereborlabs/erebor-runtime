import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile, chmod } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cache = resolve(root, 'node_modules/.cache/araphor');
const plugin = resolve(cache, 'protoc-gen-grpc-web');
const digest = '10ff6c6e58018ff9e684cff1d9c008b8cc79d915c4f8be4fd47791333e1be299';
if (process.platform !== 'linux' || process.arch !== 'x64') {
  throw new Error('The pinned browser generator requires Linux x86_64.');
}
await mkdir(cache, { recursive: true });
let binary;
try {
  binary = await readFile(plugin);
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
  const response = await fetch('https://github.com/grpc/grpc-web/releases/download/2.0.2/protoc-gen-grpc-web-2.0.2-linux-x86_64');
  if (!response.ok) throw new Error(`Generator download failed: ${response.status}`);
  binary = Buffer.from(await response.arrayBuffer());
}
if (createHash('sha256').update(binary).digest('hex') !== digest) {
  throw new Error('The browser generator does not match its pinned release.');
}
await writeFile(plugin, binary, { mode: 0o755 });
await chmod(plugin, 0o755);
const output = resolve(root, 'src/generated');
await mkdir(output, { recursive: true });
execFileSync('protoc', [
  '-I', resolve(root, '../../crates/mithril-control/proto/erebor/mithril/control/v1'),
  `--plugin=protoc-gen-js=${resolve(root, 'node_modules/.bin/protoc-gen-js')}`,
  `--plugin=protoc-gen-grpc-web=${plugin}`,
  `--js_out=import_style=commonjs,binary:${output}`,
  `--grpc-web_out=import_style=typescript,mode=grpcwebtext:${output}`,
  'client.proto',
], { stdio: 'inherit' });
