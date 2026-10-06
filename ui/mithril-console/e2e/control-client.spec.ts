import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { access, mkdtemp, readFile, realpath, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { createInterface, type Interface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { expect, test as base, type Locator, type Request } from '@playwright/test';

type Ready = {
  schema_version: number;
  endpoint: string;
  tenant_id: string;
  target: { target: string; cluster: string; container: string; node_ids: string[] };
  ca_file: string;
  certificate_file: string;
  profile_file: string;
  source_file: string;
  sql: string;
  expected_columns: string[];
  expected_rows: string[][];
  oidc_issuer: string;
  callback: string;
};

type Reply = {
  command: string;
  ok: boolean;
  expected_columns?: string[];
  expected_rows?: string[][];
  trace_id?: string;
  source?: string;
  source_sha256?: string;
  cancel_requested?: boolean;
  node_ids?: string[];
  detail?: { targets: Record<string, unknown>[] };
  result?: { complete: boolean; output_incomplete: boolean; cleanup_complete: boolean; missing_targets: number[] };
  sql?: string;
  durable_ack?: boolean;
};

class ControlFixture {
  private readonly lines: Interface;
  private readonly replies: AsyncIterableIterator<string>;
  private readonly exited: Promise<void>;
  private ended = false;
  private code: number | null = null;
  private stderr = '';
  private readyValue?: Ready;
  pin = '';

  private constructor(readonly directory: string, private readonly child: ChildProcessWithoutNullStreams) {
    this.lines = createInterface({ input: child.stdout });
    this.replies = this.lines[Symbol.asyncIterator]();
    child.stderr.on('data', (bytes: Buffer) => { this.stderr = (this.stderr + bytes.toString()).slice(-16384); });
    child.stdin.on('error', (error) => { this.stderr = (this.stderr + error.message).slice(-16384); });
    this.exited = new Promise((done) => {
      child.once('error', (error) => { this.stderr += error.message; this.ended = true; done(); });
      child.once('exit', (code) => { this.code = code; this.ended = true; done(); });
    });
  }

  get ready(): Ready {
    if (!this.readyValue) throw new Error('The Control fixture is not ready.');
    return this.readyValue;
  }

  static async start(): Promise<ControlFixture> {
    const binary = process.env.ARAPHOR_CLIENT_FIXTURE;
    if (!binary || !isAbsolute(binary)) throw new Error('Set ARAPHOR_CLIENT_FIXTURE to the absolute built mithril_observability_test path.');
    await access(binary, constants.X_OK);
    const assets = resolve(dirname(fileURLToPath(import.meta.url)), '../dist');
    await access(join(assets, 'index.html'));
    const directory = await mkdtemp(join(tmpdir(), 'araphor-browser-'));
    const child = spawn(binary, ['--case', 'query-trace-client', '--browser-fixture',
      '--output-directory', directory, '--assets', assets], { stdio: 'pipe' });
    const owner = new ControlFixture(directory, child);
    try {
      const deadline = Date.now() + 30_000;
      while (Date.now() < deadline) {
        if (owner.ended) throw new Error(`The Control fixture exited before readiness: ${owner.stderr}`);
        try {
          const path = join(directory, 'ready.json');
          if ((await stat(path)).size > 65536) throw new Error('The Control ready record exceeds its limit.');
          owner.readyValue = JSON.parse(await readFile(path, 'utf8')) as Ready;
          break;
        } catch (error) {
          if (!(error instanceof SyntaxError) && !(error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT')) throw error;
          await delay(50);
        }
      }
      const ready = owner.ready;
      const endpoint = new URL(ready.endpoint);
      const issuer = new URL(ready.oidc_issuer);
      if (ready.schema_version !== 1 || endpoint.protocol !== 'https:' || endpoint.hostname !== 'localhost'
        || !endpoint.port || ready.endpoint !== endpoint.origin || issuer.protocol !== 'https:'
        || issuer.hostname !== 'localhost' || ready.callback !== `${endpoint.origin}/oidc/session`
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(ready.tenant_id)) {
        throw new Error('The Control ready record has an invalid origin or identity.');
      }
      for (const path of [ready.ca_file, ready.certificate_file, ready.profile_file, ready.source_file]) {
        if (!isAbsolute(path) || path.length > 4096 || !(await realpath(path)).startsWith(`${directory}${sep}`)
          || !(await stat(path)).isFile() || (await stat(path)).size > 65536) {
          throw new Error('A Control fixture file is outside its owned directory or limit.');
        }
      }
      const certificate = new X509Certificate(await readFile(ready.certificate_file));
      if (!certificate.checkHost('localhost') || Date.parse(certificate.validFrom) > Date.now()
        || Date.parse(certificate.validTo) <= Date.now()) throw new Error('The fixture certificate is not currently valid for localhost.');
      owner.pin = createHash('sha256').update(certificate.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
      return owner;
    } catch (error) {
      await owner.close();
      throw error;
    }
  }

  async command(command: string, traceId?: string): Promise<Reply> {
    if (this.ended) throw new Error(`The Control fixture exited: ${this.stderr}`);
    this.child.stdin.write(`${JSON.stringify({ command, ...(traceId ? { trace_id: traceId } : {}) })}\n`);
    const stop = new AbortController();
    try {
      const next = await Promise.race([
        this.replies.next(),
        delay(15_000, undefined, { signal: stop.signal }).then(() => { throw new Error(`The ${command} fixture command timed out.`); }),
      ]);
      if (next.done) throw new Error(`The ${command} fixture reply is absent; see ${this.directory}. ${this.stderr}`);
      if (next.value.length > 65536) throw new Error('The Control fixture reply exceeds its limit.');
      const reply = JSON.parse(next.value) as Reply;
      if (reply.command !== command || reply.ok !== true) throw new Error(`The ${command} fixture command failed; see ${this.directory}. ${this.stderr}`);
      return reply;
    } finally { stop.abort(); }
  }

  async close(): Promise<void> {
    if (!this.ended) {
      this.child.stdin.end(`${JSON.stringify({ command: 'shutdown' })}\n`);
      await Promise.race([this.exited, delay(5000)]);
      if (!this.ended) {
        this.child.kill('SIGTERM');
        await Promise.race([this.exited, delay(5000)]);
      }
      if (!this.ended) { this.child.kill('SIGKILL'); await this.exited; }
    }
    this.lines.close();
    if (this.code !== 0) throw new Error(`The owned Control fixture did not exit cleanly (${this.code}): ${this.stderr}`);
  }

  static async rows(table: Locator, columns: string[] | undefined, rows: string[][] | undefined): Promise<void> {
    expect(columns).toBeDefined(); expect(rows).toBeDefined();
    await expect(table.locator('th')).toHaveText(columns!);
    await expect.poll(async () => Promise.all((await table.locator('tbody tr').all()).map((row) => row.locator('td').allTextContents()))).toEqual(rows);
  }

  static async targets(scope: Locator, state: Reply): Promise<void> {
    expect(state.detail?.targets).toHaveLength(state.node_ids!.length);
    for (const [index, target] of state.detail!.targets.entries()) {
      const value = JSON.parse((await scope.locator('pre').nth(index + 2).textContent())!);
      expect(value).toEqual({
        index: target.index,
        nodeId: target.node_id,
        nodeBootId: Buffer.from(target.node_boot_id as number[]).toString('base64'),
        clusterUid: target.cluster_uid,
        namespaceUid: target.namespace_uid,
        podUid: target.pod_uid,
        containerId: target.container_id,
        containerName: target.container_name,
        bindingId: Buffer.from(target.binding_id as number[]).toString('base64'),
        cgroupId: String(target.cgroup_id),
        containerGeneration: String(target.container_generation),
        labelEpoch: String(target.label_epoch),
        namespaceName: target.namespace_name,
        podName: target.pod_name,
      });
    }
  }
}

const test = base.extend<{}, { control: ControlFixture }>({
  control: [async ({}, use) => {
    const control = await ControlFixture.start();
    try { await use(control); } finally { await control.close(); }
  }, { scope: 'worker', timeout: 45_000 }],
  browser: [async ({ control, playwright, launchOptions, headless }, use) => {
    // This process trusts only the disposable fixture's public key.
    const browser = await playwright.chromium.launch({ ...launchOptions, headless,
      args: [...(launchOptions.args ?? []), `--ignore-certificate-errors-spki-list=${control.pin}`] });
    try { await use(browser); } finally { await browser.close(); }
  }, { scope: 'worker' }],
});

test('Control serves authenticated SQL follow and trace through the built browser client', async ({ page, context, control }, info) => {
  const ready = control.ready;
  const ended = new Set<Request>();
  const requests: Request[] = [];
  const errors: string[] = [];
  const csp: string[] = [];
  const service = '/erebor.mithril.control.v1.AraphorClientService/';
  page.on('request', (request) => { if (request.url().includes(service)) requests.push(request); });
  page.on('requestfinished', (request) => ended.add(request));
  page.on('requestfailed', (request) => ended.add(request));
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => { if (/content security policy|refused to (?:execute|apply)/i.test(message.text())) csp.push(message.text()); });
  await info.attach('fixture-ready', { path: join(control.directory, 'ready.json'), contentType: 'application/json' });
  await info.attach('fixture-trust', { body: JSON.stringify({ certificate_file: ready.certificate_file,
    spki: control.pin, scope: 'Only the owned Chromium process trusts this disposable fixture key.' }), contentType: 'application/json' });

  const denied = await page.goto(`${ready.endpoint}/login`);
  expect(denied?.status()).toBe(403);
  expect((await context.cookies()).some((cookie) => cookie.name === 'araphor-session')).toBe(false);
  await control.command('grant');
  const asset = await page.goto(`${ready.endpoint}/login`);
  await expect(page).toHaveURL(`${ready.endpoint}/`);
  const cookies = await context.cookies();
  expect(cookies.some((cookie) => cookie.name === 'araphor-session' && cookie.secure && cookie.httpOnly)).toBe(true);
  expect(cookies.some((cookie) => cookie.name === 'araphor-csrf' && cookie.secure && !cookie.httpOnly)).toBe(true);
  await page.goto(`${ready.endpoint}/#/findings`);
  const policy = asset?.headers()['content-security-policy'] ?? '';
  expect(policy).toContain("script-src 'self'");
  expect(policy).not.toMatch(/unsafe-inline|unsafe-eval/);
  const panel = page.getByRole('region', { name: 'Investigate with SQL and Trace' });
  await panel.getByLabel('Tenant UUID').fill(ready.tenant_id);
  const query = panel.getByRole('region', { name: 'Retained SQL' });
  const trace = panel.getByRole('region', { name: 'Bounded trace' });
  const timed = await control.command('window');
  expect(timed.durable_ack).toBe(true);
  expect(timed.sql).toBeTruthy();
  await query.getByRole('textbox', { name: 'SQL', exact: true }).fill(timed.sql!);
  await page.keyboard.press('Tab');
  await expect(query.getByLabel('Parameters (JSON array)')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(query.getByLabel('Follow committed changes')).toBeFocused();
  await page.keyboard.press('Space');
  await expect(query.getByLabel('Follow committed changes')).toBeChecked();
  await page.keyboard.press('Tab');
  await expect(query.getByRole('button', { name: 'Run SQL', exact: true })).toBeFocused();
  const timing = page.waitForRequest((value) => value.url().endsWith(`${service}Query`));
  await page.keyboard.press('Enter');
  const timedRequest = await timing;
  const table = query.getByRole('table');
  await expect(table.locator('th')).toHaveText(['count']);
  await expect(table.locator('tbody td').first()).toHaveText('1');
  const initial = Date.now();
  const revision = (await query.getByText(/^Operation: Complete replacement\./).textContent())!;
  expect(ended.has(timedRequest)).toBe(false);
  await expect(table.locator('tbody td').first()).toHaveText('0', { timeout: 15_000 });
  const expired = Date.now();
  expect(expired).toBeGreaterThan(initial);
  await expect(query.getByText(/^Operation: Complete replacement\./)).toHaveText(revision);
  expect(ended.has(timedRequest)).toBe(false);
  await info.attach('timer-only-window', { body: JSON.stringify({ count_initial: 1, count_expired: 0, observed_initial_ms: initial, observed_expired_ms: expired, revision, durable_ack: timed.durable_ack }), contentType: 'application/json' });
  await page.keyboard.press('Tab');
  await expect(query.getByRole('button', { name: 'Stop SQL read' })).toBeFocused();
  await page.keyboard.press('Space');
  await expect(query.getByRole('status')).toHaveText('Query read stopped. No capture was cancelled.');
  await expect.poll(() => ended.has(timedRequest)).toBe(true);

  await panel.getByLabel('Target', { exact: true }).fill(ready.target.target);
  await panel.getByLabel('Cluster', { exact: true }).fill(ready.target.cluster);
  await panel.getByLabel('Container', { exact: true }).fill(ready.target.container);
  await query.getByRole('textbox', { name: 'SQL', exact: true }).fill(ready.sql);
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await expect(query.getByLabel('Follow committed changes')).toBeFocused();
  await page.keyboard.press('Space');
  await expect(query.getByLabel('Follow committed changes')).not.toBeChecked();
  await page.keyboard.press('Tab');
  await expect(query.getByRole('button', { name: 'Run SQL', exact: true })).toBeFocused();
  await page.keyboard.press('Enter');
  await ControlFixture.rows(query.getByRole('table'), ready.expected_columns, ready.expected_rows);
  await expect(query.getByRole('status')).toHaveText('Read ended with an explicit final record.');

  const source = await readFile(ready.source_file, 'utf8');
  await trace.getByRole('combobox', { name: 'Source', exact: true }).selectOption('');
  await trace.getByRole('textbox', { name: 'Script', exact: true }).fill(source);
  await trace.getByLabel('Collection seconds').fill('120');
  await page.keyboard.press('Tab');
  await expect(trace.getByLabel('Finding reference (optional)')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(trace.getByRole('button', { name: 'Run trace', exact: true })).toBeFocused();
  await page.keyboard.press('Space');
  await expect(trace.getByText('Accepted source and scope', { exact: true })).toBeVisible();
  const id = await trace.getByLabel('Trace UUID', { exact: true }).inputValue();
  const state = await control.command('trace-state', id);
  expect(state.trace_id).toBe(id);
  expect(state.source).toBe(source);
  expect(state.source_sha256).toMatch(/^[0-9a-f]{64}$/);
  expect(state.node_ids?.length).toBeGreaterThan(0);
  expect(state.cancel_requested).toBe(false);
  await expect(trace.locator('code').filter({ hasText: state.source_sha256! })).toBeVisible();
  const scope = trace.locator('details').filter({ has: page.getByText('Accepted source and scope', { exact: true }) });
  await expect(scope.locator('pre').first()).toHaveText(source);
  expect(JSON.parse((await scope.locator('pre').nth(1).textContent())!)).toEqual({
    target: ready.target.target, cluster: ready.target.cluster,
    container: ready.target.container, nodeIdsList: ready.target.node_ids,
  });
  for (const node of state.node_ids!) await expect(scope).toContainText(node);
  await ControlFixture.targets(scope, state);
  await trace.getByRole('textbox', { name: 'Script', exact: true }).fill('BEGIN { printf("edited-after-submit\\n"); }');
  expect((await control.command('trace-state', id)).source).toBe(source);
  await expect(scope.locator('pre').first()).toHaveText(source);

  await query.getByLabel('Follow committed changes').check();
  const follow = page.waitForRequest((request) => request.url().endsWith(`${service}Query`));
  await query.getByRole('button', { name: 'Run SQL', exact: true }).click();
  const request = await follow;
  await expect(query.getByText('Complete query checkpoint', { exact: true })).toBeVisible();
  expect(request.headers()['content-type']).toMatch(/^application\/grpc-web-text/);
  expect(request.headers()['x-araphor-tenant']).toBe(ready.tenant_id);
  expect(ended.has(request)).toBe(false);
  await expect(query).toContainText('Complete replacement');
  const first = await control.command('commit');
  await ControlFixture.rows(query.getByRole('table'), first.expected_columns, first.expected_rows);
  await expect(trace.locator('.live-output')).toContainText('observed <script>text</script>');
  await expect(trace.locator('.live-output script')).toHaveCount(0);
  expect(ended.has(request)).toBe(false);

  const resumed = page.waitForRequest((value) => value.url().endsWith(`${service}Query`));
  const [, , retry] = await Promise.all([
    control.command('reconnect'),
    expect(query.getByRole('status')).toContainText('Disconnected. Resume'),
    resumed,
  ]);
  expect(ended.has(request)).toBe(true);
  await expect(query.getByRole('status')).toHaveText('Following committed changes.');
  await ControlFixture.rows(query.getByRole('table'), first.expected_columns, first.expected_rows);
  expect(retry.headers()['x-araphor-tenant']).toBe(ready.tenant_id);
  expect(ended.has(retry)).toBe(false);

  await trace.getByLabel('Finding reference (optional)').focus();
  await page.keyboard.press('Tab');
  await expect(trace.getByRole('button', { name: 'Stop capture', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(trace.getByRole('button', { name: 'Stop viewer only' })).toBeFocused();
  await page.keyboard.press('Space');
  const output = await trace.locator('.live-output').textContent();
  const second = await control.command('commit');
  await ControlFixture.rows(query.getByRole('table'), second.expected_columns, second.expected_rows);
  await expect(trace.locator('.live-output')).toHaveText(output!);
  expect((await control.command('trace-state', id)).cancel_requested).toBe(false);
  expect(requests.some((value) => value.url().endsWith(`${service}CancelTrace`))).toBe(false);
  await page.getByRole('navigation', { name: 'Console sections' }).getByRole('button', { name: 'Operations', exact: true }).click();
  await expect(panel).toHaveCount(0);
  await control.command('commit');
  await page.getByRole('navigation', { name: 'Console sections' }).getByRole('button', { name: /^Findings/ }).click();
  await expect(panel.getByRole('table')).toHaveCount(0);
  await expect(panel.getByText('Accepted source and scope', { exact: true })).toHaveCount(0);
  expect((await control.command('trace-state', id)).cancel_requested).toBe(false);
  await panel.getByLabel('Tenant UUID').fill(ready.tenant_id);
  await panel.getByLabel('Target', { exact: true }).fill(ready.target.target);
  await panel.getByLabel('Cluster', { exact: true }).fill(ready.target.cluster);
  await panel.getByLabel('Container', { exact: true }).fill(ready.target.container);
  await trace.getByText('Resume a read-only viewer', { exact: true }).click();
  await trace.getByLabel('Trace UUID', { exact: true }).fill(id);
  await trace.getByRole('button', { name: 'Resume viewer', exact: true }).click();
  await expect(trace.locator('.live-output')).not.toHaveText('No committed output received.');
  expect((await control.command('trace-state', id)).cancel_requested).toBe(false);
  const cancel = page.waitForRequest((value) => value.url().endsWith(`${service}CancelTrace`));
  await trace.getByLabel('Finding reference (optional)').focus();
  await page.keyboard.press('Tab');
  await expect(trace.getByRole('button', { name: 'Stop capture', exact: true })).toBeFocused();
  await page.keyboard.press('Enter');
  const mutation = await cancel;
  expect(Boolean(mutation.headers()['x-araphor-csrf'])).toBe(true);
  await expect.poll(async () => (await control.command('trace-state', id)).cancel_requested).toBe(true);
  await expect.poll(async () => (await control.command('trace-state', id)).result).toBeTruthy();
  const result = (await control.command('trace-state', id)).result!;
  await expect(trace).toContainText(`Collection ${result.complete ? 'complete' : 'partial'}; output ${result.output_incomplete ? 'incomplete' : 'complete'}; cleanup ${result.cleanup_complete ? 'verified' : 'unverified'}.`);
  await expect(trace).toContainText(`Missing targets: ${result.missing_targets.join(', ') || 'none'}.`);
  await expect(trace.getByRole('status')).toHaveText('Read ended with an explicit final record.');

  await query.getByRole('textbox', { name: 'SQL', exact: true }).fill("SELECT CAST('araphor-invalid-number' AS BIGINT) AS value FROM catalog LIMIT 1");
  await query.getByRole('button', { name: 'Run SQL', exact: true }).click();
  await expect(query.getByRole('status')).toContainText('EvaluationFailed');
  await query.getByRole('textbox', { name: 'SQL', exact: true }).fill(ready.sql);
  await query.getByLabel('Follow committed changes').check();
  await query.getByRole('button', { name: 'Run SQL', exact: true }).click();
  await expect(query.getByText('Complete query checkpoint', { exact: true })).toBeVisible();
  await control.command('revoke');
  await expect(query.getByRole('status')).toContainText('Access ended');
  expect(errors).toEqual([]);
  expect(csp).toEqual([]);
});
