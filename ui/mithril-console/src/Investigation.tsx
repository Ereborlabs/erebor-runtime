import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Client, wire } from './client';
import { QueryRead, TraceRead } from './clientState';
import './investigation.css';

export function Investigation() {
  const [tenant, setTenant] = useState('');
  const [target, setTarget] = useState('');
  const [cluster, setCluster] = useState('');
  const [container, setContainer] = useState('');
  const [sql, setSql] = useState('SELECT * FROM catalog');
  const [parameters, setParameters] = useState('[]');
  const [follow, setFollow] = useState(false);
  const [recipe, setRecipe] = useState('failed-opens@1');
  const [source, setSource] = useState('');
  const [seconds, setSeconds] = useState(10);
  const [finding, setFinding] = useState('');
  const [traceId, setTraceId] = useState('');
  const [saved, setSaved] = useState('');
  const [query, setQuery] = useState<QueryRead>();
  const [trace, setTrace] = useState<TraceRead>();
  const [receipt, setReceipt] = useState<wire.TraceReceipt>();
  const [draft, setDraft] = useState<wire.SubmitTraceRequest>();
  const [queryState, setQueryState] = useState('No live query.');
  const [traceState, setTraceState] = useState('No live capture.');
  const [busy, setBusy] = useState(false);
  const [, refresh] = useState(0);
  const queryStop = useRef<AbortController | undefined>(undefined);
  const traceStop = useRef<AbortController | undefined>(undefined);
  const requestStop = useRef<AbortController | undefined>(undefined);

  useEffect(() => () => {
    queryStop.current?.abort(); traceStop.current?.abort(); requestStop.current?.abort();
  }, []);

  function clearQuery() {
    queryStop.current?.abort(); setQuery(undefined);
    setQueryState('The edited input has no resume bookmark.');
  }

  function changeScope(set: (value: string) => void, value: string) {
    clearQuery(); traceStop.current?.abort(); requestStop.current?.abort();
    setTrace(undefined); setReceipt(undefined); setDraft(undefined); setBusy(false);
    setTraceId(''); setSaved(''); setTraceState('Scope changed. Previous capture execution was not cancelled.');
    set(value);
  }

  function selection() {
    return new wire.InputSelection().setTarget(target.trim()).setCluster(cluster.trim()).setContainer(container.trim());
  }

  function runQuery(event: FormEvent) {
    event.preventDefault(); queryStop.current?.abort();
    const stop = new AbortController(); queryStop.current = stop;
    const model = new QueryRead(follow); setQuery(model);
    try {
      const client = new Client(tenant);
      const request = new wire.QueryRequest().setSql(sql).setParametersList(Client.parameters(parameters))
        .setSelection(selection()).setFollow(follow);
      Client.read(
        () => client.rpc.query(request.setBookmark(model.bookmark), client.metadata()),
        (frame) => { model.receive(frame); setQueryState(follow ? 'Following committed changes.' : 'Reading…'); refresh((value) => value + 1); },
        () => Boolean(model.terminal), () => model.reconnect(), stop.signal, setQueryState,
      );
    } catch (error) { setQueryState(Client.error(error)); }
  }

  function watch(model: TraceRead, client: Client) {
    traceStop.current?.abort();
    const stop = new AbortController(); traceStop.current = stop;
    model.reconnect(); setTrace(model);
    const request = new wire.WatchTraceRequest().setTraceId(Client.id(model.id));
    Client.read(
      () => client.rpc.watchTrace(request.setBookmark(model.bookmark), client.metadata()),
      (frame) => { model.receive(frame); setTraceState('Reading committed capture output.'); refresh((value) => value + 1); },
      () => Boolean(model.result), () => model.reconnect(), stop.signal, setTraceState,
    );
  }

  async function submit(request: wire.SubmitTraceRequest) {
    requestStop.current?.abort();
    const stop = new AbortController(); requestStop.current = stop;
    setBusy(true); setDraft(request); setTraceState('Submitting the fixed source and target request…');
    try {
      const client = new Client(tenant);
      const accepted = await client.submit(request, stop.signal);
      if (stop.signal.aborted) return;
      const id = Client.uuid(accepted.getTraceId_asU8());
      setReceipt(accepted); setTraceId(id); setSaved(''); setDraft(undefined);
      watch(new TraceRead(id), client);
    } catch (error) {
      if (!stop.signal.aborted) setTraceState(`Submission is not confirmed: ${Client.error(error)}. Retry uses the same request key.`);
    } finally { if (!stop.signal.aborted) setBusy(false); }
  }

  function runTrace(event: FormEvent) {
    event.preventDefault();
    try {
      Client.id(tenant);
      const request = new wire.SubmitTraceRequest().setIdempotencyKey(Client.id(crypto.randomUUID()))
        .setSelection(selection()).setCollectionSeconds(seconds).setFindingReference(finding);
      if (recipe) request.setRecipe(recipe);
      else {
        const bytes = new TextEncoder().encode(source);
        if (!bytes.length || bytes.length > 65536) throw new Error('The script must contain 1–65536 UTF-8 bytes.');
        request.setScript(bytes);
      }
      void submit(request);
    } catch (error) { setTraceState(Client.error(error)); }
  }

  async function resumeTrace() {
    requestStop.current?.abort(); traceStop.current?.abort();
    const stop = new AbortController(); requestStop.current = stop;
    try {
      const client = new Client(tenant);
      const detail = await client.detail(Client.id(traceId), stop.signal);
      if (stop.signal.aborted) return;
      const model = new TraceRead(traceId); model.detail = detail; model.bookmark = saved.trim();
      setReceipt(detail.getReceipt()); watch(model, client);
    } catch (error) { if (!stop.signal.aborted) setTraceState(Client.error(error)); }
  }

  async function stopTrace() {
    if (!trace) return;
    requestStop.current?.abort();
    const stop = new AbortController(); requestStop.current = stop;
    try {
      const client = new Client(tenant);
      const reply = await client.cancel(Client.id(trace.id), stop.signal);
      if (stop.signal.aborted) return;
      if (!reply.getCancelRequested() || Client.uuid(reply.getTraceId_asU8()) !== trace.id) throw new Error('Cancellation was not confirmed.');
      setTraceState('Cancellation requested. Waiting for each target and verified cleanup.');
      watch(trace, client);
    } catch (error) { if (!stop.signal.aborted) setTraceState(`Cancellation is uncertain: ${Client.error(error)}`); }
  }

  async function loadSource(file?: File) {
    if (!file) return;
    try {
      if (file.size > 65536) throw new Error('The script file exceeds 65536 bytes.');
      const text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
      setSource(text); setRecipe('');
    } catch (error) { setTraceState(Client.error(error)); }
  }

  async function copy(value: string) {
    try { await navigator.clipboard.writeText(value); }
    catch { setTraceState('Clipboard access is unavailable. Select and copy the displayed value.'); }
  }

  const detail = trace?.detail;
  const result = trace?.result;
  return <section className="live-investigation" aria-labelledby="investigation-title">
    <header><div><span className="eyebrow">Live Control connection</span><h2 id="investigation-title">Investigate with SQL and Trace</h2></div><a href="/login">Sign in with OIDC</a></header>
    <p>This panel calls the current Control service. The finding list above is a scenario fixture. Select a real tenant and target here; fixture labels grant no access.</p>
    <div className="live-scope">
      <label>Tenant UUID<input value={tenant} onChange={(event) => changeScope(setTenant, event.target.value)} autoComplete="off" placeholder="00000000-0000-0001-0000-000000000002" /></label>
      <label>Target<input value={target} onChange={(event) => changeScope(setTarget, event.target.value)} placeholder="pod/namespace/name or node/name" /></label>
      <label>Cluster<input value={cluster} onChange={(event) => changeScope(setCluster, event.target.value)} /></label>
      <label>Container<input value={container} onChange={(event) => changeScope(setContainer, event.target.value)} /></label>
    </div>
    <div className="live-columns">
      <section aria-labelledby="query-title"><h3 id="query-title">Retained SQL</h3>
        <form onSubmit={runQuery}>
          <label>SQL<textarea rows={6} value={sql} onChange={(event) => { clearQuery(); setSql(event.target.value); }} spellCheck={false} /></label>
          <label>Parameters (JSON array)<textarea rows={2} value={parameters} onChange={(event) => { clearQuery(); setParameters(event.target.value); }} spellCheck={false} /></label>
          <small>Use {`{"signed":"9223372036854775807"}`} for a large integer. SQL cannot attach a probe.</small>
          <label className="live-check"><input type="checkbox" checked={follow} onChange={(event) => { clearQuery(); setFollow(event.target.checked); }} />Follow committed changes</label>
          <div className="live-actions"><button type="submit" className="primary-action">Run SQL</button><button type="button" onClick={() => { queryStop.current?.abort(); setQueryState('Query read stopped. No capture was cancelled.'); }}>Stop SQL read</button></div>
        </form>
        <p role="status" aria-live="polite">{queryState}</p>
        {query?.metadata && <>
          <p>Operation: <strong>{query.operation === wire.QueryOperation.QUERY_OPERATION_APPEND ? 'Append' : 'Complete replacement'}</strong>. Store {query.store}; epoch {query.epoch}; read revision {query.revision}.</p>
          <p>Limits: {query.metadata.getRowLimit()} rows / {query.metadata.getByteLimit()} bytes. {query.metadata.getResumeSemantics()}</p>
          {query.metadata.hasMovingResolutionNs() && <p>Moving-window resolution: {query.metadata.getMovingResolutionNs()} ns.</p>}
          {(query.limited || query.clipped) && <p className="live-warning">{query.limited ? 'The result reached its server limit. ' : ''}{query.clipped ? 'This view retains at most 2000 rows / 1 MiB of text; older displayed rows were removed.' : ''}</p>}
          <div className="live-table"><table><thead><tr>{query.metadata.getColumnsList().map((column, index) => <th key={index} title={`${column.getDataType()}; ${column.getUnits()}; ${column.getNullMeaning()}; ${column.getOwner()}; ${column.getReadiness()}`}>{column.getName()}</th>)}</tr></thead><tbody>{query.rows.map((row, index) => <tr key={index}>{row.map((value, column) => <td key={column}>{value}</td>)}</tr>)}</tbody></table></div>
          {query.missing.length > 0 && <p className="live-warning">Missing context: {query.missing.map((key) => `${key.getOwnerId()}@${key.getOwnerRevision()}`).join(', ')}</p>}
          {query.bookmark && <details><summary>Complete query checkpoint</summary><code>{query.bookmark}</code><p>Reconnect keeps this bookmark with the exact SQL, parameters and selection. Editing these inputs clears it.</p></details>}
          <Coverage rows={query.coverage} health={query.health} />
        </>}
      </section>
      <section aria-labelledby="trace-title"><h3 id="trace-title">Bounded trace</h3>
        <form onSubmit={runTrace}>
          <label>Source<select value={recipe} onChange={(event) => setRecipe(event.target.value)}><option value="failed-opens@1">Failed opens @1</option><option value="syscall-errors@1">Syscall errors @1</option><option value="">bpftrace script</option></select></label>
          {!recipe && <label>Script<textarea rows={6} value={source} onChange={(event) => setSource(event.target.value)} spellCheck={false} /></label>}
          <label>Load UTF-8 script<input type="file" accept=".bt,.txt" onChange={(event) => void loadSource(event.target.files?.[0])} /></label>
          <div className="live-scope"><label>Collection seconds<input type="number" min="1" max="300" value={seconds} onChange={(event) => setSeconds(Number(event.target.value))} /></label><label>Finding reference (optional)<input value={finding} onChange={(event) => setFinding(event.target.value)} /></label></div>
          <div className="live-actions"><button type="submit" className="primary-action" disabled={busy || Boolean(trace && !trace.result)}>Run trace</button>{draft && <button type="button" disabled={busy} onClick={() => void submit(draft)}>Retry same submission</button>}<button type="button" disabled={!trace || Boolean(result)} onClick={() => void stopTrace()}>Stop capture</button><button type="button" onClick={() => { traceStop.current?.abort(); setTraceState('Viewer stopped. Capture execution continues until cancellation or its deadline.'); }}>Stop viewer only</button></div>
        </form>
        <p role="status" aria-live="polite">{traceState}</p>
        {receipt && <p>Accepted trace: <code>{Client.uuid(receipt.getTraceId_asU8())}</code><br />Source SHA-256: <code>{Client.hex(receipt.getSourceSha256_asU8())}</code><br />Deadline: {receipt.getDeadlineUnixNs()} ns since epoch.</p>}
        <details><summary>Resume a read-only viewer</summary><label>Trace UUID<input value={traceId} onChange={(event) => setTraceId(event.target.value)} /></label><label>Complete trace bookmark (optional)<textarea rows={2} value={saved} onChange={(event) => setSaved(event.target.value)} /></label><button type="button" onClick={() => void resumeTrace()}>Resume viewer</button></details>
        {detail && <>
          <details open><summary>Accepted source and scope</summary><p>Accepted by {detail.getPrincipal()}; recipe {detail.getRecipe() || 'custom script'}; collection {detail.getCollectionSeconds()} seconds.</p><pre>{new TextDecoder().decode(detail.getSource_asU8())}</pre><h4>Requested selection</h4><pre>{JSON.stringify(detail.getRequested()?.toObject(), null, 2)}</pre><p>Finding reference: {detail.getFindingReference() || 'none'}</p><h4>Resolved target identities</h4>{detail.getTargetsList().map((item) => <pre key={item.getIndex()}>{JSON.stringify(item.toObject(), null, 2)}</pre>)}<h4>Unresolved targets</h4><pre>{JSON.stringify(detail.getUnresolvedList().map((item) => item.toObject()), null, 2)}</pre><h4>Owner limits</h4><pre>{JSON.stringify(detail.getLimits()?.toObject(), null, 2)}</pre></details>
          <p>Store {trace?.store}; epoch {trace?.epoch}; read revision {trace?.revision}.</p>
          <h4>Output (UTF-8 text view)</h4><pre className="live-output" tabIndex={0}>{trace?.output || 'No committed output received.'}</pre>
          {trace?.clipped && <p className="live-warning">The browser retains the last 1 MiB of output text. Retained server output is unchanged.</p>}
          <h4>Per-target terminal records</h4>{[...(trace?.terminals ?? [])].map(([index, terminal]) => <pre key={index}>Target {index}{'\n'}{JSON.stringify(terminal.toObject(), null, 2)}</pre>)}
          <h4>Final owner result</h4>{result ? <p className={result.getOutputIncomplete() || !result.getCleanupComplete() ? 'live-warning' : ''}>Collection {result.getComplete() ? 'complete' : 'partial'}; output {result.getOutputIncomplete() ? 'incomplete' : 'complete'}; cleanup {result.getCleanupComplete() ? 'verified' : 'unverified'}. Missing targets: {result.getMissingTargetsList().join(', ') || 'none'}.</p> : <p className="live-warning">No final owner result. Per-target termination or connection closure is not proof of complete execution or cleanup.</p>}
          <Coverage rows={trace?.coverage ?? []} health={trace?.health} />
          {trace?.bookmark && <details><summary>Complete trace checkpoint</summary><code>{trace.bookmark}</code><button type="button" onClick={() => void copy(trace.bookmark)}>Copy trace checkpoint</button></details>}
        </>}
      </section>
    </div>
    <p className="live-warning">Changing scope or leaving this panel stops reads only. It does not stop a capture. Use Stop capture and wait for its final cleanup result.</p>
  </section>;
}

function Coverage({ rows, health }: { rows: wire.QueryCoverage[]; health?: wire.QueryHealth }) {
  return <details><summary>Coverage and store health</summary>
    {!rows.length && <p>Coverage is unavailable for this result. Empty rows do not prove absence.</p>}
    {rows.map((row, index) => <pre key={index}>{JSON.stringify(row.toObject(), null, 2)}</pre>)}
    {health && <pre>{JSON.stringify(health.toObject(), null, 2)}</pre>}
  </details>;
}
