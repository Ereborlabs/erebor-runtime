import { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Client, wire } from './client';
import './administrative.css';

function Administrative() {
  const [detail, setDetail] = useState<wire.AdministrativeExecActivation>();
  const [status, setStatus] = useState('Reading the exact request…');
  const [busy, setBusy] = useState(false);
  const active = useRef<AbortController | undefined>(undefined);
  const token = window.location.pathname.match(/^\/activate\/([0-9a-f]{64})$/)?.[1];

  useEffect(() => {
    void refresh();
    return () => active.current?.abort();
  }, []);

  async function refresh() {
    active.current?.abort();
    const stop = new AbortController(); active.current = stop;
    if (!token) { setStatus('The activation token is invalid.'); return; }
    setBusy(true);
    try {
      const value = await new Client().activation(token, stop.signal);
      if (stop.signal.aborted) return;
      setDetail(value);
      setStatus(value.getAuthenticated() ? `Request state: ${value.getState()}.` : 'Sign in before approval.');
    } catch (error) { if (!stop.signal.aborted) setStatus(Client.error(error)); }
    finally { if (!stop.signal.aborted) setBusy(false); }
  }

  async function approve() {
    if (!token || !detail?.getAuthenticated() || detail.getState() !== 'PENDING') return;
    active.current?.abort();
    const stop = new AbortController(); active.current = stop;
    setBusy(true); setStatus('Requesting one-use approval…');
    try {
      const value = await new Client().approve(token, stop.signal);
      if (stop.signal.aborted) return;
      if (!value.getApproved()) throw new Error('Approval was not confirmed.');
      setStatus('Administrative exec approved once. Return to the waiting terminal.');
      detail.setState('APPROVED');
    } catch (error) {
      if (!stop.signal.aborted) setStatus(`Approval is not confirmed: ${Client.error(error)}. Refresh the request state before another action.`);
    } finally { if (!stop.signal.aborted) setBusy(false); }
  }

  return <>
    <h1>Review one administrative exec</h1>
    <p role="status" aria-live="polite">{status}</p>
    {detail && <>
      <dl>
        <dt>Authenticated approver</dt><dd>{detail.getApprover() || 'Not signed in'}</dd>
        <dt>Cluster</dt><dd>{detail.getClusterUid()}</dd>
        <dt>Namespace / Pod</dt><dd>{detail.getNamespace()} / {detail.getPod()}</dd>
        <dt>Pod UID</dt><dd>{detail.getPodUid()}</dd>
        <dt>Container</dt><dd>{detail.getContainer()}</dd>
        <dt>Command and exact arguments</dt><dd><ol>{detail.getArgvList().map((value, index) => <li key={index}><code>{JSON.stringify(value)}</code></li>)}</ol></dd>
        <dt>Resolved executable</dt><dd><code>{detail.getResolvedExecutable()}</code></dd>
        <dt>Stream flags</dt><dd>{detail.getStreamFlags()}</dd>
        <dt>Approved role</dt><dd>{detail.getApprovedRoleId()}</dd>
        <dt>Expiry (UTC nanoseconds)</dt><dd>{detail.getExpiresAtUtcNs()}</dd>
      </dl>
      <p className="approval-risk"><strong>Risk:</strong> Another restricted runtime root with the same live container, executable, and arguments can consume this one-use slot first. Stream settings are checked here but are not a Linux-task match field.</p>
      {detail.getAuthenticated()
        ? <button type="button" disabled={busy || detail.getState() !== 'PENDING'} onClick={() => void approve()}>I accept this race and approve once</button>
        : <a href={`/activate/${token}/authorize`}>Sign in to review</a>}
      <button type="button" disabled={busy} onClick={() => void refresh()}>Refresh request state</button>
    </>}
    <p>Investigation access does not grant administrative approval. This page uses its request-bound OIDC identity and separate one-use approval.</p>
  </>;
}

const root = document.getElementById('administrative-root');
if (root) createRoot(root).render(<Administrative />);
