import { useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { consoleData as data, type ConsoleFinding, type ConsoleRoute } from './consoleData';

interface ConsoleActions {
  navigate: (route: ConsoleRoute) => void;
  openSession: () => void;
  showToast: (message: string) => void;
}

const navItems: readonly [ConsoleRoute, string][] = [
  ['operations', 'Operations'],
  ['sessions', 'Sessions'],
  ['findings', 'Findings'],
  ['policies', 'Policies'],
  ['evidence', 'Evidence'],
  ['response', 'Response'],
  ['agent', 'Agent'],
  ['release', 'Release'],
];

function NavIcon({ route }: { route: ConsoleRoute }) {
  const paths: Record<ConsoleRoute, ReactNode> = {
    operations: <><path d="M4 5h16v5H4zM4 14h7v5H4zM15 14h5v5h-5z" /></>,
    sessions: <><circle cx="12" cy="12" r="8" /><path d="M8 12h3l2-4 3 8" /></>,
    findings: <><path d="M12 3 3 20h18L12 3Z" /><path d="M12 9v5m0 3h.01" /></>,
    policies: <><path d="M12 3 5 6v5c0 4.5 2.5 7.5 7 10 4.5-2.5 7-5.5 7-10V6l-7-3Z" /><path d="m9 12 2 2 4-5" /></>,
    evidence: <><path d="M5 4h14v16H5zM8 8h8M8 12h8M8 16h5" /></>,
    response: <><path d="M4 12h11m-4-4 4 4-4 4" /><path d="M17 5h3v14h-3" /></>,
    agent: <><path d="M8 9h8M8 13h5" /><path d="M5 5h14v12H9l-4 3V5Z" /><circle cx="16" cy="13" r="1" /></>,
    release: <><path d="M5 4h14v16H5zM8 9l2 2 5-5M8 16h8" /></>,
  };
  return <svg viewBox="0 0 24 24" aria-hidden="true">{paths[route]}</svg>;
}

export function ConsoleShell({ activeRoute, navigate, showToast, children }: ConsoleActions & {
  activeRoute: ConsoleRoute;
  children: ReactNode;
}) {
  function globalSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    navigate('findings');
  }

  return (
    <div className="console-shell">
      <aside className="product-rail" aria-label="Primary navigation">
        <button type="button" className="console-brand" onClick={() => navigate('operations')} aria-label="Mithril operations home">
          <span className="console-brand-mark" aria-hidden="true">M</span>
          <span><small>EREBOR</small><strong>Mithril</strong></span>
        </button>
        <nav className="console-nav" aria-label="Console sections">
          {navItems.map(([route, label]) => (
            <button key={route} type="button" className={activeRoute === route ? 'active' : ''}
              aria-current={activeRoute === route ? 'page' : undefined} onClick={() => navigate(route)}>
              <NavIcon route={route} /><span>{label}</span>
              {route === 'findings' ? <b>4</b> : null}
              {route === 'release' ? <i aria-label="Two blockers" /> : null}
            </button>
          ))}
        </nav>
        <div className="rail-status">
          <span />
          <p><strong>Scenario replay</strong><small>No control connection</small></p>
        </div>
      </aside>
      <div className="console-workspace">
        <header className="console-topbar">
          <div className="scope-identity"><span>CLUSTER</span><strong>{data.snapshot.cluster}</strong><small>/ {data.snapshot.tenant}</small></div>
          <form className="console-search" onSubmit={globalSearch}>
            <span aria-hidden="true">⌕</span>
            <input type="search" aria-label="Search the console" placeholder="Search findings, sessions, evidence…" />
            <kbd>/</kbd>
          </form>
          <span className="console-snapshot">Snapshot 14:32:22 UTC</span>
          <button type="button" className="console-help" aria-label="Console help"
            onClick={() => showToast('Fixture console: open session-hf-xnode-021 to inspect the causal replay')}>?</button>
        </header>
        <div className="console-content">{children}</div>
      </div>
    </div>
  );
}

export function ConsoleView({ route, ...actions }: ConsoleActions & { route: ConsoleRoute }) {
  if (route === 'operations') return <OperationsView {...actions} />;
  if (route === 'sessions') return <SessionsView {...actions} />;
  if (route === 'findings') return <FindingsView {...actions} />;
  if (route === 'policies') return <PoliciesView showToast={actions.showToast} />;
  if (route === 'evidence') return <EvidenceView {...actions} />;
  if (route === 'response') return <ResponseView {...actions} />;
  if (route === 'agent') return <AgentView {...actions} />;
  return <ReleaseView {...actions} />;
}

function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return (
    <header className="console-page-header">
      <div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1><p>{description}</p></div>
      {action ? <div className="page-action">{action}</div> : null}
    </header>
  );
}

function OperationsView({ navigate, openSession }: ConsoleActions) {
  return (
    <main className="console-page" id="main-content">
      <PageHeader eyebrow="Protection posture" title="Operations" description="Start with the physical result. Follow its session only when the proof needs investigation."
        action={<span className="fixture-chip"><i />{data.snapshot.mode}</span>} />
      <section className="posture-strip" aria-label="Protection posture">
        {data.metrics.map((metric) => (
          <button type="button" key={metric.label} className={`posture-metric tone-${metric.tone}`} onClick={() => navigate(metric.route as ConsoleRoute)}>
            <span>{metric.label}</span><strong>{metric.value}</strong><small>{metric.detail}</small>
          </button>
        ))}
      </section>
      <section className="priority-run" aria-labelledby="priority-title">
        <div className="priority-copy">
          <div className="priority-meta"><span className="severity-critical">CRITICAL</span><code>MF-2419 · HF-XNODE-001</code><time>14:32:22 UTC</time></div>
          <h2 id="priority-title">Cross-node workload reached a denied secret boundary</h2>
          <p>The workload started on worker-b. Its first prohibited secret open was denied before an fd or secret bytes existed.</p>
          <div className="result-line"><span className="result-pill prevented">PREVENTED</span><strong>DENIED_BEFORE_EFFECT</strong><span>complete coverage</span></div>
          <button type="button" className="primary-action" onClick={openSession}>Open causal replay <span>→</span></button>
        </div>
        <div className="causal-summary" aria-label="Session summary">
          <div className="causal-summary-head"><span>SESSION-HF-XNODE-021</span><strong>graph-7f4c.18</strong></div>
          <div className="causal-chain" aria-hidden="true">
            <span className="chain-node">agent</span><i /><span className="chain-node">Kubernetes</span><i className="cross" /><span className="chain-node denied">secret open</span>
          </div>
          <dl><div><dt>Operations</dt><dd>17</dd></div><div><dt>Machines</dt><dd>3</dd></div><div><dt>Direct edges</dt><dd>16</dd></div><div><dt>Contextual</dt><dd>2</dd></div></dl>
          <p>One shared-principal join stays contextual. All downstream Kubernetes and runtime joins are direct.</p>
        </div>
      </section>
      <div className="console-two-column">
        <section className="console-panel">
          <header className="panel-heading"><div><span className="eyebrow">Triage queue</span><h2>Open findings</h2></div><button type="button" onClick={() => navigate('findings')}>View all</button></header>
          <div className="compact-findings">{data.findings.slice(0, 4).map((finding) => <FindingRow key={finding.id} finding={finding} onClick={() => navigate('findings')} />)}</div>
        </section>
        <section className="console-panel">
          <header className="panel-heading"><div><span className="eyebrow">Evidence boundary</span><h2>Source coverage</h2></div><button type="button" onClick={() => navigate('evidence')}>Inspect</button></header>
          <div className="coverage-total"><strong>5<span>/6</span></strong><p>sources have continuous coverage</p></div>
          <div className="coverage-track"><span /></div>
          <ul className="coverage-list">{data.evidenceSources.slice(0, 4).map((source) => <li key={source.name}><span className={`source-dot ${source.state}`} /> <strong>{source.name}</strong><small>{source.lag}</small></li>)}</ul>
          <p className="boundary-warning"><strong>Known gap.</strong> GitHub audit is missing 14:21–14:24. Mithril does not convert the interval into a clean result.</p>
        </section>
      </div>
    </main>
  );
}

function SessionsView({ openSession }: ConsoleActions) {
  const [selectedId, setSelectedId] = useState<string>(data.sessions[0].id);
  const selected = data.sessions.find((session) => session.id === selectedId) ?? data.sessions[0];
  return (
    <main className="console-page">
      <PageHeader eyebrow="Agent and workload runs" title="Sessions" description="Replay stable operation identities over event time. Open a graph when the session has an immutable revision." />
      <div className="session-browser">
        <section className="session-list" aria-label="Session results">
          <div className="list-toolbar"><span>{data.sessions.length} sessions</span><select aria-label="Session result filter"><option>All results</option><option>Prevented</option><option>Verified</option><option>Partial</option></select></div>
          {data.sessions.map((session) => (
            <button type="button" key={session.id} className={selected.id === session.id ? 'active' : ''} onClick={() => setSelectedId(session.id)}>
              <time>{session.time}</time><span><small>{session.actor} · {session.scope}</small><strong>{session.title}</strong></span><b className={`result-${session.result}`}>{session.result}</b>
            </button>
          ))}
        </section>
        <aside className="session-detail">
          <span className="eyebrow">{selected.id}</span><h2>{selected.title}</h2><p>{selected.scope} · {selected.actor}</p>
          <div className="session-facts"><div><span>Graph revision</span><strong>{selected.graph}</strong></div><div><span>Operations</span><strong>{selected.operations}</strong></div><div><span>Machines</span><strong>{selected.machines}</strong></div><div><span>Proof</span><strong>{selected.proof}</strong></div></div>
          <div className="session-spine" aria-hidden="true"><span /><i /><span /><i /><span /><i /><span className={selected.result} /></div>
          {selected.replay ? <button type="button" className="primary-action" onClick={openSession}>Open causal replay <span>→</span></button> : <button type="button" className="secondary-action" disabled>Replay not included in fixture</button>}
        </aside>
      </div>
    </main>
  );
}

function FindingRow({ finding, selected, onClick }: { finding: ConsoleFinding; selected?: boolean; onClick: () => void }) {
  return (
    <button type="button" className={`console-finding-row ${selected ? 'active' : ''}`} onClick={onClick}>
      <i className={`severity-${finding.severity}`} /><span><small>{finding.id} · {finding.package} · {finding.age}</small><strong>{finding.title}</strong></span><b className={`result-${finding.outcome}`}>{finding.outcome}</b>
    </button>
  );
}

function FindingsView({ openSession }: ConsoleActions) {
  const [query, setQuery] = useState('');
  const [outcome, setOutcome] = useState('all');
  const [selectedId, setSelectedId] = useState<string>(data.findings[0].id);
  const filtered = useMemo(() => data.findings.filter((finding) => {
    const matchesText = [finding.id, finding.title, finding.scope, finding.package].join(' ').toLowerCase().includes(query.toLowerCase());
    return matchesText && (outcome === 'all' || finding.outcome === outcome);
  }), [outcome, query]);
  const selected = data.findings.find((finding) => finding.id === selectedId) ?? filtered[0] ?? data.findings[0];
  return (
    <main className="console-page">
      <PageHeader eyebrow="Immutable finding revisions" title="Findings" description="Keep proof strength, coverage, policy provenance, and weaker causal branches with every conclusion." />
      <div className="console-filterbar"><input type="search" aria-label="Filter findings" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter by ID, package, scope, or title" /><select aria-label="Filter by result" value={outcome} onChange={(event) => setOutcome(event.target.value)}><option value="all">All results</option><option value="prevented">Prevented</option><option value="verified">Verified</option><option value="partial">Partial</option><option value="outside">Outside authority</option><option value="allowed">Allowed</option></select><span>{filtered.length} / {data.findings.length}</span></div>
      <div className="finding-browser">
        <section className="finding-results" aria-label="Finding results">{filtered.length ? filtered.map((finding) => <FindingRow key={finding.id} finding={finding} selected={selected.id === finding.id} onClick={() => setSelectedId(finding.id)} />) : <p className="empty-result">No findings match these filters.</p>}</section>
        <aside className="finding-inspector">
          <div className="finding-status"><span className={`severity-${selected.severity}`}>{selected.severity}</span><b className={`result-${selected.outcome}`}>{selected.outcome}</b></div>
          <span className="eyebrow">{selected.id} · {selected.package}</span><h2>{selected.title}</h2><p>{selected.summary}</p>
          <dl><div><dt>Scope</dt><dd>{selected.scope}</dd></div><div><dt>First effect</dt><dd>{selected.firstEffect}</dd></div><div><dt>Exact result</dt><dd><code>{selected.result}</code></dd></div><div><dt>Proof</dt><dd>{selected.proof}</dd></div></dl>
          {selected.graph ? <button type="button" className="primary-action" onClick={openSession}>Open finding in replay <span>→</span></button> : <button type="button" className="secondary-action" disabled>No graph in fixture</button>}
        </aside>
      </div>
    </main>
  );
}

type EditablePolicy = {
  name: string;
  namespace: string;
  mode: string;
  source: string;
  generation: string;
  desired: number;
  active: number;
  state: string;
  detail: string;
  selector: string;
  defaultAction: string;
  rules: string;
};

function PoliciesView({ showToast }: Pick<ConsoleActions, 'showToast'>) {
  const [policies, setPolicies] = useState<EditablePolicy[]>(() => data.policies.map((policy) => ({ ...policy })));
  const [selectedName, setSelectedName] = useState<string>(data.policies[0].name);
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState('');
  const [appliedSuggestions, setAppliedSuggestions] = useState<ReadonlySet<string>>(() => new Set());
  const selected = policies.find((policy) => policy.name === selectedName) ?? policies[0];
  const [draft, setDraft] = useState<EditablePolicy>(() => ({ ...selected }));

  function selectPolicy(policy: EditablePolicy) {
    setSelectedName(policy.name);
    setDraft({ ...policy });
    setEditing(false);
    setError('');
  }

  function savePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!draft.selector.trim() || !draft.rules.trim()) {
      setError('A workload selector and at least one rule are required.');
      return;
    }
    setPolicies((current) => current.map((policy) => policy.name === draft.name ? { ...draft, selector: draft.selector.trim(), rules: draft.rules.trim() } : policy));
    setDraft((current) => ({ ...current, selector: current.selector.trim(), rules: current.rules.trim() }));
    setEditing(false);
    setError('');
    showToast('Policy draft saved locally. No control-plane write occurred.');
  }

  function applySuggestion(suggestion: (typeof data.observeSuggestions)[number]) {
    const appendRule = (rules: string) => rules.split('\n').includes(suggestion.rule) ? rules : `${rules.trim()}\n${suggestion.rule}`;
    setPolicies((current) => current.map((policy) => policy.name === selected.name ? { ...policy, rules: appendRule(policy.rules) } : policy));
    setDraft((current) => current.name === selected.name ? { ...current, rules: appendRule(current.rules) } : current);
    setAppliedSuggestions((current) => new Set([...current, suggestion.id]));
    showToast(`Suggestion applied to the local ${selected.name} draft.`);
  }

  const changedFields = ['mode', 'defaultAction', 'selector', 'rules'].filter((field) => draft[field as keyof EditablePolicy] !== selected[field as keyof EditablePolicy]).length;
  return (
    <main className="console-page">
      <PageHeader eyebrow="Desired state to physical activation" title="Policy rollout" description="Track source revisions, signed generations, exact targets, and node readback." />
      <div className="authority-banner"><strong>Status is not authority.</strong><span>The active signed node generation decides. Kubernetes status is an informational projection.</span></div>
      <section className="console-panel policy-table">
        <header className="panel-heading"><div><span className="eyebrow">WorkloadProtectionPolicy</span><h2>Desired policies</h2></div><span>{data.policies.length} sources</span></header>
        {policies.map((policy) => <button type="button" key={policy.name} className={selected.name === policy.name ? 'active' : ''} onClick={() => selectPolicy(policy)}><span><small>{policy.namespace}</small><strong>{policy.name}</strong></span><span><small>Mode</small><strong>{policy.mode}</strong></span><span><small>Source / generation</small><strong>{policy.source} / {policy.generation}</strong></span><span><small>Activation</small><strong>{policy.active} / {policy.desired}</strong><i><b style={{ width: `${policy.active / policy.desired * 100}%` }} /></i></span><em className={`policy-${policy.state.toLowerCase()}`}>{policy.state}</em></button>)}
      </section>
      <section className={`policy-editor ${editing ? 'editing' : ''}`} aria-labelledby="policy-editor-title">
        <header>
          <div><span className="eyebrow">Selected policy · source {selected.source}</span><h2 id="policy-editor-title">{selected.namespace} / {selected.name}</h2><p>Generation {selected.generation} is active on {selected.active} of {selected.desired} exact targets.</p></div>
          {!editing ? <button type="button" className="secondary-action" onClick={() => { setDraft({ ...selected }); setEditing(true); }}>Edit policy</button> : <span className="draft-count">{changedFields} changed fields</span>}
        </header>
        <form onSubmit={savePolicy}>
          <div className="policy-fields">
            <label>Mode<select value={draft.mode} disabled={!editing} onChange={(event) => setDraft({ ...draft, mode: event.target.value })}><option>Protect</option><option>Observe</option></select></label>
            <label>Default action<select value={draft.defaultAction} disabled={!editing} onChange={(event) => setDraft({ ...draft, defaultAction: event.target.value })}><option>Deny</option><option>Allow</option><option>Observe</option></select></label>
            <label className="selector-field">Workload selector<input value={draft.selector} readOnly={!editing} onChange={(event) => setDraft({ ...draft, selector: event.target.value })} /></label>
          </div>
          <label className="rules-field">Rules<textarea rows={5} value={draft.rules} readOnly={!editing} onChange={(event) => setDraft({ ...draft, rules: event.target.value })} spellCheck="false" /></label>
          <div className="editor-boundary"><strong>UI fixture boundary.</strong> Saving changes browser memory only. No candidate is signed, delivered, or activated.</div>
          {error ? <p className="form-error" role="alert">{error}</p> : null}
          {editing ? <div className="editor-actions"><button type="button" className="secondary-action" onClick={() => { setDraft({ ...selected }); setEditing(false); setError(''); }}>Cancel</button><button type="submit" className="primary-action">Save draft</button></div> : null}
        </form>
      </section>
      {selected.mode === 'Observe' ? (
        <section className="observe-suggestions" aria-labelledby="observe-suggestions-title">
          <header><div><span className="eyebrow">Observed behavior · no automatic enforcement</span><h2 id="observe-suggestions-title">Policy suggestions</h2><p>Each suggestion comes from retained evidence. Apply adds one rule to the local draft.</p></div><span>{data.observeSuggestions.filter((suggestion) => suggestion.policy === selected.name).length} suggestions</span></header>
          <div>{data.observeSuggestions.filter((suggestion) => suggestion.policy === selected.name).map((suggestion) => {
            const applied = appliedSuggestions.has(suggestion.id);
            return <article key={suggestion.id}><div className="suggestion-proof"><span>{suggestion.confidence} confidence</span><small>{suggestion.evidence}</small></div><h3>{suggestion.title}</h3><code>{suggestion.rule}</code><p>{suggestion.effect}</p><button type="button" className={applied ? 'applied' : ''} disabled={applied} onClick={() => applySuggestion(suggestion)}>{applied ? 'Applied to draft' : 'Apply suggestion'}</button></article>;
          })}</div>
          <p className="observe-boundary"><strong>Apply is not activation.</strong> Review the draft, switch mode deliberately, and use a qualified policy write path when backend integration exists.</p>
        </section>
      ) : null}
      <div className="console-two-column policy-lower">
        <section className="console-panel"><header className="panel-heading"><div><span className="eyebrow">{selected.namespace} / {selected.name}</span><h2>Exact node inventory</h2></div><em className={`policy-${selected.state.toLowerCase()}`}>{selected.state}</em></header><p className="panel-intro">{selected.detail}</p><div className="node-inventory"><div className="node-inventory-head"><span>Node</span><span>Exact identity</span><span>Generation</span><span>State</span></div>{data.rolloutNodes.map((node) => <div key={node.name}><strong>{node.name}</strong><code>{node.identity}</code><code>{node.generation}</code><span><b className={`node-${node.state.toLowerCase()}`}>{node.state}</b><small>{node.detail}</small></span></div>)}</div></section>
        <section className="console-panel"><header className="panel-heading"><div><span className="eyebrow">Bounded authority</span><h2>Exceptions</h2></div><span>2 records</span></header><div className="exception-card"><span className="eyebrow">payments-api-6f8 / app</span><h3>diagnostic-read</h3><p>One read of the diagnostics object. Expires in 8 minutes.</p><b>Pending approval</b></div><div className="exception-card"><span className="eyebrow">publisher-2bd / app</span><h3>recovery-marker</h3><p>One write. The exact grant is consumed.</p><b className="consumed">Consumed</b></div></section>
      </div>
    </main>
  );
}

function EvidenceView({ openSession }: ConsoleActions) {
  return (
    <main className="console-page">
      <PageHeader eyebrow="Immutable accepted records" title="Evidence" description="Coverage gaps stay gaps. Intake acknowledgement does not convert missing input into a clean interval." action={<span className="fixture-chip warning"><i />1 degraded source</span>} />
      <section className="console-panel"><header className="panel-heading"><div><span className="eyebrow">Coverage and cursors</span><h2>Source health</h2></div><span>5 / 6 continuous</span></header><div className="source-grid">{data.evidenceSources.map((source) => <article key={source.name} className={`evidence-source ${source.state}`}><header><span><i />{source.state}</span><strong>{source.name}</strong></header><dl><div><dt>Owner</dt><dd>{source.owner}</dd></div><div><dt>Cursor</dt><dd>{source.cursor}</dd></div><div><dt>Coverage</dt><dd>{source.coverage}</dd></div><div><dt>Lag</dt><dd>{source.lag}</dd></div></dl></article>)}</div></section>
      <section className="console-panel evidence-chain"><header className="panel-heading"><div><span className="eyebrow">MF-2419 · graph-7f4c.18</span><h2>Accepted record chain</h2></div><button type="button" onClick={openSession}>Open causal replay</button></header>{data.evidenceRecords.map((record) => <article key={`${record.time}-${record.source}`}><time>{record.time}</time><span><small>{record.source}</small><strong>{record.result}</strong><p>{record.subject}</p></span><code>{record.proof}</code></article>)}</section>
    </main>
  );
}

function ResponseView({ openSession }: ConsoleActions) {
  const [selectedAction, setSelectedAction] = useState(1);
  const action = data.response.actions[selectedAction];
  return (
    <main className="console-page">
      <PageHeader eyebrow="Typed and revision-bound" title="Response" description="Simulate the physical scope before authorization. A response cannot widen beyond its frozen finding and graph revision." />
      <section className="response-hero"><div><span className="eyebrow">PLAN {data.response.id} · {data.response.state}</span><h2>Contain the cross-node workload</h2><p>{data.response.summary}</p><button type="button" className="secondary-action" onClick={openSession}>Inspect frozen graph revision</button></div><dl><div><dt>Graph</dt><dd>{data.response.graph}</dd></div><div><dt>Finding</dt><dd>{data.response.finding}</dd></div><div><dt>Expires</dt><dd>{data.response.expires}</dd></div><div><dt>Authorization</dt><dd>{data.response.approval}</dd></div></dl></section>
      <div className="response-workbench">
        <section className="response-actions"><header><span>ORDER</span><span>ACTION AND TARGET</span><span>SCOPE</span><span>STATE</span></header>{data.response.actions.map((item, index) => <button type="button" key={item.order} className={selectedAction === index ? 'active' : ''} onClick={() => setSelectedAction(index)}><code>{item.order}</code><span><strong>{item.action}</strong><small>{item.target}</small></span><span>{item.scope}</span><b>{item.state}</b></button>)}</section>
        <aside className="blast-radius"><span className="eyebrow">Selected action</span><h2>{action.action}</h2><p>{action.target}</p><div className="blast-graphic"><span>exact target</span><strong>{action.scope}</strong><i /></div><dl><div><dt>Resolution</dt><dd>Re-resolve before effect</dd></div><div><dt>Postcondition</dt><dd>Authoritative readback + healthy watch</dd></div><div><dt>Retry</dt><dd>Idempotent within plan lifetime</dd></div></dl><div className="response-lock">Execution is unavailable in the design fixture.</div></aside>
      </div>
    </main>
  );
}

type AgentMessage = {
  id: number;
  role: 'agent' | 'user';
  text: string;
  action?: ConsoleRoute | 'session';
  actionLabel?: string;
};

function agentReply(input: string): Omit<AgentMessage, 'id' | 'role'> {
  const question = input.toLowerCase();
  if (question.includes('release') || question.includes('block')) return { text: 'The release has two blockers: active fixture equality is 131 of 133, and the GitHub recovery readback has a known audit gap. The signed claim must remain blocked.', action: 'release', actionLabel: 'Review release blockers' };
  if (question.includes('policy') || question.includes('rollout') || question.includes('generation')) return { text: 'payments-protect needs attention. Six of seven targets run generation 7f4c. worker-c keeps its last valid generation while the new probe is pending.', action: 'policies', actionLabel: 'Open policy rollout' };
  if (question.includes('evidence') || question.includes('coverage') || question.includes('gap')) return { text: 'Five of six evidence sources have continuous coverage. GitHub audit has a gap from 14:21 to 14:24, so provider-dependent negative claims are unavailable for that interval.', action: 'evidence', actionLabel: 'Inspect source coverage' };
  if (question.includes('response') || question.includes('contain')) return { text: 'Response plan rsp-28 freezes graph-7f4c.18. Network isolation affects one Pod. Suspending the shared ServiceAccount affects four active Pods and requires explicit authorization.', action: 'response', actionLabel: 'Review blast radius' };
  if (question.includes('session') || question.includes('graph') || question.includes('finding') || question.includes('investigate')) return { text: 'MF-2419 is the priority finding. The graph has 17 operations across three machines. One shared-principal join is contextual; all downstream Kubernetes and runtime joins are direct.', action: 'session', actionLabel: 'Open causal replay' };
  return { text: 'I can explain the priority finding, policy rollout, evidence gaps, response blast radius, or release blockers. I can navigate to the supporting workspace, but I cannot execute a control-plane action.', action: 'operations', actionLabel: 'Open operations' };
}

function AgentView({ navigate, openSession }: ConsoleActions) {
  const [query, setQuery] = useState('');
  const [messages, setMessages] = useState<AgentMessage[]>([
    { id: 0, role: 'agent', text: 'I am scoped to the current Mithril fixture. Ask me to investigate proof, explain policy state, find coverage gaps, review response scope, or check release blockers.' },
  ]);

  function ask(input: string) {
    const text = input.trim();
    if (!text) return;
    const reply = agentReply(text);
    setMessages((current) => [...current, { id: current.length, role: 'user', text }, { id: current.length + 1, role: 'agent', ...reply }]);
    setQuery('');
  }

  function follow(action: ConsoleRoute | 'session') {
    if (action === 'session') openSession();
    else navigate(action);
  }

  const prompts = ['Investigate the critical finding', 'Which policy needs attention?', 'Show evidence gaps', 'Explain the response blast radius', 'Why is the release blocked?'];
  return (
    <main className="console-page">
      <PageHeader eyebrow="Bounded system copilot" title="Agent mode" description="Ask about the current operating state. Every answer points to a workspace that contains the supporting fixture evidence." action={<span className="fixture-chip"><i />Local guided fixture</span>} />
      <div className="agent-workspace">
        <section className="agent-conversation" aria-labelledby="agent-conversation-title">
          <header><div className="agent-avatar" aria-hidden="true">M</div><div><h2 id="agent-conversation-title">Mithril assistant</h2><p><span /> Current snapshot · read-only guidance</p></div></header>
          <div className="agent-messages" aria-live="polite">{messages.map((message) => <article key={message.id} className={`agent-message ${message.role}`}><span>{message.role === 'agent' ? 'M' : 'YOU'}</span><div><p>{message.text}</p>{message.action ? <button type="button" onClick={() => follow(message.action!)}>{message.actionLabel}<b>→</b></button> : null}</div></article>)}</div>
          <form className="agent-input" onSubmit={(event) => { event.preventDefault(); ask(query); }}><label><span className="sr-only">Ask the Mithril assistant</span><textarea rows={2} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Ask about findings, policies, evidence, response, or release…" /></label><button type="submit" disabled={!query.trim()}>Send</button></form>
        </section>
        <aside className="agent-context">
          <span className="eyebrow">Suggested investigations</span><h2>Work from evidence</h2><div className="agent-prompts">{prompts.map((prompt) => <button type="button" key={prompt} onClick={() => ask(prompt)}>{prompt}<span>→</span></button>)}</div>
          <section><span>Current scope</span><dl><div><dt>Cluster</dt><dd>{data.snapshot.cluster}</dd></div><div><dt>Priority finding</dt><dd>MF-2419</dd></div><div><dt>Graph revision</dt><dd>graph-7f4c.18</dd></div><div><dt>Policy generation</dt><dd>7f4c · mixed</dd></div></dl></section>
          <p className="agent-boundary"><strong>Authority boundary.</strong> Agent mode reads fixture state and navigates the console. It cannot sign policy, authorize response, or claim physical effect.</p>
        </aside>
      </div>
    </main>
  );
}

function ReleaseView({ showToast }: ConsoleActions) {
  const blocked = data.conformance.filter((record) => record.state === 'blocked').length;
  async function copyDigest() {
    try { await navigator.clipboard.writeText(data.release.digest); showToast('Envelope digest copied'); }
    catch { showToast('Clipboard access is unavailable'); }
  }
  return (
    <main className="console-page">
      <PageHeader eyebrow="Digest-bound qualification" title="Release claim" description="Bind the platform, fixtures, performance, recovery, and physical results into one limited claim." />
      <section className="release-hero"><div><span className="eyebrow">{data.release.candidate}</span><h2>Candidate cannot be signed</h2><p>{blocked} required qualification records block this release claim.</p></div><span>PLATFORM MANIFEST<strong>{data.release.manifest}</strong></span></section>
      <div className="release-grid"><section className="console-panel"><header className="panel-heading"><div><span className="eyebrow">Qualification result set</span><h2>Qualification records</h2></div><span>{data.conformance.length - blocked} / {data.conformance.length} passed</span></header><ol className="qualification-list">{data.conformance.map((record) => <li key={record.id} className={record.state}><i>{record.state === 'passed' ? '✓' : '!'}</i><span><strong>{record.label}</strong><small>{record.detail}</small></span><b>{record.state}</b></li>)}</ol></section><aside className="claim-boundary"><span className="eyebrow">Limited release statement</span><h2>Claim boundary</h2><p>{data.release.claim}</p><label>Envelope digest<code>{data.release.digest}</code><button type="button" onClick={copyDigest}>Copy</button></label><div><span>Explicitly excluded</span><ul>{data.release.excluded.map((item) => <li key={item}>{item}</li>)}</ul></div><p className="boundary-warning"><strong>No silent downgrade.</strong> A blocked record narrows or prevents the claim.</p></aside></div>
    </main>
  );
}
