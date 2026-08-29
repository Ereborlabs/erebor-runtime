import { useEffect, useMemo, useRef, useState } from 'react';
import { ConsoleShell, ConsoleView } from './Console';
import type { ConsoleRoute } from './consoleData';
import { operationById, sessionGraph, type CausalEdge, type CauseStrength, type Machine, type Operation } from './data';
import {
  connectedOperationIds,
  createGraphLayout,
  edgePath,
  formatEventTime,
  NODE_HEIGHT,
  visibleAtStep,
  visibleEdges,
} from './graph';

type ViewMode = 'map' | 'ledger';
type Filter = 'all' | 'direct' | 'contextual' | 'denied';
type Selection = { type: 'operation' | 'edge'; id: string } | null;

const finalStep = Math.max(...sessionGraph.operations.map((operation) => operation.step));
const consoleRoutes = new Set<ConsoleRoute>(['operations', 'sessions', 'findings', 'policies', 'evidence', 'response', 'agent', 'release']);

function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function autoplayEnabled(): boolean {
  return new URLSearchParams(window.location.search).get('autoplay') !== '0' && !prefersReducedMotion();
}

function routeFromHash(): ConsoleRoute | 'session' {
  const path = window.location.hash.slice(1).split('?')[0].replace(/^\/+/, '');
  if (path.startsWith('sessions/')) return 'session';
  return consoleRoutes.has(path as ConsoleRoute) ? path as ConsoleRoute : 'operations';
}

export function App() {
  const [route, setRoute] = useState<ConsoleRoute | 'session'>(routeFromHash);
  const [toast, setToast] = useState('');

  useEffect(() => {
    const updateRoute = () => setRoute(routeFromHash());
    window.addEventListener('hashchange', updateRoute);
    return () => window.removeEventListener('hashchange', updateRoute);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(''), 2600);
    return () => window.clearTimeout(timer);
  }, [toast]);

  function navigate(next: ConsoleRoute) {
    window.location.hash = `/${next}`;
    window.scrollTo({ top: 0, behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
  }

  function openSession() {
    window.location.hash = `/sessions/${sessionGraph.id}?revision=${sessionGraph.graphVersion}&finding=${sessionGraph.finding}&mode=replay`;
  }

  const activeRoute = route === 'session' ? 'sessions' : route;
  const actions = { navigate, openSession, showToast: setToast };
  return (
    <>
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <ConsoleShell activeRoute={activeRoute} {...actions}>
        {route === 'session' ? <SessionReplay /> : <ConsoleView route={route} {...actions} />}
      </ConsoleShell>
      <div className={`console-toast ${toast ? 'visible' : ''}`} role="status" aria-live="polite">{toast}</div>
    </>
  );
}

function SessionReplay() {
  const autoPlay = useMemo(autoplayEnabled, []);
  const [step, setStep] = useState(autoPlay ? 0 : finalStep);
  const [playing, setPlaying] = useState(autoPlay);
  const [speed, setSpeed] = useState(1);
  const [view, setView] = useState<ViewMode>('map');
  const [selection, setSelection] = useState<Selection>(null);
  const [focusedMachine, setFocusedMachine] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const viewportRef = useRef<HTMLDivElement>(null);
  const selectedOperationId = selection?.type === 'operation' ? selection.id : null;
  const selectedEdgeId = selection?.type === 'edge' ? selection.id : null;
  const layout = useMemo(
    () => createGraphLayout(sessionGraph.operations, sessionGraph.machines, selectedOperationId),
    [selectedOperationId],
  );
  const visibleOperations = useMemo(() => visibleAtStep(sessionGraph.operations, step), [step]);
  const visibleIds = useMemo(() => new Set(visibleOperations.map((operation) => operation.id)), [visibleOperations]);
  const edges = useMemo(() => visibleEdges(sessionGraph.edges, visibleIds), [visibleIds]);
  const currentOperation = [...visibleOperations].reverse().find((operation) => operation.step === step)
    ?? visibleOperations.at(-1)!;

  useEffect(() => {
    if (!playing) return;
    const timer = window.setTimeout(() => {
      setStep((current) => {
        if (current >= finalStep) {
          setPlaying(false);
          return current;
        }
        return current + 1;
      });
    }, 760 / speed);
    return () => window.clearTimeout(timer);
  }, [playing, speed, step]);

  useEffect(() => {
    if (!playing || !viewportRef.current || !currentOperation) return;
    const position = layout.positions.get(currentOperation.id);
    if (!position) return;
    const viewport = viewportRef.current;
    const target = Math.max(0, position.x - viewport.clientWidth * 0.52);
    const top = Math.max(0, position.y - viewport.clientHeight * 0.42);
    viewport.scrollTo({ left: target, top, behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
  }, [currentOperation, layout.positions, playing]);

  useEffect(() => {
    if (!selectedOperationId || !viewportRef.current) return;
    const position = layout.positions.get(selectedOperationId);
    if (!position) return;
    const viewport = viewportRef.current;
    viewport.scrollTo({
      left: Math.max(0, position.x - Math.max(16, (viewport.clientWidth - position.width) / 2)),
      top: Math.max(0, position.y - viewport.clientHeight * 0.36),
      behavior: prefersReducedMotion() ? 'auto' : 'smooth',
    });
  }, [layout.positions, selectedOperationId]);

  useEffect(() => {
    if (!selection) return;
    const selectedStep = selection.type === 'operation'
      ? operationById.get(selection.id)?.step
      : sessionGraph.edges.find((edge) => edge.id === selection.id)
        ? Math.max(
          operationById.get(sessionGraph.edges.find((edge) => edge.id === selection.id)!.source)!.step,
          operationById.get(sessionGraph.edges.find((edge) => edge.id === selection.id)!.target)!.step,
        )
        : undefined;
    if (selectedStep !== undefined && selectedStep > step) setStep(selectedStep);
  }, [selection, step]);

  useEffect(() => {
    const params = new URLSearchParams();
    params.set('revision', sessionGraph.graphVersion);
    params.set('step', String(step));
    params.set('view', view);
    if (selection) params.set('focus', `${selection.type}:${selection.id}`);
    if (focusedMachine) params.set('node', focusedMachine);
    window.history.replaceState(null, '', `#/sessions/${sessionGraph.id}?${params.toString()}`);
  }, [focusedMachine, selection, step, view]);

  function selectOperation(operation: Operation) {
    setPlaying(false);
    setStep((current) => Math.max(current, operation.step));
    setSelection((current) => current?.type === 'operation' && current.id === operation.id
      ? null
      : { type: 'operation', id: operation.id });
  }

  function selectEdge(edge: CausalEdge) {
    setPlaying(false);
    setSelection((current) => current?.type === 'edge' && current.id === edge.id
      ? null
      : { type: 'edge', id: edge.id });
  }

  function replay() {
    setSelection(null);
    setFocusedMachine(null);
    setStep(0);
    setPlaying(true);
    viewportRef.current?.scrollTo({ left: 0, behavior: 'auto' });
  }

  function frameCurrent() {
    const position = layout.positions.get(currentOperation.id);
    const viewport = viewportRef.current;
    if (!position || !viewport) return;
    viewport.scrollTo({
      left: Math.max(0, position.x - viewport.clientWidth * 0.52),
      top: Math.max(0, position.y - viewport.clientHeight * 0.42),
      behavior: prefersReducedMotion() ? 'auto' : 'smooth',
    });
  }

  function showComplete() {
    setPlaying(false);
    setSelection(null);
    setStep(finalStep);
    requestAnimationFrame(() => viewportRef.current?.scrollTo({ left: 0, top: 0, behavior: 'smooth' }));
  }

  function search(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const match = sessionGraph.operations.find((operation) => operationMatches(operation, query, filter));
    if (!match) return;
    setStep(Math.max(step, match.step));
    setView('map');
    selectOperation(match);
    requestAnimationFrame(() => {
      const position = layout.positions.get(match.id);
      if (position && viewportRef.current) viewportRef.current.scrollTo({ left: Math.max(0, position.x - 260), behavior: 'smooth' });
    });
  }

  const contextualCount = sessionGraph.edges.filter((edge) => edge.strength === 'contextual').length;

  return (
    <main className="app-shell">
      <header className="app-header">
        <div className="brand-block">
          <div className="brand-mark" aria-hidden="true"><span /></div>
          <div>
            <div className="eyebrow">MITHRIL · SESSION EVIDENCE</div>
            <div className="brand-name">Causal replay</div>
          </div>
        </div>
        <div className="header-state" aria-label="Session state">
          <span className="state-pill confirmed">{sessionGraph.state}</span>
          <span className="state-pill prevented">{sessionGraph.result}</span>
          <span className="header-clock">{formatEventTime(currentOperation.timestamp)} UTC</span>
        </div>
      </header>

      <section className="session-header" aria-labelledby="session-title">
        <div className="session-copy">
          <div className="session-kicker">{sessionGraph.finding} · {sessionGraph.graphVersion}</div>
          <h1 id="session-title">{sessionGraph.title}</h1>
          <p>{sessionGraph.subtitle}</p>
        </div>
        <div className="view-switch" role="group" aria-label="Session view">
          <button type="button" className={view === 'map' ? 'active' : ''} aria-pressed={view === 'map'} onClick={() => setView('map')}>Map</button>
          <button type="button" className={view === 'ledger' ? 'active' : ''} aria-pressed={view === 'ledger'} onClick={() => setView('ledger')}>Ledger</button>
        </div>
      </section>

      <div className="truth-note">
        <span>Scenario replay</span>
        <p>Immutable design fixture. The current product branch does not provide graph, finding, or response APIs.</p>
      </div>

      <section className="controls" aria-label="Graph controls">
        <form className="search" onSubmit={search}>
          <span aria-hidden="true">⌕</span>
          <input value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search all operations" placeholder="Search operations, objects, actors, evidence…" />
          <kbd>↵</kbd>
        </form>
        <label className="filter-control">
          <span>SHOW</span>
          <select value={filter} onChange={(event) => setFilter(event.target.value as Filter)} aria-label="Filter graph">
            <option value="all">All evidence</option>
            <option value="direct">Direct proof</option>
            <option value="contextual">Contextual joins</option>
            <option value="denied">Denied effects</option>
          </select>
        </label>
        <div className="machine-filter" role="group" aria-label="Focus a node">
          <button type="button" className={!focusedMachine ? 'active' : ''} aria-pressed={!focusedMachine} onClick={() => setFocusedMachine(null)}>Session</button>
          {sessionGraph.machines.map((machine) => (
            <button key={machine.id} type="button" className={focusedMachine === machine.id ? 'active' : ''}
              aria-pressed={focusedMachine === machine.id}
              onClick={() => setFocusedMachine((current) => current === machine.id ? null : machine.id)}>
              {machine.name}
            </button>
          ))}
        </div>
        <div className="frame-actions" role="group" aria-label="Frame graph">
          <button type="button" onClick={() => { setPlaying(false); setSelection(null); setStep(0); viewportRef.current?.scrollTo({ left: 0, top: 0, behavior: 'smooth' }); }}>Start</button>
          <button type="button" onClick={frameCurrent}>Current</button>
          <button type="button" onClick={showComplete}>Reveal all</button>
        </div>
      </section>

      {view === 'map' ? (
        <GraphMap
          layout={layout}
          operations={visibleOperations}
          edges={edges}
          currentOperationId={currentOperation.id}
          selectedOperationId={selectedOperationId}
          selectedEdgeId={selectedEdgeId}
          query={query}
          filter={filter}
          focusedMachine={focusedMachine}
          viewportRef={viewportRef}
          onSelectOperation={selectOperation}
          onSelectEdge={selectEdge}
          onFocusMachine={setFocusedMachine}
        />
      ) : (
        <EvidenceLedger
          operations={visibleOperations}
          selectedOperationId={selectedOperationId}
          query={query}
          filter={filter}
          onSelect={selectOperation}
        />
      )}

      <footer className="playback" aria-label="Session replay controls">
        <button type="button" className="play-button" onClick={() => {
          if (step >= finalStep && !playing) replay(); else setPlaying((current) => !current);
        }} aria-label={playing ? 'Pause replay' : step >= finalStep ? 'Replay session' : 'Play replay'}>
          {playing ? 'Ⅱ' : '▶'}
        </button>
        <div className="playback-track">
          <div className="track-meta">
            <span>AGENT EVENT TIME</span>
            <span>step {step + 1}/{finalStep + 1}</span>
          </div>
          <input type="range" min="0" max={finalStep} step="1" value={step} aria-label="Replay position"
            onChange={(event) => { setPlaying(false); setSelection(null); setStep(Number(event.target.value)); }}
            style={{ '--progress': `${step / finalStep * 100}%` } as React.CSSProperties} />
        </div>
        <label className="speed">
          <span className="sr-only">Playback speed</span>
          <select value={speed} onChange={(event) => setSpeed(Number(event.target.value))}>
            <option value="0.5">0.5×</option>
            <option value="1">1×</option>
            <option value="2">2×</option>
          </select>
        </label>
        <div className="proof-summary">
          <span><i className="direct-dot" /> {sessionGraph.edges.length - contextualCount} direct</span>
          <span><i className="context-dot" /> {contextualCount} contextual</span>
        </div>
      </footer>
    </main>
  );
}

interface GraphMapProps {
  layout: ReturnType<typeof createGraphLayout>;
  operations: readonly Operation[];
  edges: readonly CausalEdge[];
  currentOperationId: string;
  selectedOperationId: string | null;
  selectedEdgeId: string | null;
  query: string;
  filter: Filter;
  focusedMachine: string | null;
  viewportRef: React.RefObject<HTMLDivElement | null>;
  onSelectOperation: (operation: Operation) => void;
  onSelectEdge: (edge: CausalEdge) => void;
  onFocusMachine: (machine: string | null) => void;
}

function GraphMap(props: GraphMapProps) {
  const selectedEdge = props.edges.find((edge) => edge.id === props.selectedEdgeId);
  const selectedEdgePosition = selectedEdge ? edgeDetailPosition(selectedEdge, props.layout) : null;

  return (
    <section className="graph-panel" aria-label="Session operation DAG">
      <div className="event-hud" aria-live="polite">
        <div className="event-hud-label">CURRENT OPERATION</div>
        <strong>{operationById.get(props.currentOperationId)?.title}</strong>
        <span>{operationById.get(props.currentOperationId)?.machineId} · {operationById.get(props.currentOperationId)?.summary}</span>
      </div>
      <div className="graph-viewport" ref={props.viewportRef} tabIndex={0} aria-label="Scrollable causal graph">
        <div className="graph-stage" style={{ width: props.layout.width, height: props.layout.height }}>
          {sessionGraph.machines.map((machine, index) => (
            <MachineLane key={machine.id} machine={machine} index={index}
              visibleCount={props.operations.filter((operation) => operation.machineId === machine.id).length}
              totalCount={sessionGraph.operations.filter((operation) => operation.machineId === machine.id).length}
              focused={props.focusedMachine === machine.id}
              dimmed={Boolean(props.focusedMachine && props.focusedMachine !== machine.id)}
              onFocus={() => props.onFocusMachine(props.focusedMachine === machine.id ? null : machine.id)} />
          ))}
          <svg className="edge-layer" width={props.layout.width} height={props.layout.height} aria-hidden="false">
            <defs>
              <marker id="arrow-direct" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" />
              </marker>
              <marker id="arrow-context" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" />
              </marker>
            </defs>
            {props.edges.map((edge) => {
              const source = props.layout.positions.get(edge.source);
              const target = props.layout.positions.get(edge.target);
              if (!source || !target) return null;
              const path = edgePath(source, target);
              const selected = edge.id === props.selectedEdgeId;
              const sourceOperation = operationById.get(edge.source)!;
              const targetOperation = operationById.get(edge.target)!;
              const crossNode = sourceOperation.machineId !== targetOperation.machineId;
              const dimmed = edgeDimmed(edge, props.filter, props.focusedMachine, sourceOperation, targetOperation);
              const labelX = (source.x + source.width + target.x) / 2;
              const labelY = (source.y + target.y) / 2 + NODE_HEIGHT / 2 - 7;
              return (
                <g key={edge.id} className={`edge-group strength-${edge.strength} ${selected ? 'selected' : ''} ${dimmed ? 'dimmed' : ''}`}>
                  <path className="edge-line" d={path} markerEnd={`url(#arrow-${edge.strength === 'contextual' ? 'context' : 'direct'})`} />
                  <path className="edge-hit" d={path} aria-hidden="true" onClick={() => props.onSelectEdge(edge)} />
                  {(crossNode || edge.strength !== 'direct') && (
                    <g className="edge-label" transform={`translate(${labelX} ${labelY})`}>
                      <rect x={-Math.max(34, edge.label.length * 3.1)} y="-10" width={Math.max(68, edge.label.length * 6.2)} height="20" rx="4" />
                      <text textAnchor="middle" dominantBaseline="central">{edge.label}</text>
                    </g>
                  )}
                </g>
              );
            })}
          </svg>
          {props.edges.map((edge) => {
            const source = props.layout.positions.get(edge.source);
            const target = props.layout.positions.get(edge.target);
            if (!source || !target) return null;
            const sourceOperation = operationById.get(edge.source)!;
            const targetOperation = operationById.get(edge.target)!;
            const point = edgeInspectPosition(source, target);
            const dimmed = edgeDimmed(edge, props.filter, props.focusedMachine, sourceOperation, targetOperation);
            return (
              <button key={`inspect-${edge.id}`} type="button"
                className={`edge-inspect strength-${edge.strength} ${edge.id === props.selectedEdgeId ? 'selected' : ''} ${dimmed ? 'dimmed' : ''}`}
                style={{ left: point.x, top: point.y }}
                aria-label={`${edge.label}, ${edge.strength} causal edge from ${sourceOperation.title} to ${targetOperation.title}`}
                title={`Inspect ${edge.label}`} onClick={() => props.onSelectEdge(edge)}>
                <span aria-hidden="true" />
              </button>
            );
          })}
          {props.operations.map((operation) => {
            const position = props.layout.positions.get(operation.id)!;
            const selected = operation.id === props.selectedOperationId;
            return (
              <OperationCard key={operation.id} operation={operation} position={position}
                selected={selected} current={operation.id === props.currentOperationId}
                dimmed={operationDimmed(operation, props.query, props.filter, props.focusedMachine)}
                connected={selected ? connectedOperationIds(sessionGraph.edges, operation.id).length : 0}
                onSelect={() => props.onSelectOperation(operation)} />
            );
          })}
          {selectedEdge && selectedEdgePosition && (
            <EdgeDetail edge={selectedEdge} x={selectedEdgePosition.x} y={selectedEdgePosition.y}
              onClose={() => props.onSelectEdge(selectedEdge)} />
          )}
        </div>
      </div>
    </section>
  );
}

function MachineLane({ machine, index, visibleCount, totalCount, focused, dimmed, onFocus }: {
  machine: Machine;
  index: number;
  visibleCount: number;
  totalCount: number;
  focused: boolean;
  dimmed: boolean;
  onFocus: () => void;
}) {
  return (
    <div className={`machine-lane ${focused ? 'focused' : ''} ${dimmed ? 'dimmed' : ''}`} style={{ height: 220 }}>
      <button type="button" className="lane-label" onClick={onFocus} aria-pressed={focused}>
        <span className="lane-status" />
        <strong>{machine.name}</strong>
        <span>{machine.role} · {machine.address}</span>
        <small>{visibleCount}/{totalCount} operations · {machine.coverage} coverage</small>
      </button>
      <span className="lane-index">NODE {String(index + 1).padStart(2, '0')}</span>
    </div>
  );
}

function OperationCard({ operation, position, selected, current, dimmed, connected, onSelect }: {
  operation: Operation;
  position: ReturnType<typeof createGraphLayout>['positions'] extends ReadonlyMap<string, infer P> ? P : never;
  selected: boolean;
  current: boolean;
  dimmed: boolean;
  connected: number;
  onSelect: () => void;
}) {
  const incoming = sessionGraph.edges.filter((edge) => edge.target === operation.id).length;
  const outgoing = sessionGraph.edges.filter((edge) => edge.source === operation.id).length;
  return (
    <article className={`operation-card outcome-${operation.outcome} proof-${operation.proof} ${selected ? 'expanded' : ''} ${current ? 'current' : ''} ${dimmed ? 'dimmed' : ''}`}
      style={{ left: position.x, top: position.y, width: position.width, minHeight: position.height }}
      data-operation-id={operation.id} data-testid={`operation-${operation.id}`}>
      <button type="button" className="operation-trigger" onClick={onSelect} aria-expanded={selected}>
        <span className="operation-topline"><b>{operation.kind}</b><time>{formatEventTime(operation.timestamp)}</time></span>
        <strong>{operation.title}</strong>
        <span className="operation-state"><i />{operation.outcome}<em>{operation.proof}</em></span>
      </button>
      {selected && (
        <div className="operation-detail">
          <p>{operation.summary}</p>
          <dl>
            <div><dt>ACTOR</dt><dd>{operation.actor}</dd></div>
            <div><dt>OBJECT</dt><dd>{operation.object}</dd></div>
            <div><dt>PROCESS</dt><dd>{operation.process}</dd></div>
            <div><dt>POLICY</dt><dd>{operation.policy}</dd></div>
          </dl>
          <div className="detail-footer">
            <span>{incoming} upstream</span><span>{outgoing} downstream</span><span>{connected} connected</span>
            {operation.evidence.map((evidence) => <code key={evidence}>{evidence}</code>)}
          </div>
        </div>
      )}
    </article>
  );
}

function EdgeDetail({ edge, x, y, onClose }: { edge: CausalEdge; x: number; y: number; onClose: () => void }) {
  return (
    <aside className={`edge-detail strength-${edge.strength}`} style={{ left: x, top: y }} data-testid="edge-detail">
      <button type="button" className="edge-close" onClick={onClose} aria-label="Close edge details">×</button>
      <div className="edge-detail-kicker">{edge.strength} causal edge</div>
      <h2>{edge.label}</h2>
      <p><strong>{operationById.get(edge.source)?.title}</strong><span>→</span><strong>{operationById.get(edge.target)?.title}</strong></p>
      <h3>JOIN EVIDENCE</h3>
      <ul>{edge.join.map((field) => <li key={field}>{field}</li>)}</ul>
      <div className="edge-evidence">{edge.evidence.map((evidence) => <code key={evidence}>{evidence}</code>)}</div>
    </aside>
  );
}

function EvidenceLedger({ operations, selectedOperationId, query, filter, onSelect }: {
  operations: readonly Operation[];
  selectedOperationId: string | null;
  query: string;
  filter: Filter;
  onSelect: (operation: Operation) => void;
}) {
  return (
    <section className="ledger" aria-label="Session evidence ledger">
      <div className="ledger-heading"><span>STEP</span><span>NODE / OPERATION</span><span>RESULT</span><span>PROOF</span><span>EVIDENCE</span></div>
      {operations.map((operation) => {
        const selected = selectedOperationId === operation.id;
        const dimmed = operationDimmed(operation, query, filter, null);
        return (
          <article key={operation.id} className={`ledger-row ${selected ? 'expanded' : ''} ${dimmed ? 'dimmed' : ''}`}>
            <button type="button" onClick={() => onSelect(operation)} aria-expanded={selected}>
              <time>{String(operation.step + 1).padStart(2, '0')} · {formatEventTime(operation.timestamp)}</time>
              <span><small>{operation.machineId} · {operation.kind}</small><strong>{operation.title}</strong></span>
              <b className={`outcome-${operation.outcome}`}>{operation.outcome}</b>
              <em>{operation.proof}</em>
              <code>{operation.evidence[0]}</code>
            </button>
            {selected && (
              <div className="ledger-detail">
                <p>{operation.summary}</p>
                <dl><div><dt>Actor</dt><dd>{operation.actor}</dd></div><div><dt>Object</dt><dd>{operation.object}</dd></div><div><dt>Process</dt><dd>{operation.process}</dd></div><div><dt>Policy</dt><dd>{operation.policy}</dd></div></dl>
              </div>
            )}
          </article>
        );
      })}
      <div className="ledger-tail">{sessionGraph.operations.length - operations.length} later operations remain beyond the replay cursor.</div>
    </section>
  );
}

function operationMatches(operation: Operation, query: string, filter: Filter): boolean {
  const normalized = query.trim().toLowerCase();
  const textMatch = !normalized || [operation.title, operation.summary, operation.actor, operation.object, operation.process, operation.policy, ...operation.evidence]
    .join(' ').toLowerCase().includes(normalized);
  const filterMatch = filter === 'all'
    || (filter === 'direct' && operation.proof === 'direct')
    || (filter === 'contextual' && operation.proof === 'contextual')
    || (filter === 'denied' && operation.outcome === 'denied');
  return textMatch && filterMatch;
}

function operationDimmed(operation: Operation, query: string, filter: Filter, focusedMachine: string | null): boolean {
  return !operationMatches(operation, query, filter) || Boolean(focusedMachine && operation.machineId !== focusedMachine);
}

function edgeDimmed(edge: CausalEdge, filter: Filter, focusedMachine: string | null, source: Operation, target: Operation): boolean {
  const filterMismatch = (filter === 'direct' && edge.strength !== 'direct')
    || (filter === 'contextual' && edge.strength !== 'contextual')
    || (filter === 'denied' && source.outcome !== 'denied' && target.outcome !== 'denied');
  const machineMismatch = focusedMachine && source.machineId !== focusedMachine && target.machineId !== focusedMachine;
  return Boolean(filterMismatch || machineMismatch);
}

function edgeDetailPosition(edge: CausalEdge, layout: ReturnType<typeof createGraphLayout>): { x: number; y: number } | null {
  const source = layout.positions.get(edge.source);
  const target = layout.positions.get(edge.target);
  if (!source || !target) return null;
  return {
    x: Math.min(layout.width - 378, Math.max(210, (source.x + source.width + target.x) / 2 - 174)),
    y: Math.min(layout.height - 240, Math.max(18, (source.y + target.y) / 2 - 34)),
  };
}

function edgeInspectPosition(source: { x: number; y: number; width: number }, target: { x: number; y: number }): { x: number; y: number } {
  return {
    x: (source.x + source.width + target.x) / 2 - 14,
    y: (source.y + target.y) / 2 + NODE_HEIGHT / 2 - 14,
  };
}
