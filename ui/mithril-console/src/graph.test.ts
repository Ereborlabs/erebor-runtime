import { describe, expect, it } from 'vitest';
import { sessionGraph } from './data';
import {
  connectedOperationIds,
  createGraphLayout,
  edgePath,
  EXPANDED_WIDTH,
  NODE_WIDTH,
  visibleAtStep,
  visibleEdges,
} from './graph';

describe('session graph', () => {
  it('keeps the requested session slice acyclic and ordered by causal rank', () => {
    const operations = new Map(sessionGraph.operations.map((operation) => [operation.id, operation]));
    for (const edge of sessionGraph.edges) {
      expect(operations.get(edge.source)!.rank).toBeLessThan(operations.get(edge.target)!.rank);
    }
  });

  it('reveals only operations and unchanged edges available at the replay step', () => {
    const operations = visibleAtStep(sessionGraph.operations, 5);
    const ids = new Set(operations.map((operation) => operation.id));
    const edges = visibleEdges(sessionGraph.edges, ids);

    expect(ids.has('pod-revision')).toBe(true);
    expect(ids.has('scheduler-bind')).toBe(false);
    expect(edges.every((edge) => ids.has(edge.source) && ids.has(edge.target))).toBe(true);
    expect(edges.every((edge) => sessionGraph.edges.includes(edge))).toBe(true);
  });

  it('expands one operation in place and moves only later causal ranks', () => {
    const closed = createGraphLayout(sessionGraph.operations, sessionGraph.machines, null);
    const open = createGraphLayout(sessionGraph.operations, sessionGraph.machines, 'secret-open');

    expect(closed.positions.get('secret-open')!.width).toBe(NODE_WIDTH);
    expect(open.positions.get('secret-open')!.width).toBe(EXPANDED_WIDTH);
    expect(open.positions.get('app-active')!.x).toBe(closed.positions.get('app-active')!.x);
    expect(open.positions.get('finding')!.x).toBeGreaterThan(closed.positions.get('finding')!.x);
  });

  it('keeps multiple causal parents and connected neighbors', () => {
    const incoming = sessionGraph.edges.filter((edge) => edge.target === 'prepared');
    expect(incoming.map((edge) => edge.source).sort()).toEqual(['candidate-delivery', 'runtime-stage']);
    expect([...connectedOperationIds(sessionGraph.edges, 'prepared')].sort()).toEqual([
      'app-active', 'candidate-delivery', 'runtime-stage',
    ]);
  });

  it('draws a directional path between operation headers', () => {
    const layout = createGraphLayout(sessionGraph.operations, sessionGraph.machines, null);
    const path = edgePath(layout.positions.get('app-active')!, layout.positions.get('secret-open')!);
    expect(path).toMatch(/^M /);
    expect(path).toContain(' C ');
    expect(path).toContain(String(layout.positions.get('secret-open')!.x));
  });
});
