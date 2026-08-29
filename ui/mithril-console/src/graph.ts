import type { CausalEdge, Machine, Operation } from './data';

export const NODE_WIDTH = 158;
export const NODE_HEIGHT = 70;
export const EXPANDED_WIDTH = 326;
export const LANE_HEIGHT = 220;
export const GRAPH_START_X = 214;
export const RANK_GAP = 190;

export interface Point {
  x: number;
  y: number;
}

export interface OperationPosition extends Point {
  width: number;
  height: number;
  machineIndex: number;
}

export interface GraphLayout {
  width: number;
  height: number;
  positions: ReadonlyMap<string, OperationPosition>;
}

export function createGraphLayout(
  operations: readonly Operation[],
  machines: readonly Machine[],
  selectedOperationId: string | null,
): GraphLayout {
  const ranks = [...new Set(operations.map((operation) => operation.rank))].sort((left, right) => left - right);
  const selectedRank = operations.find((operation) => operation.id === selectedOperationId)?.rank;
  const rankX = new Map<number, number>();
  let cursor = GRAPH_START_X;
  for (const rank of ranks) {
    rankX.set(rank, cursor);
    cursor += rank === selectedRank ? EXPANDED_WIDTH + 54 : RANK_GAP;
  }

  const machineIndex = new Map(machines.map((machine, index) => [machine.id, index]));
  const positions = new Map<string, OperationPosition>();
  for (const operation of operations) {
    const index = machineIndex.get(operation.machineId);
    if (index === undefined) continue;
    const expanded = operation.id === selectedOperationId;
    positions.set(operation.id, {
      x: rankX.get(operation.rank) ?? GRAPH_START_X,
      y: index * LANE_HEIGHT + 72,
      width: expanded ? EXPANDED_WIDTH : NODE_WIDTH,
      height: expanded ? 176 : NODE_HEIGHT,
      machineIndex: index,
    });
  }

  return {
    width: Math.max(980, cursor + 120),
    height: machines.length * LANE_HEIGHT,
    positions,
  };
}

export function visibleAtStep(operations: readonly Operation[], step: number): readonly Operation[] {
  return operations.filter((operation) => operation.step <= step);
}

export function visibleEdges(
  edges: readonly CausalEdge[],
  visibleOperationIds: ReadonlySet<string>,
): readonly CausalEdge[] {
  return edges.filter((edge) => visibleOperationIds.has(edge.source) && visibleOperationIds.has(edge.target));
}

export function connectedOperationIds(edges: readonly CausalEdge[], operationId: string): readonly string[] {
  return [...new Set(edges.flatMap((edge) => {
    if (edge.source === operationId) return [edge.target];
    if (edge.target === operationId) return [edge.source];
    return [];
  }))];
}

export function edgePath(source: OperationPosition, target: OperationPosition): string {
  const sourceX = source.x + source.width;
  const sourceY = source.y + NODE_HEIGHT / 2;
  const targetX = target.x;
  const targetY = target.y + NODE_HEIGHT / 2;
  const distance = Math.max(48, (targetX - sourceX) * 0.42);
  return `M ${sourceX} ${sourceY} C ${sourceX + distance} ${sourceY}, ${targetX - distance} ${targetY}, ${targetX} ${targetY}`;
}

export function formatEventTime(value: string): string {
  return new Intl.DateTimeFormat('en-CA', {
    hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3,
    hour12: false, timeZone: 'UTC',
  }).format(new Date(value));
}
