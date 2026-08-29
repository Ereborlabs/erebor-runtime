export type CauseStrength = 'direct' | 'contextual' | 'contradicted' | 'superseded';
export type CoverageState = 'complete' | 'gapped' | 'unknown';
export type Outcome = 'observed' | 'allowed' | 'verified' | 'succeeded' | 'denied' | 'confirmed' | 'proposed';

export interface Machine {
  id: string;
  name: string;
  role: string;
  address: string;
  coverage: CoverageState;
}

export interface Operation {
  id: string;
  step: number;
  rank: number;
  machineId: string;
  kind: string;
  title: string;
  summary: string;
  timestamp: string;
  outcome: Outcome;
  proof: CauseStrength;
  actor: string;
  object: string;
  process: string;
  policy: string;
  coverage: CoverageState;
  evidence: readonly string[];
}

export interface CausalEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  strength: CauseStrength;
  join: readonly string[];
  evidence: readonly string[];
}

export interface SessionGraph {
  id: string;
  title: string;
  subtitle: string;
  graphVersion: string;
  finding: string;
  state: string;
  result: string;
  startedAt: string;
  machines: readonly Machine[];
  operations: readonly Operation[];
  edges: readonly CausalEdge[];
}

export const sessionGraph: SessionGraph = {
  id: 'session-hf-xnode-021',
  title: 'Credentialed agent created a workload on another node',
  subtitle: 'The workload started. Its first prohibited secret read was denied before effect.',
  graphVersion: 'graph-7f4c.18',
  finding: 'HF-XNODE-001 / revision 4',
  state: 'CONFIRMED',
  result: 'PREVENTED',
  startedAt: '2026-08-28T14:32:18.140Z',
  machines: [
    { id: 'worker-a', name: 'worker-a', role: 'source workload', address: '10.42.1.17', coverage: 'complete' },
    { id: 'control-plane', name: 'control-plane', role: 'Kubernetes authority', address: '10.42.0.1', coverage: 'complete' },
    { id: 'worker-b', name: 'worker-b', role: 'target workload', address: '10.42.2.21', coverage: 'complete' },
  ],
  operations: [
    {
      id: 'session-open', step: 0, rank: 0, machineId: 'worker-a', kind: 'session',
      title: 'Agent session observed', summary: 'A protected agent entry started in payments-api.',
      timestamp: '2026-08-28T14:32:18.140Z', outcome: 'observed', proof: 'direct',
      actor: 'payments-agent', object: 'session/session-hf-xnode-021', process: 'agent.py · pid 3184',
      policy: 'payments-protect@118', coverage: 'complete', evidence: ['obs-wa-8801'],
    },
    {
      id: 'policy-source', step: 0, rank: 0, machineId: 'control-plane', kind: 'policy',
      title: 'Policy revision active', summary: 'The exact signed policy source and target inventory were current.',
      timestamp: '2026-08-28T14:32:18.140Z', outcome: 'verified', proof: 'direct',
      actor: 'mithril-control', object: 'WorkloadProtectionPolicy/payments-protect', process: 'control · leader 3',
      policy: 'source 118 · generation 7f4c', coverage: 'complete', evidence: ['policy-src-118', 'activation-ack-wb-77'],
    },
    {
      id: 'agent-entry', step: 1, rank: 1, machineId: 'worker-a', kind: 'process',
      title: 'Application entry active', summary: 'The signed application entry installed the agent role.',
      timestamp: '2026-08-28T14:32:18.392Z', outcome: 'allowed', proof: 'direct',
      actor: 'task/7be2', object: '/opt/app/agent.py', process: 'python · pid 3184',
      policy: 'role agent-runtime · entry application', coverage: 'complete', evidence: ['obs-wa-8802', 'binding-wa-c31'],
    },
    {
      id: 'node-ready', step: 1, rank: 1, machineId: 'worker-b', kind: 'readiness',
      title: 'Node authority healthy', summary: 'The node session, boot, BPF state, and admission gate were current.',
      timestamp: '2026-08-28T14:32:18.401Z', outcome: 'verified', proof: 'direct',
      actor: 'mithril-node', object: 'Node/worker-b@uid-b21', process: 'mithril-node · boot b-91',
      policy: 'label epoch 12', coverage: 'complete', evidence: ['node-session-wb-91', 'health-wb-441'],
    },
    {
      id: 'credential-open', step: 2, rank: 2, machineId: 'worker-a', kind: 'file',
      title: 'ServiceAccount token opened', summary: 'The exact task opened the projected credential for read.',
      timestamp: '2026-08-28T14:32:19.008Z', outcome: 'allowed', proof: 'direct',
      actor: 'task/7be2', object: '/var/run/secrets/kubernetes.io/serviceaccount/token', process: 'python · pid 3184',
      policy: 'rule k8s-token-read', coverage: 'complete', evidence: ['obs-wa-8807', 'object-92d1'],
    },
    {
      id: 'api-send', step: 3, rank: 3, machineId: 'worker-a', kind: 'network',
      title: 'Kubernetes request sent', summary: 'The same process sent a Pod create request on its API socket.',
      timestamp: '2026-08-28T14:32:19.441Z', outcome: 'succeeded', proof: 'direct',
      actor: 'task/7be2 · socket 0x9f2', object: '10.42.0.1:6443', process: 'python · pid 3184',
      policy: 'rule kubernetes-api', coverage: 'complete', evidence: ['obs-wa-8811', 'socket-9f2'],
    },
    {
      id: 'api-request', step: 4, rank: 4, machineId: 'control-plane', kind: 'request',
      title: 'Pod create accepted', summary: 'The API server authenticated the ServiceAccount and accepted the request.',
      timestamp: '2026-08-28T14:32:19.516Z', outcome: 'succeeded', proof: 'contextual',
      actor: 'system:serviceaccount:payments:payments-api', object: 'POST pods', process: 'kube-apiserver',
      policy: 'request uid req-4f39', coverage: 'complete', evidence: ['audit-4f39', 'request-4f39'],
    },
    {
      id: 'pod-revision', step: 5, rank: 5, machineId: 'control-plane', kind: 'object',
      title: 'Pod revision persisted', summary: 'Kubernetes stored one immutable Pod UID and resource version.',
      timestamp: '2026-08-28T14:32:19.588Z', outcome: 'verified', proof: 'direct',
      actor: 'kube-apiserver', object: 'Pod/payments-debug@uid-p74', process: 'etcd transaction',
      policy: 'resourceVersion 882104', coverage: 'complete', evidence: ['object-p74-rv882104'],
    },
    {
      id: 'scheduler-bind', step: 6, rank: 6, machineId: 'control-plane', kind: 'binding',
      title: 'Scheduler selected worker-b', summary: 'The persisted Pod UID was bound to the current ready node UID.',
      timestamp: '2026-08-28T14:32:19.742Z', outcome: 'verified', proof: 'direct',
      actor: 'kube-scheduler', object: 'Pod uid-p74 → Node uid-b21', process: 'scheduler binding',
      policy: 'binding bind-332a', coverage: 'complete', evidence: ['binding-332a', 'node-session-wb-91'],
    },
    {
      id: 'candidate-delivery', step: 7, rank: 7, machineId: 'control-plane', kind: 'policy',
      title: 'Target candidate delivered', summary: 'Control sent the signed workload material only to worker-b.',
      timestamp: '2026-08-28T14:32:19.910Z', outcome: 'verified', proof: 'direct',
      actor: 'PolicyRolloutOwner', object: 'candidate/cand-7f4c-b21', process: 'NodePolicy gRPC',
      policy: 'generation 7f4c · target p74', coverage: 'complete', evidence: ['candidate-7f4c-b21', 'delivery-ack-77'],
    },
    {
      id: 'runtime-stage', step: 7, rank: 7, machineId: 'worker-b', kind: 'runtime',
      title: 'Runtime facts staged', summary: 'The first createRuntime hook staged immutable container facts without authority.',
      timestamp: '2026-08-28T14:32:19.934Z', outcome: 'verified', proof: 'direct',
      actor: 'containerd + NRI', object: 'container ctr-b6d4', process: 'runc create · held',
      policy: 'stage nonce stg-91a', coverage: 'complete', evidence: ['runtime-stage-91a', 'cri-container-b6d4'],
    },
    {
      id: 'prepared', step: 8, rank: 8, machineId: 'worker-b', kind: 'runtime',
      title: 'Container binding prepared', summary: 'Policy and exact cgroup binding readback passed before release.',
      timestamp: '2026-08-28T14:32:20.084Z', outcome: 'verified', proof: 'direct',
      actor: 'mithril-node', object: 'binding cgroup-814 · ctr-b6d4', process: 'held pid 6128',
      policy: 'PREPARED · generation 7f4c', coverage: 'complete', evidence: ['binding-cgroup-814', 'readback-7f4c'],
    },
    {
      id: 'app-active', step: 9, rank: 9, machineId: 'worker-b', kind: 'process',
      title: 'Application entry active', summary: 'The approved exec closed prepared-runtime trust and installed one role.',
      timestamp: '2026-08-28T14:32:20.221Z', outcome: 'allowed', proof: 'direct',
      actor: 'task/b812', object: '/bin/sh', process: 'sh · pid 6128',
      policy: 'ACTIVE · role debug-job', coverage: 'complete', evidence: ['exec-b812', 'entry-debug-job'],
    },
    {
      id: 'secret-open', step: 10, rank: 10, machineId: 'worker-b', kind: 'file',
      title: 'Secret object open denied', summary: 'The exact open was rejected before an fd or secret bytes existed.',
      timestamp: '2026-08-28T14:32:20.672Z', outcome: 'denied', proof: 'direct',
      actor: 'task/b812', object: '/var/run/secrets/cloud/token', process: 'sh · pid 6128',
      policy: 'rule cloud-token-deny · errno EACCES', coverage: 'complete', evidence: ['obs-wb-4421', 'decision-deny-443'],
    },
    {
      id: 'finding', step: 11, rank: 11, machineId: 'control-plane', kind: 'finding',
      title: 'Cross-node finding confirmed', summary: 'The graph retained one contextual task-to-request join and exact downstream joins.',
      timestamp: '2026-08-28T14:32:21.019Z', outcome: 'confirmed', proof: 'direct',
      actor: 'HF-XNODE-001', object: 'finding/f-74ac revision 4', process: 'GraphAndFindingOwner',
      policy: 'graph-7f4c.18', coverage: 'complete', evidence: ['finding-f74ac-r4', 'coverage-set-09'],
    },
    {
      id: 'response-plan', step: 12, rank: 12, machineId: 'control-plane', kind: 'response',
      title: 'Containment plan proposed', summary: 'The plan froze this graph revision and disclosed the Pod-wide blast radius.',
      timestamp: '2026-08-28T14:32:21.310Z', outcome: 'proposed', proof: 'direct',
      actor: 'ResponseCoordinator', object: 'plan/rsp-28 revision 1', process: 'simulation only',
      policy: 'requires operator authorization', coverage: 'complete', evidence: ['response-plan-28-r1'],
    },
    {
      id: 'healthy-watch', step: 13, rank: 13, machineId: 'worker-b', kind: 'coverage',
      title: 'Denied branch stayed closed', summary: 'Healthy coverage showed no successful replacement secret access.',
      timestamp: '2026-08-28T14:32:22.004Z', outcome: 'verified', proof: 'direct',
      actor: 'CoverageHealthOwner', object: 'interval cov-wb-441', process: 'node evidence stream',
      policy: 'observation complete', coverage: 'complete', evidence: ['coverage-wb-441', 'watch-rsp-28'],
    },
  ],
  edges: [
    { id: 'e-session-entry', source: 'session-open', target: 'agent-entry', label: 'entry identity', strength: 'direct', join: ['binding c31', 'task 7be2'], evidence: ['obs-wa-8801', 'obs-wa-8802'] },
    { id: 'e-entry-credential', source: 'agent-entry', target: 'credential-open', label: 'same task', strength: 'direct', join: ['task 7be2', 'process 3184'], evidence: ['obs-wa-8802', 'obs-wa-8807'] },
    { id: 'e-credential-send', source: 'credential-open', target: 'api-send', label: 'task + socket', strength: 'direct', join: ['task 7be2', 'socket 0x9f2'], evidence: ['obs-wa-8807', 'obs-wa-8811'] },
    { id: 'e-send-request', source: 'api-send', target: 'api-request', label: 'shared principal', strength: 'contextual', join: ['ServiceAccount payments-api', 'destination 10.42.0.1:6443', 'causal order'], evidence: ['obs-wa-8811', 'audit-4f39'] },
    { id: 'e-request-object', source: 'api-request', target: 'pod-revision', label: 'request UID', strength: 'direct', join: ['request req-4f39', 'Pod uid-p74', 'resourceVersion 882104'], evidence: ['request-4f39', 'object-p74-rv882104'] },
    { id: 'e-object-bind', source: 'pod-revision', target: 'scheduler-bind', label: 'Pod UID', strength: 'direct', join: ['Pod uid-p74', 'binding bind-332a'], evidence: ['object-p74-rv882104', 'binding-332a'] },
    { id: 'e-ready-bind', source: 'node-ready', target: 'scheduler-bind', label: 'node UID + boot', strength: 'direct', join: ['Node uid-b21', 'boot b-91', 'label epoch 12'], evidence: ['node-session-wb-91', 'binding-332a'] },
    { id: 'e-policy-candidate', source: 'policy-source', target: 'candidate-delivery', label: 'source revision', strength: 'direct', join: ['source 118', 'generation 7f4c'], evidence: ['policy-src-118', 'candidate-7f4c-b21'] },
    { id: 'e-bind-candidate', source: 'scheduler-bind', target: 'candidate-delivery', label: 'target snapshot', strength: 'direct', join: ['Pod uid-p74', 'Node uid-b21', 'candidate cand-7f4c-b21'], evidence: ['binding-332a', 'candidate-7f4c-b21'] },
    { id: 'e-bind-runtime', source: 'scheduler-bind', target: 'runtime-stage', label: 'container target', strength: 'direct', join: ['Pod uid-p74', 'container ctr-b6d4', 'Node uid-b21'], evidence: ['binding-332a', 'runtime-stage-91a'] },
    { id: 'e-candidate-prepared', source: 'candidate-delivery', target: 'prepared', label: 'signed generation', strength: 'direct', join: ['candidate cand-7f4c-b21', 'generation 7f4c'], evidence: ['delivery-ack-77', 'readback-7f4c'] },
    { id: 'e-stage-prepared', source: 'runtime-stage', target: 'prepared', label: 'stage nonce', strength: 'direct', join: ['stage stg-91a', 'container ctr-b6d4', 'held pid 6128'], evidence: ['runtime-stage-91a', 'binding-cgroup-814'] },
    { id: 'e-prepared-active', source: 'prepared', target: 'app-active', label: 'exec commit', strength: 'direct', join: ['binding cgroup-814', 'task b812', 'entry debug-job'], evidence: ['binding-cgroup-814', 'exec-b812'] },
    { id: 'e-active-deny', source: 'app-active', target: 'secret-open', label: 'exact task + object', strength: 'direct', join: ['task b812', 'object cloud-token', 'rule cloud-token-deny'], evidence: ['exec-b812', 'decision-deny-443'] },
    { id: 'e-deny-finding', source: 'secret-open', target: 'finding', label: 'immutable evidence', strength: 'direct', join: ['observation obs-wb-4421', 'graph graph-7f4c.18'], evidence: ['obs-wb-4421', 'finding-f74ac-r4'] },
    { id: 'e-request-finding', source: 'api-request', target: 'finding', label: 'context retained', strength: 'contextual', join: ['request req-4f39', 'shared ServiceAccount'], evidence: ['audit-4f39', 'finding-f74ac-r4'] },
    { id: 'e-finding-response', source: 'finding', target: 'response-plan', label: 'frozen revision', strength: 'direct', join: ['finding f-74ac r4', 'graph graph-7f4c.18'], evidence: ['finding-f74ac-r4', 'response-plan-28-r1'] },
    { id: 'e-response-watch', source: 'response-plan', target: 'healthy-watch', label: 'required watch', strength: 'direct', join: ['plan rsp-28 r1', 'coverage cov-wb-441'], evidence: ['response-plan-28-r1', 'coverage-wb-441'] },
  ],
};

export const operationById = new Map(sessionGraph.operations.map((operation) => [operation.id, operation]));

