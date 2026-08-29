export const consoleData = {
  snapshot: {
    capturedAt: '2026-08-28T14:32:22.004Z',
    tenant: 'erebor-labs',
    cluster: 'production-ca1',
    mode: 'Scenario replay',
  },
  metrics: [
    { label: 'Protected workloads', value: '18 / 19', detail: '1 admission pending', tone: 'good', route: 'policies' },
    { label: 'Active generation', value: '6 / 7', detail: 'worker-c staged', tone: 'warn', route: 'policies' },
    { label: 'Evidence sources', value: '5 / 6', detail: 'GitHub audit delayed', tone: 'warn', route: 'evidence' },
    { label: 'Open findings', value: '4', detail: '1 critical · 2 high', tone: 'critical', route: 'findings' },
  ],
  sessions: [
    { id: 'session-hf-xnode-021', time: '14:32:18', actor: 'payments-agent', scope: 'payments / payments-api', title: 'Credentialed agent created a workload on another node', machines: 3, operations: 17, result: 'prevented', proof: '16 direct · 2 contextual', graph: 'graph-7f4c.18', replay: true },
    { id: 'session-hf-local-104', time: '14:29:02', actor: 'model-evaluator', scope: 'models / evaluator', title: 'Credential relay flow fenced and verified', machines: 1, operations: 11, result: 'verified', proof: '11 direct', graph: 'graph-21ba.9', replay: false },
    { id: 'session-provider-033', time: '13:48:14', actor: 'model-publisher', scope: 'delivery / publisher', title: 'Provider request retained a shared-principal branch', machines: 2, operations: 9, result: 'partial', proof: '8 direct · 1 contextual', graph: 'graph-a09c.3', replay: false },
  ],
  findings: [
    { id: 'MF-2419', severity: 'critical', outcome: 'prevented', age: 'now', title: 'Cross-node workload reached a denied secret boundary', package: 'HF-XNODE-001', scope: 'payments / payments-api', summary: 'A credentialed agent created a workload on worker-b. The workload started. Mithril denied its first prohibited secret open before an fd or secret bytes existed.', firstEffect: 'Secret object open', result: 'DENIED_BEFORE_EFFECT', proof: '16 direct · 2 contextual · complete coverage', graph: true },
    { id: 'MF-2417', severity: 'high', outcome: 'verified', age: '3m', title: 'Credential relay flow fenced and verified', package: 'HF-DW-001', scope: 'models / evaluator', summary: 'The exact socket was fenced. Readback and a healthy watch interval show that the flow did not return.', firstEffect: 'TCP send', result: 'VERIFIED', proof: '11 direct · complete coverage', graph: false },
    { id: 'MF-2412', severity: 'high', outcome: 'partial', age: '44m', title: 'Provider request retained a shared-principal branch', package: 'HF-PROC-001', scope: 'delivery / publisher', summary: 'Provider audit proves the request. A shared installation principal prevents an exact process-to-request join.', firstEffect: 'Provider API request', result: 'PARTIAL', proof: '8 direct · 1 contextual', graph: false },
    { id: 'MF-2402', severity: 'medium', outcome: 'outside', age: '2h', title: 'In-memory packaging had no distinguishable file effect', package: 'HF-005', scope: 'research / packer', summary: 'The bytes remained inside the process before an allowed encrypted upload. Mithril records the boundary and does not invent a file result.', firstEffect: 'Encrypted payload', result: 'OUTSIDE_AUTHORITY', proof: 'Exact local process · payload unobservable', graph: false },
    { id: 'MF-2391', severity: 'low', outcome: 'allowed', age: '4h', title: 'Signed trainer read the approved model shard', package: 'HF-LOCAL-001', scope: 'models / trainer', summary: 'The admitted application entry read an approved object under the current node generation.', firstEffect: 'File open', result: 'ALLOWED', proof: 'Exact actor, object, policy, and result', graph: false },
  ],
  policies: [
    { name: 'payments-protect', namespace: 'payments', mode: 'Protect', source: '118', generation: '7f4c', desired: 7, active: 6, state: 'Mixed', detail: 'worker-c is staged. Its last valid generation remains active.', selector: 'app=payments-api', defaultAction: 'Deny', rules: 'allow file.read model-cache/**\ndeny file.read secrets/**\nallow network.connect kubernetes-api' },
    { name: 'model-delivery', namespace: 'delivery', mode: 'Protect', source: '42', generation: '21ba', desired: 3, active: 3, state: 'Current', detail: 'All exact targets acknowledge the signed candidate.', selector: 'app=model-publisher', defaultAction: 'Deny', rules: 'allow file.read release/**\nallow network.connect registry.internal\ndeny process.exec shell' },
    { name: 'research-observe', namespace: 'research', mode: 'Observe', source: '8', generation: '11d8', desired: 4, active: 4, state: 'Observe', detail: 'The policy records effects. It does not make a prevention claim.', selector: 'team=research', defaultAction: 'Observe', rules: 'observe file.read datasets/**\nobserve network.connect external\nobserve process.exec notebook-kernel' },
  ],
  observeSuggestions: [
    { id: 'sug-dataset-cache', policy: 'research-observe', title: 'Allow signed dataset cache reads', rule: 'allow file.read datasets/cache/**', evidence: '184 exact reads · 7 workloads · 14 days', confidence: 'High', effect: 'Narrows one observed file branch to a signed cache path.' },
    { id: 'sug-model-registry', policy: 'research-observe', title: 'Allow the internal model registry', rule: 'allow network.connect registry.models.internal:443', evidence: '63 exact connects · mTLS identity retained', confidence: 'High', effect: 'Keeps other external destinations in Observe mode.' },
    { id: 'sug-shell-boundary', policy: 'research-observe', title: 'Propose a shell execution boundary', rule: 'deny process.exec /bin/sh outside=notebook-kernel', evidence: '3 shell starts · 0 signed workflow matches', confidence: 'Review', effect: 'Would prevent unmatched shell entry after Protect activation.' },
  ],
  rolloutNodes: [
    { name: 'worker-a', identity: 'uid-a17c · boot 884', generation: '7f4c', state: 'Active', detail: 'readback complete' },
    { name: 'worker-b', identity: 'uid-b802 · boot 311', generation: '7f4c', state: 'Active', detail: 'readback complete' },
    { name: 'worker-c', identity: 'uid-c09f · boot 154', generation: '6e21', state: 'Staged', detail: '7f4c probe pending · 6e21 active' },
  ],
  evidenceSources: [
    { name: 'File effects', owner: 'node', cursor: 'epoch 884 · seq 39812', state: 'healthy', coverage: 'Continuous', lag: '18 ms' },
    { name: 'Process identity', owner: 'node', cursor: 'epoch 884 · seq 8011', state: 'healthy', coverage: 'Continuous', lag: '11 ms' },
    { name: 'Network effects', owner: 'node', cursor: 'epoch 884 · seq 21044', state: 'healthy', coverage: 'Continuous', lag: '23 ms' },
    { name: 'Kubernetes audit', owner: 'control', cursor: 'rv 893018', state: 'healthy', coverage: 'Continuous', lag: '420 ms' },
    { name: 'Control intake', owner: 'control', cursor: 'commit 44d2', state: 'healthy', coverage: 'Durable to 14:32:22', lag: '31 ms' },
    { name: 'GitHub audit', owner: 'connector', cursor: 'page 71', state: 'degraded', coverage: 'Gap 14:21–14:24', lag: '11 min' },
  ],
  evidenceRecords: [
    { time: '14:32:22.004', source: 'node-watch', result: 'DENIED_BRANCH_CLOSED', subject: 'task b812 · cloud/token', proof: 'healthy interval' },
    { time: '14:32:20.672', source: 'file-effect', result: 'DENIED_BEFORE_EFFECT', subject: 'task b812 → cloud/token', proof: 'exact task + object + rule' },
    { time: '14:32:19.742', source: 'kubernetes-audit', result: 'BOUND', subject: 'Pod uid-p74 → Node uid-b21', proof: 'exact Pod UID + node UID' },
    { time: '14:32:19.516', source: 'kubernetes-audit', result: 'REQUEST_ACCEPTED', subject: 'ServiceAccount payments-api', proof: 'contextual process join' },
  ],
  response: {
    id: 'rsp-28', state: 'Proposed', graph: 'graph-7f4c.18', finding: 'MF-2419 revision 4', expires: '14:47 UTC', approval: 'Required',
    summary: 'The plan freezes the confirmed finding and graph revision. Simulation shows one shared identity target.',
    actions: [
      { order: '01', action: 'Isolate workload network', target: 'Pod payments/payments-debug@uid-p74', scope: 'one Pod', state: 'Ready' },
      { order: '02', action: 'Suspend Kubernetes identity', target: 'ServiceAccount payments/payments-api', scope: '4 active Pods', state: 'Approval required' },
      { order: '03', action: 'Verify postcondition', target: 'Pod uid-p74 + node watch', scope: 'healthy interval', state: 'Pending' },
    ],
  },
  conformance: [
    { id: 'platform', label: 'Platform manifest', detail: 'amd64 · Linux 6.8 · containerd 2.2 · Kubernetes 1.35', state: 'passed' },
    { id: 'ownership', label: 'Ownership and least privilege', detail: 'One owner and one writer per durable state', state: 'passed' },
    { id: 'fixtures', label: 'Active fixture equality', detail: '131 / 133 required cases recorded', state: 'blocked' },
    { id: 'upgrade', label: 'Upgrade and rollback', detail: 'Node, Control, ABI, policy, and trust rotation passed', state: 'passed' },
    { id: 'performance', label: 'Capacity and performance', detail: 'Evidence-enabled bounds retained', state: 'passed' },
    { id: 'providers', label: 'Provider recovery readback', detail: 'GitHub audit gap prevents an exact result', state: 'blocked' },
    { id: 'artifacts', label: 'Signed artifacts and provenance', detail: 'Image, Helm, SBOM, and source digests match', state: 'passed' },
  ],
  release: {
    candidate: 'mithril 0.9.0-rc2', manifest: 'qual-amd64-k8s135-2c8e',
    digest: 'sha256:8f8b1f4093a8c78660aa32b4adf7d777ad9c3eff96470b791afe6887935e1f07',
    claim: 'Linux and Kubernetes pre-effect prevention with loss-aware evidence, cross-node causality, and typed verified response on the named platform manifest.',
    excluded: ['Seccomp', 'L7 mediation', 'Checkpoint authority', 'Named CI adapters'],
  },
} as const;

export type ConsoleRoute = 'operations' | 'sessions' | 'findings' | 'policies' | 'evidence' | 'response' | 'release';
export type ConsoleFinding = (typeof consoleData.findings)[number];
