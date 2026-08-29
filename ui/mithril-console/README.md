# Mithril console fixture

This package is an isolated design fixture for the Mithril console. It does not import or change Mithril or Erebor Runtime code.

The console contains Operations, Sessions, Findings, Policy rollout, Evidence, Response, and Release workspaces. The Sessions workspace opens the causal replay for one immutable graph revision.

Policy rollout supports policy selection and a local draft editor. The editor validates the workload selector and rule set. A saved draft changes browser memory only. It does not write to Mithril Control.

An Observe policy shows evidence-backed policy suggestions. Apply adds the proposed rule to the local draft. Apply does not switch the policy to Protect mode or activate enforcement.

The replay keeps each machine in a stable lane. It shows first-class operation and cross-node edges. Select an operation to expand its evidence in the map. Select an edge point or edge line to inspect its join fields. The ledger uses the same replay cursor and selection.

The fixture states its product boundary in the interface. The current product branch does not provide the graph, finding, or response application programming interfaces (APIs).

## Run

Run these commands from this directory:

```sh
npm install
npm run dev
```

Open `http://127.0.0.1:4173/` to start in Operations. Use the primary navigation to open each workspace.

Open `http://127.0.0.1:4173/#/sessions/session-hf-xnode-021` to open the causal replay. The replay starts automatically. Open `http://127.0.0.1:4173/?autoplay=0#/sessions/session-hf-xnode-021` to show the complete graph at startup.

## Verify

```sh
npm run check
npm test
npm run build
npm run test:e2e
```

The browser tests verify console navigation, temporal replay, operation expansion, direct and contextual edge inspection, node focus, ledger synchronization, responsive overflow, and critical accessibility violations.

See [IMPLEMENTATION_REVIEW.md](IMPLEMENTATION_REVIEW.md) for the source review route and implementation limits.
