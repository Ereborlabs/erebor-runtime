# Recovered Research

- [Native compression and consumed journals](results/araphor-compression-storage-2026-11-13.md)
  records 32 matched runs with default and experimental compression policies.
  It measures allocated blocks across safe journal collection at the same
  retained event count. Both builds pass the focused checks. The engine
  checkout is restored; production still uses batch payloads.
- [Compact source keys](results/araphor-compact-storage-2026-11-13.md)
  records 32 matched batch/record runs with 81-byte and 16-byte event keys.
  Compact keys reduce record storage space. Per-record intake and bulk reads
  still cost more than compact batches in the reported medians. Both late
  slow runs remain in the report. Production storage is unchanged.
- [Per-record and batch event storage](results/araphor-record-storage-2026-11-13.md)
  records 24 matched runs with real Fjall keyspaces. Per-record values improve
  point reads and cost more throughput, bulk-read time, and allocated space.
  The current production owner is a separate reference. Native table history
  and production migration are not qualified by these proofs of concept.
- [DuckDB replacement with versioned Fjall](araphor-fjall-integration.md)
  maps the completed engine APIs to Data, Graph, native DataFusion providers,
  original-log subscription wakes, and batch notification writes. Production
  integration and the incident performance targets remain not done.
- [Native kernel evidence replacement results](results/araphor-kernel-evidence-2026-11-12.md)
  records the matched production comparison, source hashes, focused checks,
  and costs of the collector's native storage replacement.
- [Araphor durable storage investigation](araphor-durable-storage-investigation.md)
  compares redb, Fjall, and a custom transaction log against current Data
  snapshots, atomic commits, raw journals, Graph ownership, and measured costs.
  Engine selection and performance qualification remain not done.
- [Compliance wedge research](compliance/README.md)
- [Interview findings](interviews/)
- [Generated research](generated/) — kept separate because these are
  office-hours or other assistant-generated working documents, not validated
  product requirements.
- [Runtime and Defender learning guide](erebor-runtime-and-defender-learning.md)
  — technical design guidance for governing agent effects and building the
  future defensive control plane.
- [Erebor Defender: Linux enforcement, correlation, and response engineering](erebor-defender-learning-from-tetragon-and-falco.md)
  — a Defender-owned task/process/effect and response architecture built from
  Linux, container-runtime, Kubernetes, and provider decision points; existing
  products are optional implementation studies and evidence adapters.
- [Cilium and Tetragon network-enforcement lessons](cilium-tetragon-network-enforcement-lessons.md)
  — source-grounded socket lifetime, actor-stage, final-flow, DNS, response,
  recovery, and physical-test rules for the Mithril network plane.
- [Mithril BPF evidence and recovery audit](mithril-bpf-evidence-recovery-audit.md)
  — current Interceptor safety properties, evidence gaps, checked-in Cilium
  and Tetragon lessons, and constraints for durable coverage and recovery.
- [Hugging Face Agent Intrusion: Published Live Action Stream](hugging-face-agent-intrusion-live-action-stream.md)
  — a normalized record of the 21 representative actions published in the
  interactive incident replay, explicitly distinct from the recovered raw log.
- [Hugging Face Agent Intrusion: Erebor Defender Implementation Analysis](hugging-face-agent-intrusion-analysis.md)
  — implementation-level native task/exec/effect graphs, kernel prevention
  without changing the multi-job worker architecture, deterministic
  correlation, honest task-versus-cgroup containment, provider recovery, and
  acceptance tests mapped to the published technical timeline.
- [Agent Intrusions: Victim-Side Mithril Prevention](agentic-cyber-incidents-mithril-prevention-analysis.md):
  Exact access gained on attacked services, the first victim-side Mithril
  stop, current plan status, missing controls, and required fixtures for
  incidents reported by OpenAI, Anthropic, the UK AI Security Institute, and
  other operators.

The remaining top-level research files cover ICP discovery, buyer evidence,
competitor assessment, AI adoption, and an OpenClaw OAuth consent lab.
