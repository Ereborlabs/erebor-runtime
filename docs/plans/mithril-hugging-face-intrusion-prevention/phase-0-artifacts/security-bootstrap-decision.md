# Phase 1 Control/Node Security Bootstrap Decision

Status: Phase 0 decision; limited to the private bootstrap needed by Phase 1.

## Bootstrap contract

1. An operator-approved enrollment gives a node a one-use enrollment identifier and proof. The node generates its private key locally; private key bytes never leave the node.
2. The Control trust root signs a short-lived node certificate bound to the immutable node identifier. Nodes pin the configured Control root; Control pins its node-issuer root. Rotation retains an explicit previous-root overlap and anti-rollback generation.
3. The node opens one outbound gRPC connection to Control using mutual TLS. Control never dials a node and workload code receives neither endpoint credentials nor the channel.
4. The first authenticated message offers a closed protocol-version set. Phase 1 accepts only the exact common version; no common version fails closed without changing installed local enforcement.
5. Each direction uses a connection nonce plus strictly increasing sequence number. Control stores the last accepted node sequence, and the node durably stores the last accepted Control sequence before applying authority-bearing state. A repeated nonce/sequence, skipped required state, or body/digest mismatch is rejected.
6. Loss of Control connectivity prevents new admission and new authority. Already installed local denial remains active and is reported as enforcing without current Control observation; no connection failure converts a deny or unknown state to allow.

## Deliberate limits

Phase 1 exposes no public API, provider connector, general message bus, or pluggable identity provider. Certificate issuance may initially be an operator-local command behind the Control owner. Provider-specific workload identity and authorization arrive only in their owning phases.
