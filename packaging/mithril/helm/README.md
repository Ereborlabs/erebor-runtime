# Mithril Kubernetes Package

This chart installs the `mithril-node` DaemonSet, `mithril-control`, the
`WorkloadProtectionPolicy` and `WorkloadProtectionException` CRDs, and the
fail-closed admission webhooks.

Control can list both resources and patch only their status subresources. The
chart also creates unbound `mithril-policy-writer` and
`mithril-exception-writer` ClusterRoles. Bind each role only in the namespaces
where that operator acts. Neither writer receives the other resource by
default.

## Node Selection

Set `node.nodeSelector` and `node.affinity` on the DaemonSet. Control reads
these fields from the live DaemonSet. There is no second Mithril node-pool
setting. Pod admission adds the derived constraints and the
`mithril.erebor.dev/ready=true` requirement. The Kubernetes scheduler then
selects one ready node.

Each selected host must contain its unique node configuration at
`node.configHostPath` and its unique mTLS identity directory at
`node.identityHostPath`. The DaemonSet supplies `spec.nodeName` through
`MITHRIL_KUBERNETES_NODE_NAME`. In this mode, the node derives its
effect-controller cgroup from `/proc/self/cgroup`; it does not use a
precomputed Pod cgroup path. The node service account has no Kubernetes API
token or RBAC permissions.

## Admission TLS And Control Configuration

Create `control.admission.tlsSecretName` with `tls.crt` and `tls.key`. The
certificate must authenticate `mithril-control.<namespace>.svc`. Set
`control.admission.caBundle` to the base64-encoded CA bundle.

The Control configuration Secret must contain `control.json`. Its Kubernetes
fields must use this contract:

```json
{
  "kubernetes_policy": {
    "tenant_id": "<tenant UUID>",
    "cluster_uid": "<cluster UUID>",
    "signer": {
      "signing_key_id": "<key ID>",
      "signing_key_path": "/etc/mithril/policy-signing-key",
      "seal_request_path": "/etc/mithril/profile-seal-request.json",
      "distribution_sequence_epoch": 1,
      "candidate_validity_ns": 300000000000
    }
  },
  "kubernetes_nodes": {
    "daemon_set_namespace": "<release namespace>",
    "daemon_set_name": "mithril-node",
    "session_ttl_seconds": 15,
    "reconcile_interval_ms": 1000
  },
  "kubernetes_admission": {
    "listen": "0.0.0.0:9443",
    "tls_certificate_path": "/etc/mithril/admission-tls/tls.crt",
    "tls_private_key_path": "/etc/mithril/admission-tls/tls.key",
    "maximum_request_bytes": 1048576,
    "request_timeout_ms": 4000
  }
}
```

Set the server request timeout below the webhook timeout. The Control
configuration does not define a protected tenant, namespace, or Mithril node
selector. `control.nodeSelector` only selects the Node that runs the Control
Pod. Use it when the Control persistent volume has Node affinity.

The node configuration must enable `container_runtime` and
`runtime_admission`. Its admission socket must equal
`node.runtimeHook.socketPath`, and its timeout must equal
`node.runtimeHook.timeoutMs`. Set `runtimeTimeoutSeconds` above that client
timeout. The OCI runtime terminates a hook that exceeds this outer limit.

## Runtime Hook

The measured init container installs `mithril-oci-hook`, an OCI base spec, a
recovery manifest, and one containerd v3 drop-in on each selected K3s host. The
drop-in sets the base spec on containerd's default CRI runtime. A Pod does not
need a RuntimeClass. Containerd invokes the hook directly; no NRI process is
installed or retained.

The first `createRuntime` hook denies the exact hostile incident shape. When
the node socket is unavailable, it denies every new CRI container except the
exact measured installer and `mithril-node` recovery shapes. A healthy node
admits ordinary unprotected containers and receives each protected container
through the existing ordered admission stages. The hook logs the decision code
for each denial and exact recovery. Healthy unprotected decisions use debug
level.

The installer restarts the active `k3s` or `k3s-agent` service only when the
loaded base spec changes. It then reads back the generated containerd
configuration and every marked file. It refuses an unowned file or an existing
foreign base spec on the default runtime.

## Operational Logs

`control.logFilter` and `node.logFilter` set `RUST_LOG` for their service
containers. `node.logFilter` also applies to the installed OCI hooks. Both
values default to `info`. Use a Rust target to enable bounded detail for one
owner, for example:

```yaml
node:
  logFilter: info,mithril_node::runtime_admission=debug
control:
  logFilter: info,mithril_control::store=trace
```

A Helm upgrade changes the Pod template and restarts the affected owner. Logs
remain human-readable service stderr. The filter does not change policy,
evidence, readiness, or enforcement state. The chart bounds each value and
rejects line breaks. The service validates the complete filter before startup.

Helm uninstall removes Kubernetes release objects. It does not remove the
owned hook binary, containerd drop-in, OCI base spec, recovery manifest, or
pinned BPF state. The missing node admission socket blocks all new CRI starts
except exact measured Mithril recovery. Direct non-CRI starts remain subject to
the retained BPF incident floor. Run the independently signed node
decommission flow when host enforcement must be removed.

## Verification

```sh
rtk bash packaging/mithril/helm/tests/verify.sh
```

The test lints and renders the chart. It checks the DaemonSet-derived selector,
quarantine toleration, node identity input, runtime hook, webhook rules, TLS,
timeouts, health probes, and RBAC boundary.
