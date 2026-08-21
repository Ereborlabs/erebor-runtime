# Code Review Suggestions

This note records only reviewed changes with a better replacement. A note does
not authorize implementation.

## Resolve path-terminal conflicts during determinization

Source:
[`compile_with_path_tree_denies`](../../../crates/mithril-control/src/policy/path.rs#L312).

### Finding

The nested scan at lines 330 through 346 compares every pair of path patterns.
Each comparison walks up to 255 components. Its cost is quadratic in the
number of patterns before the compiler runs the determinization that it needs
anyway.

The pairwise check is also weaker than the required result. Three different
rules can overlap one path and form an override cycle: A overrides B, B
overrides C, and C overrides A. Every pair passes the current check, but no
rule overrides the complete set. `terminal_for` then returns no terminal and
the determinized graph loses the match instead of rejecting the policy.

The current production caller creates only exact components from
`ExactFileObjectConfig`. The `Wildcard` variant has no production source
caller. Recursive path-tree denial uses its internal self-loop, not that
variant.

### Probable solution

Keep every terminal candidate on the intermediate graph state. During the
existing subset-construction pass in `determinize`, build one precedence DAG
for each reachable set of conflicting terminal patterns. Its nodes are only
the candidates with unequal authority. An edge points from the higher-
precedence candidate to the lower-precedence candidate. Different reachable
sets produce different DAGs. One pattern can occur in more than one DAG.

Explicit `overrides_rule_ids` add edges only for candidates that can overlap.
Reject a cycle. After grouping candidates with the same authority, require one
source node in the directed acyclic graph. That node is the winner; its
transitive successors lose. More than one source means that an incompatible
candidate has no declared precedence. A terminal with no incompatible peer is
valid and needs no edge.

The signed policy sender controls wildcard precedence through a new,
policy-level setting. The default mode is `WILDCARD_WINS`. In that mode, add an
implicit edge from a wildcard pattern to an exact pattern only when the
wildcard pattern strictly contains the exact pattern's language. For example,
`/app/*` precedes `/app/config`. Two cross-wildcard patterns such as `/app/*`
and `/*/config` have no containment relation, so they still need an explicit
edge. A policy-level `EXACT_WINS` or `EXPLICIT_ONLY` mode can change this
default.

The setting changes an enforcement decision. Put it in a new signed policy
schema and include it in canonical bytes. Do not make it a node-local setting.
The current production source creates no wildcard path patterns. The internal
self-loop for recursive path-tree denial is not a policy wildcard and must not
use this precedence setting.

This removes `patterns_overlap` and the all-pairs scan. It checks the terminal
sets that the kernel graph can reach, rejects cycles, and gives each conflict
set one winner.

If wildcard path patterns are not a required public capability, remove the
unused `PathPatternComponentV1::Wildcard` variant instead. The remaining
exact-path trie detects conflicts at one terminal state and has no general
pattern-overlap algorithm.

### Required proof

- An unequal exact duplicate without an override fails compilation.
- A chain A overrides B, B overrides C compiles with A as the transitive
  winner.
- A three-rule override cycle fails with `PATH_TERMINAL_CONFLICT`.
- An active conflict set with two source nodes fails with
  `PATH_TERMINAL_CONFLICT`.
- Under `WILDCARD_WINS`, `/app/*` wins over `/app/config`. Under
  `EXACT_WINS`, `/app/config` wins.
- Cross-wildcard overlap needs an explicit precedence edge in every mode.
- Changing the policy-level precedence setting changes canonical bytes and
  requires a new signed policy schema.
- Existing exact-object and recursive path-tree-deny lowering retains its
  current graph rows.

## Make the signed policy the source of path authority

Source:
[`lower_path_tables`](../../../crates/mithril-node/src/policy.rs#L3331),
[`ExactFileObjectConfig`](../../../crates/mithril-node/src/config.rs#L98), and
[`LocalObjectSelectorV1`](../../../crates/mithril-control/src/policy/source.rs#L647).

### Finding

`lower_path_tables` combines two independent inputs. The signed artifact
supplies path-tree `DENY` floors. `NodeConfig.exact_file_objects` supplies an
unsigned exact-object key, class, canonical path, and live mount and inode
identity. The signed artifact can refer only to `EXACT:<key>`.

This lets node configuration select the physical target for a signed file
rule. It also requires an object to be resolved before the current static
configuration can activate a policy. A Pod and its mount namespace can be
absent when Control distributes that policy.

The source has no production transition from a CRI container-start event to a
local exact-object resolution. The inspection command and the E2E fixtures
create `ExactFileObjectConfig` records outside that policy lifecycle.

### Probable solution

Make the signed policy the only source of file selectors, object classes,
operations, and dispositions. Do not use `NodeConfig` to select a protected
file or to give an exact-object key its policy meaning. Keep node configuration
only for local operation, such as transport endpoints, state storage, and BPF
loader settings.

Replace the source-policy `EXACT:<numeric-key>` selector with a signed path
selector identified by a policy rule ID. The selector names its canonical path
and whether it is exact or recursive. The existing signed rule disposition and
`operation_ids` state the permitted or denied operations. For example, the
policy can express `ALLOW OPEN_READ` for one exact path, `DENY OPEN_WRITE` for
that path, or `DENY OPEN_WRITE` recursively below a path. Do not add separate
open, read, and write configuration channels.

When Control distributes a policy, stage its path graph before the selected
container exists. At a trusted CRI container-start event, acquire the
container's held mount namespace and root. Resolve each signed exact-path
selector in that namespace. The result is node-owned measured state:

```text
signed path-selector rule ID
  -> mount namespace, selected mount, device, inode, inode generation,
     canonical components, and topology snapshot
```

Compile an opaque numeric handle from that signed rule ID only for the BPF map
ABI. It is not a policy selector and it is not node configuration. Stage and
read back the measured binding with the candidate generation before activation.
If an exact path is absent or cannot be resolved, do not grant its positive
authority. Re-resolve after a container replacement, mount-topology change, or
object replacement.

A signed recursive `DENY` path floor remains usable for a future file. It
matches the live canonical path and denies before exact-object lookup. An
exact-path `ALLOW` still requires the measured binding, so a replacement inode,
mount alias, or overlay copy-up cannot inherit the old allow.

Remove `NodeConfig.exact_file_objects` from policy activation. The inspection
command can remain diagnostic, but it must not produce an authority input. The
CRI resolution path owns the only production producer of measured exact-object
state.

### Required proof

- Changing a signed path, disposition, object class, or operation changes the
  canonical policy bytes and signature input.
- A policy can stage before its selected Pod exists.
- At CRI container start, the node resolves the signed exact path inside that
  container's mount namespace and activates its allow only after map readback.
- An absent or unresolved exact path grants no allow.
- A recursive signed deny blocks a file created after policy staging without an
  exact-object binding.
- Replacing an allowed file, changing its selected mount, or invalidating its
  mount view removes positive authority until a new signed-selector resolution
  completes.
- No node configuration field can map a signed file rule to a path, class, or
  exact-object key.

## Reuse the cache-row lookup after an insert collision

Source:
[`canonical_mount_cache_build_step`](../../../bpf/erebor-interceptor/programs/identity_path.bpf.h#L304).

### Finding

Each callback inserts one candidate with `BPF_NOEXIST`. When a row already
exists for the same root dentry, the update fails as expected. The condition
at lines 364 through 367 looks up that row only to prove that it exists. The
next statement looks up the same row again to obtain `cached` for the spin
lock and lowest-mount-ID comparison.

This path occurs for repeated root dentries and concurrent cache builders. It
performs two identical map-lookup helper calls while one lookup can provide
both the existence check and the value pointer.

### Probable solution

Attempt the `BPF_NOEXIST` update, then look up the row once. Ignore the update
result after that lookup. A non-null row means that this callback inserted it
or that another callback already owns it. A null row means that neither case
produced a usable cache row, so preserve `goto failed`.

```c
(void)bpf_map_update_elem(&canonical_mount_cache, key, initial,
                          BPF_NOEXIST);
cached = bpf_map_lookup_elem(&canonical_mount_cache, key);
if (!cached)
    goto failed;
```

Keep the existing spin lock and lower-`mnt_id_unique` replacement. They retain
the correct result when several candidates share one root dentry.

### Required proof

- The BPF program compiles and passes verifier loading on supported x86_64 and
  arm64 targets.
- The first candidate creates a usable row.
- A second candidate for the same key retains the lower `mnt_id_unique`.
- A failed update with no readable row sets `build->failed` and prevents a
  ready cache state.
- A concurrent insert collision still obtains and locks a non-null row.

## Name the mount-tree scan-depth bound

Source:
[`identity_maps.h`](../../../bpf/erebor-interceptor/programs/identity_maps.h#L51)
and
[`mount_scan_push`](../../../bpf/erebor-interceptor/programs/identity_path.bpf.h#L284).

### Finding

`MAX_CANONICAL_PATH_COMPONENTS_V1` defines the maximum number of canonical
path components. The mount-tree scan also uses that constant for its explicit
red-black-tree stack. The two limits have different meanings. The tree stack
stores pending `struct rb_node` addresses. It does not store path components.

The same constant currently controls the `mount_scan_stack` array, the stack
depth check, and the verifier index masks. This coupling makes a reader infer
that the mount scan is limited by path depth. It also makes a future path-limit
change silently change mount-tree scratch storage.

### Probable solution

Define `MAX_CANONICAL_MOUNT_SCAN_DEPTH_V1` with the current value `255`. Use
it for `mount_scan_stack`, its depth check, and both verifier index masks.
Keep `MAX_CANONICAL_PATH_COMPONENTS_V1` only for path-component storage and
path-walk bounds.

Keeping the value at `255` makes this a naming-only change. It preserves the
current BPF scratch-map value layout, verifier ranges, and 4,096-mount scan
behavior. A later change to the depth value needs a separate bound proof and a
map ABI migration review.

### Required proof

- The BPF scratch-map value size and layout remain unchanged.
- `mount_scan_stack`, its push check, and its pop index use only
  `MAX_CANONICAL_MOUNT_SCAN_DEPTH_V1`.
- `path_component_views`, path matching, and the 255-component acceptance
  proof continue to use `MAX_CANONICAL_PATH_COMPONENTS_V1`.
- Update
  [`bpf_path_walks_use_meta_component_and_namespace_budgets`](../../../crates/erebor-interceptor/src/bundled.rs#L1217)
  to check the two named bounds.
- The bundled BPF object and supported architecture verifier loads pass.
