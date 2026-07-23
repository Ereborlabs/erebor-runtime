# Phase 8: Filesystem Loose Function Owners And Test Fixtures

Status: Done.

## Purpose

Fix the filesystem crate's remaining loose-function smell with ownership-first,
readability-first refactors.

This phase exists because the filesystem crate still reads too much like a
chain of module-level functions. The goal is not to blindly turn every small
helper into a struct. The goal is to make ownership obvious: storage planning,
normalization, metadata application, overlay probing, checkpoint staging,
promotion application, transaction catalog handling, rollback, and test setup
should be owned by named structs or real trait seams when that improves the
reader's ability to follow lifecycle and state.

API compatibility is not a constraint for this phase. It is acceptable to break
crate APIs or test helper APIs when doing so removes unclear ownership, provided
behavior is preserved, tests are not removed, and all affected call sites are
updated.

## Scope

- Refactor production loose functions in `crates/erebor-runtime-filesystem`
  into owner methods, owner collaborators, or existing real trait seams when it
  improves readability.
- Keep public API doors only when they are the crate's intended user-facing
  entry points; route them immediately to an owning request/workflow/reader.
- Keep private stateless helpers only when they are local to an owner and a
  method would make the owner harder to read.
- Move validation behavior onto validated value types or named validator
  owners. In particular, promotion IDs, transaction names, mount plans, and
  relative paths should not remain stray `validate_*` functions when an owner
  makes the contract clearer.
- Group test helper functions into reusable fixture structs. `#[test]`
  functions may remain module-level because the Rust test harness requires
  them, but setup, assertions, file writes, temp roots, repository doubles, and
  command/metadata helpers should move onto fixture owners when reused or when
  they carry context.
- Preserve all existing tests. Do not remove tests to make the refactor pass.
- Retain the `ostree` crate-backed repository owner. Do not reintroduce a
  stringly OSTree command runner as the domain abstraction.
- Avoid unnecessary copies while moving behavior. Borrow read-only context,
  move values at natural ownership boundaries, and clone only where the owner
  truly needs independent data.
- Keep readable cohesive files together even if they exceed 300 lines. Split
  only when the split makes ownership easier to follow.

## Production Baseline Inventory

Current command:

```sh
rg -n "^(pub(\\([^)]*\\))?\\s+)?(async\\s+)?fn\\s+[A-Za-z0-9_]+" crates/erebor-runtime-filesystem/src -g '*.rs' -g '!**/tests.rs' -g '!**/tests/*.rs'
```

Current count: 169 production module-level functions.

| File | Loose functions |
| --- | --- |
| `src/checkpoint.rs` | `commit_session_checkpoint`, `commit_normalized_session_checkpoint_with_repository`, `checkpoint_manifest_ref`, `volume_layer_ref` |
| `src/checkpoint/stage.rs` | `stage_volume_layer`, `reset_stage`, `write_layer_manifest`, `stage_entry`, `apply_directory_metadata`, `directory_metadata`, `stage_opaque_replace`, `stage_visible_tree`, `apply_source_metadata`, `copy_regular`, `write_symlink`, `create_parent`, `safe_relative`, `invalid_layer_path` |
| `src/linux_overlay_session.rs` | `ensure_linux_platform`, `ensure_required_commands`, `command_available`, `set_wrapper_permissions` |
| `src/linux_overlay_session/plan.rs` | `prepare_mounts`, `prepare_volume_mount`, `canonical_existing_dir`, `canonical_volume_dir`, `ensure_safe_mount_pair`, `ensure_not_root`, `mount_path_text`, `validate_mount_isolation`, `validate_mounts_do_not_overlap`, `paths_overlap` |
| `src/linux_overlay_session/script.rs` | `render_wrapper`, `push_cleanup`, `push_mount_commands`, `push_identity_functions`, `sh` |
| `src/metadata.rs` | `layer_metadata`, `host_metadata`, `apply_layer_metadata`, `apply_host_metadata`, `copy_path_metadata`, `apply_metadata`, `apply_ownership`, `apply_mode`, `apply_mtime`, `apply_xattrs`, `restorable_xattrs`, `list_xattrs`, `read_xattr`, `missing_or_unsupported`, `file_type` |
| `src/normalizer.rs` | `normalize_session_layers`, `normalize_volume_layer`, `walk_upperdir`, `write_manifest` |
| `src/normalizer/entry.rs` | `normalize_entry`, `normalize_symlink`, `create_or_replace_operation`, `whiteout_delete_path`, `manifest_path`, `validate_relative_path`, `safe_symlink_target`, `unsupported_path`, `layer_metadata` |
| `src/normalizer/opaque.rs` | `opaque_operation`, `count_visible_entries`, `layer_metadata` |
| `src/normalizer/proc.rs` | `ensure_no_active_writers`, `inspect_process`, `fd_is_writer`, `parse_flags`, `path_is_watched`, `pid_from_name`, `permission_or_race` |
| `src/overlay.rs` | `is_control_file_name`, `is_opaque_marker_file`, `is_whiteout`, `is_whiteout_entry`, `opaque_marker`, `unsupported_reasons`, `metadata_sidecars`, `has_overlay_marker`, `read_xattr`, `list_xattrs`, `missing_or_unsupported` |
| `src/promotion.rs` | `promote_session_checkpoint` |
| `src/promotion/apply.rs` | `apply_volume_layer`, `rollback_volume`, `apply_operation`, `write_layer_entry`, `apply_layer_directory_metadata`, `directory_metadata`, `rollback_entry`, `copy_directory` |
| `src/promotion/catalog.rs` | `list_transaction_catalog`, `show_transaction_target`, `rename_transaction_target`, `rollback_transaction_target`, `list_transaction_catalog_with_repository`, `show_transaction_target_with_repository`, `rename_transaction_target_with_repository`, `rollback_transaction_target_with_repository` |
| `src/promotion/catalog/journal.rs` | `append_rename_event`, `append_rollback_event`, `rollback_refs`, `append_event`, `catalog_journal_path`, `create_parent` |
| `src/promotion/catalog/load.rs` | `load_catalog`, `committed_promotion_ids`, `promotion_id_from_ref`, `load_transaction`, `read_layer_manifest`, `transaction_state`, `change_from_operation`, `catalog_checkout_root` |
| `src/promotion/catalog/resolve.rs` | `resolve_target`, `target_key`, `selected_volumes`, `ensure_unique_name`, `validate_name`, `resolve_handle`, `resolve_name` |
| `src/promotion/catalog/state.rs` | `catalog_path`, `catalog_dir`, `create_parent`, `catalog_version`, `unix_time_ms` |
| `src/promotion/checkout.rs` | `checkout_tree` |
| `src/promotion/ids.rs` | `validate_promotion_id`, `promotion_manifest_ref`, `promotion_preimage_ref`, `volume_for_id`, `manifest_for_volume`, `invalid_promotion_id` |
| `src/promotion/io.rs` | `write_preimage_manifest`, `write_promotion_manifest`, `read_promotion_manifest`, `read_preimage_manifest`, `write_json_manifest`, `read_json_manifest` |
| `src/promotion/journal.rs` | `fail_if_existing_incomplete`, `ensure_journal_applied`, `ensure_manifest_applied`, `ensure_manifest_or_journal_applied` |
| `src/promotion/layer.rs` | `ensure_layer_promotable` |
| `src/promotion/path.rs` | `safe_relative`, `create_parent`, `remove_path`, `invalid_path` |
| `src/promotion/preimage.rs` | `capture_volume_preimage`, `verify_preimage_matches_host`, `reset_stage`, `capture_absent`, `capture_present`, `capture_present_or_absent`, `copy_directory` |
| `src/promotion/preimage_size.rs` | `add_bytes` |
| `src/promotion/rollback.rs` | `rollback_promotion`, `rollback_promotion_with_repository`, `rollback_promotion_volumes_with_repository`, `ensure_local_journal_not_incomplete` |
| `src/storage.rs` | `prepare_with_initializer`, `storage_plan`, `volume_storage_plan`, `required_directories` |
| `src/storage/ostree.rs` | `initialize_ostree_repo` |

## Target Production Owners

Implement in readability-preserving slices. Do not split cohesive logic just to
reduce line count.

1. `FilesystemStoragePreparer`

   Owns storage creation and directory planning in `src/storage.rs`. Move
   `prepare_with_initializer`, `storage_plan`, `volume_storage_plan`, and
   `required_directories` behind the owner. Keep the public crate entry point
   only as a thin constructor call if still useful.

2. `FilesystemSessionLayerNormalizer`, `FilesystemVolumeLayerNormalizer`,
   `FilesystemLayerEntryNormalizer`, `OpaqueLayerNormalizer`, and
   `ActiveWriterProbe`

   Own normalization, entry co