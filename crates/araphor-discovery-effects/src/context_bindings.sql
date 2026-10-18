WITH
__binding_records AS (
    SELECT records.*,
        named_struct('stream', named_struct(
            'tenant_id', tenant_id, 'node_id', node_id, 'node_boot_id', node_boot_id,
            'label_epoch', label_epoch, 'source_id', source_id, 'source_epoch', source_epoch),
            'cpu_id', cpu_id, 'durable_cursor', source_cursor) AS record_id,
        named_struct(
            'workload_selector_id', catalog_key_workload_selector_id,
            'protected_scope_id', catalog_key_protected_scope_id,
            'execution_set_id', catalog_key_execution_set_id,
            'entry_kind', catalog_key_entry_kind,
            'role_id', catalog_key_role_id,
            'process_state_id', catalog_key_process_state_id,
            'effect_family', CAST(catalog_key_effect_family AS SMALLINT UNSIGNED),
            'operation_id', catalog_key_operation_id,
            'operation', CAST(catalog_key_operation AS SMALLINT UNSIGNED),
            'operation_argument', catalog_key_operation_argument,
            'argument_wildcard', catalog_key_argument_wildcard,
            'object_selector', catalog_key_object_selector,
            'binding_lifecycle', catalog_key_binding_lifecycle) AS static_key,
        encode(binding_id, 'hex') AS binding_hex,
        encode(execution_set_id, 'hex') AS execution_hex,
        encode(authority_domain_id, 'hex') AS authority_hex
    FROM records
    WHERE catalog_profile_id IS NOT NULL
        AND octet_length(encode(process_instance_id, 'hex')) = 32
        AND encode(process_instance_id, 'hex') <> '00000000000000000000000000000000'
        AND octet_length(encode(entry_instance_id, 'hex')) = 32
        AND encode(entry_instance_id, 'hex') <> '00000000000000000000000000000000'
        AND entry_rule_id > 0 AND octet_length(encode(execution_set_id, 'hex')) = 32
),
__binding_identities AS (
    SELECT record.*,
        concat_ws('-', substr(binding_hex, 1, 8), substr(binding_hex, 9, 4),
            substr(binding_hex, 13, 4), substr(binding_hex, 17, 4),
            substr(binding_hex, 21, 12)) AS binding_uuid,
        concat_ws('-', substr(execution_hex, 1, 8), substr(execution_hex, 9, 4),
            substr(execution_hex, 13, 4), substr(execution_hex, 17, 4),
            substr(execution_hex, 21, 12)) AS execution_uuid,
        concat_ws('-', substr(authority_hex, 1, 8), substr(authority_hex, 9, 4),
            substr(authority_hex, 13, 4), substr(authority_hex, 17, 4),
            substr(authority_hex, 21, 12)) AS authority_uuid
    FROM __binding_records AS record
),
__binding_revisions AS (
    SELECT policies.*, MAX(commit_revision) OVER (
        PARTITION BY tenant_id, source_revision_id
    ) AS current_revision
    FROM policies
),
__binding_policies AS (
    SELECT policy.*, COUNT(*) OVER (
        PARTITION BY tenant_id, source_revision_id
    ) AS current_count
    FROM __binding_revisions AS policy
    WHERE commit_revision = current_revision
),
__binding_keys AS (
    SELECT DISTINCT tenant_id, source_revision_id, lifetime_key,
        UNNEST(compiled_keys) AS static_key
    FROM __binding_policies
),
__binding_targets AS (
    SELECT target.*,
        named_struct(
            'workload', named_struct(
                'node_id', node_id,
                'workload_binding_generation_digest', workload_binding_generation_digest,
                'execution_set_id', execution_set_id,
                'cluster_uid', cluster_uid, 'namespace_uid', namespace_uid,
                'controller_uid', controller_uid, 'service_account_uid', service_account_uid,
                'pod_uid', pod_uid, 'container_id', container_id,
                'container_name', container_name, 'container_kind', container_kind,
                'image_digest', image_digest, 'pod_labels', pod_labels,
                'kubernetes', CASE WHEN profile_id IS NULL THEN NULL ELSE named_struct(
                    'namespace_name', namespace_name, 'pod_name', pod_name,
                    'profile_id', profile_id, 'policy_source_revision_id', policy_source_revision_id,
                    'binding_id', binding_id_text, 'protected_scope_id', protected_scope_id,
                    'workload_selector_id', workload_selector_id,
                    'kubernetes_node_name', kubernetes_node_name,
                    'kubernetes_node_uid', kubernetes_node_uid,
                    'node_boot_id', node_boot_id_text, 'label_epoch', label_epoch) END),
            'signed_profile_digest', signed_profile_digest,
            'source_revision_id', source_revision_id) AS candidate
    FROM targets AS target
),
__binding_candidates AS (
    SELECT record.record_id, target.candidate, target.workload_digest_valid,
        target.workload_binding_generation_digest AS subject_revision,
        target.image_digest, record.catalog_policy_document_digest AS configuration_digest,
        record.process_instance_id, record.entry_instance_id, record.binding_id,
        record.role_id, record.state_id, record.entry_rule_id,
        record.catalog_profile_version AS catalog_revision, record.static_key,
        named_struct('profile_id', record.catalog_profile_id,
            'profile_version', record.catalog_profile_version,
            'source_revision_id', target.source_revision_id,
            'signed_profile_digest', target.signed_profile_digest) AS policy_revision,
        CASE WHEN policy.current_count <> 1
            OR target.execution_set_id <> record.execution_uuid
            OR NOT array_has(policy.execution_set_ids, record.catalog_key_execution_set_id)
            OR target.protected_scope_id <> record.catalog_key_protected_scope_id
            OR target.workload_selector_id <> record.catalog_key_workload_selector_id
            OR key.static_key IS NULL THEN 1 ELSE 0 END AS invalid
    FROM __binding_identities AS record
    JOIN __binding_targets AS target
        ON target.tenant_id = record.tenant_id AND target.node_id = record.node_id
        AND target.node_boot_id_text = encode(record.node_boot_id, 'hex')
        AND target.label_epoch = record.label_epoch
        AND target.binding_id_text = record.binding_uuid
        AND target.profile_id = record.catalog_profile_id
        AND target.policy_source_revision_id = target.source_revision_id
    JOIN __binding_policies AS policy
        ON policy.tenant_id = record.tenant_id
        AND policy.source_revision_id = target.source_revision_id
        AND policy.profile_id = record.catalog_profile_id
        AND policy.profile_version = record.catalog_profile_version
        AND policy.policy_document_digest = record.catalog_policy_document_digest
    LEFT JOIN __binding_keys AS key
        ON key.tenant_id = policy.tenant_id
        AND key.source_revision_id = policy.source_revision_id
        AND key.lifetime_key = policy.lifetime_key AND key.static_key = record.static_key
    WHERE record.authority_hex = ''
        OR record.authority_uuid = record.catalog_key_protected_scope_id
),
__binding_valid AS (
    SELECT record_id
    FROM __binding_candidates
    GROUP BY record_id
    HAVING COUNT(DISTINCT candidate) = 1 AND MAX(invalid) = 0
        AND BOOL_AND(workload_digest_valid)
)
SELECT DISTINCT candidate.record_id, subject_revision, image_digest, configuration_digest,
    process_instance_id, entry_instance_id, binding_id, role_id, state_id, entry_rule_id,
    catalog_revision, static_key, policy_revision
FROM __binding_candidates AS candidate
JOIN __binding_valid AS valid ON candidate.record_id = valid.record_id
