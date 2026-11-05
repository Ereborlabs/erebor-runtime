WITH wanted AS (
    SELECT DISTINCT record FROM frontier
), selected AS (
    SELECT event.*, wanted.record
    FROM after.events event JOIN wanted
        ON event.tenant_id = wanted.record['stream']['tenant_id']
        AND event.node_id = wanted.record['stream']['node_id']
        AND event.node_boot_id = wanted.record['stream']['node_boot_id']
        AND event.label_epoch = wanted.record['stream']['label_epoch']
        AND event.source_id = wanted.record['stream']['source_id']
        AND event.source_epoch = wanted.record['stream']['source_epoch']
        AND event.cpu_id = wanted.record['cpu_id']
        AND event.source_cursor = wanted.record['durable_cursor']
), gaps AS (
    SELECT tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id,
        COUNT(*) > 0 AS gapped
    FROM coverage WHERE kind IN ('expired', 'recovery', 'pending')
    GROUP BY tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id
), qualified AS (
    SELECT event.*, araphor_temporal_coverage(event.temporal_coverage, event.kernel_sequence,
        named_struct('state', receipt.state,
            'first_sequence', receipt.first_sequence, 'last_sequence', receipt.last_sequence,
            'gap_reasons', receipt.gap_reasons,
            'opening_attempted', receipt.opening_attempted,
            'opening_suppressed', receipt.opening_suppressed,
            'opening_requested', receipt.opening_requested,
            'opening_emitted', receipt.opening_emitted,
            'opening_lost', receipt.opening_lost,
            'opening_classifier_miss_count', receipt.opening_classifier_miss_count,
            'opening_unresolved', receipt.opening_unresolved,
            'opening_next_sequence', receipt.opening_next_sequence,
            'closing_attempted', receipt.closing_attempted,
            'closing_suppressed', receipt.closing_suppressed,
            'closing_requested', receipt.closing_requested,
            'closing_emitted', receipt.closing_emitted,
            'closing_lost', receipt.closing_lost,
            'closing_classifier_miss_count', receipt.closing_classifier_miss_count,
            'closing_unresolved', receipt.closing_unresolved,
            'closing_next_sequence', receipt.closing_next_sequence),
        COALESCE(gaps.gapped, FALSE), COUNT(*) OVER (PARTITION BY event.record)) AS temporal
    FROM selected event LEFT JOIN coverage receipt
        ON receipt.kind = 'interval' AND event.tenant_id = receipt.tenant_id
        AND event.node_id = receipt.node_id AND event.node_boot_id = receipt.node_boot_id
        AND event.label_epoch = receipt.label_epoch AND event.source_id = receipt.source_id
        AND event.source_epoch = receipt.source_epoch AND event.cpu_id = receipt.cpu_id
        AND event.source_epoch = receipt.interval_source_epoch
        AND event.coverage_interval_id = receipt.interval_id
    LEFT JOIN gaps ON event.tenant_id = gaps.tenant_id AND event.node_id = gaps.node_id
        AND event.node_boot_id = gaps.node_boot_id AND event.label_epoch = gaps.label_epoch
        AND event.source_id = gaps.source_id AND event.source_epoch = gaps.source_epoch
        AND event.cpu_id = gaps.cpu_id
)
SELECT record AS id,
    named_struct('commit_revision', commit_revision, 'ordinal', ordinal) AS position,
    named_struct('task_cookie', task_cookie, 'target_task_cookie', target_task_cookie,
        'process_lineage_id', process_lineage_id, 'authority_domain_id', authority_domain_id,
        'execution_set_id', execution_set_id, 'exact_object_id', exact_object_id,
        'destination_id', destination_id, 'policy_rule_id', policy_rule_id,
        'reason', reason, 'decision', decision, 'effect_family', effect_family,
        'operation', operation, 'operation_argument', operation_argument,
        'configured_errno', configured_errno, 'kernel_result', kernel_result,
        'exact_file_object', CASE WHEN exact_profile_generation_ref_id IS NOT NULL THEN
            named_struct('profile_generation_ref_id', exact_profile_generation_ref_id,
                'mount_id_unique', mount_id_unique, 'inode', inode,
                'inode_generation', inode_generation, 'mount_namespace_inode', mount_namespace_inode,
                'filesystem_device', filesystem_device) END) AS effect,
    ingested_utc_ns, observed_boottime_ns, profile_generation_ref_id,
    kernel_sequence AS original_kernel_sequence, coverage_interval_id,
    NULLIF(NULLIF(process_instance_id, X''), X'00000000000000000000000000000000') AS process_instance_id,
    NULLIF(NULLIF(entry_instance_id, X''), X'00000000000000000000000000000000') AS entry_instance_id,
    NULLIF(NULLIF(binding_id, X''), X'00000000000000000000000000000000') AS binding_id,
    NULLIF(role_id, arrow_cast(0, 'UInt32')) AS role_id,
    NULLIF(state_id, arrow_cast(0, 'UInt32')) AS state_id,
    NULLIF(entry_rule_id, arrow_cast(0, 'UInt32')) AS entry_rule_id,
    named_struct('source_authority', arrow_cast(0, 'UInt8'),
        'local_subject_binding', arrow_cast(CASE WHEN task_cookie > 0 THEN 0 ELSE 4 END, 'UInt8'),
        'remote_subject_binding', arrow_cast(5, 'UInt8'),
        'operation_result_authority', arrow_cast(0, 'UInt8'),
        'temporal_coverage', temporal, 'integrity', arrow_cast(1, 'UInt8')) AS proof_quality
FROM qualified ORDER BY record
