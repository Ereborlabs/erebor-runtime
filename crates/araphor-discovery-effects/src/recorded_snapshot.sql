WITH
__discovery_cte_metadata AS (
    SELECT COUNT(*) AS metadata_count, MIN(tenant_id) AS tenant_id,
        MIN(source_revision) AS source_revision, MIN(proof_kind) AS proof_kind
    FROM metadata
),
__discovery_cte_record_values AS (
    SELECT tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch,
        cpu_id, source_cursor, framed_record,
        CASE WHEN octet_length(encode(coverage_interval_id, 'hex')) = 32
            THEN coverage_interval_id ELSE source_id END AS coverage_interval_id,
        profile_generation_ref_id, temporal_coverage, task_cookie, target_task_cookie,
        process_lineage_id, authority_domain_id, execution_set_id, exact_object_id,
        destination_id, policy_rule_id, reason, decision, effect_family, operation,
        operation_argument, configured_errno, kernel_result, context_schema_version,
        kernel_sequence, process_instance_id, entry_instance_id, binding_id,
        role_id, state_id, entry_rule_id, exact_profile_generation_ref_id,
        mount_id_unique, inode, inode_generation, mount_namespace_inode, filesystem_device,
        (tenant_id IS NULL OR node_id IS NULL OR node_boot_id IS NULL OR label_epoch IS NULL
            OR source_id IS NULL OR source_epoch IS NULL OR cpu_id IS NULL OR source_cursor IS NULL
            OR framed_record IS NULL OR coverage_interval_id IS NULL OR temporal_coverage IS NULL
            OR task_cookie IS NULL OR process_lineage_id IS NULL OR authority_domain_id IS NULL
            OR execution_set_id IS NULL OR exact_object_id IS NULL OR destination_id IS NULL
            OR policy_rule_id IS NULL OR reason IS NULL OR decision IS NULL OR effect_family IS NULL
            OR operation IS NULL OR configured_errno IS NULL OR kernel_result IS NULL
            OR (exact_profile_generation_ref_id IS NOT NULL AND (
                mount_id_unique IS NULL OR inode IS NULL OR inode_generation IS NULL
                OR mount_namespace_inode IS NULL OR filesystem_device IS NULL)))
            AS required_record_missing,
        COUNT(*) OVER (PARTITION BY tenant_id, node_id, node_boot_id, label_epoch,
            source_id, source_epoch, cpu_id, source_cursor) AS delivery_count,
        named_struct('tenant_id', tenant_id, 'node_id', node_id,
            'node_boot_id', node_boot_id, 'label_epoch', label_epoch,
            'source_id', source_id, 'source_epoch', source_epoch) AS stream,
        named_struct('stream', named_struct('tenant_id', tenant_id, 'node_id', node_id,
            'node_boot_id', node_boot_id, 'label_epoch', label_epoch,
            'source_id', source_id, 'source_epoch', source_epoch),
            'cpu_id', cpu_id, 'durable_cursor', source_cursor) AS record_id
    FROM records
),
__discovery_cte_record_versions AS (
    SELECT DISTINCT * FROM __discovery_cte_record_values
),
__discovery_cte_records AS (
    SELECT * FROM (
        SELECT value.*, COUNT(*) OVER (PARTITION BY record_id) AS record_versions,
            ROW_NUMBER() OVER (
                PARTITION BY record_id ORDER BY framed_record
                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
            ) AS version_rank
        FROM __discovery_cte_record_versions AS value
    ) AS ranked WHERE version_rank = 1
),
__discovery_cte_context_versions AS (
    SELECT DISTINCT record_id, subject_revision, image_digest, configuration_digest,
        process_instance_id, entry_instance_id, binding_id, role_id, state_id,
        entry_rule_id, catalog_revision, static_key, policy_revision,
        (record_id IS NULL OR record_id['stream'] IS NULL
            OR record_id['stream']['tenant_id'] IS NULL OR record_id['stream']['node_id'] IS NULL
            OR record_id['stream']['node_boot_id'] IS NULL OR record_id['stream']['label_epoch'] IS NULL
            OR record_id['stream']['source_id'] IS NULL OR record_id['stream']['source_epoch'] IS NULL
            OR record_id['cpu_id'] IS NULL OR record_id['durable_cursor'] IS NULL
            OR subject_revision IS NULL OR image_digest IS NULL OR configuration_digest IS NULL
            OR process_instance_id IS NULL OR entry_instance_id IS NULL OR binding_id IS NULL
            OR role_id IS NULL OR state_id IS NULL OR entry_rule_id IS NULL OR catalog_revision IS NULL
            OR static_key IS NULL OR static_key['workload_selector_id'] IS NULL
            OR static_key['protected_scope_id'] IS NULL OR static_key['execution_set_id'] IS NULL
            OR static_key['entry_kind'] IS NULL OR static_key['role_id'] IS NULL
            OR static_key['process_state_id'] IS NULL OR static_key['effect_family'] IS NULL
            OR static_key['operation_id'] IS NULL OR static_key['operation'] IS NULL
            OR static_key['operation_argument'] IS NULL OR static_key['argument_wildcard'] IS NULL
            OR static_key['object_selector'] IS NULL OR static_key['binding_lifecycle'] IS NULL
            OR policy_revision IS NULL OR policy_revision['profile_id'] IS NULL
            OR policy_revision['profile_version'] IS NULL OR policy_revision['source_revision_id'] IS NULL
            OR policy_revision['signed_profile_digest'] IS NULL) AS required_context_missing
    FROM contexts
),
__discovery_cte_contexts AS (
    SELECT * FROM (
        SELECT value.*, COUNT(*) OVER (PARTITION BY record_id) AS context_versions,
            ROW_NUMBER() OVER (
                PARTITION BY record_id ORDER BY record_id
                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
            ) AS version_rank
        FROM __discovery_cte_context_versions AS value
    ) AS ranked WHERE version_rank = 1
),
__discovery_cte_exclusion_versions AS (
    SELECT DISTINCT record_id, reason FROM exclusions
),
__discovery_cte_exclusions AS (
    SELECT * FROM (
        SELECT value.*, COUNT(*) OVER (PARTITION BY record_id) AS exclusion_versions,
            ROW_NUMBER() OVER (
                PARTITION BY record_id ORDER BY reason
                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
            ) AS version_rank
        FROM __discovery_cte_exclusion_versions AS value
    ) AS ranked WHERE version_rank = 1
),
__discovery_cte_ranges AS (
    SELECT ranges.*, ROW_NUMBER() OVER (
        ORDER BY tenant_id, node_id, node_boot_id, label_epoch, source_id,
            source_epoch, cpu_id, first_cursor, last_cursor
        ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    ) AS range_index
    FROM ranges
),
__discovery_cte_range_previous AS (
    SELECT value.*, LAG(last_cursor) OVER position AS previous_last,
        LAG(coverage_revision) OVER position AS previous_revision,
        LAG(coverage_interval_id) OVER position AS previous_interval
    FROM __discovery_cte_ranges AS value
    WINDOW position AS (
        PARTITION BY tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id
        ORDER BY first_cursor, last_cursor
    )
),
__discovery_cte_joined AS (
    SELECT record.*, context.record_id AS context_record_id,
        context.subject_revision, context.image_digest, context.configuration_digest,
        context.process_instance_id AS bound_process_instance_id,
        context.entry_instance_id AS bound_entry_instance_id,
        context.binding_id AS bound_binding_id,
        context.role_id AS bound_role_id, context.state_id AS bound_state_id,
        context.entry_rule_id AS bound_entry_rule_id, context.catalog_revision,
        context.static_key, context.policy_revision, context.context_versions,
        context.required_context_missing,
        exclusion.record_id AS exclusion_record_id, exclusion.reason AS exclusion_reason,
        exclusion.exclusion_versions, metadata.tenant_id AS metadata_tenant_id, metadata.proof_kind,
        COUNT(range.range_index) OVER (PARTITION BY record.record_id) AS range_matches
    FROM __discovery_cte_records AS record
    FULL JOIN __discovery_cte_contexts AS context ON record.record_id = context.record_id
    FULL JOIN __discovery_cte_exclusions AS exclusion
        ON COALESCE(record.record_id, context.record_id) = exclusion.record_id
    LEFT JOIN __discovery_cte_ranges AS range
        ON record.tenant_id = range.tenant_id AND record.node_id = range.node_id
        AND record.node_boot_id = range.node_boot_id AND record.label_epoch = range.label_epoch
        AND record.source_id = range.source_id AND record.source_epoch = range.source_epoch
        AND record.cpu_id = range.cpu_id AND record.coverage_interval_id = range.coverage_interval_id
        AND record.source_cursor BETWEEN range.first_cursor AND range.last_cursor
    CROSS JOIN __discovery_cte_metadata AS metadata
),
__discovery_cte_classified AS (
    SELECT value.*, CASE
        WHEN record_id IS NULL AND context_record_id IS NOT NULL THEN 'orphan context'
        WHEN record_id IS NULL AND exclusion_record_id IS NOT NULL THEN 'orphan exclusion'
        WHEN record_versions > 1 THEN 'record bytes'
        WHEN context_versions > 1 THEN 'context values'
        WHEN exclusion_versions > 1 THEN 'exclusion reason'
        WHEN required_record_missing THEN 'record fields'
        WHEN required_context_missing THEN 'context fields'
        WHEN tenant_id IS DISTINCT FROM metadata_tenant_id THEN 'record tenant'
        WHEN range_matches <> 1 THEN 'record range'
        WHEN exclusion_record_id IS NOT NULL AND (exclusion_reason IS NULL OR exclusion_reason = '')
            THEN 'exclusion reason'
        ELSE NULL END AS relational_error,
        arrow_cast(CASE
        WHEN record_id IS NULL OR exclusion_reason IS NOT NULL THEN NULL
        WHEN context_record_id IS NULL THEN 'MISSING_RECORDED_CONTEXT'
        WHEN profile_generation_ref_id IS NULL OR octet_length(encode(exact_object_id, 'hex')) = 0
            THEN 'MISSING_EXACT_OBJECT_OR_GENERATION'
        WHEN static_key['effect_family'] <> effect_family
            OR static_key['operation'] <> operation
            OR (NOT static_key['argument_wildcard']
                AND static_key['operation_argument'] <> COALESCE(operation_argument, 0))
            THEN 'CONTEXT_OPERATION_MISMATCH'
        WHEN context_schema_version IS NOT NULL AND (
            COALESCE(octet_length(encode(process_instance_id, 'hex')), 0) = 0
            OR COALESCE(octet_length(encode(entry_instance_id, 'hex')), 0) = 0
            OR COALESCE(octet_length(encode(binding_id, 'hex')), 0) = 0
            OR COALESCE(role_id, 0) = 0 OR COALESCE(state_id, 0) = 0
            OR COALESCE(entry_rule_id, 0) = 0)
            THEN 'MISSING_SOURCE_LIFETIME'
        WHEN context_schema_version IS NOT NULL AND (
            (process_instance_id IS DISTINCT FROM bound_process_instance_id)
            OR (entry_instance_id IS DISTINCT FROM bound_entry_instance_id)
            OR (binding_id IS DISTINCT FROM bound_binding_id)
            OR (role_id IS DISTINCT FROM bound_role_id)
            OR (state_id IS DISTINCT FROM bound_state_id)
            OR (entry_rule_id IS DISTINCT FROM bound_entry_rule_id))
            THEN 'CONTRADICTORY_SOURCE_CONTEXT'
        WHEN context_schema_version IS NULL AND proof_kind = 'OBSERVED_RUNTIME'
            THEN 'MISSING_DECISION_CONTEXT'
        ELSE NULL END, 'Utf8') AS unresolved_reason
    FROM __discovery_cte_joined AS value
),
__discovery_cte_keys AS (
    SELECT value.*, CASE WHEN record_id IS NOT NULL
        AND exclusion_reason IS NULL AND unresolved_reason IS NULL THEN named_struct(
        'stream', stream, 'cpu_id', cpu_id,
        'subject_revision', subject_revision, 'image_digest', image_digest,
        'configuration_digest', configuration_digest,
        'process_instance_id', bound_process_instance_id,
        'entry_instance_id', bound_entry_instance_id, 'binding_id', bound_binding_id,
        'role_id', bound_role_id, 'state_id', bound_state_id,
        'entry_rule_id', bound_entry_rule_id, 'catalog_revision', catalog_revision,
        'static_key', static_key, 'policy_revision', policy_revision,
        'generation', profile_generation_ref_id, 'coverage_interval_id', coverage_interval_id,
        'temporal_coverage', temporal_coverage,
        'effect', named_struct(
            'task_cookie', task_cookie, 'target_task_cookie', target_task_cookie,
            'process_lineage_id', process_lineage_id, 'authority_domain_id', authority_domain_id,
            'execution_set_id', execution_set_id, 'exact_object_id', exact_object_id,
            'destination_id', destination_id, 'policy_rule_id', policy_rule_id,
            'reason', reason, 'decision', decision, 'effect_family', effect_family,
            'operation', operation, 'operation_argument', operation_argument,
            'configured_errno', configured_errno, 'kernel_result', kernel_result,
            'exact_file_object', CASE WHEN exact_profile_generation_ref_id IS NULL THEN NULL
                ELSE named_struct('profile_generation_ref_id', exact_profile_generation_ref_id,
                    'mount_id_unique', mount_id_unique, 'inode', inode,
                    'inode_generation', inode_generation,
                    'mount_namespace_inode', mount_namespace_inode,
                    'filesystem_device', filesystem_device) END),
        'physical_result', arrow_cast(CASE WHEN decision = 1 AND kernel_result < 0
            THEN 'PREVENTED' ELSE 'UNKNOWN' END, 'Utf8'),
        'proof_kind', proof_kind) ELSE NULL END AS key
    FROM __discovery_cte_classified AS value
),
__discovery_cte_sampled AS (
    SELECT value.*, ROW_NUMBER() OVER (
        PARTITION BY key ORDER BY record_id
        ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    ) AS sample_rank
    FROM __discovery_cte_keys AS value
),
__discovery_cte_atom_rows AS (
    SELECT key, CAST(COUNT(record_id) AS BIGINT UNSIGNED) AS accepted,
        CAST(COUNT(key) AS BIGINT UNSIGNED) AS count,
        CAST(COUNT(unresolved_reason) AS BIGINT UNSIGNED) AS unresolved_count,
        CAST(COUNT(exclusion_reason) AS BIGINT UNSIGNED) AS excluded_count,
        SUM(CAST(COALESCE(delivery_count, 1) - 1 AS DECIMAL(38, 0))) AS duplicates,
        MIN(source_cursor) AS first_cursor, MAX(source_cursor) AS last_cursor,
        array_agg(record_id ORDER BY record_id) FILTER (
            WHERE key IS NOT NULL AND sample_rank <= 8) AS evidence_sample,
        COALESCE(array_agg(named_struct('record_id', record_id, 'reason', unresolved_reason)
            ORDER BY record_id) FILTER (WHERE unresolved_reason IS NOT NULL), []) AS unresolved,
        COALESCE(array_agg(named_struct('record_id', record_id, 'reason', exclusion_reason)
            ORDER BY record_id) FILTER (WHERE exclusion_reason IS NOT NULL), []) AS excluded,
        MIN(relational_error) AS relational_error
    FROM __discovery_cte_sampled GROUP BY key
),
__discovery_cte_atoms AS (
    SELECT COALESCE(array_agg(named_struct('key', key, 'count', count,
        'first_cursor', first_cursor, 'last_cursor', last_cursor,
        'evidence_sample', evidence_sample) ORDER BY
        key['stream']['tenant_id'], key['stream']['node_id'], key['stream']['node_boot_id'],
        key['stream']['label_epoch'], key['stream']['source_id'], key['stream']['source_epoch'],
        key['cpu_id'], key['subject_revision'], key['image_digest'], key['configuration_digest'],
        key['process_instance_id'], key['entry_instance_id'], key['binding_id'],
        key['role_id'], key['state_id'], key['entry_rule_id'], key['catalog_revision'],
        key['static_key']['workload_selector_id'], key['static_key']['protected_scope_id'],
        key['static_key']['execution_set_id'], key['static_key']['entry_kind'],
        key['static_key']['role_id'], key['static_key']['process_state_id'],
        key['static_key']['effect_family'], key['static_key']['operation_id'],
        key['static_key']['operation'], key['static_key']['operation_argument'],
        key['static_key']['argument_wildcard'], key['static_key']['object_selector'],
        key['static_key']['binding_lifecycle'], key['policy_revision']['profile_id'],
        key['policy_revision']['profile_version'], key['policy_revision']['source_revision_id'],
        key['policy_revision']['signed_profile_digest'], key['generation'],
        key['coverage_interval_id'], key['temporal_coverage'], key['effect']['task_cookie'],
        key['effect']['target_task_cookie'] NULLS FIRST, key['effect']['process_lineage_id'],
        key['effect']['authority_domain_id'], key['effect']['execution_set_id'],
        key['effect']['exact_object_id'], key['effect']['destination_id'],
        key['effect']['policy_rule_id'], key['effect']['reason'], key['effect']['decision'],
        key['effect']['effect_family'], key['effect']['operation'],
        key['effect']['operation_argument'] NULLS FIRST, key['effect']['configured_errno'],
        key['effect']['kernel_result'],
        key['effect']['exact_file_object']['profile_generation_ref_id'] NULLS FIRST,
        key['effect']['exact_file_object']['mount_id_unique'] NULLS FIRST,
        key['effect']['exact_file_object']['inode'] NULLS FIRST,
        key['effect']['exact_file_object']['inode_generation'] NULLS FIRST,
        key['effect']['exact_file_object']['mount_namespace_inode'] NULLS FIRST,
        key['effect']['exact_file_object']['filesystem_device'] NULLS FIRST,
        key['physical_result']) FILTER (WHERE key IS NOT NULL), []) AS atoms,
        COALESCE(flatten(array_agg(unresolved)), []) AS unresolved,
        COALESCE(flatten(array_agg(excluded)), []) AS excluded,
        COALESCE(SUM(CAST(accepted AS DECIMAL(38, 0))), CAST(0 AS DECIMAL(38, 0))) AS accepted_total,
        COALESCE(SUM(CAST(count AS DECIMAL(38, 0))), CAST(0 AS DECIMAL(38, 0))) AS included_total,
        COALESCE(SUM(CAST(unresolved_count AS DECIMAL(38, 0))), CAST(0 AS DECIMAL(38, 0))) AS unresolved_total,
        COALESCE(SUM(CAST(excluded_count AS DECIMAL(38, 0))), CAST(0 AS DECIMAL(38, 0))) AS excluded_total,
        COALESCE(SUM(duplicates), CAST(0 AS DECIMAL(38, 0))) AS duplicate_total,
        MIN(relational_error) AS relational_error
    FROM __discovery_cte_atom_rows
),
__discovery_cte_range_counts AS (
    SELECT range.range_index, CAST(COUNT(record.source_cursor) AS BIGINT UNSIGNED) AS record_count,
        COALESCE(BOOL_OR(record.temporal_coverage = 2), FALSE) AS observed_gap,
        COALESCE(BOOL_OR(record.temporal_coverage = 0), FALSE) AS observed_unknown
    FROM __discovery_cte_ranges AS range
    LEFT JOIN __discovery_cte_records AS record
        ON range.tenant_id = record.tenant_id AND range.node_id = record.node_id
        AND range.node_boot_id = record.node_boot_id AND range.label_epoch = record.label_epoch
        AND range.source_id = record.source_id AND range.source_epoch = record.source_epoch
        AND range.cpu_id = record.cpu_id AND range.coverage_interval_id = record.coverage_interval_id
        AND record.source_cursor BETWEEN range.first_cursor AND range.last_cursor
    GROUP BY range.range_index
),
__discovery_cte_range_states AS (
    SELECT range.*, CASE
        WHEN range.tenant_id IS DISTINCT FROM metadata.tenant_id THEN 'coverage tenant'
        WHEN range.tenant_id IS NULL OR node_id IS NULL OR node_boot_id IS NULL OR label_epoch IS NULL
            OR source_id IS NULL OR source_epoch IS NULL OR cpu_id IS NULL
            OR first_cursor IS NULL OR last_cursor IS NULL OR expected_records IS NULL
            OR first_cursor = 0 OR last_cursor < first_cursor
            OR CAST(expected_records AS DECIMAL(20, 0))
                > CAST(last_cursor AS DECIMAL(20, 0)) - CAST(first_cursor AS DECIMAL(20, 0)) + 1
            OR coverage_revision IS NULL OR coverage_interval_id IS NULL
            OR state IS NULL OR state NOT IN ('HEALTHY', 'GAPPED', 'UNKNOWN', 'CLOSED')
            OR gap_reasons IS NULL
            OR array_position(gap_reasons, arrow_cast(NULL, 'Utf8')) IS NOT NULL
            OR (state = 'HEALTHY' AND array_length(gap_reasons) <> 0)
            OR (coverage_revision = 0 AND NOT (
                state IN ('UNKNOWN', 'GAPPED') AND array_length(gap_reasons) > 0))
            THEN 'coverage identity'
        WHEN previous_last >= first_cursor THEN 'snapshot overlap'
        ELSE NULL END AS relational_error,
        CASE
        WHEN counts.record_count <> range.expected_records OR counts.observed_gap THEN 'GAPPED'
        WHEN counts.observed_unknown AND range.state <> 'GAPPED' THEN 'UNKNOWN'
        ELSE range.state END AS qualified_state,
        array_sort(array_distinct(array_concat(range.gap_reasons,
            CASE WHEN counts.record_count <> range.expected_records
                THEN ['INPUT_RANGE_INCOMPLETE'] ELSE [] END,
            CASE WHEN counts.observed_gap THEN ['OBSERVATION_COVERAGE_GAPPED'] ELSE [] END,
            CASE WHEN counts.observed_unknown THEN ['OBSERVATION_COVERAGE_UNKNOWN'] ELSE [] END
        ))) AS qualified_reasons
    FROM __discovery_cte_range_previous AS range
    JOIN __discovery_cte_range_counts AS counts ON range.range_index = counts.range_index
    CROSS JOIN __discovery_cte_metadata AS metadata
),
__discovery_cte_range_marked AS (
    SELECT value.*, CASE WHEN previous_last IS NULL
        OR CAST(first_cursor AS DECIMAL(20, 0)) - CAST(previous_last AS DECIMAL(20, 0)) <> 1
        OR (coverage_revision IS DISTINCT FROM previous_revision)
        OR (coverage_interval_id IS DISTINCT FROM previous_interval)
        THEN 1 ELSE 0 END AS boundary
    FROM __discovery_cte_range_states AS value
),
__discovery_cte_range_groups AS (
    SELECT value.*, SUM(boundary) OVER (
        PARTITION BY tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id
        ORDER BY first_cursor, last_cursor ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    ) AS range_group
    FROM __discovery_cte_range_marked AS value
),
__discovery_cte_coverage_rows AS (
    SELECT tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id,
        MIN(first_cursor) AS first_cursor, MAX(last_cursor) AS last_cursor,
        SUM(CAST(expected_records AS DECIMAL(38, 0))) AS expected_total,
        coverage_revision, coverage_interval_id,
        arrow_cast(CASE MAX(CASE qualified_state WHEN 'GAPPED' THEN 3 WHEN 'UNKNOWN' THEN 2
            WHEN 'CLOSED' THEN 1 ELSE 0 END)
            WHEN 3 THEN 'GAPPED' WHEN 2 THEN 'UNKNOWN' WHEN 1 THEN 'CLOSED' ELSE 'HEALTHY' END,
            'Utf8') AS state,
        arrow_cast(array_sort(array_distinct(flatten(array_agg(qualified_reasons)))),
            'List(Utf8)') AS gap_reasons,
        MIN(relational_error) AS relational_error
    FROM __discovery_cte_range_groups
    GROUP BY tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id,
        coverage_revision, coverage_interval_id, range_group
),
__discovery_cte_coverage AS (
    SELECT COALESCE(array_agg(named_struct(
        'stream', named_struct('tenant_id', tenant_id, 'node_id', node_id,
            'node_boot_id', node_boot_id, 'label_epoch', label_epoch,
            'source_id', source_id, 'source_epoch', source_epoch),
        'cpu_id', cpu_id, 'first_cursor', first_cursor, 'last_cursor', last_cursor,
        'expected_records', CASE WHEN expected_total <= CAST('18446744073709551615' AS DECIMAL(38, 0))
            THEN CAST(expected_total AS BIGINT UNSIGNED) ELSE CAST(NULL AS BIGINT UNSIGNED) END,
        'coverage_revision', coverage_revision, 'coverage_interval_id', coverage_interval_id,
        'state', state, 'gap_reasons', gap_reasons)
        ORDER BY tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch,
            cpu_id, first_cursor), []) AS coverage,
        COALESCE(MIN(relational_error), MIN(CASE
            WHEN expected_total > CAST('18446744073709551615' AS DECIMAL(38, 0)) THEN 'count'
            ELSE NULL END)) AS relational_error
    FROM __discovery_cte_coverage_rows
),
__discovery_cte_lifecycle_cases AS (
    SELECT * FROM (VALUES
        (0, 'STARTUP'), (1, 'STEADY_WORK'), (2, 'PROBES'), (3, 'RESTART'),
        (4, 'ROLLOUT'), (5, 'SHUTDOWN'), (6, 'RECOVERY'), (7, 'SCHEDULED_WORK'),
        (8, 'APPROVED_MAINTENANCE')) AS cases(case_rank, lifecycle_case)
),
__discovery_cte_lifecycle_states AS (
    SELECT "case", MIN(state) FILTER (WHERE state <> 'MISSING') AS known_state,
        MIN(reason) FILTER (WHERE state IN ('DECLARED', 'NOT_APPLICABLE', 'UNSUPPORTED')) AS reason,
        CASE WHEN COUNT(DISTINCT state) FILTER (WHERE state <> 'MISSING') > 1
            OR COUNT(DISTINCT reason) FILTER (
                WHERE state IN ('DECLARED', 'NOT_APPLICABLE', 'UNSUPPORTED')) > 1
            THEN 'lifecycle state'
            ELSE MIN(CASE
                WHEN state IS NULL OR state NOT IN (
                    'RECORDED', 'DECLARED', 'MISSING', 'NOT_APPLICABLE', 'UNSUPPORTED')
                    THEN 'lifecycle state'
                WHEN state = 'RECORDED' AND (records IS NULL OR array_length(records) = 0)
                    THEN 'lifecycle records'
                WHEN state IN ('DECLARED', 'NOT_APPLICABLE', 'UNSUPPORTED')
                    AND (reason IS NULL OR reason = '') THEN 'lifecycle reason'
                ELSE NULL END) END AS relational_error
    FROM lifecycle GROUP BY "case"
),
__discovery_cte_lifecycle_ids AS (
    SELECT "case", UNNEST(records) AS record_id FROM lifecycle WHERE state = 'RECORDED'
),
__discovery_cte_lifecycle_records AS (
    SELECT ids."case", array_agg(ids.record_id ORDER BY ids.record_id) AS records,
        MIN(CASE WHEN record.record_id IS NULL THEN 'lifecycle records' ELSE NULL END)
            AS relational_error
    FROM (SELECT DISTINCT "case", record_id FROM __discovery_cte_lifecycle_ids) AS ids
    LEFT JOIN __discovery_cte_records AS record ON ids.record_id = record.record_id
    GROUP BY ids."case"
),
__discovery_cte_lifecycle AS (
    SELECT array_agg(named_struct('case', arrow_cast(cases.lifecycle_case, 'Utf8'),
        'state', arrow_cast(COALESCE(states.known_state, 'MISSING'), 'Utf8'),
        'records', COALESCE(ids.records, []), 'reason', states.reason)
        ORDER BY cases.case_rank) FILTER (WHERE cases.case_rank IS NOT NULL) AS lifecycle,
        MIN(CASE WHEN cases.case_rank IS NULL THEN 'lifecycle case'
            ELSE COALESCE(states.relational_error, ids.relational_error) END) AS relational_error
    FROM __discovery_cte_lifecycle_cases AS cases
    FULL JOIN __discovery_cte_lifecycle_states AS states ON cases.lifecycle_case = states."case"
    LEFT JOIN __discovery_cte_lifecycle_records AS ids
        ON COALESCE(cases.lifecycle_case, states."case") = ids."case"
)
SELECT CAST(3 AS INT UNSIGNED) AS schema_version,
    metadata.tenant_id, metadata.source_revision, metadata.proof_kind,
    atoms.atoms, coverage.coverage, atoms.unresolved, atoms.excluded,
    lifecycle.lifecycle,
    CASE WHEN atoms.accepted_total <= CAST('18446744073709551615' AS DECIMAL(38, 0))
        THEN CAST(atoms.accepted_total AS BIGINT UNSIGNED)
        ELSE CAST(NULL AS BIGINT UNSIGNED) END AS accepted_records,
    CASE WHEN atoms.included_total <= CAST('18446744073709551615' AS DECIMAL(38, 0))
        THEN CAST(atoms.included_total AS BIGINT UNSIGNED)
        ELSE CAST(NULL AS BIGINT UNSIGNED) END AS included_records,
    CASE WHEN atoms.unresolved_total <= CAST('18446744073709551615' AS DECIMAL(38, 0))
        THEN CAST(atoms.unresolved_total AS BIGINT UNSIGNED)
        ELSE CAST(NULL AS BIGINT UNSIGNED) END AS unresolved_records,
    CASE WHEN atoms.excluded_total <= CAST('18446744073709551615' AS DECIMAL(38, 0))
        THEN CAST(atoms.excluded_total AS BIGINT UNSIGNED)
        ELSE CAST(NULL AS BIGINT UNSIGNED) END AS excluded_records,
    CASE WHEN atoms.duplicate_total <= CAST('18446744073709551615' AS DECIMAL(38, 0))
        THEN CAST(atoms.duplicate_total AS BIGINT UNSIGNED)
        ELSE CAST(NULL AS BIGINT UNSIGNED) END AS duplicate_deliveries,
    arrow_cast(CASE
        WHEN metadata.metadata_count <> 1 OR metadata.tenant_id IS NULL
            OR metadata.source_revision IS NULL OR metadata.source_revision = ''
            OR metadata.proof_kind IS NULL OR metadata.proof_kind NOT IN (
                'OBSERVED_RUNTIME', 'RECORDED_INPUT', 'SYNTHETIC', 'CONFIGURATION_SCAN')
            THEN 'metadata'
        ELSE COALESCE(atoms.relational_error, coverage.relational_error, lifecycle.relational_error,
            CASE WHEN atoms.accepted_total > CAST('18446744073709551615' AS DECIMAL(38, 0))
                OR atoms.included_total > CAST('18446744073709551615' AS DECIMAL(38, 0))
                OR atoms.unresolved_total > CAST('18446744073709551615' AS DECIMAL(38, 0))
                OR atoms.excluded_total > CAST('18446744073709551615' AS DECIMAL(38, 0))
                OR atoms.duplicate_total > CAST('18446744073709551615' AS DECIMAL(38, 0))
                OR atoms.included_total + atoms.unresolved_total + atoms.excluded_total
                    <> atoms.accepted_total THEN 'count' ELSE NULL END)
        END, 'Utf8') AS __discovery_error
FROM __discovery_cte_metadata AS metadata
CROSS JOIN __discovery_cte_atoms AS atoms
CROSS JOIN __discovery_cte_coverage AS coverage
CROSS JOIN __discovery_cte_lifecycle AS lifecycle
