WITH
__discovery_merge_left AS (
    SELECT COUNT(*) OVER () AS row_count, named_struct('schema_version', schema_version, 'tenant_id', tenant_id,
        'source_revision', source_revision, 'proof_kind', proof_kind,
        'accepted_records', accepted_records, 'included_records', included_records,
        'unresolved_records', unresolved_records, 'excluded_records', excluded_records,
        'atoms', atoms, 'coverage', coverage, 'unresolved', unresolved,
        'excluded', excluded, 'lifecycle', lifecycle) AS snapshot FROM left_snapshot
),
__discovery_merge_right AS (
    SELECT COUNT(*) OVER () AS row_count, named_struct('schema_version', schema_version, 'tenant_id', tenant_id,
        'source_revision', source_revision, 'proof_kind', proof_kind,
        'accepted_records', accepted_records, 'included_records', included_records,
        'unresolved_records', unresolved_records, 'excluded_records', excluded_records,
        'atoms', atoms, 'coverage', coverage, 'unresolved', unresolved,
        'excluded', excluded, 'lifecycle', lifecycle) AS snapshot FROM right_snapshot
),
__discovery_merge_pair AS (
    SELECT left_side.snapshot AS prior, right_side.snapshot AS incoming,
        COALESCE(left_side.row_count, 0) AS left_count, right_side.row_count AS right_count,
        (left_side.snapshot IS NULL
            OR (left_side.snapshot IS NOT DISTINCT FROM right_side.snapshot)) AS discard_prior,
        COALESCE(array_except(array_element(right_side.snapshot['lifecycle'], 1)['records'],
            array_element(right_side.snapshot['lifecycle'], 1)['records']), []) AS empty_records
    FROM __discovery_merge_right AS right_side
    LEFT JOIN __discovery_merge_left AS left_side ON TRUE
),
__discovery_merge_combined AS (
    SELECT incoming['schema_version'] AS schema_version, incoming['tenant_id'] AS tenant_id,
        incoming['source_revision'] AS source_revision, incoming['proof_kind'] AS proof_kind,
        left_count, right_count,
        CAST(incoming['accepted_records'] AS DECIMAL(38, 0))
            + CASE WHEN discard_prior THEN 0 ELSE CAST(prior['accepted_records'] AS DECIMAL(38, 0)) END AS accepted_total,
        CAST(incoming['included_records'] AS DECIMAL(38, 0))
            + CASE WHEN discard_prior THEN 0 ELSE CAST(prior['included_records'] AS DECIMAL(38, 0)) END AS included_total,
        CAST(incoming['unresolved_records'] AS DECIMAL(38, 0))
            + CASE WHEN discard_prior THEN 0 ELSE CAST(prior['unresolved_records'] AS DECIMAL(38, 0)) END AS unresolved_total,
        CAST(incoming['excluded_records'] AS DECIMAL(38, 0))
            + CASE WHEN discard_prior THEN 0 ELSE CAST(prior['excluded_records'] AS DECIMAL(38, 0)) END AS excluded_total,
        CASE WHEN discard_prior THEN incoming['atoms']
            ELSE array_concat(prior['atoms'], incoming['atoms']) END AS atoms,
        CASE WHEN discard_prior THEN incoming['coverage']
            ELSE array_concat(prior['coverage'], incoming['coverage']) END AS coverage,
        CASE WHEN discard_prior THEN incoming['unresolved']
            ELSE array_concat(prior['unresolved'], incoming['unresolved']) END AS unresolved,
        CASE WHEN discard_prior THEN incoming['excluded']
            ELSE array_concat(prior['excluded'], incoming['excluded']) END AS excluded,
        array_concat(CASE WHEN discard_prior THEN incoming['lifecycle']
            ELSE array_concat(prior['lifecycle'], incoming['lifecycle']) END,
            [named_struct('case', arrow_cast('STARTUP', 'Utf8'), 'state', arrow_cast('MISSING', 'Utf8'), 'records', empty_records, 'reason', arrow_cast(NULL, 'Utf8')),
                named_struct('case', arrow_cast('STEADY_WORK', 'Utf8'), 'state', arrow_cast('MISSING', 'Utf8'), 'records', empty_records, 'reason', arrow_cast(NULL, 'Utf8')),
                named_struct('case', arrow_cast('PROBES', 'Utf8'), 'state', arrow_cast('MISSING', 'Utf8'), 'records', empty_records, 'reason', arrow_cast(NULL, 'Utf8')),
                named_struct('case', arrow_cast('RESTART', 'Utf8'), 'state', arrow_cast('MISSING', 'Utf8'), 'records', empty_records, 'reason', arrow_cast(NULL, 'Utf8')),
                named_struct('case', arrow_cast('ROLLOUT', 'Utf8'), 'state', arrow_cast('MISSING', 'Utf8'), 'records', empty_records, 'reason', arrow_cast(NULL, 'Utf8')),
                named_struct('case', arrow_cast('SHUTDOWN', 'Utf8'), 'state', arrow_cast('MISSING', 'Utf8'), 'records', empty_records, 'reason', arrow_cast(NULL, 'Utf8')),
                named_struct('case', arrow_cast('RECOVERY', 'Utf8'), 'state', arrow_cast('MISSING', 'Utf8'), 'records', empty_records, 'reason', arrow_cast(NULL, 'Utf8')),
                named_struct('case', arrow_cast('SCHEDULED_WORK', 'Utf8'), 'state', arrow_cast('MISSING', 'Utf8'), 'records', empty_records, 'reason', arrow_cast(NULL, 'Utf8')),
                named_struct('case', arrow_cast('APPROVED_MAINTENANCE', 'Utf8'), 'state', arrow_cast('MISSING', 'Utf8'), 'records', empty_records, 'reason', arrow_cast(NULL, 'Utf8'))]) AS lifecycle,
        CASE WHEN
            (((incoming['schema_version'] IS NULL OR incoming['tenant_id'] IS NULL)
                OR (incoming['source_revision'] IS NULL OR incoming['proof_kind'] IS NULL))
                OR ((incoming['atoms'] IS NULL OR incoming['coverage'] IS NULL)
                    OR (incoming['unresolved'] IS NULL OR incoming['excluded'] IS NULL)))
            OR ((incoming['lifecycle'] IS NULL OR incoming['accepted_records'] IS NULL)
                OR ((incoming['included_records'] IS NULL OR incoming['unresolved_records'] IS NULL)
                    OR incoming['excluded_records'] IS NULL)) THEN 'snapshot schema'
        WHEN prior IS NOT NULL AND (
            (((prior['schema_version'] IS NULL OR prior['tenant_id'] IS NULL)
                OR (prior['source_revision'] IS NULL OR prior['proof_kind'] IS NULL))
                OR ((prior['atoms'] IS NULL OR prior['coverage'] IS NULL)
                    OR (prior['unresolved'] IS NULL OR prior['excluded'] IS NULL)))
            OR ((prior['lifecycle'] IS NULL OR prior['accepted_records'] IS NULL)
                OR ((prior['included_records'] IS NULL OR prior['unresolved_records'] IS NULL)
                    OR prior['excluded_records'] IS NULL))) THEN 'snapshot schema'
        WHEN incoming['schema_version'] <> 3
            OR (prior IS NOT NULL AND prior['schema_version'] <> 3) THEN 'snapshot schema'
        WHEN prior IS NOT NULL AND (
            (prior['tenant_id'] IS DISTINCT FROM incoming['tenant_id'])
            OR (prior['source_revision'] IS DISTINCT FROM incoming['source_revision'])
            OR (prior['proof_kind'] IS DISTINCT FROM incoming['proof_kind'])) THEN 'snapshot source'
        ELSE NULL END AS metadata_error
    FROM __discovery_merge_pair
),
__discovery_merge_items AS (
    SELECT schema_version, tenant_id, source_revision, proof_kind, left_count, right_count,
        accepted_total, included_total, unresolved_total, excluded_total, metadata_error,
        UNNEST(atoms) AS atom, UNNEST(coverage) AS range,
        UNNEST(unresolved) AS unresolved, UNNEST(excluded) AS excluded,
        UNNEST(lifecycle) AS lifecycle, UNNEST([TRUE]) AS header
    FROM __discovery_merge_combined
),
__discovery_merge_previous AS (
    SELECT item.*,
        LAG(range['last_cursor']) OVER position AS previous_last,
        LAG(range['coverage_revision']) OVER position AS previous_revision,
        LAG(range['coverage_interval_id']) OVER position AS previous_interval
    FROM __discovery_merge_items AS item
    WINDOW position AS (
        PARTITION BY range['stream'], range['cpu_id']
        ORDER BY range['first_cursor'], range['last_cursor']
        ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    )
),
__discovery_merge_marked AS (
    SELECT item.*, CASE WHEN previous_last IS NULL
        OR CAST(range['first_cursor'] AS DECIMAL(20, 0)) - CAST(previous_last AS DECIMAL(20, 0)) <> 1
        OR (range['coverage_revision'] IS DISTINCT FROM previous_revision)
        OR (range['coverage_interval_id'] IS DISTINCT FROM previous_interval)
        THEN 1 ELSE 0 END AS boundary
    FROM __discovery_merge_previous AS item
),
__discovery_merge_values AS (
    SELECT item.*, atom['key'] AS key, range['stream'] AS stream, range['cpu_id'] AS cpu_id,
        range['coverage_revision'] AS coverage_revision,
        range['coverage_interval_id'] AS coverage_interval_id, lifecycle['case'] AS lifecycle_case,
        SUM(boundary) OVER (
            PARTITION BY range['stream'], range['cpu_id']
            ORDER BY range['first_cursor'], range['last_cursor']
            ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        ) AS range_group
    FROM __discovery_merge_marked AS item
),
__discovery_merge_groups AS (
    SELECT key, stream, cpu_id, coverage_revision, coverage_interval_id, range_group, lifecycle_case,
        GROUPING(key) AS atom_group, GROUPING(stream) AS coverage_group,
        GROUPING(lifecycle_case) AS lifecycle_group,
        MIN(schema_version) AS schema_version, MIN(tenant_id) AS tenant_id,
        MIN(source_revision) AS source_revision, MIN(proof_kind) AS proof_kind,
        MIN(left_count) AS left_count, MIN(right_count) AS right_count,
        MIN(accepted_total) AS accepted_total, MIN(included_total) AS included_total,
        MIN(unresolved_total) AS unresolved_total, MIN(excluded_total) AS excluded_total,
        MIN(metadata_error) AS metadata_error,
        SUM(CAST(atom['count'] AS DECIMAL(38, 0))) AS atom_total,
        MIN(atom['first_cursor']) AS atom_first, MAX(atom['last_cursor']) AS atom_last,
        array_slice(array_sort(array_distinct(array_concat(flatten(array_agg(atom['evidence_sample'])
            FILTER (WHERE atom IS NOT NULL)), []))), 1, 8) AS evidence_sample,
        MIN(range['first_cursor']) AS first_cursor, MAX(range['last_cursor']) AS last_cursor,
        SUM(CAST(range['expected_records'] AS DECIMAL(38, 0))) AS expected_total,
        arrow_cast(CASE MAX(CASE WHEN range['state'] = 'GAPPED' THEN 3
            WHEN range['state'] = 'UNKNOWN' THEN 2 WHEN range['state'] = 'CLOSED' THEN 1 ELSE 0 END)
            WHEN 3 THEN 'GAPPED' WHEN 2 THEN 'UNKNOWN' WHEN 1 THEN 'CLOSED' ELSE 'HEALTHY' END, 'Utf8') AS state,
        CASE WHEN COUNT(*) FILTER (WHERE range IS NOT NULL) = 1
            THEN array_element(array_agg(range['gap_reasons']) FILTER (WHERE range IS NOT NULL), 1)
            ELSE array_sort(array_distinct(flatten(array_agg(range['gap_reasons'])
                FILTER (WHERE range IS NOT NULL)))) END AS gap_reasons,
        MIN(CASE WHEN previous_last >= range['first_cursor'] THEN 'snapshot overlap' ELSE NULL END) AS range_error,
        COALESCE(array_agg(unresolved ORDER BY unresolved['record_id'])
            FILTER (WHERE unresolved IS NOT NULL), []) AS unresolved,
        COALESCE(array_agg(excluded ORDER BY excluded['record_id'])
            FILTER (WHERE excluded IS NOT NULL), []) AS excluded,
        COUNT(*) FILTER (WHERE lifecycle IS NOT NULL) AS lifecycle_count,
        MIN(lifecycle['state']) FILTER (WHERE lifecycle['state'] <> 'MISSING') AS lifecycle_state,
        MIN(lifecycle['reason']) FILTER (WHERE lifecycle['state'] IN (
            'DECLARED', 'NOT_APPLICABLE', 'UNSUPPORTED')) AS lifecycle_reason,
        COALESCE(array_sort(array_distinct(flatten(array_agg(lifecycle['records'])
            FILTER (WHERE lifecycle['state'] = 'RECORDED')))), []) AS lifecycle_records,
        CASE WHEN COUNT(DISTINCT lifecycle['state']) FILTER (WHERE lifecycle['state'] <> 'MISSING') > 1
            OR COUNT(DISTINCT lifecycle['reason']) FILTER (WHERE lifecycle['state'] IN (
                'DECLARED', 'NOT_APPLICABLE', 'UNSUPPORTED')) > 1 THEN 'lifecycle state' ELSE NULL END AS lifecycle_error
    FROM __discovery_merge_values
    GROUP BY GROUPING SETS ((key), (stream, cpu_id, coverage_revision, coverage_interval_id, range_group), (lifecycle_case), ())
),
__discovery_merge_snapshot AS (
    SELECT MIN(schema_version) AS schema_version, MIN(tenant_id) AS tenant_id,
        MIN(source_revision) AS source_revision, MIN(proof_kind) AS proof_kind,
        COALESCE(array_agg(named_struct('key', key,
            'count', CASE WHEN atom_total <= CAST('18446744073709551615' AS DECIMAL(38, 0))
                THEN CAST(atom_total AS BIGINT UNSIGNED) ELSE CAST(NULL AS BIGINT UNSIGNED) END,
            'first_cursor', atom_first, 'last_cursor', atom_last, 'evidence_sample', evidence_sample) ORDER BY
        key['stream']['tenant_id'], key['stream']['node_id'], key['stream']['node_boot_id'],
        key['stream']['label_epoch'], key['stream']['source_id'], key['stream']['source_epoch'],
        key['cpu_id'], key['subject_revision'], key['image_digest'],
        key['configuration_digest'], key['process_instance_id'], key['entry_instance_id'],
        key['binding_id'], key['role_id'], key['state_id'],
        key['entry_rule_id'], key['catalog_revision'], key['static_key']['workload_selector_id'],
        key['static_key']['protected_scope_id'], key['static_key']['execution_set_id'], key['static_key']['entry_kind'],
        key['static_key']['role_id'], key['static_key']['process_state_id'], key['static_key']['effect_family'],
        key['static_key']['operation_id'], key['static_key']['operation'], key['static_key']['operation_argument'],
        key['static_key']['argument_wildcard'], key['static_key']['object_selector'], key['static_key']['binding_lifecycle'],
        key['policy_revision']['profile_id'], key['policy_revision']['profile_version'], key['policy_revision']['source_revision_id'],
        key['policy_revision']['signed_profile_digest'], key['generation'], key['coverage_interval_id'],
        key['temporal_coverage'], key['effect']['task_cookie'], key['effect']['target_task_cookie'] NULLS FIRST,
        key['effect']['process_lineage_id'], key['effect']['authority_domain_id'], key['effect']['execution_set_id'],
        key['effect']['exact_object_id'], key['effect']['destination_id'], key['effect']['policy_rule_id'],
        key['effect']['reason'], key['effect']['decision'], key['effect']['effect_family'],
        key['effect']['operation'], key['effect']['operation_argument'] NULLS FIRST, key['effect']['configured_errno'],
        key['effect']['kernel_result'], key['effect']['exact_file_object']['profile_generation_ref_id'] NULLS FIRST, key['effect']['exact_file_object']['mount_id_unique'] NULLS FIRST,
        key['effect']['exact_file_object']['inode'] NULLS FIRST, key['effect']['exact_file_object']['inode_generation'] NULLS FIRST, key['effect']['exact_file_object']['mount_namespace_inode'] NULLS FIRST,
        key['effect']['exact_file_object']['filesystem_device'] NULLS FIRST, key['physical_result']) FILTER (WHERE atom_group = 0 AND key IS NOT NULL), []) AS atoms,
        COALESCE(array_agg(named_struct('stream', stream, 'cpu_id', cpu_id,
            'first_cursor', first_cursor, 'last_cursor', last_cursor,
            'expected_records', CASE WHEN expected_total <= CAST('18446744073709551615' AS DECIMAL(38, 0))
                THEN CAST(expected_total AS BIGINT UNSIGNED) ELSE CAST(NULL AS BIGINT UNSIGNED) END,
            'coverage_revision', coverage_revision, 'coverage_interval_id', coverage_interval_id,
            'state', state, 'gap_reasons', gap_reasons) ORDER BY stream, cpu_id, first_cursor)
            FILTER (WHERE coverage_group = 0 AND stream IS NOT NULL), []) AS coverage,
        COALESCE(array_element(array_agg(unresolved) FILTER (WHERE atom_group = 1
            AND coverage_group = 1 AND lifecycle_group = 1), 1), []) AS unresolved,
        COALESCE(array_element(array_agg(excluded) FILTER (WHERE atom_group = 1
            AND coverage_group = 1 AND lifecycle_group = 1), 1), []) AS excluded,
        array_agg(named_struct('case', arrow_cast(lifecycle_case, 'Utf8'),
            'state', arrow_cast(COALESCE(lifecycle_state, 'MISSING'), 'Utf8'),
            'records', lifecycle_records, 'reason', lifecycle_reason)
            ORDER BY CASE lifecycle_case WHEN 'STARTUP' THEN 0 WHEN 'STEADY_WORK' THEN 1
                WHEN 'PROBES' THEN 2 WHEN 'RESTART' THEN 3 WHEN 'ROLLOUT' THEN 4
                WHEN 'SHUTDOWN' THEN 5 WHEN 'RECOVERY' THEN 6 WHEN 'SCHEDULED_WORK' THEN 7
                WHEN 'APPROVED_MAINTENANCE' THEN 8 ELSE 9 END)
            FILTER (WHERE lifecycle_group = 0 AND lifecycle_case IN ('STARTUP', 'STEADY_WORK', 'PROBES',
                'RESTART', 'ROLLOUT', 'SHUTDOWN', 'RECOVERY', 'SCHEDULED_WORK', 'APPROVED_MAINTENANCE')) AS lifecycle,
        CASE WHEN MIN(accepted_total) <= CAST('18446744073709551615' AS DECIMAL(38, 0))
            THEN CAST(MIN(accepted_total) AS BIGINT UNSIGNED) ELSE CAST(NULL AS BIGINT UNSIGNED) END AS accepted_records,
        CASE WHEN MIN(included_total) <= CAST('18446744073709551615' AS DECIMAL(38, 0))
            THEN CAST(MIN(included_total) AS BIGINT UNSIGNED) ELSE CAST(NULL AS BIGINT UNSIGNED) END AS included_records,
        CASE WHEN MIN(unresolved_total) <= CAST('18446744073709551615' AS DECIMAL(38, 0))
            THEN CAST(MIN(unresolved_total) AS BIGINT UNSIGNED) ELSE CAST(NULL AS BIGINT UNSIGNED) END AS unresolved_records,
        CASE WHEN MIN(excluded_total) <= CAST('18446744073709551615' AS DECIMAL(38, 0))
            THEN CAST(MIN(excluded_total) AS BIGINT UNSIGNED) ELSE CAST(NULL AS BIGINT UNSIGNED) END AS excluded_records,
        COALESCE(CASE WHEN COALESCE(MIN(left_count), 0) > 1 OR COALESCE(MIN(right_count), 0) <> 1
                THEN 'snapshot count' ELSE NULL END,
            MIN(metadata_error),
            MIN(CASE WHEN atom_group = 0 AND atom_total > CAST('18446744073709551615' AS DECIMAL(38, 0))
                THEN 'count' ELSE NULL END),
            MIN(range_error) FILTER (WHERE coverage_group = 0),
            MIN(CASE WHEN coverage_group = 0 AND expected_total > CAST('18446744073709551615' AS DECIMAL(38, 0))
                THEN 'count' ELSE NULL END),
            MIN(CASE WHEN lifecycle_group = 0 AND lifecycle_count > 0 THEN CASE
                WHEN lifecycle_case IS NULL OR lifecycle_case NOT IN ('STARTUP', 'STEADY_WORK', 'PROBES',
                    'RESTART', 'ROLLOUT', 'SHUTDOWN', 'RECOVERY', 'SCHEDULED_WORK', 'APPROVED_MAINTENANCE')
                    THEN 'lifecycle case'
                ELSE lifecycle_error END ELSE NULL END),
            CASE WHEN (MIN(accepted_total) > CAST('18446744073709551615' AS DECIMAL(38, 0))
                    OR MIN(included_total) > CAST('18446744073709551615' AS DECIMAL(38, 0)))
                OR (MIN(unresolved_total) > CAST('18446744073709551615' AS DECIMAL(38, 0))
                    OR MIN(excluded_total) > CAST('18446744073709551615' AS DECIMAL(38, 0)))
                OR MIN(included_total) + MIN(unresolved_total) + MIN(excluded_total) <> MIN(accepted_total)
                THEN 'count' ELSE NULL END) AS __discovery_error
    FROM __discovery_merge_groups
)
SELECT * EXCLUDE (__discovery_error) FROM __discovery_merge_snapshot
WHERE COALESCE(CAST('Discovery merge input: ' || __discovery_error AS BOOLEAN), TRUE)
