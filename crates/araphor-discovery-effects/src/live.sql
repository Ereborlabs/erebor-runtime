WITH
__live_state AS (
    SELECT state.*, GREATEST(COALESCE(consumed_cursor, CAST(0 AS BIGINT UNSIGNED)),
        COALESCE(resume_floor, CAST(0 AS BIGINT UNSIGNED))) AS frontier
    FROM state RIGHT JOIN (SELECT COUNT(*) AS state_rows FROM state) AS count ON TRUE
),
__live_prior AS (
    SELECT snapshot['schema_version'] AS schema_version,
        snapshot['tenant_id'] AS tenant_id,
        snapshot['source_revision'] AS source_revision,
        snapshot['proof_kind'] AS proof_kind,
        snapshot['accepted_records'] AS accepted_records,
        snapshot['included_records'] AS included_records,
        snapshot['unresolved_records'] AS unresolved_records,
        snapshot['excluded_records'] AS excluded_records,
        snapshot['atoms'] AS atoms,
        snapshot['coverage'] AS coverage,
        snapshot['unresolved'] AS unresolved,
        snapshot['excluded'] AS excluded,
        snapshot['lifecycle'] AS lifecycle FROM __live_state WHERE snapshot IS NOT NULL AND NOT COALESCE(sealed, FALSE)
),
__live_unresolved AS (
    SELECT UNNEST(unresolved) AS item FROM __live_prior
),
__live_ids AS (
    SELECT record.*, named_struct('stream', named_struct('tenant_id', record.tenant_id, 'node_id', record.node_id, 'node_boot_id', record.node_boot_id, 'label_epoch', record.label_epoch, 'source_id', record.source_id, 'source_epoch', record.source_epoch), 'cpu_id', record.cpu_id, 'durable_cursor', record.source_cursor) AS record_id
    FROM records AS record
),
__live_candidates AS (
    SELECT record.* EXCLUDE (record_id)
    FROM __live_ids AS record CROSS JOIN __live_state AS state
    WHERE record.source_cursor > state.frontier
        OR record.record_id IN (SELECT item['record_id'] FROM __live_unresolved)
),
__live_bindings AS (
    SELECT * FROM (
@@CONTEXT_SQL@@
    ) AS bindings
),
__live_selected AS (
    SELECT record.* EXCLUDE (record_id)
    FROM __live_ids AS record CROSS JOIN __live_state AS state
    WHERE record.source_cursor > state.frontier
        OR (record.record_id IN (SELECT item['record_id'] FROM __live_unresolved)
            AND record.record_id IN (SELECT record_id FROM __live_bindings))
),
__live_selected_ids AS (
    SELECT DISTINCT named_struct('stream', named_struct('tenant_id', record.tenant_id, 'node_id', record.node_id, 'node_boot_id', record.node_boot_id, 'label_epoch', record.label_epoch, 'source_id', record.source_id, 'source_epoch', record.source_epoch), 'cpu_id', record.cpu_id, 'durable_cursor', record.source_cursor) AS record_id, record.source_cursor
    FROM __live_selected AS record
),
__live_repairs AS (
    SELECT selected.record_id
    FROM __live_selected_ids AS selected CROSS JOIN __live_state AS state
    WHERE selected.source_cursor <= state.frontier
),
__live_repair_count AS (
    SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS count FROM __live_repairs
),
__live_unresolved_kept AS (
    SELECT COALESCE(array_agg(item ORDER BY item['record_id']), []) AS unresolved
    FROM __live_unresolved
    WHERE item['record_id'] NOT IN (SELECT record_id FROM __live_repairs)
),
__live_ranges AS (
    SELECT * FROM (
@@DELTA_COVERAGE_SQL@@
    ) AS ranges
),
__live_exclusions AS (
    SELECT exclusion.* FROM exclusions AS exclusion
    JOIN __live_selected_ids AS selected ON exclusion.record_id = selected.record_id
),
__live_empty_lifecycle AS (
    SELECT * FROM lifecycle WHERE FALSE
),
__live_delta AS (
    SELECT * FROM (
@@RECORDED_SQL@@
    ) AS delta
),
__live_append AS (
    SELECT record.* FROM records AS record CROSS JOIN __live_state AS state
    WHERE record.source_cursor > state.frontier
),
__live_append_ranges AS (
    SELECT * FROM (
@@APPEND_COVERAGE_SQL@@
    ) AS ranges
),
__live_append_qualified AS (
    SELECT * FROM (
@@APPEND_QUALIFY_SQL@@
    ) AS qualified
),
__live_old_ranges AS (
    SELECT UNNEST(coverage) AS value FROM __live_prior
),
__live_old_flat AS (
    SELECT value['stream']['tenant_id'] AS tenant_id,
        value['stream']['node_id'] AS node_id,
        value['stream']['node_boot_id'] AS node_boot_id,
        value['stream']['label_epoch'] AS label_epoch,
        value['stream']['source_id'] AS source_id,
        value['stream']['source_epoch'] AS source_epoch,
        value['cpu_id'] AS cpu_id, value['first_cursor'] AS first_cursor,
        value['last_cursor'] AS last_cursor, value['expected_records'] AS expected_records,
        value['coverage_revision'] AS coverage_revision,
        value['coverage_interval_id'] AS coverage_interval_id,
        value['state'] AS state, value['gap_reasons'] AS gap_reasons
    FROM __live_old_ranges
),
__live_complete AS (
    SELECT range.*, COUNT(record.source_cursor) AS retained_records
    FROM __live_old_flat AS range LEFT JOIN records AS record
        ON range.tenant_id = record.tenant_id AND range.node_id = record.node_id AND range.node_boot_id = record.node_boot_id AND range.label_epoch = record.label_epoch AND range.source_id = record.source_id AND range.source_epoch = record.source_epoch AND range.cpu_id = record.cpu_id
        AND record.source_cursor BETWEEN range.first_cursor AND range.last_cursor
        AND range.coverage_interval_id = CASE
            WHEN octet_length(encode(record.coverage_interval_id, 'hex')) = 32
                THEN record.coverage_interval_id ELSE record.source_id END
    GROUP BY range.tenant_id, range.node_id, range.node_boot_id, range.label_epoch, range.source_id, range.source_epoch, range.cpu_id, range.first_cursor, range.last_cursor, range.expected_records, range.coverage_revision, range.coverage_interval_id, range.state, range.gap_reasons
),
__live_refresh_records AS (
    SELECT record.* FROM records AS record JOIN __live_complete AS range
        ON range.tenant_id = record.tenant_id AND range.node_id = record.node_id AND range.node_boot_id = record.node_boot_id AND range.label_epoch = record.label_epoch AND range.source_id = record.source_id AND range.source_epoch = record.source_epoch AND range.cpu_id = record.cpu_id
        AND record.source_cursor BETWEEN range.first_cursor AND range.last_cursor
        AND range.expected_records > 0 AND range.retained_records = range.expected_records
),
__live_refresh_ranges AS (
    SELECT * FROM (
@@REFRESH_COVERAGE_SQL@@
    ) AS ranges
),
__live_refresh_qualified AS (
    SELECT * FROM (
@@REFRESH_QUALIFY_SQL@@
    ) AS qualified
),
__live_prior_ranges AS (
    SELECT range.tenant_id, range.node_id, range.node_boot_id, range.label_epoch, range.source_id, range.source_epoch, range.cpu_id, range.first_cursor, range.last_cursor, range.expected_records, range.coverage_revision, range.coverage_interval_id, range.state, range.gap_reasons FROM __live_complete AS range
    WHERE range.expected_records = 0 OR range.retained_records <> range.expected_records
    UNION ALL
    SELECT * FROM __live_refresh_qualified
),
__live_prior_coverage AS (
    SELECT COALESCE(array_agg(named_struct('stream', named_struct('tenant_id', tenant_id, 'node_id', node_id, 'node_boot_id', node_boot_id, 'label_epoch', label_epoch, 'source_id', source_id, 'source_epoch', source_epoch), 'cpu_id', cpu_id, 'first_cursor', first_cursor, 'last_cursor', last_cursor, 'expected_records', expected_records, 'coverage_revision', coverage_revision, 'coverage_interval_id', coverage_interval_id, 'state', state, 'gap_reasons', gap_reasons) ORDER BY tenant_id, node_id,
        node_boot_id, label_epoch, source_id, source_epoch, cpu_id, first_cursor), []) AS coverage
    FROM __live_prior_ranges
),
__live_append_coverage AS (
    SELECT COALESCE(array_agg(named_struct('stream', named_struct('tenant_id', tenant_id, 'node_id', node_id, 'node_boot_id', node_boot_id, 'label_epoch', label_epoch, 'source_id', source_id, 'source_epoch', source_epoch), 'cpu_id', cpu_id, 'first_cursor', first_cursor, 'last_cursor', last_cursor, 'expected_records', expected_records, 'coverage_revision', coverage_revision, 'coverage_interval_id', coverage_interval_id, 'state', state, 'gap_reasons', gap_reasons) ORDER BY tenant_id, node_id,
        node_boot_id, label_epoch, source_id, source_epoch, cpu_id, first_cursor), []) AS coverage
    FROM __live_append_qualified
),
__live_lifecycle_states AS (
    SELECT "case", MIN(state) FILTER (WHERE state <> 'MISSING') AS state,
        MIN(reason) FILTER (WHERE state IN ('DECLARED', 'NOT_APPLICABLE', 'UNSUPPORTED')) AS reason,
        CASE WHEN COUNT(DISTINCT state) FILTER (WHERE state <> 'MISSING') > 1
            OR COUNT(DISTINCT reason) FILTER (WHERE state IN (
                'DECLARED', 'NOT_APPLICABLE', 'UNSUPPORTED')) > 1 THEN 'lifecycle state'
            ELSE MIN(CASE WHEN state IS NULL OR state NOT IN (
                'RECORDED', 'DECLARED', 'MISSING', 'NOT_APPLICABLE', 'UNSUPPORTED')
                THEN 'lifecycle state'
            WHEN state = 'RECORDED' AND (records IS NULL OR array_length(records) = 0)
                THEN 'lifecycle records'
            WHEN state IN ('DECLARED', 'NOT_APPLICABLE', 'UNSUPPORTED')
                AND (reason IS NULL OR reason = '') THEN 'lifecycle reason'
            ELSE NULL END) END AS relational_error
    FROM lifecycle GROUP BY "case"
),
__live_lifecycle_ids AS (
    SELECT "case", UNNEST(records) AS record_id FROM lifecycle WHERE state = 'RECORDED'
),
__live_lifecycle_records AS (
    SELECT "case", array_agg(record_id ORDER BY record_id) AS records,
        CASE WHEN COUNT(*) > 64 THEN 'lifecycle records' ELSE NULL END AS relational_error
    FROM (SELECT DISTINCT "case", record_id FROM __live_lifecycle_ids) AS ids GROUP BY "case"
),
__live_lifecycle AS (
    SELECT array_agg(named_struct('case', arrow_cast(cases.lifecycle_case, 'Utf8'),
        'state', arrow_cast(COALESCE(states.state, 'MISSING'), 'Utf8'),
        'records', COALESCE(records.records, []), 'reason', states.reason)
        ORDER BY cases.case_rank) FILTER (WHERE cases.case_rank IS NOT NULL) AS lifecycle,
        MIN(CASE WHEN cases.case_rank IS NULL THEN 'lifecycle case'
            ELSE COALESCE(states.relational_error, records.relational_error) END) AS relational_error
    FROM (VALUES (0, 'STARTUP'), (1, 'STEADY_WORK'), (2, 'PROBES'), (3, 'RESTART'),
        (4, 'ROLLOUT'), (5, 'SHUTDOWN'), (6, 'RECOVERY'), (7, 'SCHEDULED_WORK'),
        (8, 'APPROVED_MAINTENANCE')) AS cases(case_rank, lifecycle_case)
    FULL JOIN __live_lifecycle_states AS states ON cases.lifecycle_case = states."case"
    LEFT JOIN __live_lifecycle_records AS records
        ON COALESCE(cases.lifecycle_case, states."case") = records."case"
),
__live_left AS (
    SELECT prior.* REPLACE (
        CASE WHEN repairs.count <= prior.accepted_records
            THEN prior.accepted_records - repairs.count ELSE CAST(NULL AS BIGINT UNSIGNED) END
            AS accepted_records,
        CASE WHEN repairs.count <= prior.unresolved_records
            THEN prior.unresolved_records - repairs.count ELSE CAST(NULL AS BIGINT UNSIGNED) END
            AS unresolved_records,
        kept.unresolved AS unresolved, qualified.coverage AS coverage)
    FROM __live_prior AS prior
    CROSS JOIN __live_repair_count AS repairs
    CROSS JOIN __live_unresolved_kept AS kept
    CROSS JOIN __live_prior_coverage AS qualified
),
__live_right AS (
    SELECT delta.* EXCLUDE (duplicate_deliveries) REPLACE (
        coverage.coverage AS coverage, lifecycle.lifecycle AS lifecycle)
    FROM __live_delta AS delta CROSS JOIN __live_append_coverage AS coverage
    CROSS JOIN __live_lifecycle AS lifecycle
    WHERE COALESCE(CAST('Discovery live input: ' || lifecycle.relational_error AS BOOLEAN), TRUE)
),
__live_merged AS (
    SELECT * FROM (
@@MERGE_SQL@@
    ) AS merged
),
__live_facts AS (
    SELECT GREATEST(COALESCE(MAX(policy.commit_revision), CAST(0 AS BIGINT UNSIGNED)),
        COALESCE(MAX(state.facts_revision), CAST(0 AS BIGINT UNSIGNED))) AS facts_revision
    FROM __live_state AS state LEFT JOIN targets AS target
        ON target.tenant_id = state.tenant_id AND target.node_id = state.node_id
        AND target.node_boot_id_text = encode(state.node_boot_id, 'hex')
        AND target.label_epoch = state.label_epoch
    LEFT JOIN policies AS policy
        ON policy.tenant_id = target.tenant_id
        AND policy.source_revision_id = target.source_revision_id
        AND policy.signed_profile_digest = target.signed_profile_digest
        AND policy.profile_id = target.profile_id
),
__live_new_gaps AS (
    SELECT COALESCE(array_agg(gap ORDER BY gap['first_cursor'], gap['last_cursor'],
        gap['commit_revision']), []) AS gaps
    FROM (SELECT UNNEST(gaps) AS gap, COALESCE(consumed_cursor, 0) AS cursor
        FROM __live_state) AS captured
    WHERE gap['last_cursor'] > cursor
),
__live_bytes AS (
    SELECT COALESCE(SUM(CAST(octet_length(encode(framed_record, 'hex')) / 2 AS DECIMAL(38, 0))), 0)
        + CAST(COALESCE((SELECT CASE WHEN COALESCE(sealed, FALSE) THEN 0
            ELSE input_bytes END FROM __live_state), 0) AS DECIMAL(38, 0)) AS input_bytes
    FROM __live_append
),
__live_output AS (
    SELECT named_struct('tenant_id', state.tenant_id, 'node_id', state.node_id,
        'node_boot_id', state.node_boot_id, 'label_epoch', state.label_epoch,
        'source_id', state.source_id, 'source_epoch', state.source_epoch) AS source,
        state.cpu_id, state.processor_present, state.retired, state.resume_floor,
        state.retained_floor, state.frontier AS expected_cursor,
        state.contiguous_cursor AS consumed_cursor, state.current_result_id,
        state.result_commit_revision, state.source_coverage_revision AS coverage_revision,
        state.interval_id, state.profile_revision, facts.facts_revision,
        state.created_utc_ns, state.updated_utc_ns, state.sealed,
        CASE WHEN bytes.input_bytes <= CAST('18446744073709551615' AS DECIMAL(38, 0))
            THEN CAST(bytes.input_bytes AS BIGINT UNSIGNED)
            ELSE CAST(NULL AS BIGINT UNSIGNED) END AS input_bytes,
        ((CASE WHEN COALESCE(state.sealed, FALSE) THEN FALSE
            ELSE COALESCE(state.incomplete, FALSE) END)
            OR COALESCE(array_length(CASE WHEN COALESCE(state.sealed, FALSE)
                THEN new_gaps.gaps ELSE state.gaps END), 0) > 0) AS incomplete,
        CASE WHEN COALESCE(state.sealed, FALSE) THEN new_gaps.gaps
            ELSE state.gaps END AS gaps, state.context_refs,
        named_struct('schema_version', merged.schema_version, 'tenant_id', merged.tenant_id, 'source_revision', merged.source_revision, 'proof_kind', merged.proof_kind, 'accepted_records', merged.accepted_records, 'included_records', merged.included_records, 'unresolved_records', merged.unresolved_records, 'excluded_records', merged.excluded_records, 'atoms', merged.atoms, 'coverage', merged.coverage, 'unresolved', merged.unresolved, 'excluded', merged.excluded, 'lifecycle', merged.lifecycle) AS snapshot,
        state.snapshot AS previous_snapshot, state.coverage_revision AS previous_coverage_revision,
        state.facts_revision AS previous_facts_revision, bytes.input_bytes AS checked_bytes,
        state.frontier, state.contiguous_cursor, state.source_coverage_revision,
        COALESCE(state.resume_floor > COALESCE(state.consumed_cursor, 0), FALSE) AS pending_resume,
        (SELECT COUNT(*) FROM state) AS state_count,
        (SELECT COUNT(DISTINCT source_cursor) FROM __live_append) AS append_count
    FROM __live_merged AS merged CROSS JOIN __live_state AS state
    CROSS JOIN __live_facts AS facts CROSS JOIN __live_bytes AS bytes
    CROSS JOIN __live_new_gaps AS new_gaps
)
SELECT * EXCLUDE (previous_snapshot, previous_coverage_revision, previous_facts_revision, checked_bytes, frontier,
    contiguous_cursor, source_coverage_revision, pending_resume, state_count, append_count)
FROM __live_output
WHERE COALESCE(CAST('Discovery live input: ' || CASE
    WHEN state_count <> 1 THEN 'state count'
    WHEN checked_bytes > 18446744073709551615 THEN 'input bytes'
    WHEN processor_present AND retained_floor <= frontier AND (contiguous_cursor < frontier
        OR CAST(append_count AS DECIMAL(20, 0))
            <> CAST(contiguous_cursor AS DECIMAL(20, 0)) - CAST(frontier AS DECIMAL(20, 0)))
        THEN 'input frontier' ELSE NULL END AS BOOLEAN), TRUE)
    AND (NOT COALESCE(sealed, FALSE) OR append_count > 0 OR pending_resume
        OR NOT processor_present OR retained_floor > frontier)
    AND (NOT processor_present OR retained_floor > frontier OR pending_resume
        OR previous_snapshot IS NULL OR (snapshot IS DISTINCT FROM previous_snapshot)
        OR consumed_cursor <> expected_cursor
        OR (coverage_revision IS DISTINCT FROM previous_coverage_revision)
        OR (facts_revision IS DISTINCT FROM previous_facts_revision))
