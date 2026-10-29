WITH state AS (
    SELECT *, GREATEST(COALESCE(consumed_cursor, 0), COALESCE(resume_floor, 0)) AS frontier
    FROM graph_state WHERE processor_present AND NOT COALESCE(retired, FALSE)
), heads AS (
    SELECT h.tenant_id, h.source_key, h.first_cursor, h.last_cursor, h.commit_revision,
        h.notice_context_revision, h.notice_coverage_revision,
        h.witness_deadline_utc_ns, h.retained_input_expired
    FROM graph_manifest h JOIN state USING (tenant_id, source_key)
    QUALIFY ROW_NUMBER() OVER (PARTITION BY tenant_id, source_key, first_cursor
        ORDER BY commit_revision DESC) = 1
), facts AS (
    SELECT COALESCE(MAX(context.commit_revision), 0) AS revision
    FROM context_versions context JOIN state
        ON context.tenant_id = state.tenant_id
        AND context.lifetime_key = CAST(state.node_id AS BYTEA)
    WHERE context.owner_id IN (
        'mithril-control/policy-candidate', 'mithril-control/activation-ack')
), boundary AS (
    SELECT COALESCE(MAX(CASE WHEN retained_input_expired THEN last_cursor ELSE 0 END), 0) AS expired_until,
        COUNT(*) FILTER (WHERE NOT retained_input_expired AND (
            heads.first_cursor <= state.retained_floor
            OR witness_deadline_utc_ns <= state.capture_time_utc_ns)) AS pending
    FROM heads CROSS JOIN state
), retained AS (
    SELECT MIN(events.source_cursor) AS first_cursor
    FROM events CROSS JOIN state CROSS JOIN boundary
    WHERE events.source_cursor > GREATEST(state.retained_floor, boundary.expired_until)
), work AS (
    SELECT retained.first_cursor, state.contiguous_cursor AS last_cursor, 0 AS priority
    FROM retained CROSS JOIN state CROSS JOIN boundary
    WHERE state.contiguous_cursor > state.frontier AND boundary.pending = 0
        AND retained.first_cursor <= state.contiguous_cursor
    UNION ALL
    SELECT heads.first_cursor, heads.last_cursor, 1 AS priority
    FROM heads CROSS JOIN state CROSS JOIN facts CROSS JOIN boundary
    WHERE NOT heads.retained_input_expired AND boundary.pending = 0
        AND (heads.notice_context_revision < facts.revision
            OR heads.notice_coverage_revision < state.coverage_revision)
), selected AS (
    SELECT first_cursor, last_cursor FROM work ORDER BY priority, first_cursor LIMIT 1
)
SELECT events.* FROM events CROSS JOIN selected
WHERE events.source_cursor BETWEEN selected.first_cursor AND selected.last_cursor
