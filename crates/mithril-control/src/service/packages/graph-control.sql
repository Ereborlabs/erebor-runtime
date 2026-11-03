WITH state AS (
    SELECT *, GREATEST(COALESCE(consumed_cursor, 0), COALESCE(resume_floor, 0)) AS frontier
    FROM graph_state WHERE processor_present AND NOT COALESCE(retired, FALSE)
), heads AS (
    SELECT h.tenant_id, h.source_key, h.graph_result_id, h.first_cursor, h.last_cursor,
        h.commit_revision, h.notice_context_revision, h.notice_coverage_revision,
        h.witness_deadline_utc_ns, h.retained_input_expired, h.restricted_count
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
), packed AS (
    SELECT state.tenant_id, state.source_key, state.node_id, state.node_boot_id,
        state.label_epoch, state.source_id, state.source_epoch,
        state.retained_floor, state.contiguous_cursor, state.frontier, state.coverage_revision,
        boundary.expired_until, boundary.pending, facts.revision AS fact_revision,
        MIN(heads.first_cursor) FILTER (WHERE capture.resume_window
            AND NOT heads.retained_input_expired AND heads.restricted_count IS NOT NULL
            AND heads.first_cursor > state.retained_floor
            AND heads.witness_deadline_utc_ns > state.capture_time_utc_ns) AS append_first,
        ARRAY_AGG(named_struct(
            'graph_result_id', heads.graph_result_id,
            'first_cursor', heads.first_cursor,
            'last_cursor', heads.last_cursor,
            'commit_revision', heads.commit_revision,
            'notice_context_revision', heads.notice_context_revision,
            'notice_coverage_revision', heads.notice_coverage_revision,
            'retained_input_expired', heads.retained_input_expired
        )) AS heads
    FROM state CROSS JOIN boundary CROSS JOIN facts CROSS JOIN graph_capture capture
    LEFT JOIN heads USING (tenant_id, source_key)
    GROUP BY ALL
), initialization AS (
    SELECT packed.*, CASE WHEN append_first IS NULL AND pending = 0
        AND contiguous_cursor > frontier THEN tenant_id ELSE CAST(NULL AS BYTEA) END AS event_tenant_id
    FROM packed
), retained AS (
    SELECT based.tenant_id, based.source_key,
        ANY_VALUE(based.contiguous_cursor) AS contiguous_cursor,
        ANY_VALUE(based.frontier) AS frontier,
        ANY_VALUE(based.pending) AS pending,
        ANY_VALUE(based.fact_revision) AS fact_revision,
        ANY_VALUE(based.coverage_revision) AS coverage_revision,
        ANY_VALUE(based.append_first) AS append_first,
        ANY_VALUE(based.heads) AS heads,
        MIN(events.source_cursor) AS retained_first
    FROM initialization based LEFT JOIN events
        ON events.tenant_id = based.event_tenant_id
        AND events.node_id = based.node_id
        AND events.node_boot_id = based.node_boot_id
        AND events.label_epoch = based.label_epoch
        AND events.source_id = based.source_id
        AND events.source_epoch = based.source_epoch
        AND based.append_first IS NULL AND based.pending = 0
        AND based.contiguous_cursor > based.frontier
        AND events.source_cursor > GREATEST(based.retained_floor, based.expired_until)
        AND events.source_cursor <= based.contiguous_cursor
    GROUP BY based.tenant_id, based.source_key
), selected AS (
    SELECT source_key, contiguous_cursor, frontier, pending, fact_revision, coverage_revision,
        COALESCE(append_first, retained_first) AS first_cursor, UNNEST(heads) AS head
    FROM retained
), matched AS (
    SELECT source_key, first_cursor, contiguous_cursor, frontier, pending,
        MAX(head['graph_result_id']) FILTER (WHERE head['first_cursor'] = first_cursor) AS base_result_id,
        MAX(head['commit_revision']) FILTER (WHERE head['first_cursor'] = first_cursor) AS base_commit_revision,
        COALESCE(ARRAY_AGG(named_struct(
            'source_key', source_key,
            'first_cursor', head['first_cursor'],
            'last_cursor', head['last_cursor'],
            'base_result_id', head['graph_result_id'],
            'base_commit_revision', head['commit_revision'],
            'priority', 1
        )) FILTER (WHERE head['graph_result_id'] IS NOT NULL
            AND NOT head['retained_input_expired'] AND pending = 0
            AND (head['notice_context_revision'] < fact_revision
                OR head['notice_coverage_revision'] < coverage_revision)), []) AS notices
    FROM selected
    GROUP BY ALL
), work AS (
    SELECT UNNEST(array_concat(
        CASE WHEN contiguous_cursor > frontier AND pending = 0 AND first_cursor <= contiguous_cursor
            THEN [named_struct(
                'source_key', source_key,
                'first_cursor', first_cursor,
                'last_cursor', contiguous_cursor,
                'base_result_id', base_result_id,
                'base_commit_revision', base_commit_revision,
                'priority', 0
            )] ELSE [] END,
        notices
    )) AS candidate
    FROM matched
)
SELECT candidate['source_key'] AS source_key, candidate['first_cursor'] AS first_cursor,
    candidate['last_cursor'] AS last_cursor, candidate['base_result_id'] AS base_result_id,
    candidate['base_commit_revision'] AS base_commit_revision
FROM work ORDER BY candidate['priority'], candidate['first_cursor'] LIMIT 1
