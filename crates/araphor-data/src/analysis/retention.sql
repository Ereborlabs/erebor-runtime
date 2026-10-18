cfg AS (
    SELECT ?::UBIGINT AS now_ns, ?::UBIGINT AS age_ns, ?::UBIGINT AS max_bytes,
        ?::UBIGINT AS global_threshold, ?::UBIGINT AS tenant_threshold{source}
), receipts AS (
    SELECT stream_key, tenant_id, contiguous_cursor AS accepted FROM source_receipts
    UNION ALL SELECT stream_key, tenant_id,
        last_sequence + CASE WHEN terminal IS NULL THEN 0 ELSE 1 END FROM trace_receipts
), required AS (
    SELECT stream_key, tenant_id, MIN(consumed_cursor) AS consumed
    FROM processor_progress WHERE class = 'required' AND NOT retired GROUP BY stream_key, tenant_id
), pins AS (
    SELECT segment_id, MAX(expires_utc_ns) AS pin_until FROM evidence_refs GROUP BY segment_id
), totals AS (
    SELECT tenant_id, SUM(committed_end)::HUGEINT AS tenant_bytes FROM segments
    WHERE state = 'Live' GROUP BY tenant_id
), base AS (
    SELECT s.*, r.accepted, COALESCE(p.pin_until, 0)::UBIGINT AS pin_until,
        cfg.now_ns, cfg.age_ns, cfg.max_bytes,
        (cfg.max_bytes IS NOT NULL AND t.tenant_bytes > cfg.max_bytes) AS over_bytes,
        t.tenant_bytes,
        ((cfg.global_threshold IS NOT NULL AND
            (SELECT COALESCE(SUM(logical_bytes), 0)::HUGEINT FROM logical) >= cfg.global_threshold)
         OR (cfg.tenant_threshold IS NOT NULL AND COALESCE(l.logical_bytes, 0) >= cfg.tenant_threshold)) AS pressure
    FROM segments s JOIN receipts r USING (stream_key, tenant_id)
    JOIN totals t USING (tenant_id) CROSS JOIN cfg
    LEFT JOIN required q USING (stream_key, tenant_id)
    LEFT JOIN pins p USING (segment_id) LEFT JOIN logical l USING (tenant_id)
    WHERE s.state = 'Live' AND s.last_cursor <= LEAST(COALESCE(q.consumed, r.accepted), r.accepted)
        {scope}
), ready AS (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY last_intake_utc_ns, segment_id) AS rank,
        COALESCE(SUM(committed_end) OVER (PARTITION BY tenant_id ORDER BY last_intake_utc_ns, segment_id
            ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING), 0)::HUGEINT AS prior_bytes
    FROM base WHERE pin_until <= now_ns
), selected AS (
    SELECT * FROM ready WHERE (age_ns IS NOT NULL AND last_intake_utc_ns::HUGEINT + age_ns <= now_ns)
        OR (max_bytes IS NOT NULL AND tenant_bytes - prior_bytes > max_bytes)
        OR (pressure AND rank = 1)
)
