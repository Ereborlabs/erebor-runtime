CREATE VIEW discovery.coverage_ranges AS
SELECT
    tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id,
    MIN(source_cursor) AS first_cursor,
    MAX(source_cursor) AS last_cursor,
    CAST(COUNT(*) AS BIGINT UNSIGNED) AS expected_records,
    coverage_revision,
    coverage_interval_id,
    arrow_cast(state, 'Utf8') AS state,
    arrow_cast(CASE WHEN gap_reasons = '' THEN CAST([] AS VARCHAR[])
        ELSE string_to_array(gap_reasons, ',') END, 'List(Utf8)') AS gap_reasons
FROM (
    SELECT marked.*,
        SUM(boundary) OVER (
            PARTITION BY tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id, coverage_revision
            ORDER BY source_cursor ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        ) AS range_id
    FROM (
        SELECT previous.*,
            CASE WHEN previous_cursor IS NULL
                OR CAST(source_cursor AS DECIMAL(20, 0)) - CAST(previous_cursor AS DECIMAL(20, 0)) <> 1
                OR (coverage_interval_id IS DISTINCT FROM previous_interval)
                OR (coverage_revision IS DISTINCT FROM previous_revision)
                OR (state IS DISTINCT FROM previous_state)
                OR (gap_reasons IS DISTINCT FROM previous_reasons)
            THEN 1 ELSE 0 END AS boundary
        FROM (
            SELECT qualified.*,
                LAG(source_cursor) OVER position AS previous_cursor,
                LAG(coverage_interval_id) OVER position AS previous_interval,
                LAG(coverage_revision) OVER position AS previous_revision,
                LAG(state) OVER position AS previous_state,
                LAG(gap_reasons) OVER position AS previous_reasons
            FROM (
