CREATE VIEW discovery.observed_effects AS
SELECT
    tenant_id,
    node_id,
    node_boot_id,
    label_epoch,
    source_id,
    source_epoch,
    cpu_id,
    binding_id,
    coverage_interval_id,
    effect_family,
    operation,
    temporal_coverage,
    exact_object_id,
    destination_id,
    decision,
    kernel_result,
    COUNT(*) AS event_count,
    MIN(source_cursor) AS first_cursor,
    MAX(source_cursor) AS last_cursor,
    MIN(received_at) AS first_received_at,
    MAX(received_at) AS last_received_at
FROM events
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16;
