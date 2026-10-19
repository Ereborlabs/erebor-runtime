SELECT range.tenant_id, range.node_id, range.node_boot_id, range.label_epoch,
    range.source_id, range.source_epoch, range.cpu_id, range.first_cursor,
    range.last_cursor, range.expected_records, range.coverage_revision,
    range.coverage_interval_id,
    arrow_cast(CASE WHEN COUNT(record.source_cursor) <> range.expected_records
        OR COALESCE(BOOL_OR(record.temporal_coverage = 2), FALSE) THEN 'GAPPED'
        WHEN COALESCE(BOOL_OR(record.temporal_coverage = 0), FALSE)
            AND range.state <> 'GAPPED' THEN 'UNKNOWN' ELSE range.state END, 'Utf8') AS state,
    arrow_cast(array_sort(array_distinct(array_concat(range.gap_reasons,
        CASE WHEN COUNT(record.source_cursor) <> range.expected_records
            THEN ['INPUT_RANGE_INCOMPLETE'] ELSE [] END,
        CASE WHEN COALESCE(BOOL_OR(record.temporal_coverage = 2), FALSE)
            THEN ['OBSERVATION_COVERAGE_GAPPED'] ELSE [] END,
        CASE WHEN COALESCE(BOOL_OR(record.temporal_coverage = 0), FALSE)
            THEN ['OBSERVATION_COVERAGE_UNKNOWN'] ELSE [] END))), 'List(Utf8)') AS gap_reasons
FROM ranges AS range
LEFT JOIN records AS record ON range.tenant_id = record.tenant_id
    AND range.node_id = record.node_id AND range.node_boot_id = record.node_boot_id
    AND range.label_epoch = record.label_epoch AND range.source_id = record.source_id
    AND range.source_epoch = record.source_epoch AND range.cpu_id = record.cpu_id
    AND record.source_cursor BETWEEN range.first_cursor AND range.last_cursor
    AND range.coverage_interval_id = CASE WHEN octet_length(encode(record.coverage_interval_id, 'hex')) = 32
        THEN record.coverage_interval_id ELSE record.source_id END
GROUP BY range.tenant_id, range.node_id, range.node_boot_id, range.label_epoch,
    range.source_id, range.source_epoch, range.cpu_id, range.first_cursor,
    range.last_cursor, range.expected_records, range.coverage_revision,
    range.coverage_interval_id, range.state, range.gap_reasons
