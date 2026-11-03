SELECT * EXCLUDE (report_interval, report_state, report_reasons, report_gap, report_complete),
    CASE WHEN report_interval IS NULL THEN 'UNKNOWN'
        WHEN report_gap THEN 'GAPPED'
        WHEN report_complete THEN
            CASE WHEN report_state = 'CLOSED' THEN 'CLOSED' ELSE 'HEALTHY' END
        ELSE 'UNKNOWN' END AS state,
    CASE WHEN report_interval IS NULL THEN 'MISSING_COVERAGE_REPORT'
        WHEN report_reasons <> '' THEN report_reasons
        WHEN report_gap THEN 'SOURCE_COVERAGE_GAPPED'
        WHEN report_complete THEN ''
        ELSE 'COVERAGE_UNQUALIFIED' END AS gap_reasons
FROM (
    SELECT event.*,
        COALESCE(receipt.coverage_revision, CAST(0 AS BIGINT UNSIGNED)) AS coverage_revision,
        proof.interval_id AS report_interval,
        proof.interval_revision,
        proof.state AS report_state,
        proof.gap_reasons AS report_reasons,
        proof.has_gap AS report_gap,
        (proof.complete AND event.temporal_coverage = 1
            AND event.kernel_sequence >= proof.first_sequence
            AND event.kernel_sequence <= proof.last_sequence) AS report_complete
    FROM (
        SELECT * REPLACE (
            CASE WHEN octet_length(encode(coverage_interval_id, 'hex')) = 32
                THEN coverage_interval_id ELSE source_id END AS coverage_interval_id
        ) FROM events
    ) AS event
    LEFT JOIN (SELECT * FROM coverage WHERE kind = 'receipt') AS receipt
        ON event.tenant_id = receipt.tenant_id
        AND event.node_id = receipt.node_id
        AND event.node_boot_id = receipt.node_boot_id
        AND event.label_epoch = receipt.label_epoch
        AND event.source_id = receipt.source_id
        AND event.source_epoch = receipt.source_epoch
        AND event.cpu_id = receipt.cpu_id
    LEFT JOIN (
        SELECT checked.*,
            (state IN ('HEALTHY', 'CLOSED') AND NOT has_gap
                AND CAST(opening_suppressed AS DECIMAL(20, 0))
                    + CAST(opening_requested AS DECIMAL(20, 0))
                    = CAST(opening_attempted AS DECIMAL(20, 0))
                AND CAST(opening_emitted AS DECIMAL(20, 0))
                    + CAST(opening_lost AS DECIMAL(20, 0))
                    = CAST(opening_requested AS DECIMAL(20, 0))
                AND CAST(closing_suppressed AS DECIMAL(20, 0))
                    + CAST(closing_requested AS DECIMAL(20, 0))
                    = CAST(closing_attempted AS DECIMAL(20, 0))
                AND CAST(closing_emitted AS DECIMAL(20, 0))
                    + CAST(closing_lost AS DECIMAL(20, 0))
                    = CAST(closing_requested AS DECIMAL(20, 0))
                AND opening_next_sequence <= first_sequence
                AND closing_next_sequence >= last_sequence) AS complete
        FROM (
            SELECT coverage.*,
                (state = 'GAPPED' OR gap_reasons <> ''
                    OR (opening_attempted IS NOT NULL AND closing_attempted IS NOT NULL
                        AND (closing_lost <> opening_lost
                            OR closing_suppressed <> opening_suppressed
                            OR closing_unresolved <> opening_unresolved
                            OR closing_classifier_miss_count <> opening_classifier_miss_count
                            OR closing_attempted < opening_attempted
                            OR closing_requested < opening_requested
                            OR closing_emitted < opening_emitted
                            OR closing_next_sequence < opening_next_sequence))) AS has_gap
            FROM coverage
            WHERE kind = 'interval'
        ) AS checked
    ) AS proof
        ON event.tenant_id = proof.tenant_id
        AND event.node_id = proof.node_id
        AND event.node_boot_id = proof.node_boot_id
        AND event.label_epoch = proof.label_epoch
        AND event.source_id = proof.source_id
        AND event.source_epoch = proof.source_epoch
        AND event.cpu_id = proof.cpu_id
        AND receipt.coverage_revision = proof.coverage_revision
        AND event.coverage_interval_id = proof.interval_id
        AND event.source_epoch = proof.interval_source_epoch
) AS joined
