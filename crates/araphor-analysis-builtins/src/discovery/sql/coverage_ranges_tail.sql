            ) AS qualified
            WINDOW position AS (
                PARTITION BY tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id, coverage_revision
                ORDER BY source_cursor
            )
        ) AS previous
    ) AS marked
) AS ranges
GROUP BY tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id,
    coverage_revision, coverage_interval_id, state, gap_reasons, range_id;
