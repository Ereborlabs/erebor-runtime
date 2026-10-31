WITH indexed AS (
    SELECT graph_records.*, ROW_NUMBER() OVER (ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) - 1 AS record_row
    FROM graph_records
), fact_keys AS (
    SELECT record, array_agg(key ORDER BY key['tenant_id'], key['owner_id'],
        key['entity_key'], key['lifetime_key'], key['owner_revision']) AS keys
    FROM graph_facts GROUP BY record
), support AS (
    SELECT array_agg(named_struct('record', indexed.id, 'proof', indexed.proof_quality,
        'facts', COALESCE(fact_keys.keys, [])) ORDER BY indexed.id) AS support
    FROM indexed LEFT JOIN fact_keys ON fact_keys.record = indexed.record_row
)
SELECT root.id AS record, config.window_ns,
    COALESCE((SELECT bool_or(sensitivity = 'HostRestricted') FROM graph_facts), FALSE) AS restricted,
    support.support
FROM indexed root CROSS JOIN support CROSS JOIN graph_settings config
ORDER BY root.id
