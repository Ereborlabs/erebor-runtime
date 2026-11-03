WITH indexed AS (
    SELECT graph_records.*, ROW_NUMBER() OVER (ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) - 1 AS record_row
    FROM graph_records
), fact_keys AS (
    SELECT record, array_agg(key ORDER BY key['tenant_id'], key['owner_id'],
        key['entity_key'], key['lifetime_key'], key['owner_revision']) AS keys
    FROM graph_facts GROUP BY record
), qualified AS (
    SELECT * FROM indexed
), causal_ids AS (
    {support}
), base_support AS (
    SELECT DISTINCT root_row, support_row FROM causal_ids
), policy_references AS (
    SELECT base.root_row, UNNEST(policy.value['policy']['observations']) AS id
    FROM base_support base JOIN graph_facts policy
        ON policy.record = base.support_row AND policy.value['tag'] = 'POLICY'
), support_ids AS (
    SELECT root_row, support_row FROM base_support
    UNION
    SELECT provenance.root_row, selected.record_row AS support_row
    FROM policy_references provenance JOIN indexed selected ON selected.id = provenance.id
), support AS (
    SELECT members.root_row,
        array_agg(named_struct('record', selected.id, 'proof', selected.proof_quality,
            'facts', COALESCE(fact_keys.keys, [])) ORDER BY selected.id) AS support
    FROM support_ids members
    JOIN qualified selected ON selected.record_row = members.support_row
    LEFT JOIN fact_keys ON fact_keys.record = selected.record_row
    GROUP BY members.root_row
)
SELECT root.id AS record, config.window_ns,
    COALESCE((SELECT bool_or(sensitivity = 'HostRestricted') FROM graph_facts), FALSE) AS restricted,
    support.support
FROM qualified root JOIN support ON support.root_row = root.record_row
CROSS JOIN graph_settings config
ORDER BY root.id
