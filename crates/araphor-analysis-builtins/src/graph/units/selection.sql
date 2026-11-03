WITH fact_keys AS (
    SELECT record, array_agg(key ORDER BY key['tenant_id'], key['owner_id'],
        key['entity_key'], key['lifetime_key'], key['owner_revision']) AS keys
    FROM graph_facts GROUP BY record
), qualified AS (
    SELECT * FROM graph_records
), causal_ids AS (
    {support}
), base_support AS (
    SELECT DISTINCT root_id, support_id FROM causal_ids
), policy_references AS (
    SELECT base.root_id, UNNEST(policy.value['policy']['observations']) AS id
    FROM base_support base JOIN graph_facts policy
        ON policy.record = base.support_id AND policy.value['tag'] = 'POLICY'
), support_ids AS (
    SELECT root_id, support_id FROM base_support
    UNION
    SELECT provenance.root_id, selected.id AS support_id
    FROM policy_references provenance JOIN graph_records selected ON selected.id = provenance.id
), support AS (
    SELECT members.root_id,
        array_agg(named_struct('record', selected.id, 'proof', selected.proof_quality,
            'facts', COALESCE(fact_keys.keys, [])) ORDER BY selected.id) AS support
    FROM support_ids members
    JOIN qualified selected ON selected.id = members.support_id
    LEFT JOIN fact_keys ON fact_keys.record = selected.id
    GROUP BY members.root_id
)
SELECT root.id AS record, config.window_ns,
    config.restricted,
    support.support
FROM qualified root JOIN support ON support.root_id = root.id
CROSS JOIN graph_settings config
ORDER BY root.id
