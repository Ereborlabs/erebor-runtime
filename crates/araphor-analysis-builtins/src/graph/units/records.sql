WITH selected AS (
    SELECT record AS id FROM units
), references AS (
    SELECT UNNEST(facts.value['policy']['observations']) AS id
    FROM selected JOIN graph_facts facts ON facts.record = selected.id
    WHERE facts.value['tag'] = 'POLICY'
), wanted AS (
    SELECT id FROM selected UNION SELECT id FROM references
)
SELECT records.* FROM graph_records records JOIN wanted ON records.id = wanted.id
ORDER BY records.id
