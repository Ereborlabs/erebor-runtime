WITH support AS (
    SELECT UNNEST(support) AS item FROM units
), keys AS (
    SELECT DISTINCT item['record'] AS id, UNNEST(item['facts']) AS key FROM support
)
SELECT arrow_cast(delivered.__row_index, 'UInt32') AS record,
    fact.key, fact.sensitivity, fact.value
FROM keys JOIN graph_facts fact ON fact.record = keys.id AND fact.key = keys.key
JOIN records delivered ON delivered.id = keys.id
ORDER BY fact.key['tenant_id'], fact.key['owner_id'], fact.key['entity_key'],
    fact.key['lifetime_key'], fact.key['owner_revision']
