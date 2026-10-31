WITH support AS (
    SELECT UNNEST(support) AS item FROM units
), keys AS (
    SELECT DISTINCT item['record'] AS id, UNNEST(item['facts']) AS key FROM support
), indexed AS (
    SELECT id, ROW_NUMBER() OVER (ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) - 1 AS record_row FROM graph_records
)
SELECT arrow_cast(delivered.__row_index, 'UInt32') AS record,
    fact.key, fact.sensitivity, fact.value
FROM keys JOIN indexed ON indexed.id = keys.id
JOIN graph_facts fact ON fact.record = indexed.record_row AND fact.key = keys.key
JOIN records delivered ON delivered.id = indexed.id
ORDER BY fact.key['tenant_id'], fact.key['owner_id'], fact.key['entity_key'],
    fact.key['lifetime_key'], fact.key['owner_revision']
