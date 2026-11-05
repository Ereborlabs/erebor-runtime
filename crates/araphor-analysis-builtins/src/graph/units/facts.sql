SELECT arrow_cast(delivered.__row_index, 'UInt32') AS record,
    fact.key, fact.sensitivity, fact.value
FROM graph_facts fact JOIN records delivered ON delivered.id = fact.record
ORDER BY fact.key['tenant_id'], fact.key['owner_id'], fact.key['entity_key'],
    fact.key['lifetime_key'], fact.key['owner_revision']
