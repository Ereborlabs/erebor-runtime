SELECT input.record, input.event,
    array_agg(DISTINCT named_struct('context', candidate.raw_context,
        'key_struct', candidate.key_struct)) AS candidates,
    array_agg(DISTINCT ack.raw_context) AS acknowledgements
FROM __control_events input
LEFT JOIN __control_candidates candidate
    ON input.event.tenant_id = candidate.key_struct.tenant_id
    AND input.event.node_id = candidate.key_struct.node_id
    AND input.event.catalog_profile_id = candidate.key_struct.profile_id
    AND input.event.catalog_profile_version = candidate.key_struct.profile_version
    AND input.event.catalog_policy_document_digest = candidate.key_struct.policy_document_digest
LEFT JOIN __control_acks ack
    ON ack.raw_context.tenant_id = candidate.raw_context.tenant_id
    AND ack.raw_context.entity_key = candidate.raw_context.entity_key
    AND ack.raw_context.lifetime_key = candidate.raw_context.lifetime_key
GROUP BY input.record, input.event
