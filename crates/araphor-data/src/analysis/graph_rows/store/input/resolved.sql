WITH material AS (
    SELECT candidate.key_struct.tenant_id AS tenant_id,
        candidate.key_struct.node_id AS node_id,
        candidate.key_struct.profile_id AS profile_id,
        candidate.key_struct.profile_version AS profile_version,
        candidate.key_struct.policy_document_digest AS policy_document_digest,
        array_agg(DISTINCT named_struct('context', candidate.raw_context,
            'key_struct', candidate.key_struct)) AS candidates,
        array_agg(DISTINCT ack.raw_context) AS acknowledgements
    FROM __graph_input_candidates candidate
    LEFT JOIN __graph_input_acks ack
        ON ack.raw_context.tenant_id = candidate.raw_context.tenant_id
        AND ack.raw_context.entity_key = candidate.raw_context.entity_key
        AND ack.raw_context.lifetime_key = candidate.raw_context.lifetime_key
    GROUP BY candidate.key_struct.tenant_id, candidate.key_struct.node_id,
        candidate.key_struct.profile_id, candidate.key_struct.profile_version,
        candidate.key_struct.policy_document_digest
), input AS (
    SELECT record, first_value(event) AS event
    FROM __graph_input_events
    GROUP BY record
)
SELECT input.record, input.event,
    coalesce(material.candidates, []) AS candidates,
    coalesce(material.acknowledgements, []) AS acknowledgements
FROM input LEFT JOIN material
    ON input.event.tenant_id = material.tenant_id
    AND input.event.node_id = material.node_id
    AND input.event.catalog_profile_id = material.profile_id
    AND input.event.catalog_profile_version = material.profile_version
    AND input.event.catalog_policy_document_digest = material.policy_document_digest
