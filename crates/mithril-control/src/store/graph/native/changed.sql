WITH cutoff AS (
    SELECT COALESCE(notice_context_revision, 0) AS revision FROM graph_control
), candidates AS (
    SELECT * FROM __control_candidates_inserted
    UNION SELECT * FROM __control_candidates_removed
    UNION SELECT candidate.* FROM __control_candidates_after candidate CROSS JOIN cutoff
        WHERE candidate.raw_context.commit_revision > cutoff.revision
    UNION SELECT candidate.* FROM __control_candidates_before candidate CROSS JOIN cutoff
        WHERE candidate.raw_context.commit_revision > cutoff.revision
), acks AS (
    SELECT * FROM __control_acks_inserted
    UNION SELECT * FROM __control_acks_removed
    UNION SELECT ack.* FROM __control_acks_after ack CROSS JOIN cutoff
        WHERE ack.raw_context.commit_revision > cutoff.revision
    UNION SELECT ack.* FROM __control_acks_before ack CROSS JOIN cutoff
        WHERE ack.raw_context.commit_revision > cutoff.revision
), events AS (
    SELECT * FROM __control_events_after
    UNION SELECT * FROM __control_events_before
), candidate_versions AS (
    SELECT * FROM __control_candidates_after
    UNION SELECT * FROM __control_candidates_before
), changed_profiles AS (
    SELECT key_struct FROM candidates
    UNION
    SELECT candidate.key_struct FROM acks ack JOIN candidate_versions candidate
        ON ack.raw_context.tenant_id = candidate.raw_context.tenant_id
        AND ack.raw_context.entity_key = candidate.raw_context.entity_key
        AND ack.raw_context.lifetime_key = candidate.raw_context.lifetime_key
)
SELECT record FROM __control_events_inserted
UNION SELECT record FROM __control_events_removed
UNION
SELECT input.record FROM changed_profiles profile JOIN events input
    ON input.event.tenant_id = profile.key_struct.tenant_id
    AND input.event.node_id = profile.key_struct.node_id
    AND input.event.catalog_profile_id = profile.key_struct.profile_id
    AND input.event.catalog_profile_version = profile.key_struct.profile_version
    AND input.event.catalog_policy_document_digest = profile.key_struct.policy_document_digest
