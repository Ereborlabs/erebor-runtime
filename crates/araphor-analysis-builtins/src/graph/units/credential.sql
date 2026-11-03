WITH candidate_reads AS (
    SELECT DISTINCT root.id AS root_id, selected.id AS read_id,
        credential.value['credential']['object_id'] AS object_id,
        credential.value['credential']['principal_id'] AS principal_id
    FROM qualified root
    JOIN qualified selected ON selected.position <= root.position
    JOIN graph_facts credential ON credential.record = selected.id
        AND credential.value['tag'] = 'CREDENTIAL'
        AND credential.value['credential']['object_id'] = selected.effect['exact_object_id']
    LEFT JOIN graph_facts trigger ON trigger.record = root.id
        AND trigger.value['tag'] IN ('CHANNEL', 'AUTHORITY_USE')
    CROSS JOIN graph_settings config
    WHERE selected.observed_boottime_ns <= root.observed_boottime_ns
        AND root.observed_boottime_ns - LEAST(root.observed_boottime_ns, selected.observed_boottime_ns)
            <= config.window_ns
        AND (selected.id = root.id
            OR (trigger.value['tag'] = 'CHANNEL'
                AND ((root.effect['task_cookie'] > 0
                        AND root.effect['task_cookie'] = selected.effect['task_cookie'])
                    OR root.process_instance_id = selected.process_instance_id))
            OR (trigger.value['tag'] = 'AUTHORITY_USE'
                AND ((trigger.value['authority_use']['task_cookie'] > 0
                        AND trigger.value['authority_use']['task_cookie'] = selected.effect['task_cookie'])
                    OR trigger.value['authority_use']['process_instance_id'] = selected.process_instance_id
                    OR trigger.value['authority_use']['principal_id'] = credential.value['credential']['principal_id'])))
), authorities AS (
    SELECT DISTINCT candidate.root_id, candidate.read_id, selected.id AS authority_id,
        authority.value['authority_use']['socket_object_id'] AS socket_id
    FROM candidate_reads candidate
    JOIN qualified root ON root.id = candidate.root_id
    JOIN qualified original ON original.id = candidate.read_id
    JOIN qualified selected ON selected.position <= root.position
    JOIN graph_facts authority ON authority.record = selected.id
        AND authority.value['tag'] = 'AUTHORITY_USE'
        AND (authority.value['authority_use']['credential_object_id'] = candidate.object_id
            OR authority.value['authority_use']['principal_id'] = candidate.principal_id)
    CROSS JOIN graph_settings config
    WHERE original.observed_boottime_ns <= selected.observed_boottime_ns
        AND selected.observed_boottime_ns - LEAST(selected.observed_boottime_ns, original.observed_boottime_ns)
            <= config.window_ns
), channels AS (
    SELECT DISTINCT authority.root_id, selected.id AS channel_id
    FROM authorities authority
    JOIN qualified root ON root.id = authority.root_id
    JOIN qualified original ON original.id = authority.read_id
    JOIN qualified selected ON selected.position <= root.position
    JOIN graph_facts channel ON channel.record = selected.id
        AND channel.value['tag'] = 'CHANNEL'
        AND channel.value['channel']['socket_object_id'] = authority.socket_id
    CROSS JOIN graph_settings config
    WHERE original.observed_boottime_ns <= selected.observed_boottime_ns
        AND selected.observed_boottime_ns - LEAST(selected.observed_boottime_ns, original.observed_boottime_ns)
            <= config.window_ns
)
SELECT id AS root_id, id AS support_id FROM qualified
UNION ALL
SELECT root_id, read_id AS support_id FROM candidate_reads
UNION ALL
SELECT root_id, authority_id AS support_id FROM authorities
UNION ALL
SELECT root_id, channel_id AS support_id FROM channels
