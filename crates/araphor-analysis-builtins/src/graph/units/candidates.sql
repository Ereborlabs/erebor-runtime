WITH root_facts AS (
    SELECT facts.* FROM graph_facts facts JOIN units ON facts.record = units.record
), current_index AS (
    SELECT facts.record, facts.value['tag'] AS tag,
        CASE WHEN facts.value['tag'] = 'AUTHORITY_USE' THEN facts.value['authority_use']['task_cookie']
            ELSE records.effect['task_cookie'] END AS task_cookie,
        CASE WHEN facts.value['tag'] = 'AUTHORITY_USE' THEN facts.value['authority_use']['process_instance_id']
            ELSE records.process_instance_id END AS process_instance_id,
        CASE WHEN facts.value['tag'] = 'CREDENTIAL' THEN facts.value['credential']['principal_id']
            ELSE facts.value['authority_use']['principal_id'] END AS principal_id,
        CASE WHEN facts.value['tag'] = 'CREDENTIAL' THEN facts.value['credential']['object_id']
            ELSE facts.value['authority_use']['credential_object_id'] END AS object_id,
        CASE WHEN facts.value['tag'] = 'CHANNEL' THEN facts.value['channel']['socket_object_id']
            ELSE facts.value['authority_use']['socket_object_id'] END AS socket_object_id
    FROM root_facts facts JOIN graph_records records ON records.id = facts.record
    WHERE facts.value['tag'] IN ('CREDENTIAL', 'AUTHORITY_USE', 'CHANNEL')
), candidates AS (
    SELECT properties['record'] AS record, properties['tag'] AS tag,
        properties['task_cookie'] AS task_cookie, properties['process_instance_id'] AS process_instance_id,
        properties['principal_id'] AS principal_id, properties['object_id'] AS object_id,
        properties['socket_object_id'] AS socket_object_id
    FROM graph.credential_candidates_v1
    UNION SELECT * FROM current_index
), triggers AS (
    SELECT records.effect['task_cookie'] AS task_cookie, records.process_instance_id,
        CAST(NULL AS VARCHAR) AS principal_id
    FROM units JOIN graph_records records ON records.id = units.record
    JOIN root_facts facts ON facts.record = units.record
    WHERE records.effect['effect_family'] = {network} AND facts.value['tag'] = 'CHANNEL'
    UNION
    SELECT value['authority_use']['task_cookie'], value['authority_use']['process_instance_id'],
        value['authority_use']['principal_id']
    FROM root_facts WHERE value['tag'] = 'AUTHORITY_USE'
), credentials AS (
    SELECT DISTINCT candidate.* FROM candidates candidate
    LEFT JOIN units ON units.record = candidate.record
    LEFT JOIN triggers ON (triggers.task_cookie > 0 AND candidate.task_cookie = triggers.task_cookie)
        OR candidate.process_instance_id = triggers.process_instance_id
        OR candidate.principal_id = triggers.principal_id
    WHERE candidate.tag = 'CREDENTIAL' AND (units.record IS NOT NULL
        OR triggers.task_cookie IS NOT NULL OR triggers.process_instance_id IS NOT NULL
        OR triggers.principal_id IS NOT NULL)
), authorities AS (
    SELECT DISTINCT candidate.* FROM candidates candidate JOIN credentials
        ON candidate.object_id = credentials.object_id OR candidate.principal_id = credentials.principal_id
    WHERE candidate.tag = 'AUTHORITY_USE'
), channels AS (
    SELECT DISTINCT candidate.record FROM candidates candidate JOIN authorities
        ON candidate.socket_object_id = authorities.socket_object_id
    WHERE candidate.tag = 'CHANNEL'
), selected AS (
    SELECT record AS id FROM units
    UNION SELECT record FROM credentials
    UNION SELECT record FROM authorities
    UNION SELECT record FROM channels
), references AS (
    SELECT UNNEST(facts.value['policy']['observations']) AS id
    FROM selected JOIN graph_facts facts ON facts.record = selected.id
    WHERE facts.value['tag'] = 'POLICY'
), wanted AS (
    SELECT id FROM selected UNION SELECT id FROM references
)
SELECT records.* FROM graph_records records JOIN wanted ON records.id = wanted.id
ORDER BY records.id
