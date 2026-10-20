WITH
record_conflicts AS (
    SELECT CASE WHEN COUNT(DISTINCT payload) > 1 THEN 'context evidence' END AS kind
    FROM evidence GROUP BY id
),
records AS (
    SELECT * FROM evidence
    QUALIFY ROW_NUMBER() OVER (PARTITION BY id ORDER BY payload) = 1
),
record_marked AS (
    SELECT records.*, CASE
        WHEN records.subject <> scope.subject THEN 'EVIDENCE_SUBJECT_MISMATCH'
        WHEN time IS NULL OR time < from_ns OR time > cutoff_ns
            THEN 'EVIDENCE_OUTSIDE_WINDOW_OR_UNDATED'
        END AS reason
    FROM records CROSS JOIN scope
),
record_ranked AS (
    SELECT *, ROW_NUMBER() OVER (
        ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    ) AS position
    FROM record_marked WHERE reason IS NULL
),
record_selected AS (
    SELECT record_ranked.*, CASE WHEN evidence_limit IS NOT NULL AND position > evidence_limit
        THEN 'EVIDENCE_HANDLE_LIMIT' END AS omission
    FROM record_ranked CROSS JOIN scope
),
fact_conflicts AS (
    SELECT CASE WHEN COUNT(DISTINCT payload) > 1 THEN 'context fact' END AS kind
    FROM facts GROUP BY kind, key
),
fact_distinct AS (
    SELECT * FROM facts
    QUALIFY ROW_NUMBER() OVER (PARTITION BY kind, key ORDER BY payload) = 1
),
fact_marked AS (
    SELECT fact_distinct.*, CASE
        WHEN fact_distinct.subject <> scope.subject THEN 'FACT_SUBJECT_MISMATCH'
        WHEN recorded = 0 OR recorded > cutoff_ns OR valid_from IS NULL
            OR valid_from > cutoff_ns OR valid_until <= from_ns
            THEN 'FACT_OUTSIDE_WINDOW_OR_UNDATED'
        WHEN NOT array_has(scope.sensitivities, sensitivity) THEN 'FACT_ACCESS_DENIED'
        END AS reason
    FROM fact_distinct CROSS JOIN scope
),
fact_ranked AS (
    SELECT *, ROW_NUMBER() OVER (
        ORDER BY kind, key ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    ) AS position
    FROM fact_marked WHERE reason IS NULL
),
fact_selected AS (
    SELECT fact_ranked.*, CASE WHEN fact_limit IS NOT NULL AND position > fact_limit
        THEN 'OWNER_FACT_LIMIT' END AS omission
    FROM fact_ranked CROSS JOIN scope
),
document_conflicts AS (
    SELECT CASE WHEN COUNT(DISTINCT version) > 1 THEN 'context document revision' END AS kind
    FROM documents GROUP BY id, revision
),
document_versions AS (
    SELECT * FROM documents
    QUALIFY ROW_NUMBER() OVER (PARTITION BY id, revision ORDER BY version) = 1
),
document_history AS (
    SELECT *, LAG(imported) OVER (PARTITION BY id ORDER BY revision) AS prior_imported,
        LAG(subject) OVER (PARTITION BY id ORDER BY revision) AS prior_subject,
        LAG(method) OVER (PARTITION BY id ORDER BY revision) AS prior_method,
        LAG(kind) OVER (PARTITION BY id ORDER BY revision) AS prior_kind,
        LAG(origin) OVER (PARTITION BY id ORDER BY revision) AS prior_origin
    FROM document_versions
),
history_conflicts AS (
    SELECT CASE WHEN prior_imported > imported OR prior_subject <> subject
        OR prior_method <> method OR prior_kind <> kind OR prior_origin <> origin
        THEN 'context revision history' END AS kind FROM document_history
),
document_latest AS (
    SELECT document_versions.* FROM document_versions CROSS JOIN scope
    WHERE imported <= cutoff_ns
    QUALIFY ROW_NUMBER() OVER (PARTITION BY id ORDER BY revision DESC) = 1
),
document_marked AS (
    SELECT document_latest.*, CASE
        WHEN document_latest.subject <> scope.subject THEN 'DOCUMENT_SUBJECT_MISMATCH'
        WHEN document_latest.method <> scope.method THEN 'DOCUMENT_METHOD_MISMATCH'
        WHEN NOT array_has(scope.sensitivities, sensitivity) THEN 'DOCUMENT_ACCESS_DENIED'
        WHEN valid_from > cutoff_ns OR valid_until <= from_ns THEN 'DOCUMENT_OUTSIDE_WINDOW'
        END AS reason
    FROM document_latest CROSS JOIN scope
),
document_eligible AS (
    SELECT * FROM document_marked WHERE reason IS NULL
),
document_sources AS (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY origin ORDER BY id) AS source_position
    FROM document_eligible
),
document_allowed AS (
    SELECT document_sources.* FROM document_sources CROSS JOIN scope
    WHERE source_limit IS NULL OR source_position <= source_limit
),
document_ranked AS (
    SELECT *, ROW_NUMBER() OVER (ORDER BY id) AS position FROM document_allowed
),
selected_count AS (
    SELECT (SELECT COUNT(*) FROM record_selected WHERE omission IS NULL)
        + (SELECT COUNT(*) FROM fact_selected WHERE omission IS NULL) AS count
),
document_selected AS (
    SELECT document_ranked.*, CASE
        WHEN handle_limit IS NOT NULL
            AND CAST(position AS DECIMAL(38,0)) + CAST(selected_count.count AS DECIMAL(38,0))
                > CAST(handle_limit AS DECIMAL(38,0))
        THEN 'DOCUMENT_HANDLE_LIMIT' END AS omission
    FROM document_ranked CROSS JOIN scope CROSS JOIN selected_count
),
source_counts AS (
    SELECT origin AS key, CAST(COUNT(*) AS BIGINT UNSIGNED) AS count
    FROM document_eligible GROUP BY origin
),
conflicting_kinds AS (
    SELECT kind FROM document_eligible GROUP BY kind HAVING COUNT(DISTINCT text) > 1
),
conflict_ranked AS (
    SELECT document_eligible.*, ROW_NUMBER() OVER (PARTITION BY kind ORDER BY id) AS position
    FROM document_eligible JOIN conflicting_kinds USING (kind)
),
conflict_selected AS (
    SELECT conflict_ranked.*, (conflict_limit IS NOT NULL AND position > conflict_limit) AS omitted
    FROM conflict_ranked CROSS JOIN scope
),
conflicts AS (
    SELECT kind, MIN(kind_rank) AS kind_rank,
        COALESCE(array_agg(id ORDER BY id) FILTER (WHERE NOT omitted), []) AS ids
    FROM conflict_selected GROUP BY kind
),
omission_rows AS (
    SELECT reason FROM record_marked WHERE reason IS NOT NULL
    UNION ALL SELECT omission FROM record_selected WHERE omission IS NOT NULL
    UNION ALL SELECT reason FROM fact_marked WHERE reason IS NOT NULL
    UNION ALL SELECT omission FROM fact_selected WHERE omission IS NOT NULL
    UNION ALL SELECT 'DOCUMENT_AFTER_CUTOFF' FROM document_versions CROSS JOIN scope WHERE imported > cutoff_ns
    UNION ALL SELECT reason FROM document_marked WHERE reason IS NOT NULL
    UNION ALL SELECT 'DOCUMENT_SOURCE_LIMIT' FROM document_sources CROSS JOIN scope
        WHERE source_limit IS NOT NULL AND source_position > source_limit
    UNION ALL SELECT omission FROM document_selected WHERE omission IS NOT NULL
    UNION ALL SELECT 'CONFLICT_HANDLE_LIMIT' FROM conflict_selected WHERE omitted
),
omissions AS (
    SELECT reason AS key, CAST(COUNT(*) AS BIGINT UNSIGNED) AS count FROM omission_rows GROUP BY reason
),
errors AS (
    SELECT kind FROM record_conflicts UNION ALL SELECT kind FROM fact_conflicts
    UNION ALL SELECT kind FROM document_conflicts UNION ALL SELECT kind FROM history_conflicts
    UNION ALL SELECT CASE WHEN document_limit IS NOT NULL
        AND (SELECT COUNT(*) FROM document_latest) > document_limit
        THEN 'context document count' END FROM scope
)
SELECT
    (SELECT COALESCE(array_agg(payload ORDER BY id), []) FROM record_selected WHERE omission IS NULL) AS records,
    (SELECT COALESCE(array_agg(payload ORDER BY kind, key), []) FROM fact_selected WHERE omission IS NULL) AS facts,
    (SELECT COALESCE(array_agg(payload ORDER BY id), []) FROM document_selected WHERE omission IS NULL) AS documents,
    (SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) FROM document_eligible) AS available,
    (SELECT COALESCE(array_agg(named_struct('key',key,'count',count) ORDER BY key), []) FROM source_counts) AS sources,
    (SELECT COALESCE(array_agg(named_struct('key',key,'count',count) ORDER BY key), []) FROM omissions) AS omissions,
    (SELECT COALESCE(array_agg(named_struct('kind',kind,'ids',ids) ORDER BY kind_rank), []) FROM conflicts) AS conflicts,
    (SELECT MIN(kind) FROM errors) AS error
