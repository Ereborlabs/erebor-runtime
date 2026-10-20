WITH current_findings AS (
    SELECT * FROM findings
    QUALIFY ROW_NUMBER() OVER (
        PARTITION BY tenant_id, finding_id ORDER BY commit_revision DESC, graph_result_id DESC
    ) = 1
), current_routes AS (
    SELECT * FROM notification_routes
    QUALIFY DENSE_RANK() OVER (
        PARTITION BY tenant_id, route_id ORDER BY route_revision DESC
    ) = 1
), approved_routes AS (
    SELECT * FROM current_routes
    WHERE grant_current
), matching_routes AS (
    SELECT finding.tenant_id, finding.finding_id, finding.finding_revision,
        finding.graph_result_id AS result_id, route.route_id, route.route_revision
    FROM current_findings finding JOIN approved_routes route
        ON route.tenant_id = finding.tenant_id
            AND array_has(route.package_ids, finding.package_id)
), missing_routes AS (
    SELECT candidate.finding_id, candidate.result_id
    FROM matching_routes candidate LEFT ANTI JOIN notifications state
        ON state.tenant_id = candidate.tenant_id
            AND state.finding_id = candidate.finding_id
            AND state.finding_revision = candidate.finding_revision
            AND state.route_id = candidate.route_id
            AND state.route_revision = candidate.route_revision
), unmatched_findings AS (
    SELECT finding.*
    FROM current_findings finding LEFT ANTI JOIN matching_routes route
        ON route.tenant_id = finding.tenant_id AND route.finding_id = finding.finding_id
), missing_findings AS (
    SELECT finding.finding_id, finding.graph_result_id AS result_id
    FROM unmatched_findings finding LEFT ANTI JOIN notifications state
        ON state.tenant_id = finding.tenant_id
            AND state.finding_id = finding.finding_id
            AND state.finding_revision = finding.finding_revision
), routing AS (
    SELECT finding_id, result_id FROM missing_routes
    UNION
    SELECT finding_id, result_id FROM missing_findings
)
SELECT finding_id, result_id, arrow_cast(NULL, 'Binary') AS notification_id FROM routing
UNION ALL
SELECT CAST(NULL AS VARCHAR) AS finding_id, CAST(NULL AS VARCHAR) AS result_id,
    notification_id FROM notifications WHERE delivery_ready
