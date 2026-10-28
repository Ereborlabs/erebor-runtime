WITH current_findings AS (
    SELECT *,
        CASE severity WHEN 'info' THEN 0 WHEN 'warning' THEN 1
            WHEN 'high' THEN 2 WHEN 'critical' THEN 3 END AS priority_rank,
        CASE sensitivity WHEN 'public' THEN 0 WHEN 'tenant' THEN 1
            WHEN 'host_restricted' THEN 2 END AS sensitivity_rank
    FROM findings
    QUALIFY ROW_NUMBER() OVER (
        PARTITION BY tenant_id, finding_id ORDER BY commit_revision DESC, graph_result_id DESC
    ) = 1
), current_states AS (
    SELECT *,
        CASE source_priority WHEN 'info' THEN 0 WHEN 'warning' THEN 1
            WHEN 'high' THEN 2 WHEN 'critical' THEN 3 END AS priority_rank,
        CASE sensitivity WHEN 'public' THEN 0 WHEN 'tenant' THEN 1
            WHEN 'host_restricted' THEN 2 END AS sensitivity_rank
    FROM notifications
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
        finding.required_action, finding.priority_rank, finding.sensitivity_rank,
        finding.graph_result_id AS result_id, route.route_id, route.route_revision,
        escalation.route_id AS escalation_route_id,
        escalation.route_revision AS escalation_route_revision
    FROM current_findings finding JOIN approved_routes route
        ON route.tenant_id = finding.tenant_id
            AND array_has(route.package_ids, finding.package_id)
    LEFT JOIN current_routes escalation
        ON escalation.tenant_id = route.tenant_id
            AND escalation.route_id = route.escalation_route_id
), missing_routes AS (
    SELECT candidate.finding_id, candidate.result_id
    FROM matching_routes candidate LEFT ANTI JOIN current_states state
        ON state.tenant_id = candidate.tenant_id
            AND state.finding_id = candidate.finding_id
            AND state.finding_revision = candidate.finding_revision
            AND (state.required_action IS NOT DISTINCT FROM candidate.required_action)
            AND state.priority_rank >= candidate.priority_rank
            AND state.sensitivity_rank >= candidate.sensitivity_rank
            AND state.route_id = candidate.route_id
            AND state.route_revision = candidate.route_revision
            AND (state.escalation_route_id IS NOT DISTINCT FROM candidate.escalation_route_id)
            AND (state.escalation_route_revision IS NOT DISTINCT FROM candidate.escalation_route_revision)
), unmatched_findings AS (
    SELECT finding.*
    FROM current_findings finding LEFT ANTI JOIN matching_routes route
        ON route.tenant_id = finding.tenant_id AND route.finding_id = finding.finding_id
), missing_findings AS (
    SELECT finding.finding_id, finding.graph_result_id AS result_id
    FROM unmatched_findings finding LEFT ANTI JOIN current_states state
        ON state.tenant_id = finding.tenant_id
            AND state.finding_id = finding.finding_id
            AND state.finding_revision = finding.finding_revision
            AND (state.required_action IS NOT DISTINCT FROM finding.required_action)
            AND state.priority_rank >= finding.priority_rank
            AND state.sensitivity_rank >= finding.sensitivity_rank
), routing AS (
    SELECT finding_id, result_id FROM missing_routes
    UNION
    SELECT finding_id, result_id FROM missing_findings
), ready_states AS (
    SELECT state.finding_id, state.notification_id FROM current_states state
    LEFT JOIN approved_routes route
        ON route.tenant_id = state.tenant_id AND route.route_id = state.route_id
    LEFT JOIN current_routes escalation
        ON escalation.tenant_id = route.tenant_id
            AND escalation.route_id = route.escalation_route_id
    WHERE state.delivery_ready OR (
        state.kind = 'unconfirmed_concern' AND NOT state.acknowledged
        AND route.route_id IS NOT NULL
        AND ((state.route_revision IS DISTINCT FROM route.route_revision)
            OR (state.escalation_route_id IS DISTINCT FROM escalation.route_id)
            OR (state.escalation_route_revision IS DISTINCT FROM escalation.route_revision))
    )
)
SELECT routing.finding_id, routing.result_id, ready.notification_id
FROM routing FULL OUTER JOIN ready_states ready
    ON routing.finding_id = ready.finding_id
ORDER BY notification_id NULLS LAST
