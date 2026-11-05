WITH selected AS (
    SELECT state.tenant_id, state.node_id, state.node_boot_id, state.label_epoch,
        state.source_id, state.source_epoch, control.first_cursor, control.last_cursor
    FROM graph_control control JOIN graph_state state USING (source_key)
)
SELECT events.* FROM events JOIN selected USING (
    tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch)
WHERE events.source_cursor BETWEEN selected.first_cursor AND selected.last_cursor
