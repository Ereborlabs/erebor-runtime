WITH support AS (
    SELECT UNNEST(support) AS item FROM units
), selected AS (
    SELECT DISTINCT item['record'] AS id FROM support
)
SELECT r.id, r.position, r.effect, r.ingested_utc_ns, r.observed_boottime_ns,
    r.profile_generation_ref_id, r.original_kernel_sequence, r.coverage_interval_id,
    r.process_instance_id, r.entry_instance_id, r.binding_id, r.role_id,
    r.state_id, r.entry_rule_id, r.proof_quality
FROM graph_records r JOIN selected ON selected.id = r.id
ORDER BY r.id
