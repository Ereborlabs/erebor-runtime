CREATE SEQUENCE graph_finding_values_seq;
CREATE TABLE graph_finding_values (
    value_id UBIGINT PRIMARY KEY, tenant_id BLOB NOT NULL, finding_id VARCHAR NOT NULL,
    package_id VARCHAR NOT NULL, package_version UBIGINT NOT NULL, subject_ref UBIGINT NOT NULL,
    state VARCHAR NOT NULL, window_start_utc_ns BIGINT NOT NULL, window_end_utc_ns BIGINT NOT NULL,
    evidence_refs UBIGINT[] NOT NULL, required_coverage_interval_ids BLOB[] NOT NULL,
    policy_provenance BLOB NOT NULL, effects BLOB NOT NULL, reason BLOB NOT NULL,
    severity VARCHAR NOT NULL, sensitivity VARCHAR NOT NULL, required_action VARCHAR,
    limits VARCHAR[] NOT NULL, value_hash BLOB NOT NULL CHECK (octet_length(value_hash) = 32)
);
CREATE INDEX graph_finding_hash ON graph_finding_values (value_hash);
CREATE VIEW graph_findings AS
    SELECT m.result_id,
        (row_number() OVER (PARTITION BY m.result_id ORDER BY f.finding_id) - 1)::UINTEGER AS ordinal,
        f.tenant_id, f.finding_id, f.package_id, f.package_version, f.subject_ref,
        f.state, f.window_start_utc_ns, f.window_end_utc_ns, f.evidence_refs,
        f.required_coverage_interval_ids, f.policy_provenance, f.effects, f.reason,
        f.severity, f.sensitivity, f.required_action, f.limits, f.value_id
    FROM (SELECT DISTINCT result_id, value_ref FROM graph_selected_members WHERE member_kind = 4) m
    JOIN graph_finding_values f ON f.value_id = m.value_ref;
CREATE VIEW graph_finding_keys AS
    SELECT DISTINCT m.result_id, f.finding_id
    FROM graph_selected_members m
    JOIN graph_finding_values f ON f.value_id = m.value_ref
    WHERE m.member_kind = 4;
