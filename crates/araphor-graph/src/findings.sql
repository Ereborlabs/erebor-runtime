CREATE TABLE graph_finding_values (
    value_id UBIGINT PRIMARY KEY,
    tenant_id BLOB NOT NULL,
    finding_id VARCHAR NOT NULL,
    package_id VARCHAR NOT NULL,
    package_version UBIGINT NOT NULL,
    subject_ref UBIGINT NOT NULL,
    state VARCHAR NOT NULL,
    window_start_utc_ns BIGINT NOT NULL,
    window_end_utc_ns BIGINT NOT NULL,
    evidence_refs UBIGINT[] NOT NULL,
    required_coverage_interval_ids BLOB[] NOT NULL,
    policy_provenance BLOB NOT NULL,
    effects BLOB NOT NULL,
    reason BLOB NOT NULL,
    severity VARCHAR NOT NULL,
    sensitivity VARCHAR NOT NULL,
    required_action VARCHAR,
    limits VARCHAR[] NOT NULL
);
CREATE INDEX graph_finding_identity ON graph_finding_values (tenant_id, finding_id);
CREATE TABLE graph_finding_membership (
    lineage_id UBIGINT NOT NULL,
    value_id UBIGINT NOT NULL,
    valid_from UBIGINT NOT NULL,
    valid_to UBIGINT,
    PRIMARY KEY (lineage_id, value_id, valid_from),
    CHECK (valid_to IS NULL OR valid_to > valid_from)
);
CREATE VIEW graph_findings AS
    SELECT v.result_id,
        (row_number() OVER (PARTITION BY v.result_id ORDER BY f.finding_id) - 1)::UINTEGER AS ordinal,
        f.tenant_id, f.finding_id, f.package_id, f.package_version, f.subject_ref,
        f.state, f.window_start_utc_ns, f.window_end_utc_ns, f.evidence_refs,
        f.required_coverage_interval_ids, f.policy_provenance, f.effects,
        f.reason, f.severity, f.sensitivity, f.required_action, f.limits
    FROM graph_versions v
    JOIN graph_finding_membership m ON m.lineage_id = v.lineage_id
        AND m.valid_from <= v.commit_revision
        AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
    JOIN graph_finding_values f USING (value_id);
