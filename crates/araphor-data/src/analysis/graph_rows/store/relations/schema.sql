CREATE SEQUENCE graph_sources_seq;
CREATE SEQUENCE graph_evidence_seq;
CREATE SEQUENCE graph_producer_scopes_seq;
CREATE SEQUENCE graph_position_values_seq;
CREATE SEQUENCE graph_branch_values_seq;
CREATE SEQUENCE graph_fact_values_seq;
CREATE SEQUENCE graph_owner_values_seq;
CREATE TABLE graph_sources (
    source_ref UBIGINT PRIMARY KEY, stream_key BLOB NOT NULL UNIQUE, tenant_id BLOB NOT NULL,
    identity BLOB NOT NULL
);
CREATE TABLE graph_evidence (
    evidence_id UBIGINT PRIMARY KEY, source_ref UBIGINT NOT NULL,
    cpu_id UINTEGER NOT NULL, durable_cursor UBIGINT NOT NULL,
    UNIQUE (source_ref, cpu_id, durable_cursor), CHECK (durable_cursor > 0)
);
CREATE TABLE graph_producer_scopes (
    scope_id UBIGINT PRIMARY KEY, tenant_id BLOB NOT NULL, source_ref UBIGINT,
    producer_kind UTINYINT NOT NULL, view_id VARCHAR, instance_id VARCHAR, call_id UBIGINT,
    first_cursor UBIGINT NOT NULL, created_revision UBIGINT NOT NULL,
    CHECK (producer_kind <= 2),
    CHECK ((producer_kind=0 AND view_id IS NOT NULL AND view_id<>''
        AND instance_id IS NOT NULL AND instance_id<>'' AND call_id IS NOT NULL) OR
        (producer_kind IN (1,2) AND source_ref IS NOT NULL AND view_id IS NULL
            AND instance_id IS NULL AND call_id IS NULL))
);
CREATE TABLE graph_producer_versions (
    result_id VARCHAR PRIMARY KEY, scope_id UBIGINT NOT NULL, commit_revision UBIGINT NOT NULL,
    base_result_id VARCHAR, subject_count UBIGINT NOT NULL, edge_count UBIGINT NOT NULL,
    finding_count UBIGINT NOT NULL, state_count UBIGINT NOT NULL,
    selected_state_ref UBIGINT,
    evidence_count UBIGINT NOT NULL DEFAULT 0, position_count UBIGINT NOT NULL DEFAULT 0,
    fact_count UBIGINT NOT NULL DEFAULT 0,
    restricted_count UBIGINT,
    captured_revision UBIGINT,
    package_id VARCHAR, package_revision VARCHAR, image_digest VARCHAR,
    CHECK (captured_revision IS NULL OR (captured_revision > 0 AND captured_revision < commit_revision)),
    CHECK (selected_state_ref IS NULL OR selected_state_ref > 0),
    UNIQUE (scope_id, commit_revision)
);
CREATE TABLE graph_owner_values (
    scope_id UBIGINT NOT NULL, owner_ref UBIGINT NOT NULL, owner_key BLOB NOT NULL,
    PRIMARY KEY(scope_id, owner_ref), UNIQUE(scope_id, owner_key)
);
CREATE TABLE graph_producer_members (
    scope_id UBIGINT NOT NULL, unit_ref UBIGINT NOT NULL DEFAULT 0,
    member_kind UTINYINT NOT NULL, member_key BLOB NOT NULL,
    value_ref UBIGINT NOT NULL, anchor_record_id UBIGINT, anchor_fact BLOB,
    reason_code VARCHAR, ordinal UINTEGER NOT NULL,
    valid_from UBIGINT NOT NULL, valid_to UBIGINT,
    PRIMARY KEY (scope_id, unit_ref, member_kind, member_key, valid_from),
    CHECK (member_kind IN (0,1,2,3,4,6,7,8,9,10)), CHECK (valid_to IS NULL OR valid_to > valid_from)
);
CREATE INDEX graph_producer_lookup ON graph_producer_members (scope_id, member_kind, member_key);
CREATE INDEX graph_producer_units ON graph_producer_members (unit_ref);
CREATE INDEX graph_producer_keys ON graph_producer_members (member_key);
CREATE INDEX graph_producer_opened ON graph_producer_members (valid_from);
CREATE INDEX graph_producer_closed ON graph_producer_members (valid_to);
CREATE TABLE graph_versions (
    result_id VARCHAR PRIMARY KEY, commit_revision UBIGINT NOT NULL,
    metadata_result_id VARCHAR NOT NULL, derive_branches BOOLEAN NOT NULL,
    expired BOOLEAN NOT NULL
);
CREATE TABLE graph_result_producers (
    result_id VARCHAR NOT NULL, producer_result_id VARCHAR NOT NULL,
    PRIMARY KEY (result_id, producer_result_id)
);
CREATE VIEW graph_selected_members AS
    SELECT DISTINCT b.result_id, m.member_kind, m.member_key, m.value_ref, m.ordinal
    FROM graph_result_producers b
    JOIN graph_producer_versions v ON v.result_id = b.producer_result_id
    JOIN graph_producer_members m ON m.scope_id = v.scope_id
        AND m.valid_from <= v.commit_revision
        AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
    WHERE m.member_kind NOT IN (9,10);
CREATE TABLE graph_position_values (
    value_ref UBIGINT PRIMARY KEY, evidence_id UBIGINT NOT NULL,
    commit_revision UBIGINT NOT NULL, ordinal UINTEGER NOT NULL,
    UNIQUE (evidence_id, commit_revision, ordinal), CHECK (commit_revision > 0)
);
CREATE TABLE graph_branch_values (
    branch_id UBIGINT PRIMARY KEY, tenant_id BLOB NOT NULL, body BLOB NOT NULL
);
CREATE INDEX graph_branch_body ON graph_branch_values (body);
CREATE TABLE graph_fact_values (
    fact_id UBIGINT PRIMARY KEY, tenant_id BLOB NOT NULL, body BLOB NOT NULL
);
CREATE INDEX graph_fact_body ON graph_fact_values (body);
