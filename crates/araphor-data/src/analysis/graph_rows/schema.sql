CREATE SEQUENCE graph_sources_seq;
CREATE SEQUENCE graph_evidence_seq;
CREATE SEQUENCE graph_producer_scopes_seq;
CREATE SEQUENCE graph_subject_values_seq;
CREATE SEQUENCE graph_edge_values_seq;
CREATE SEQUENCE graph_edge_properties_seq;
CREATE SEQUENCE graph_progress_values_seq;
CREATE SEQUENCE graph_position_values_seq;
CREATE SEQUENCE graph_branch_values_seq;
CREATE SEQUENCE graph_fact_values_seq;
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
    scope_id UBIGINT PRIMARY KEY, tenant_id BLOB NOT NULL, source_ref UBIGINT NOT NULL,
    producer_kind UTINYINT NOT NULL, instance_id VARCHAR, call_id UBIGINT,
    package_id VARCHAR, package_revision VARCHAR, image_digest VARCHAR,
    first_cursor UBIGINT NOT NULL, created_revision UBIGINT NOT NULL,
    CHECK (producer_kind <= 2),
    CHECK ((producer_kind=0 AND instance_id IS NOT NULL AND instance_id<>'' AND call_id IS NOT NULL
        AND package_id IS NOT NULL AND package_id<>'' AND package_revision IS NOT NULL AND package_revision<>''
        AND image_digest IS NOT NULL AND image_digest<>'') OR
        (producer_kind IN (1,2) AND instance_id IS NULL AND call_id IS NULL AND package_id IS NULL
            AND package_revision IS NULL AND image_digest IS NULL))
);
CREATE TABLE graph_producer_versions (
    result_id VARCHAR PRIMARY KEY, scope_id UBIGINT NOT NULL, commit_revision UBIGINT NOT NULL,
    base_result_id VARCHAR, subject_count UBIGINT NOT NULL, edge_count UBIGINT NOT NULL,
    finding_count UBIGINT NOT NULL, progress_count UBIGINT NOT NULL,
    derived_progress_digest BLOB,
    CHECK (derived_progress_digest IS NULL OR octet_length(derived_progress_digest)=32),
    UNIQUE (scope_id, commit_revision)
);
CREATE TABLE graph_producer_members (
    scope_id UBIGINT NOT NULL, member_kind UTINYINT NOT NULL, member_key BLOB NOT NULL,
    value_ref UBIGINT NOT NULL, anchor_record_id UBIGINT, anchor_fact BLOB,
    reason_code VARCHAR, ordinal UINTEGER NOT NULL,
    valid_from UBIGINT NOT NULL, valid_to UBIGINT,
    PRIMARY KEY (scope_id, member_kind, member_key, valid_from),
    CHECK (member_kind <= 7), CHECK (valid_to IS NULL OR valid_to > valid_from)
);
CREATE INDEX graph_producer_lookup ON graph_producer_members (scope_id, member_kind, member_key);
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
        AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision);
CREATE TABLE graph_subject_values (
    subject_id UBIGINT PRIMARY KEY, tenant_id BLOB NOT NULL,
    authority_rank UTINYINT NOT NULL, authority_text VARCHAR NOT NULL,
    authority_boot BLOB NOT NULL, authority_epoch UBIGINT NOT NULL,
    subject_kind UTINYINT NOT NULL, identity BLOB NOT NULL,
    UNIQUE (tenant_id, authority_rank, authority_text, authority_boot, authority_epoch, subject_kind, identity)
);
CREATE VIEW graph_subjects AS
    SELECT m.result_id,
        (row_number() OVER (PARTITION BY m.result_id ORDER BY s.tenant_id,
            s.authority_rank, s.authority_text, s.authority_boot, s.authority_epoch,
            s.subject_kind, s.identity) - 1)::UINTEGER AS ordinal,
        s.tenant_id, s.authority_rank, s.authority_text, s.authority_boot,
        s.authority_epoch, s.subject_kind, s.identity, s.subject_id
    FROM (SELECT DISTINCT result_id, value_ref FROM graph_selected_members WHERE member_kind = 2) m
    JOIN graph_subject_values s ON s.subject_id = m.value_ref;
CREATE TABLE graph_edge_properties (
    property_ref UBIGINT PRIMARY KEY, property_hash BLOB NOT NULL,
    edge_type VARCHAR NOT NULL, edge_rank UTINYINT NOT NULL,
    package_id VARCHAR NOT NULL, cause VARCHAR NOT NULL, cause_rank UTINYINT NOT NULL,
    proof_quality STRUCT(source_authority UTINYINT, local_subject_binding UTINYINT,
        remote_subject_binding UTINYINT, operation_result_authority UTINYINT,
        temporal_coverage UTINYINT, integrity UTINYINT) NOT NULL,
    required_coverage_interval_ids BLOB[] NOT NULL,
    CHECK (octet_length(property_hash) = 32)
);
CREATE INDEX graph_property_hash ON graph_edge_properties (property_hash);
CREATE TABLE graph_edge_values (
    edge_id UBIGINT PRIMARY KEY, value_hash BLOB NOT NULL,
    from_ref UBIGINT NOT NULL, to_ref UBIGINT NOT NULL,
    property_ref UBIGINT NOT NULL, evidence_refs UBIGINT[] NOT NULL,
    first_boottime_ns UBIGINT NOT NULL, last_boottime_ns UBIGINT NOT NULL,
    CHECK (first_boottime_ns <= last_boottime_ns), CHECK (octet_length(value_hash) = 32)
);
CREATE INDEX graph_edge_hash ON graph_edge_values (value_hash);
CREATE TABLE graph_progress_values (
    value_ref UBIGINT PRIMARY KEY, evidence_id UBIGINT NOT NULL,
    digest BLOB NOT NULL CHECK (octet_length(digest) = 32), state VARCHAR,
    UNIQUE (evidence_id, digest, state)
);
CREATE TABLE graph_position_values (
    value_ref UBIGINT PRIMARY KEY, evidence_id UBIGINT NOT NULL,
    commit_revision UBIGINT NOT NULL, ordinal UINTEGER NOT NULL,
    UNIQUE (evidence_id, commit_revision, ordinal), CHECK (commit_revision > 0)
);
CREATE TABLE graph_branch_values (
    branch_id UBIGINT PRIMARY KEY, tenant_id BLOB NOT NULL,
    value_hash BLOB NOT NULL CHECK (octet_length(value_hash) = 32), body BLOB NOT NULL
);
CREATE INDEX graph_branch_hash ON graph_branch_values (value_hash);
CREATE TABLE graph_fact_values (
    fact_id UBIGINT PRIMARY KEY, tenant_id BLOB NOT NULL,
    value_hash BLOB NOT NULL CHECK (octet_length(value_hash) = 32), body BLOB NOT NULL
);
CREATE INDEX graph_fact_hash ON graph_fact_values (value_hash);
CREATE VIEW graph_relationships AS
    WITH evidence AS (
        SELECT m.result_id, e.evidence_id,
            (row_number() OVER (PARTITION BY m.result_id ORDER BY e.cpu_id, e.durable_cursor) - 1)::UINTEGER AS ordinal
        FROM graph_selected_members m JOIN graph_evidence e ON m.value_ref = e.evidence_id
        WHERE m.member_kind = 0
    ), selected AS (
        SELECT DISTINCT m.result_id, e.edge_id,e.value_hash,e.from_ref,e.to_ref,
            p.edge_type,p.edge_rank,p.package_id,p.cause,p.cause_rank,e.evidence_refs,
            p.proof_quality,p.required_coverage_interval_ids,e.first_boottime_ns,e.last_boottime_ns
        FROM graph_selected_members m JOIN graph_edge_values e ON e.edge_id=m.value_ref
        LEFT JOIN graph_edge_properties p USING(property_ref) WHERE m.member_kind=3
    ), edge_evidence AS (
        SELECT e.result_id, e.edge_id, list(o.ordinal ORDER BY refs.position)::UINTEGER[] AS evidence
        FROM selected e CROSS JOIN unnest(e.evidence_refs) WITH ORDINALITY AS refs(evidence_id, position)
        LEFT JOIN evidence o ON o.result_id=e.result_id AND o.evidence_id=refs.evidence_id
        GROUP BY e.result_id,e.edge_id
    ), resolved AS (
        SELECT e.result_id, e.edge_id, source.ordinal AS from_subject_id,
            target.ordinal AS to_subject_id, e.edge_type, e.edge_rank, e.package_id,
            e.cause, e.cause_rank,
            coalesce(proof.evidence,[]::UINTEGER[]) AS evidence,
            e.proof_quality, e.required_coverage_interval_ids, e.first_boottime_ns, e.last_boottime_ns
        FROM selected e LEFT JOIN edge_evidence proof ON proof.result_id=e.result_id AND proof.edge_id=e.edge_id
        LEFT JOIN graph_subjects source ON source.result_id = e.result_id AND source.subject_id = e.from_ref
        LEFT JOIN graph_subjects target ON target.result_id = e.result_id AND target.subject_id = e.to_ref
    )
    SELECT result_id,
        (row_number() OVER (PARTITION BY result_id ORDER BY from_subject_id, to_subject_id,
            edge_rank, package_id, evidence, cause_rank) - 1)::UINTEGER AS ordinal,
        from_subject_id, to_subject_id, edge_type, package_id, cause, evidence,
        proof_quality, required_coverage_interval_ids, first_boottime_ns, last_boottime_ns, edge_id
    FROM resolved;
