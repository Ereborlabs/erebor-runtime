CREATE SEQUENCE graph_edge_values_seq;
CREATE SEQUENCE graph_edge_properties_seq;
CREATE TABLE graph_edge_properties (
    property_ref UBIGINT PRIMARY KEY, property_key BLOB NOT NULL,
    edge_type VARCHAR NOT NULL, edge_rank UTINYINT NOT NULL,
    package_id VARCHAR NOT NULL, cause VARCHAR NOT NULL, cause_rank UTINYINT NOT NULL,
    proof_quality STRUCT(source_authority UTINYINT, local_subject_binding UTINYINT,
        remote_subject_binding UTINYINT, operation_result_authority UTINYINT,
        temporal_coverage UTINYINT, integrity UTINYINT) NOT NULL,
    required_coverage_interval_ids BLOB[] NOT NULL,
    CHECK (octet_length(property_key) > 0)
);
CREATE INDEX graph_property_key ON graph_edge_properties (property_key);
CREATE TABLE graph_edge_values (
    edge_id UBIGINT PRIMARY KEY, value_key BLOB NOT NULL,
    from_ref UBIGINT NOT NULL, to_ref UBIGINT NOT NULL,
    property_ref UBIGINT NOT NULL, evidence_refs UBIGINT[] NOT NULL,
    first_boottime_ns UBIGINT NOT NULL, last_boottime_ns UBIGINT NOT NULL,
    CHECK (first_boottime_ns <= last_boottime_ns), CHECK (octet_length(value_key) > 0)
);
CREATE INDEX graph_edge_key ON graph_edge_values (value_key);
CREATE VIEW graph_relationships AS
    WITH evidence AS (
        SELECT m.result_id, e.evidence_id,
            (row_number() OVER (PARTITION BY m.result_id ORDER BY e.cpu_id, e.durable_cursor) - 1)::UINTEGER AS ordinal
        FROM graph_selected_members m JOIN graph_evidence e ON m.value_ref = e.evidence_id
        WHERE m.member_kind = 0
    ), selected AS (
        SELECT DISTINCT m.result_id, e.edge_id,e.from_ref,e.to_ref,
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
