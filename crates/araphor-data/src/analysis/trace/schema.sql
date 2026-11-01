CREATE TABLE trace_intents (
    tenant_id BLOB NOT NULL,
    request_id BLOB NOT NULL,
    source BLOB NOT NULL,
    source_sha256 BLOB NOT NULL,
    bindings VARCHAR NOT NULL,
    authority BLOB NOT NULL,
    accepted_unix_ns UBIGINT NOT NULL,
    deadline_unix_ns UBIGINT NOT NULL,
    host_sensitive BOOLEAN NOT NULL,
    PRIMARY KEY (tenant_id, request_id)
);
CREATE TABLE trace_states (
    tenant_id BLOB NOT NULL,
    request_id BLOB NOT NULL,
    revision UBIGINT NOT NULL,
    cancel_requested BOOLEAN NOT NULL,
    read_revoked BOOLEAN NOT NULL,
    PRIMARY KEY (tenant_id, request_id, revision),
    FOREIGN KEY (tenant_id, request_id) REFERENCES trace_intents (tenant_id, request_id)
);
CREATE VIEW traces AS
    SELECT i.tenant_id, i.request_id, i.source, i.source_sha256, i.bindings,
        i.authority, i.accepted_unix_ns, i.deadline_unix_ns, i.host_sensitive,
        s.revision, s.cancel_requested, s.read_revoked
    FROM trace_intents i JOIN trace_states s USING (tenant_id, request_id)
    QUALIFY row_number() OVER (
        PARTITION BY i.tenant_id, i.request_id ORDER BY s.revision DESC) = 1;
CREATE TABLE trace_versions (
    stream_key BLOB NOT NULL,
    identity_json VARCHAR NOT NULL,
    tenant_id BLOB NOT NULL,
    last_sequence UBIGINT NOT NULL,
    output_bytes UBIGINT NOT NULL,
    terminal VARCHAR,
    retained_floor UBIGINT NOT NULL,
    commit_revision UBIGINT NOT NULL,
    version_revision UBIGINT NOT NULL,
    PRIMARY KEY (stream_key, version_revision)
);
CREATE VIEW trace_receipts AS
    SELECT stream_key, identity_json, tenant_id, last_sequence, output_bytes,
        terminal, retained_floor, commit_revision
    FROM trace_versions
    QUALIFY row_number() OVER (PARTITION BY stream_key ORDER BY version_revision DESC) = 1;
