CREATE TABLE source_versions (
    stream_key BLOB NOT NULL,
    identity_json VARCHAR NOT NULL,
    tenant_id BLOB NOT NULL,
    cpu_id UINTEGER NOT NULL,
    contiguous_cursor UBIGINT NOT NULL,
    coverage_revision UBIGINT NOT NULL,
    retained_floor UBIGINT NOT NULL,
    commit_revision UBIGINT NOT NULL,
    PRIMARY KEY (stream_key, commit_revision)
);
CREATE VIEW source_receipts AS
    SELECT stream_key, identity_json, tenant_id, cpu_id, contiguous_cursor,
        coverage_revision, retained_floor, commit_revision FROM source_versions
    QUALIFY ROW_NUMBER() OVER (
        PARTITION BY stream_key ORDER BY commit_revision DESC) = 1;
