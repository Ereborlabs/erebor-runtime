CREATE TABLE processor_versions (
    processor_id VARCHAR NOT NULL,
    method_version UBIGINT NOT NULL,
    tenant_id BLOB NOT NULL,
    stream_key BLOB NOT NULL,
    class VARCHAR NOT NULL,
    consumed_cursor UBIGINT NOT NULL,
    resume_floor UBIGINT NOT NULL,
    coverage_revision UBIGINT NOT NULL,
    context_revision UBIGINT NOT NULL,
    start_cursor UBIGINT NOT NULL,
    required_floor UBIGINT NOT NULL,
    retired BOOLEAN NOT NULL,
    retirement_id VARCHAR NOT NULL,
    retirement_reason VARCHAR NOT NULL,
    retirement_cursor UBIGINT NOT NULL,
    retirement_revision UBIGINT NOT NULL,
    result_id VARCHAR NOT NULL,
    commit_revision UBIGINT NOT NULL,
    PRIMARY KEY (processor_id, method_version, tenant_id, stream_key, commit_revision)
);
CREATE VIEW processor_progress AS
    SELECT processor_id, method_version, tenant_id, stream_key, class,
        consumed_cursor, resume_floor, coverage_revision, context_revision,
        start_cursor, required_floor, retired, retirement_id, retirement_reason,
        retirement_cursor, retirement_revision, result_id
    FROM processor_versions
    QUALIFY ROW_NUMBER() OVER (PARTITION BY processor_id, method_version,
        tenant_id, stream_key ORDER BY commit_revision DESC) = 1;
