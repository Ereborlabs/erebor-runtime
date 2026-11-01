CREATE TABLE analysis_results (
    result_id VARCHAR PRIMARY KEY,
    tenant_id BLOB NOT NULL,
    processor_id VARCHAR NOT NULL,
    body BLOB NOT NULL,
    request_meta BLOB NOT NULL,
    commit_revision UBIGINT NOT NULL,
    stream_key BLOB,
    method_version UBIGINT,
    interval_id VARCHAR,
    profile_revision UBIGINT,
    facts_revision UBIGINT,
    coverage_revision UBIGINT,
    first_cursor UBIGINT
);
CREATE TABLE result_notices (
    tenant_id BLOB NOT NULL,
    result_id VARCHAR NOT NULL,
    commit_revision UBIGINT NOT NULL,
    facts_revision UBIGINT NOT NULL,
    coverage_revision UBIGINT NOT NULL,
    PRIMARY KEY (tenant_id, result_id, commit_revision)
);
