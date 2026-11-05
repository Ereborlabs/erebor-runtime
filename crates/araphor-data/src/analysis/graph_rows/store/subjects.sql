CREATE SEQUENCE graph_subject_values_seq;
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
