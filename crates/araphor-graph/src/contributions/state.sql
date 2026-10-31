CREATE SEQUENCE graph_unit_state_values_seq;
CREATE TABLE graph_unit_state_values (
    value_ref UBIGINT PRIMARY KEY, unit_ref UBIGINT NOT NULL, state_tag VARCHAR NOT NULL, state_declared VARCHAR,
    position_revision UBIGINT NOT NULL, position_ordinal UINTEGER NOT NULL,
    fact_tenant BLOB, fact_owner VARCHAR, fact_entity BLOB, fact_lifetime BLOB,
    fact_revision UBIGINT, fact_hash BLOB,
    value_hash BLOB NOT NULL CHECK (octet_length(value_hash)=32),
    CHECK (unit_ref>0 AND position_revision>0 AND state_tag<>''),
    CHECK ((fact_tenant IS NULL AND fact_owner IS NULL AND fact_entity IS NULL
        AND fact_lifetime IS NULL AND fact_revision IS NULL AND fact_hash IS NULL)
        OR (fact_tenant IS NOT NULL AND octet_length(fact_tenant)=16
            AND fact_owner IS NOT NULL AND fact_owner<>''
            AND fact_entity IS NOT NULL AND octet_length(fact_entity)>0
            AND fact_lifetime IS NOT NULL AND octet_length(fact_lifetime)>0
            AND fact_revision IS NOT NULL AND fact_hash IS NOT NULL
            AND octet_length(fact_hash)=32))
);
CREATE INDEX graph_unit_state_hash ON graph_unit_state_values(value_hash);
