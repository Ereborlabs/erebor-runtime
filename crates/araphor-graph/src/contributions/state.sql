CREATE SEQUENCE graph_unit_state_values_seq;
CREATE TABLE graph_unit_state_values (
    value_ref UBIGINT PRIMARY KEY, unit_ref UBIGINT, state_tag VARCHAR NOT NULL, state_declared VARCHAR,
    position_revision UBIGINT, position_ordinal UINTEGER,
    fact_tenant BLOB, fact_owner VARCHAR, fact_entity BLOB, fact_lifetime BLOB,
    fact_revision UBIGINT, fact_ref UBIGINT, fact_sensitivity VARCHAR,
    value_key BLOB NOT NULL CHECK (octet_length(value_key)>0),
    CHECK (state_tag<>''),
    CHECK ((unit_ref IS NULL AND position_revision IS NULL AND position_ordinal IS NULL
            AND fact_tenant IS NULL AND fact_owner IS NULL AND fact_entity IS NULL
            AND fact_lifetime IS NULL AND fact_revision IS NULL AND fact_ref IS NULL AND fact_sensitivity IS NULL)
        OR (unit_ref IS NOT NULL AND unit_ref>0 AND position_revision IS NOT NULL
            AND position_revision>0 AND position_ordinal IS NOT NULL)),
    CHECK ((fact_tenant IS NULL AND fact_owner IS NULL AND fact_entity IS NULL
        AND fact_lifetime IS NULL AND fact_revision IS NULL AND fact_ref IS NULL AND fact_sensitivity IS NULL)
        OR (fact_tenant IS NOT NULL AND octet_length(fact_tenant)=16
            AND fact_owner IS NOT NULL AND fact_owner<>''
            AND fact_entity IS NOT NULL AND octet_length(fact_entity)>0
            AND fact_lifetime IS NOT NULL AND octet_length(fact_lifetime)>0
            AND fact_revision IS NOT NULL AND fact_ref IS NOT NULL AND fact_ref>0
            AND fact_sensitivity IS NOT NULL AND fact_sensitivity IN ('public','tenant','host_restricted')))
);
CREATE INDEX graph_unit_state_key ON graph_unit_state_values(value_key);
