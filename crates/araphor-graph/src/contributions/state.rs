use std::{cmp::Ordering, io::Cursor};

use araphor_analysis_builtins::{
    discovery::{DiscoveryRecordIdV1, EvidenceIntakeIdentityV1},
    graph::{AnalysisContextKeyV1, FactAnchor, GraphPackageStateV1, Position, UnitState},
};
use duckdb::{params, Connection, Row};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::{
    error::{ContractSnafu, DatabaseSnafu, DecodingSnafu, EncodingSnafu, InvalidSnafu},
    Result,
};

pub struct StateValue {
    pub unit: u64,
    pub state: UnitState,
    pub anchor: Option<FactAnchor>,
}

pub struct StateRows;

pub(super) struct StateHead {
    value: u64,
    unit: u64,
    record: DiscoveryRecordIdV1,
    state: UnitState,
    fact_hash: Option<Vec<u8>>,
}

impl StateHead {
    fn compare(&self, other: &Self) -> Result<Ordering> {
        match (&self.state.fact, &other.state.fact) {
            (Some(left), Some(right)) => Ok(left.cmp(right).then(self.record.cmp(&other.record))),
            (None, None) => Ok(self.record.cmp(&other.record)),
            _ => InvalidSnafu {
                field: "unit state order mode",
            }
            .fail(),
        }
    }
}

impl StateRows {
    pub const SCHEMA: &'static str = include_str!("state.sql");

    pub fn intern(writer: &Connection, values: &[StateValue]) -> Result<Vec<u64>> {
        if values.is_empty() {
            return Ok(Vec::new());
        }
        writer.execute_batch("CREATE TEMP TABLE graph_state_stage AS SELECT * EXCLUDE(value_ref) FROM graph_unit_state_values WHERE false")
            .context(DatabaseSnafu { operation: "create unit state candidates" })?;
        let result = (|| {
            let mut hashes = Vec::with_capacity(values.len());
            {
                let mut appender = writer
                    .appender("graph_state_stage")
                    .context(DatabaseSnafu {
                        operation: "open unit state candidates",
                    })?;
                for value in values {
                    let (tag, declared) = value.state.state.native_fields();
                    GraphPackageStateV1::from_native(tag.clone(), declared.clone())
                        .context(ContractSnafu)?;
                    if value.unit == 0
                        || value.state.position.commit_revision == 0
                        || value
                            .state
                            .fact
                            .as_ref()
                            .is_some_and(|key| !key.valid() || key.owner_revision == 0)
                        || value.state.fact.as_ref()
                            != value.anchor.as_ref().map(|anchor| &anchor.key)
                    {
                        return InvalidSnafu {
                            field: "unit state value",
                        }
                        .fail();
                    }
                    let fact_hash = value
                        .anchor
                        .as_ref()
                        .map(Self::encode)
                        .transpose()?
                        .map(|body| Self::hash(&body));
                    let hash = Self::value_hash(value.unit, &value.state, fact_hash.as_deref())?;
                    let fact = value.state.fact.as_ref();
                    appender
                        .append_row(params![
                            value.unit,
                            &tag,
                            declared.as_deref(),
                            value.state.position.commit_revision,
                            value.state.position.ordinal,
                            fact.map(|key| key.tenant_id.to_vec()),
                            fact.map(|key| key.owner_id.as_str()),
                            fact.map(|key| key.entity_key.as_slice()),
                            fact.map(|key| key.lifetime_key.as_slice()),
                            fact.map(|key| key.owner_revision),
                            fact_hash,
                            &hash
                        ])
                        .context(DatabaseSnafu {
                            operation: "append unit state candidates",
                        })?;
                    hashes.push(hash);
                }
                appender.flush().context(DatabaseSnafu {
                    operation: "flush unit state candidates",
                })?;
            }
            let equal = "saved.unit_ref=stage.unit_ref AND saved.state_tag=stage.state_tag AND saved.state_declared IS NOT DISTINCT FROM stage.state_declared AND saved.position_revision=stage.position_revision AND saved.position_ordinal=stage.position_ordinal AND saved.fact_tenant IS NOT DISTINCT FROM stage.fact_tenant AND saved.fact_owner IS NOT DISTINCT FROM stage.fact_owner AND saved.fact_entity IS NOT DISTINCT FROM stage.fact_entity AND saved.fact_lifetime IS NOT DISTINCT FROM stage.fact_lifetime AND saved.fact_revision IS NOT DISTINCT FROM stage.fact_revision AND saved.fact_hash IS NOT DISTINCT FROM stage.fact_hash";
            let collision: bool = writer.query_row(&format!("SELECT EXISTS(SELECT 1 FROM graph_state_stage stage JOIN graph_unit_state_values saved USING(value_hash) WHERE NOT ({equal}))"), [], |row| row.get(0))
                .context(DatabaseSnafu { operation: "check unit state hash" })?;
            if collision {
                return InvalidSnafu {
                    field: "unit state hash collision",
                }
                .fail();
            }
            writer.execute_batch(&format!("INSERT INTO graph_unit_state_values SELECT nextval('graph_unit_state_values_seq'),stage.* FROM (SELECT DISTINCT * FROM graph_state_stage) stage WHERE NOT EXISTS(SELECT 1 FROM graph_unit_state_values saved WHERE saved.value_hash=stage.value_hash AND {equal})"))
                .context(DatabaseSnafu { operation: "intern unit state candidates" })?;
            let mut statement = writer.prepare("SELECT value_ref,value_hash FROM graph_unit_state_values WHERE value_hash IN (SELECT value_hash FROM graph_state_stage)")
                .context(DatabaseSnafu { operation: "prepare unit state references" })?;
            let mut indexed = std::collections::BTreeMap::new();
            let mut rows = statement.query([]).context(DatabaseSnafu {
                operation: "read unit state references",
            })?;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance unit state references",
            })? {
                if indexed
                    .insert(
                        Self::column::<Vec<u8>>(row, 1)?,
                        Self::column::<u64>(row, 0)?,
                    )
                    .is_some()
                {
                    return InvalidSnafu {
                        field: "duplicate unit state value",
                    }
                    .fail();
                }
            }
            hashes
                .iter()
                .map(|hash| {
                    indexed.get(hash).copied().ok_or_else(|| {
                        InvalidSnafu {
                            field: "unit state reference",
                        }
                        .build()
                    })
                })
                .collect()
        })();
        let cleanup = writer
            .execute_batch("DROP TABLE graph_state_stage")
            .context(DatabaseSnafu {
                operation: "release unit state candidates",
            });
        let result = result?;
        cleanup?;
        Ok(result)
    }

    pub(super) fn prior(
        writer: &Connection,
        scope: u64,
        revision: u64,
    ) -> Result<Option<StateHead>> {
        let (head, prior, count): (Option<u64>, Option<u64>, u64) = writer.query_row(
            "SELECT previous.selected_state_ref,previous.commit_revision,coalesce(previous.state_count,0) FROM graph_producer_versions current LEFT JOIN graph_producer_versions previous ON previous.result_id=current.base_result_id WHERE current.scope_id=? AND current.commit_revision=?",
            params![scope,revision], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))
            .context(DatabaseSnafu { operation: "read unit state frontier" })?;
        let Some(prior) = prior else {
            return Ok(None);
        };
        if let Some(value) = head {
            return Self::selected(writer, scope, prior, value).map(Some);
        }
        if count > 0 {
            return InvalidSnafu {
                field: "unit state frontier is absent",
            }
            .fail();
        }
        Ok(None)
    }

    pub(super) fn staged(writer: &Connection, scope: u64, reset: bool) -> Result<Vec<StateHead>> {
        let source: u64 = writer
            .query_row(
                "SELECT source_ref FROM graph_producer_scopes WHERE scope_id=?",
                params![scope],
                |row| row.get(0),
            )
            .context(DatabaseSnafu {
                operation: "read unit state scope",
            })?;
        let query = format!("SELECT {},stage.member_key,stage.anchor_record_id,stage.anchor_fact,stage.unit_ref,stage.reason_code,stage.ordinal FROM graph_contribution_stage stage LEFT JOIN graph_unit_state_values state ON state.value_ref=stage.value_ref LEFT JOIN graph_evidence evidence ON evidence.evidence_id=state.unit_ref LEFT JOIN graph_sources source USING(source_ref) WHERE stage.member_kind=8", Self::columns());
        let mut statement = writer.prepare(&query).context(DatabaseSnafu {
            operation: "prepare staged unit states",
        })?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read staged unit states",
        })?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance staged unit states",
        })? {
            let value = Self::decode(row)?;
            Self::check_member(row, &value, source)?;
            values.push(value);
        }
        if let Some(first) = values.first() {
            for value in &values {
                first.compare(value)?;
            }
        }
        drop(rows);
        drop(statement);
        let query = format!("SELECT {},member.member_key,member.anchor_record_id,member.anchor_fact,member.unit_ref,member.reason_code,member.ordinal FROM graph_producer_members member LEFT JOIN graph_unit_state_values state ON state.value_ref=member.value_ref LEFT JOIN graph_evidence evidence ON evidence.evidence_id=state.unit_ref LEFT JOIN graph_sources source USING(source_ref) WHERE member.scope_id=? AND member.member_kind=8 AND member.valid_to IS NULL AND (? OR member.unit_ref IN (SELECT unit_ref FROM graph_contribution_stage))", Self::columns());
        let mut statement = writer.prepare(&query).context(DatabaseSnafu {
            operation: "prepare prior unit state members",
        })?;
        let mut rows = statement
            .query(params![scope, reset])
            .context(DatabaseSnafu {
                operation: "read prior unit state members",
            })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance prior unit state members",
        })? {
            let head = Self::decode(row)?;
            Self::check_member(row, &head, source)?;
        }
        Ok(values)
    }

    pub(super) fn advance(
        writer: &Connection,
        scope: u64,
        revision: u64,
        prior: Option<StateHead>,
        candidates: Vec<StateHead>,
        reset: bool,
    ) -> Result<()> {
        let mut selected = if reset {
            None
        } else if let Some(prior) = prior {
            let active: bool = writer.query_row("SELECT EXISTS(SELECT 1 FROM graph_producer_members WHERE scope_id=? AND unit_ref=? AND member_kind=8 AND value_ref=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?))",params![scope,prior.unit,prior.value,revision,revision],|row|row.get(0))
                .context(DatabaseSnafu { operation: "check surviving unit state" })?;
            if active {
                Some(prior)
            } else {
                Self::fallback(writer, scope, revision)?
            }
        } else {
            None
        };
        for candidate in candidates {
            if selected
                .as_ref()
                .map(|old| candidate.compare(old))
                .transpose()?
                .is_none_or(|order| order.is_gt())
            {
                selected = Some(candidate);
            }
        }
        writer.execute("UPDATE graph_producer_versions SET selected_state_ref=? WHERE scope_id=? AND commit_revision=?",params![selected.map(|head|head.value),scope,revision])
            .context(DatabaseSnafu { operation: "record selected unit state" })?;
        Ok(())
    }

    pub fn current(
        writer: &Connection,
        scope: u64,
        revision: u64,
        default: GraphPackageStateV1,
    ) -> Result<GraphPackageStateV1> {
        let value:Option<u64>=writer.query_row("SELECT selected_state_ref FROM graph_producer_versions WHERE scope_id=? AND commit_revision=?",params![scope,revision],|row|row.get(0))
            .context(DatabaseSnafu { operation: "read selected unit state" })?;
        match value {
            Some(value) => Ok(Self::selected(writer, scope, revision, value)?.state.state),
            None => Ok(default),
        }
    }

    fn fallback(writer: &Connection, scope: u64, revision: u64) -> Result<Option<StateHead>> {
        let (value,modes):(Option<u64>,u64)=writer.query_row(
            "WITH selected AS (SELECT state.*,evidence.cpu_id,evidence.durable_cursor FROM graph_producer_members member JOIN graph_unit_state_values state ON state.value_ref=member.value_ref JOIN graph_evidence evidence ON evidence.evidence_id=state.unit_ref WHERE member.scope_id=? AND member.member_kind=8 AND member.valid_from<=? AND (member.valid_to IS NULL OR member.valid_to>?)) SELECT (SELECT value_ref FROM selected ORDER BY fact_tenant DESC NULLS LAST,fact_owner DESC NULLS LAST,fact_entity DESC NULLS LAST,fact_lifetime DESC NULLS LAST,fact_revision DESC NULLS LAST,cpu_id DESC,durable_cursor DESC LIMIT 1),(SELECT count(DISTINCT fact_tenant IS NOT NULL) FROM selected)",params![scope,revision,revision],|row|Ok((row.get(0)?,row.get(1)?)))
            .context(DatabaseSnafu { operation: "select surviving unit state" })?;
        if modes > 1 {
            return InvalidSnafu {
                field: "unit state order mode",
            }
            .fail();
        }
        value
            .map(|value| Self::selected(writer, scope, revision, value))
            .transpose()
    }

    fn selected(writer: &Connection, scope: u64, revision: u64, value: u64) -> Result<StateHead> {
        let query=format!("SELECT {},member.member_key,member.anchor_record_id,member.anchor_fact,member.unit_ref,member.reason_code,member.ordinal FROM graph_producer_members member JOIN graph_unit_state_values state ON state.value_ref=member.value_ref JOIN graph_evidence evidence ON evidence.evidence_id=state.unit_ref JOIN graph_sources source USING(source_ref) WHERE member.scope_id=? AND member.member_kind=8 AND member.value_ref=? AND member.valid_from<=? AND (member.valid_to IS NULL OR member.valid_to>?)",Self::columns());
        let source: u64 = writer
            .query_row(
                "SELECT source_ref FROM graph_producer_scopes WHERE scope_id=?",
                params![scope],
                |row| row.get(0),
            )
            .context(DatabaseSnafu {
                operation: "read selected state scope",
            })?;
        let mut statement = writer.prepare(&query).context(DatabaseSnafu {
            operation: "prepare selected unit state",
        })?;
        let mut rows = statement
            .query(params![scope, value, revision, revision])
            .context(DatabaseSnafu {
                operation: "read selected unit state",
            })?;
        let row = rows
            .next()
            .context(DatabaseSnafu {
                operation: "advance selected unit state",
            })?
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "selected unit state membership",
                }
                .build()
            })?;
        let head = Self::decode(row)?;
        Self::check_member(row, &head, source)?;
        if rows
            .next()
            .context(DatabaseSnafu {
                operation: "check selected unit state count",
            })?
            .is_some()
        {
            return InvalidSnafu {
                field: "duplicate selected unit state",
            }
            .fail();
        }
        Ok(head)
    }

    pub fn validate(writer: &Connection) -> Result<()> {
        let duplicate: bool = writer.query_row("SELECT EXISTS(SELECT 1 FROM graph_unit_state_values GROUP BY value_hash HAVING count(*)>1)",[],|row|row.get(0)).context(DatabaseSnafu {operation:"check duplicate unit states"})?;
        if duplicate {
            return InvalidSnafu {
                field: "duplicate unit state value",
            }
            .fail();
        }
        let query=format!("SELECT {} FROM graph_unit_state_values state LEFT JOIN graph_evidence evidence ON evidence.evidence_id=state.unit_ref LEFT JOIN graph_sources source USING(source_ref)",Self::columns());
        let mut statement = writer.prepare(&query).context(DatabaseSnafu {
            operation: "prepare unit state validation",
        })?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read unit state validation",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance unit state validation",
        })? {
            Self::decode(row)?;
        }
        drop(rows);
        drop(statement);
        let query=format!("SELECT {},member.member_key,member.anchor_record_id,member.anchor_fact,member.unit_ref,member.reason_code,member.ordinal,owner.source_ref FROM graph_producer_members member JOIN graph_producer_scopes owner USING(scope_id) LEFT JOIN graph_unit_state_values state ON state.value_ref=member.value_ref LEFT JOIN graph_evidence evidence ON evidence.evidence_id=state.unit_ref LEFT JOIN graph_sources source ON source.source_ref=evidence.source_ref WHERE member.member_kind=8",Self::columns());
        let mut statement = writer.prepare(&query).context(DatabaseSnafu {
            operation: "prepare unit state member validation",
        })?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read unit state member validation",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance unit state member validation",
        })? {
            let head = Self::decode(row)?;
            Self::check_member(row, &head, Self::column(row, 23)?)?;
        }
        drop(rows);
        drop(statement);
        let mut statement = writer
            .prepare(
                "SELECT scope_id,commit_revision,selected_state_ref FROM graph_producer_versions",
            )
            .context(DatabaseSnafu {
                operation: "prepare unit state index validation",
            })?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read unit state index validation",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance unit state index validation",
        })? {
            let scope = Self::column(row, 0)?;
            let revision = Self::column(row, 1)?;
            let selected: Option<u64> = Self::column(row, 2)?;
            if Self::fallback(writer, scope, revision)?.map(|head| head.value) != selected {
                return InvalidSnafu {
                    field: "unit state index mismatch",
                }
                .fail();
            }
        }
        Ok(())
    }

    fn columns() -> &'static str {
        "state.value_ref,state.unit_ref,state.state_tag,state.state_declared,state.position_revision,state.position_ordinal,state.fact_tenant,state.fact_owner,state.fact_entity,state.fact_lifetime,state.fact_revision,state.fact_hash,state.value_hash,source.identity,evidence.cpu_id,evidence.durable_cursor,evidence.source_ref"
    }

    fn decode(row: &Row<'_>) -> Result<StateHead> {
        let source: EvidenceIntakeIdentityV1 =
            Self::decode_body(&Self::column::<Vec<u8>>(row, 13)?)?;
        let tenant: Option<Vec<u8>> = Self::column(row, 6)?;
        let fact = tenant
            .map(|tenant| -> Result<AnalysisContextKeyV1> {
                Ok(AnalysisContextKeyV1 {
                    tenant_id: tenant.try_into().map_err(|_| {
                        InvalidSnafu {
                            field: "unit state fact tenant",
                        }
                        .build()
                    })?,
                    owner_id: Self::column(row, 7)?,
                    entity_key: Self::column(row, 8)?,
                    lifetime_key: Self::column(row, 9)?,
                    owner_revision: Self::column(row, 10)?,
                })
            })
            .transpose()?;
        let head = StateHead {
            value: Self::column(row, 0)?,
            unit: Self::column(row, 1)?,
            record: DiscoveryRecordIdV1 {
                stream: source,
                cpu_id: Self::column(row, 14)?,
                durable_cursor: Self::column(row, 15)?,
            },
            state: UnitState {
                state: GraphPackageStateV1::from_native(
                    Self::column(row, 2)?,
                    Self::column(row, 3)?,
                )
                .context(ContractSnafu)?,
                position: Position {
                    commit_revision: Self::column(row, 4)?,
                    ordinal: Self::column(row, 5)?,
                },
                fact,
            },
            fact_hash: Self::column(row, 11)?,
        };
        if head.unit == 0
            || head.state.position.commit_revision == 0
            || head.state.fact.as_ref().is_some_and(|key| {
                !key.valid()
                    || key.owner_revision == 0
                    || key.tenant_id != head.record.stream.tenant_id
            })
            || head.state.fact.is_some() != head.fact_hash.is_some()
            || Self::value_hash(head.unit, &head.state, head.fact_hash.as_deref())?
                != Self::column::<Vec<u8>>(row, 12)?
        {
            return InvalidSnafu {
                field: "unit state native value",
            }
            .fail();
        }
        Ok(head)
    }

    fn check_member(row: &Row<'_>, head: &StateHead, source: u64) -> Result<()> {
        let fact: Option<Vec<u8>> = Self::column(row, 19)?;
        let anchor: Option<FactAnchor> = fact.as_deref().map(Self::decode_body).transpose()?;
        if Self::column::<u64>(row, 16)? != source
            || Self::column::<Vec<u8>>(row, 17)? != Self::hash(&Self::encode(&head.record)?)
            || Self::column::<Option<u64>>(row, 18)? != Some(head.unit)
            || Self::column::<u64>(row, 20)? != head.unit
            || Self::column::<Option<String>>(row, 21)?.is_some()
            || Self::column::<u32>(row, 22)? != 0
            || fact.as_deref().map(Self::hash) != head.fact_hash
            || anchor.as_ref().map(|anchor| &anchor.key) != head.state.fact.as_ref()
            || anchor
                .as_ref()
                .is_some_and(|anchor| anchor.record.stream != head.record.stream)
            || anchor.as_ref().map(Self::encode).transpose()? != fact
        {
            return InvalidSnafu {
                field: "unit state membership value",
            }
            .fail();
        }
        Ok(())
    }

    fn value_hash(unit: u64, state: &UnitState, fact_hash: Option<&[u8]>) -> Result<Vec<u8>> {
        Ok(Self::hash(&Self::encode(&(
            unit,
            state.state.native_fields(),
            state.position,
            &state.fact,
            fact_hash,
        ))?))
    }
    fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        value
            .serialize(&mut rmp_serde::Serializer::new(&mut bytes).with_struct_map())
            .context(EncodingSnafu)?;
        Ok(bytes)
    }
    fn hash(bytes: &[u8]) -> Vec<u8> {
        Sha256::digest(bytes).to_vec()
    }
    fn decode_body<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        let mut decoder = rmp_serde::Deserializer::new(Cursor::new(bytes));
        let value = T::deserialize(&mut decoder).context(DecodingSnafu)?;
        if decoder.position() != bytes.len() as u64 {
            return InvalidSnafu {
                field: "unit state trailing bytes",
            }
            .fail();
        }
        Ok(value)
    }
    fn column<T: duckdb::types::FromSql>(row: &Row<'_>, index: usize) -> Result<T> {
        row.get(index).context(DatabaseSnafu {
            operation: "decode unit state row",
        })
    }
}

#[cfg(test)]
mod tests;
