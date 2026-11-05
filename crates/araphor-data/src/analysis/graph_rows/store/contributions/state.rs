use std::{cmp::Ordering, io::Cursor};

use crate::analysis::graph_rows::store::{
    source::{DiscoveryRecordIdV1, EvidenceIntakeIdentityV1},
    values::{
        AnalysisContextKeyV1, ContextSensitivityV1, FactAnchor, GraphFactV1, GraphPackageStateV1,
        GraphStateChange, Position,
    },
};
use duckdb::{params, Connection, Row};
use serde::{de::DeserializeOwned, Serialize};
use snafu::ResultExt as _;

use crate::analysis::graph_rows::store::{
    error::{ContractSnafu, DatabaseSnafu, DecodingSnafu, EncodingSnafu, InvalidSnafu},
    native::NativeRows,
    Result,
};

pub struct StateValue<'a> {
    pub unit: u64,
    pub state: GraphStateChange,
    pub anchor: Option<(&'a FactAnchor, u64)>,
}

pub struct StateRows;

pub(super) struct StateHead {
    value: u64,
    unit: u64,
    record: DiscoveryRecordIdV1,
    state: GraphStateChange,
    fact_ref: Option<u64>,
    sensitivity: Option<ContextSensitivityV1>,
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

    pub fn intern(writer: &Connection, values: &[StateValue<'_>]) -> Result<Vec<u64>> {
        if values.is_empty() {
            return Ok(Vec::new());
        }
        let mut keys = std::collections::BTreeMap::<Vec<u8>, Vec<usize>>::new();
        for (ordinal, value) in values.iter().enumerate() {
            let (tag, declared) = value.state.state.native_fields();
            GraphPackageStateV1::from_native(tag, declared).context(ContractSnafu)?;
            let anchor = value.anchor.map(|(anchor, _)| anchor);
            let fact_ref = value.anchor.map(|(_, reference)| reference);
            if value.unit == 0
                || value.state.position.commit_revision == 0
                || fact_ref.is_some_and(|reference| reference == 0)
                || value
                    .state
                    .fact
                    .as_ref()
                    .is_some_and(|key| !key.valid() || key.owner_revision == 0)
                || value.state.fact.as_ref() != anchor.map(|anchor| &anchor.key)
            {
                return InvalidSnafu {
                    field: "unit state value",
                }
                .fail();
            }
            let key = Self::value_key(
                value.unit,
                &value.state,
                fact_ref,
                anchor.map(|anchor| anchor.sensitivity),
            )?;
            keys.entry(key).or_default().push(ordinal);
        }
        let mut select=writer.prepare(
            "WITH candidates AS MATERIALIZED (SELECT * FROM graph_unit_state_values WHERE value_key=?)
             SELECT value_ref,unit_ref IS NOT DISTINCT FROM ? AND state_tag=?
                AND state_declared IS NOT DISTINCT FROM ? AND position_revision IS NOT DISTINCT FROM ?
                AND position_ordinal IS NOT DISTINCT FROM ? AND fact_tenant IS NOT DISTINCT FROM ?
                AND fact_owner IS NOT DISTINCT FROM ? AND fact_entity IS NOT DISTINCT FROM ?
                AND fact_lifetime IS NOT DISTINCT FROM ? AND fact_revision IS NOT DISTINCT FROM ?
                AND fact_ref IS NOT DISTINCT FROM ? AND fact_sensitivity IS NOT DISTINCT FROM ?
             FROM candidates"
        ).context(DatabaseSnafu {operation:"prepare unit state candidates"})?;
        let mut ids = vec![0; values.len()];
        let mut missing = Vec::new();
        for (key, ordinals) in &keys {
            let value = &values[ordinals[0]];
            let (tag, declared) = value.state.state.native_fields();
            let fact = value.state.fact.as_ref();
            let fact_ref = value.anchor.map(|(_, reference)| reference);
            let sensitivity = value.anchor.map(|(anchor, _)| anchor.sensitivity);
            let mut rows = select
                .query(params![
                    key,
                    value.unit,
                    &tag,
                    declared.as_deref(),
                    value.state.position.commit_revision,
                    value.state.position.ordinal,
                    fact.map(|key| key.tenant_id.as_slice()),
                    fact.map(|key| key.owner_id.as_str()),
                    fact.map(|key| key.entity_key.as_slice()),
                    fact.map(|key| key.lifetime_key.as_slice()),
                    fact.map(|key| key.owner_revision),
                    fact_ref,
                    sensitivity.map(<&'static str>::from)
                ])
                .context(DatabaseSnafu {
                    operation: "read unit state candidates",
                })?;
            let mut saved = None;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance unit state candidates",
            })? {
                let id = Self::column::<u64>(row, 0)?;
                if saved.replace(id).is_some() || id == 0 || !Self::column::<bool>(row, 1)? {
                    return InvalidSnafu {
                        field: "unit state native value",
                    }
                    .fail();
                }
            }
            if let Some(id) = saved {
                for ordinal in ordinals {
                    ids[*ordinal] = id;
                }
            } else {
                missing.push((key.as_slice(), ordinals.as_slice()));
            }
        }
        drop(select);
        let allocated = NativeRows::allocate(writer, "graph_unit_state_values_seq", missing.len())?;
        if !missing.is_empty() {
            let mut appender =
                writer
                    .appender("graph_unit_state_values")
                    .context(DatabaseSnafu {
                        operation: "open unit state values",
                    })?;
            for ((key, ordinals), id) in missing.into_iter().zip(allocated) {
                let value = &values[ordinals[0]];
                let (tag, declared) = value.state.state.native_fields();
                let fact = value.state.fact.as_ref();
                appender
                    .append_row(params![
                        id,
                        value.unit,
                        &tag,
                        declared.as_deref(),
                        value.state.position.commit_revision,
                        value.state.position.ordinal,
                        fact.map(|key| key.tenant_id.as_slice()),
                        fact.map(|key| key.owner_id.as_str()),
                        fact.map(|key| key.entity_key.as_slice()),
                        fact.map(|key| key.lifetime_key.as_slice()),
                        fact.map(|key| key.owner_revision),
                        value.anchor.map(|(_, reference)| reference),
                        value
                            .anchor
                            .map(|(anchor, _)| <&'static str>::from(anchor.sensitivity)),
                        key
                    ])
                    .context(DatabaseSnafu {
                        operation: "append unit state values",
                    })?;
                for ordinal in ordinals {
                    ids[*ordinal] = id;
                }
            }
            appender.flush().context(DatabaseSnafu {
                operation: "flush unit state values",
            })?;
        }
        Ok(ids)
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
            if count == 0 {
                Self::default(writer, value)?;
                return Ok(None);
            }
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
        let query = format!("SELECT {},stage.member_key,stage.anchor_record_id,stage.anchor_fact,stage.unit_ref,stage.reason_code,stage.ordinal FROM graph_contribution_stage stage LEFT JOIN graph_unit_state_values state ON state.value_ref=stage.value_ref LEFT JOIN graph_evidence evidence ON evidence.evidence_id=state.unit_ref LEFT JOIN graph_sources source USING(source_ref) WHERE stage.scope_id=? AND stage.member_kind=8", Self::columns());
        let mut statement = writer.prepare(&query).context(DatabaseSnafu {
            operation: "prepare staged unit states",
        })?;
        let mut rows = statement.query(params![scope]).context(DatabaseSnafu {
            operation: "read staged unit states",
        })?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance staged unit states",
        })? {
            let value = Self::decode(row)?;
            Self::check_member(writer, row, &value, source)?;
            values.push(value);
        }
        if let Some(first) = values.first() {
            for value in &values {
                first.compare(value)?;
            }
        }
        drop(rows);
        drop(statement);
        let query = format!("SELECT {},member.member_key,member.anchor_record_id,member.anchor_fact,member.unit_ref,member.reason_code,member.ordinal FROM graph_producer_members member LEFT JOIN graph_unit_state_values state ON state.value_ref=member.value_ref LEFT JOIN graph_evidence evidence ON evidence.evidence_id=state.unit_ref LEFT JOIN graph_sources source USING(source_ref) WHERE member.scope_id=? AND member.member_kind=8 AND member.valid_to IS NULL AND (? OR member.unit_ref IN (SELECT unit_ref FROM graph_contribution_stage WHERE scope_id=?))", Self::columns());
        let mut statement = writer.prepare(&query).context(DatabaseSnafu {
            operation: "prepare prior unit state members",
        })?;
        let mut rows = statement
            .query(params![scope, reset, scope])
            .context(DatabaseSnafu {
                operation: "read prior unit state members",
            })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance prior unit state members",
        })? {
            let head = Self::decode(row)?;
            Self::check_member(writer, row, &head, source)?;
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

    pub fn finish(
        writer: &Connection,
        scope: u64,
        revision: u64,
        default: &GraphPackageStateV1,
    ) -> Result<GraphPackageStateV1> {
        let count: u64 = writer.query_row("SELECT state_count FROM graph_producer_versions version JOIN graph_producer_scopes scope USING(scope_id) WHERE version.scope_id=? AND version.commit_revision=? AND scope.producer_kind=0",params![scope,revision],|row|row.get(0))
            .context(DatabaseSnafu { operation: "read final unit state count" })?;
        if count == 0 {
            let (tag, declared) = default.native_fields();
            GraphPackageStateV1::from_native(tag.clone(), declared.clone())
                .context(ContractSnafu)?;
            let key = Self::default_key(default)?;
            let mut statement=writer.prepare("WITH candidates AS MATERIALIZED (SELECT * FROM graph_unit_state_values WHERE value_key=?) SELECT value_ref FROM candidates")
                .context(DatabaseSnafu { operation: "prepare default state value" })?;
            let mut rows = statement.query(params![&key]).context(DatabaseSnafu {
                operation: "find default state value",
            })?;
            let mut count = 0;
            let mut value = None;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance default state value",
            })? {
                count += 1;
                value = Some(Self::column(row, 0)?);
            }
            drop(rows);
            drop(statement);
            let value = match (count, value) {
                (0, None) => {
                    writer.query_row("INSERT INTO graph_unit_state_values(value_ref,state_tag,state_declared,value_key) VALUES(nextval('graph_unit_state_values_seq'),?,?,?) RETURNING value_ref",params![tag,declared,key],|row|row.get(0))
                        .context(DatabaseSnafu { operation: "intern default state value" })?
                }
                (1, Some(value)) if Self::default(writer, value)? == *default => value,
                _ => return InvalidSnafu { field: "duplicate default state value" }.fail(),
            };
            writer.execute("UPDATE graph_producer_versions SET selected_state_ref=? WHERE scope_id=? AND commit_revision=?",params![value,scope,revision])
                .context(DatabaseSnafu { operation: "record default unit state" })?;
        }
        Self::current(writer, scope, revision)
    }

    pub fn current(reader: &Connection, scope: u64, revision: u64) -> Result<GraphPackageStateV1> {
        let (value, count):(Option<u64>,u64)=reader.query_row("SELECT selected_state_ref,state_count FROM graph_producer_versions version JOIN graph_producer_scopes scope USING(scope_id) WHERE version.scope_id=? AND version.commit_revision=? AND scope.producer_kind=0",params![scope,revision],|row|Ok((row.get(0)?,row.get(1)?)))
            .context(DatabaseSnafu { operation: "read selected unit state" })?;
        let value = value.ok_or_else(|| {
            InvalidSnafu {
                field: "selected unit state is absent",
            }
            .build()
        })?;
        if count == 0 {
            Self::default(reader, value)
        } else {
            Ok(Self::selected(reader, scope, revision, value)?.state.state)
        }
    }

    fn default(reader: &Connection, value: u64) -> Result<GraphPackageStateV1> {
        let (tag,declared,empty,key):(String,Option<String>,bool,Vec<u8>)=reader.query_row(
            "SELECT state_tag,state_declared,unit_ref IS NULL AND position_revision IS NULL AND position_ordinal IS NULL
                AND fact_tenant IS NULL AND fact_owner IS NULL AND fact_entity IS NULL
                AND fact_lifetime IS NULL AND fact_revision IS NULL AND fact_ref IS NULL
                AND fact_sensitivity IS NULL,value_key FROM graph_unit_state_values WHERE value_ref=?",
            params![value],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))
        ).context(DatabaseSnafu { operation:"read default state value" })?;
        let state = GraphPackageStateV1::from_native(tag, declared).context(ContractSnafu)?;
        if value == 0 || !empty || key != Self::default_key(&state)? {
            return InvalidSnafu {
                field: "default state native value",
            }
            .fail();
        }
        Ok(state)
    }

    fn default_key(state: &GraphPackageStateV1) -> Result<Vec<u8>> {
        Self::encode(&(
            None::<u64>,
            state.native_fields(),
            None::<Position>,
            None::<AnalysisContextKeyV1>,
            None::<u64>,
            None::<ContextSensitivityV1>,
        ))
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
        Self::check_member(writer, row, &head, source)?;
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
        let duplicate: bool = writer.query_row("SELECT EXISTS(SELECT 1 FROM graph_unit_state_values GROUP BY value_key HAVING count(*)>1)",[],|row|row.get(0)).context(DatabaseSnafu {operation:"check duplicate unit states"})?;
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
            if Self::column::<Option<u64>>(row, 1)?.is_none() {
                Self::default(writer, Self::column(row, 0)?)?;
            } else {
                let head = Self::decode(row)?;
                Self::fact(writer, &head)?;
            }
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
            Self::check_member(writer, row, &head, Self::column(row, 24)?)?;
        }
        drop(rows);
        drop(statement);
        let mut statement = writer
            .prepare(
                "SELECT version.scope_id,version.commit_revision,version.selected_state_ref,scope.producer_kind,version.state_count FROM graph_producer_versions version JOIN graph_producer_scopes scope USING(scope_id)",
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
            let expected = Self::fallback(writer, scope, revision)?.map(|head| head.value);
            let kind: u8 = Self::column(row, 3)?;
            let count: u64 = Self::column(row, 4)?;
            if kind == 0 && count == 0 && expected.is_none() {
                let value = selected.ok_or_else(|| {
                    InvalidSnafu {
                        field: "default unit state is absent",
                    }
                    .build()
                })?;
                Self::default(writer, value)?;
            } else if expected != selected
                || (kind == 0 && (count == 0) != expected.is_none())
                || (kind != 0 && selected.is_some())
            {
                return InvalidSnafu {
                    field: "unit state index mismatch",
                }
                .fail();
            }
        }
        Ok(())
    }

    fn columns() -> &'static str {
        "state.value_ref,state.unit_ref,state.state_tag,state.state_declared,state.position_revision,state.position_ordinal,state.fact_tenant,state.fact_owner,state.fact_entity,state.fact_lifetime,state.fact_revision,state.fact_ref,state.fact_sensitivity,state.value_key,source.identity,evidence.cpu_id,evidence.durable_cursor,evidence.source_ref"
    }

    fn decode(row: &Row<'_>) -> Result<StateHead> {
        let source: EvidenceIntakeIdentityV1 =
            Self::decode_body(&Self::column::<Vec<u8>>(row, 14)?)?;
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
        let sensitivity = Self::column::<Option<String>>(row, 12)?
            .map(|value| {
                ContextSensitivityV1::try_from(value.as_str()).map_err(|_| {
                    InvalidSnafu {
                        field: "unit state fact sensitivity",
                    }
                    .build()
                })
            })
            .transpose()?;
        let head = StateHead {
            value: Self::column(row, 0)?,
            unit: Self::column(row, 1)?,
            record: DiscoveryRecordIdV1 {
                stream: source,
                cpu_id: Self::column(row, 15)?,
                durable_cursor: Self::column(row, 16)?,
            },
            state: GraphStateChange {
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
            fact_ref: Self::column(row, 11)?,
            sensitivity,
        };
        if head.value == 0
            || head.unit == 0
            || head.state.position.commit_revision == 0
            || head.state.fact.as_ref().is_some_and(|key| {
                !key.valid()
                    || key.owner_revision == 0
                    || key.tenant_id != head.record.stream.tenant_id
            })
            || head.state.fact.is_some() != head.fact_ref.is_some()
            || head.state.fact.is_some() != head.sensitivity.is_some()
            || head.fact_ref.is_some_and(|reference| reference == 0)
            || Self::value_key(head.unit, &head.state, head.fact_ref, head.sensitivity)?
                != Self::column::<Vec<u8>>(row, 13)?
        {
            return InvalidSnafu {
                field: "unit state native value",
            }
            .fail();
        }
        Ok(head)
    }

    fn fact(reader: &Connection, head: &StateHead) -> Result<Option<GraphFactV1>> {
        head.fact_ref
            .map(|reference| {
                let (tenant, body): (Vec<u8>, Vec<u8>) = reader
                    .query_row(
                        "SELECT tenant_id,body FROM graph_fact_values WHERE fact_id=?",
                        params![reference],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .context(DatabaseSnafu {
                        operation: "read unit state fact",
                    })?;
                let fact: GraphFactV1 = Self::decode_body(&body)?;
                if tenant.as_slice() != head.record.stream.tenant_id
                    || fact.record_id.stream != head.record.stream
                    || Self::encode(&fact)? != body
                {
                    return InvalidSnafu {
                        field: "unit state native fact",
                    }
                    .fail();
                }
                Ok(fact)
            })
            .transpose()
    }

    fn check_member(
        reader: &Connection,
        row: &Row<'_>,
        head: &StateHead,
        source: u64,
    ) -> Result<()> {
        let fact: Option<Vec<u8>> = Self::column(row, 20)?;
        let anchor: Option<FactAnchor> = fact.as_deref().map(Self::decode_body).transpose()?;
        let pooled = Self::fact(reader, head)?;
        if Self::column::<u64>(row, 17)? != source
            || Self::column::<Vec<u8>>(row, 18)? != Self::encode(&head.record)?
            || Self::column::<Option<u64>>(row, 19)? != Some(head.unit)
            || Self::column::<u64>(row, 21)? != head.unit
            || Self::column::<Option<String>>(row, 22)?.is_some()
            || Self::column::<u32>(row, 23)? != 0
            || anchor.as_ref().map(|anchor| &anchor.key) != head.state.fact.as_ref()
            || anchor.as_ref().map(|anchor| anchor.sensitivity) != head.sensitivity
            || anchor
                .as_ref()
                .map(|anchor| (&anchor.record, &anchor.value))
                != pooled.as_ref().map(|fact| (&fact.record_id, &fact.value))
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

    fn value_key(
        unit: u64,
        state: &GraphStateChange,
        fact_ref: Option<u64>,
        sensitivity: Option<ContextSensitivityV1>,
    ) -> Result<Vec<u8>> {
        Self::encode(&(
            Some(unit),
            state.state.native_fields(),
            Some(state.position),
            &state.fact,
            fact_ref,
            sensitivity,
        ))
    }
    fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        value
            .serialize(&mut rmp_serde::Serializer::new(&mut bytes).with_struct_map())
            .context(EncodingSnafu)?;
        Ok(bytes)
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
