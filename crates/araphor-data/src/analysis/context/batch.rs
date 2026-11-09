use std::collections::BTreeMap;
use std::sync::Arc;

use duckdb::{params, Connection, Transaction};
use snafu::ResultExt as _;

use super::{version_key, AnalysisContextVersionV1, VerifiedPackages};
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisDatabaseSnafu, AnalysisStore,
    PackageErrorCodeV1 as Code, Result,
};

pub(in crate::analysis) struct PreparedFact {
    source: Arc<crate::ManagedDerivedSource>,
    ordinal: usize,
    version: Vec<u8>,
    record: super::facts::FactRecord,
    _memory: Box<dyn std::any::Any + Send + Sync>,
}

impl PreparedFact {
    pub(in crate::analysis) fn new(
        source: Arc<crate::ManagedDerivedSource>,
        ordinal: usize,
        reserve: &mut impl FnMut(usize) -> Result<Box<dyn std::any::Any + Send + Sync>>,
    ) -> Result<Self> {
        let value = &source.context_values()[ordinal];
        let _scratch = reserve(
            value
                .body
                .len()
                .checked_mul(8)
                .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<crate::GraphFactV1>()))
                .ok_or_else(|| Code::Limit.error("derived fact decode memory"))?,
        )?;
        let memory = reserve(
            value
                .key
                .allocated_bytes()
                .checked_add(std::mem::size_of_val(&value.key))
                .and_then(|bytes| bytes.checked_mul(16))
                .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<Self>()))
                .ok_or_else(|| Code::Limit.error("derived fact preparation memory"))?,
        )?;
        if !value.valid() {
            return Err(Code::Invalid.error("derived context identity"));
        }
        let record = super::facts::FactRecord::from_context(value)?
            .ok_or_else(|| Code::Invalid.error("derived fact context"))?;
        let version = version_key(&value.key)?;
        Ok(Self {
            source,
            ordinal,
            version,
            record,
            _memory: memory,
        })
    }
    pub(in crate::analysis) fn value(&self) -> &AnalysisContextVersionV1 {
        &self.source.context_values()[self.ordinal]
    }
}

impl AnalysisStore {
    pub(in crate::analysis) fn import_fact_rows(
        &self,
        connection: &Transaction<'_>,
        contexts: &[PreparedFact],
        revision: u64,
        verified: &mut VerifiedPackages,
        cached: bool,
    ) -> Result<BTreeMap<AnalysisContextKeyV1, AnalysisContextRefV1>> {
        if contexts.is_empty() {
            return Ok(BTreeMap::new());
        }
        if revision == 0 {
            return Err(Code::Invalid.error("derived context transaction"));
        }
        connection.execute_batch("CREATE TEMP TABLE managed_fact_inputs (
            ordinal UBIGINT PRIMARY KEY,tenant_id BLOB,owner_id VARCHAR,entity_key BLOB,lifetime_key BLOB,
            owner_revision UBIGINT,valid_from_utc_ns UBIGINT,valid_until_utc_ns UBIGINT,sensitivity VARCHAR,
            body BLOB,version_key BLOB UNIQUE,record_key BLOB,stream_key BLOB,source_cursor UBIGINT,new_value BOOLEAN DEFAULT false)")
            .context(AnalysisDatabaseSnafu { operation:"create derived context inputs" })?;
        let result = self.apply_fact_rows(connection, contexts, revision, verified, cached);
        let cleanup = connection
            .execute_batch("DROP TABLE managed_fact_inputs")
            .context(AnalysisDatabaseSnafu {
                operation: "release derived context inputs",
            });
        let result = result?;
        cleanup?;
        Ok(result)
    }

    fn apply_fact_rows(
        &self,
        connection: &Connection,
        contexts: &[PreparedFact],
        revision: u64,
        verified: &mut VerifiedPackages,
        cached: bool,
    ) -> Result<BTreeMap<AnalysisContextKeyV1, AnalysisContextRefV1>> {
        Self::append_fact_inputs(connection, contexts)?;
        for value in contexts.iter().map(PreparedFact::value).filter(|value| {
            matches!(
                value.key.owner_id.as_str(),
                crate::NOTIFICATION_STATE_OWNER
                    | crate::NOTIFICATION_ROUTE_OWNER
                    | "discovery-context-v1"
                    | "native-package-v1"
            )
        }) {
            let mut current = Some(revision);
            self.context_rows(
                connection,
                std::slice::from_ref(value),
                false,
                None,
                &mut current,
                verified,
            )?;
            if current != Some(revision) {
                return Err(Code::Conflict.error("derived context owner revision"));
            }
        }
        let references =
            self.check_fact_inputs(connection, contexts, revision, verified, true, cached)?;
        connection.execute("INSERT INTO context_versions SELECT q.tenant_id,q.owner_id,q.entity_key,q.lifetime_key,q.owner_revision,
            q.valid_from_utc_ns,q.valid_until_utc_ns,q.sensitivity,q.body,?,q.version_key
            FROM managed_fact_inputs q WHERE q.new_value",params![revision])
            .context(AnalysisDatabaseSnafu { operation:"insert canonical derived context batch" })?;
        connection.execute_batch("INSERT INTO graph_fact_records SELECT q.version_key,q.record_key,q.stream_key,q.source_cursor FROM managed_fact_inputs q WHERE q.new_value")
            .context(AnalysisDatabaseSnafu { operation:"index canonical derived context batch" })?;
        Ok(references)
    }
    pub(in crate::analysis) fn inspect_fact_rows(
        &self,
        connection: &Connection,
        contexts: &[PreparedFact],
        revision: u64,
        verified: &mut VerifiedPackages,
    ) -> Result<BTreeMap<AnalysisContextKeyV1, AnalysisContextRefV1>> {
        if contexts.is_empty() {
            return Ok(BTreeMap::new());
        }
        connection.execute_batch("CREATE TEMP TABLE managed_fact_inputs (
            ordinal UBIGINT PRIMARY KEY,tenant_id BLOB,owner_id VARCHAR,entity_key BLOB,lifetime_key BLOB,
            owner_revision UBIGINT,valid_from_utc_ns UBIGINT,valid_until_utc_ns UBIGINT,sensitivity VARCHAR,
            body BLOB,version_key BLOB UNIQUE,record_key BLOB,stream_key BLOB,source_cursor UBIGINT,new_value BOOLEAN DEFAULT false)")
            .context(AnalysisDatabaseSnafu { operation:"create derived context inputs" })?;
        let result = (|| {
            Self::append_fact_inputs(connection, contexts)?;
            self.check_fact_inputs(connection, contexts, revision, verified, false, false)
        })();
        let cleanup = connection
            .execute_batch("DROP TABLE managed_fact_inputs")
            .context(AnalysisDatabaseSnafu {
                operation: "release derived context inputs",
            });
        let values = result?;
        cleanup?;
        Ok(values)
    }

    fn append_fact_inputs(connection: &Connection, contexts: &[PreparedFact]) -> Result<()> {
        {
            let mut appender = connection
                .appender_with_columns(
                    "managed_fact_inputs",
                    &[
                        "ordinal",
                        "tenant_id",
                        "owner_id",
                        "entity_key",
                        "lifetime_key",
                        "owner_revision",
                        "valid_from_utc_ns",
                        "valid_until_utc_ns",
                        "sensitivity",
                        "body",
                        "version_key",
                        "record_key",
                        "stream_key",
                        "source_cursor",
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "open derived context inputs",
                })?;
            for (ordinal, prepared) in contexts.iter().enumerate() {
                let value = prepared.value();
                let key = &value.key;
                let record = &prepared.record;
                let sensitivity: &'static str = value.sensitivity.into();
                appender
                    .append_row(params![
                        ordinal as u64,
                        key.tenant_id.as_slice(),
                        key.owner_id,
                        key.entity_key,
                        key.lifetime_key,
                        key.owner_revision,
                        value.valid_from_utc_ns,
                        value.valid_until_utc_ns,
                        sensitivity,
                        value.body,
                        prepared.version,
                        record.record,
                        record.stream,
                        record.cursor
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append derived context input",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush derived context inputs",
            })?;
        }
        Ok(())
    }

    fn check_fact_inputs(
        &self,
        connection: &Connection,
        contexts: &[PreparedFact],
        revision: u64,
        verified: &mut VerifiedPackages,
        bind: bool,
        cached: bool,
    ) -> Result<BTreeMap<AnalysisContextKeyV1, AnalysisContextRefV1>> {
        let (conflict,invalid): (bool,bool) = connection.query_row("WITH state AS (
            SELECT c.version_key IS NOT NULL AS stored,
                c.version_key IS NOT NULL AND (c.tenant_id IS DISTINCT FROM q.tenant_id OR c.owner_id IS DISTINCT FROM q.owner_id
                OR c.entity_key IS DISTINCT FROM q.entity_key OR c.lifetime_key IS DISTINCT FROM q.lifetime_key
                OR c.owner_revision IS DISTINCT FROM q.owner_revision OR c.valid_from_utc_ns IS DISTINCT FROM q.valid_from_utc_ns
                OR c.valid_until_utc_ns IS DISTINCT FROM q.valid_until_utc_ns OR c.sensitivity IS DISTINCT FROM q.sensitivity
                OR c.body IS DISTINCT FROM q.body) AS conflict,
                c.version_key IS NULL AND f.version_key IS NOT NULL AS orphan,
                f.record_key IS DISTINCT FROM q.record_key OR f.stream_key IS DISTINCT FROM q.stream_key OR f.source_cursor IS DISTINCT FROM q.source_cursor AS invalid
            FROM managed_fact_inputs q LEFT JOIN context_versions c USING(version_key) LEFT JOIN graph_fact_records f USING(version_key)
        ) SELECT EXISTS(SELECT 1 FROM state WHERE conflict),EXISTS(SELECT 1 FROM state WHERE orphan OR (stored AND NOT conflict AND invalid))",[],|row| Ok((row.get(0)?,row.get(1)?)))
            .context(AnalysisDatabaseSnafu { operation:"check immutable derived context batch" })?;
        if invalid {
            return Err(Code::Invalid.error("canonical fact index"));
        }
        if conflict {
            return crate::AnalysisConflictSnafu.fail();
        }
        connection.execute_batch("UPDATE managed_fact_inputs q SET new_value=NOT EXISTS(SELECT 1 FROM context_versions c WHERE c.version_key=q.version_key)")
            .context(AnalysisDatabaseSnafu { operation:"select absent derived contexts" })?;
        let states = connection.prepare("SELECT q.ordinal,c.commit_revision FROM managed_fact_inputs q LEFT JOIN context_versions c USING(version_key) ORDER BY q.ordinal")
            .and_then(|mut query| query.query_map([],|row| Ok((row.get::<_,u64>(0)?,row.get::<_,Option<u64>>(1)?)))?.collect::<duckdb::Result<Vec<_>>>())
            .context(AnalysisDatabaseSnafu { operation:"read derived context batch state" })?;
        if states.len() != contexts.len() {
            return Err(Code::Invalid.error("derived context batch cardinality"));
        }
        let mut references = BTreeMap::new();
        for (expected, ((ordinal, saved), prepared)) in states.into_iter().zip(contexts).enumerate()
        {
            let value = prepared.value();
            let key = &value.key;
            if ordinal != expected as u64 {
                return Err(Code::Invalid.error("derived context batch order"));
            }
            if !cached {
                if saved.is_some() {
                    self.verify_context_packages(connection, value, verified)?;
                } else {
                    Self::context_packages(connection, value, verified)?;
                }
            }
            if saved.is_none() {
                self.storage.check_context(value.body.len() as u64)?;
            }
            if saved.is_some_and(|saved| saved == 0 || saved > revision) {
                return Err(Code::Invalid.error("derived context stored revision"));
            }
            if saved.is_none() && !bind {
                continue;
            }
            references.insert(
                key.clone(),
                AnalysisContextRefV1 {
                    key: key.clone(),
                    commit_revision: saved.unwrap_or(revision),
                },
            );
        }
        Ok(references)
    }
}
