use std::collections::BTreeSet;
use std::path::Path;

use duckdb::{params, Connection};
use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};

use super::{AnalysisReadControl, AnalysisStore};
use crate::{
    AnalysisConflictSnafu, AnalysisDatabaseSnafu, JsonSnafu, Result, TraceIdentityV1,
    TraceInvalidSnafu, TraceSourceV1, MAX_TRACE_TARGETS,
};

const MAX_AUTHORITY_BYTES: usize = 1024 * 1024;
const TRACE_PAGE_ROWS: usize = 16;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceBindingV1 {
    pub identity: TraceIdentityV1,
    pub binding_id: [u8; 16],
    pub namespace_uid: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceIntentV1 {
    pub tenant_id: [u8; 16],
    pub request_id: [u8; 16],
    pub source: TraceSourceV1,
    pub bindings: Vec<TraceBindingV1>,
    /// Control owns this bounded record. It does not contain source bytes.
    pub authority: Vec<u8>,
    pub accepted_unix_ns: u64,
    pub deadline_unix_ns: u64,
    pub host_sensitive: bool,
}

impl TraceIntentV1 {
    pub fn validate(&self) -> Result<()> {
        self.source.validate()?;
        ensure!(
            self.tenant_id != [0; 16]
                && self.request_id != [0; 16]
                && !self.bindings.is_empty()
                && self.bindings.len() <= MAX_TRACE_TARGETS
                && !self.authority.is_empty()
                && self.authority.len() <= MAX_AUTHORITY_BYTES
                && self.accepted_unix_ns > 0
                && self.deadline_unix_ns > self.accepted_unix_ns
                && self.deadline_unix_ns - self.accepted_unix_ns <= 315_000_000_000,
            TraceInvalidSnafu {
                reason: "trace intent identity, lifetime, or size is invalid",
            }
        );
        let mut executions = BTreeSet::new();
        for binding in &self.bindings {
            binding.identity.validate()?;
            ensure!(
                binding.identity.tenant_id == self.tenant_id
                    && binding.binding_id != [0; 16]
                    && binding.identity.request_id == self.request_id
                    && binding.identity.source_sha256 == self.source.sha256
                    && executions.insert(binding.identity.execution_id)
                    && !binding.namespace_uid.is_empty()
                    && binding.namespace_uid.len() <= 256
                    && !binding.namespace_uid.chars().any(char::is_control),
                TraceInvalidSnafu {
                    reason: "trace intent changed or repeated a frozen binding",
                }
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TraceStateV1 {
    pub tenant_id: [u8; 16],
    pub request_id: [u8; 16],
    pub revision: u64,
    pub cancel_requested: bool,
    pub read_revoked: bool,
}

#[derive(Debug)]
pub struct TraceIntentPageV1 {
    pub intents: Vec<(TraceStateV1, TraceIntentV1)>,
    pub next_request: Option<[u8; 16]>,
}

impl AnalysisStore {
    pub(crate) fn check_trace_reads(
        &self,
        tenant: [u8; 16],
        requests: &[[u8; 16]],
        control: &AnalysisReadControl,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<()> {
        if tenant == [0; 16] || requests.len() > 1024 || requests.contains(&[0; 16]) {
            return crate::QueryDeniedSnafu.fail();
        }
        let mut reader = self.reader_wait(Some(control), permit)?;
        control.run(&mut reader, |snapshot| {
            let mut statement = snapshot
                .prepare("SELECT read_revoked FROM traces WHERE tenant_id = ? AND request_id = ?")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare current trace reads",
                })?;
            for request in requests {
                control.check()?;
                let mut rows = statement
                    .query(params![tenant.as_slice(), request.as_slice()])
                    .context(AnalysisDatabaseSnafu {
                        operation: "read current trace state",
                    })?;
                let row = rows.next().context(AnalysisDatabaseSnafu {
                    operation: "read current trace row",
                })?;
                let Some(row) = row else {
                    return crate::QueryDeniedSnafu.fail();
                };
                let revoked: bool = row.get(0).context(AnalysisDatabaseSnafu {
                    operation: "decode current trace state",
                })?;
                if revoked {
                    return crate::QueryDeniedSnafu.fail();
                }
            }
            control.check()
        })
    }

    pub(super) fn read_trace_receipt(
        &self,
        snapshot: &Connection,
        identity: &TraceIdentityV1,
    ) -> Result<super::TraceOutputReceiptV1> {
        let mut statement = snapshot.prepare(
            "SELECT identity_json, last_sequence, output_bytes, terminal, retained_floor, commit_revision
             FROM trace_receipts WHERE stream_key = ?",
        ).context(AnalysisDatabaseSnafu { operation: "prepare trace input receipt" })?;
        let mut rows = statement
            .query(params![super::raw::RawIdentity::Diagnostic(
                identity.clone()
            )
            .key()
            .as_slice()])
            .context(AnalysisDatabaseSnafu {
                operation: "read trace input receipt",
            })?;
        let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read trace receipt row",
        })?
        else {
            return Ok(super::TraceOutputReceiptV1 {
                identity: identity.clone(),
                last_sequence: 0,
                output_bytes: 0,
                terminal: None,
                retained_floor: 0,
                commit_revision: 0,
            });
        };
        let (json, sequence, bytes, terminal, floor, revision): (
            String,
            u64,
            u64,
            Option<String>,
            u64,
            u64,
        ) = (
            row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode trace receipt identity",
            })?,
            row.get(1).context(AnalysisDatabaseSnafu {
                operation: "decode trace receipt sequence",
            })?,
            row.get(2).context(AnalysisDatabaseSnafu {
                operation: "decode trace receipt bytes",
            })?,
            row.get(3).context(AnalysisDatabaseSnafu {
                operation: "decode trace receipt terminal",
            })?,
            row.get(4).context(AnalysisDatabaseSnafu {
                operation: "decode trace receipt floor",
            })?,
            row.get(5).context(AnalysisDatabaseSnafu {
                operation: "decode trace receipt revision",
            })?,
        );
        let stored: TraceIdentityV1 =
            serde_json::from_str(&json).context(JsonSnafu { path: &self.root })?;
        let terminal = terminal
            .as_deref()
            .map(|json| super::raw::TraceRecord::terminal(json.as_bytes(), &self.root))
            .transpose()?;
        if stored != *identity
            || sequence > 4096
            || bytes > crate::MAX_TRACE_OUTPUT_BYTES
            || floor > sequence + u64::from(terminal.is_some())
            || terminal.as_ref().is_some_and(|value| {
                value.execution_id != identity.execution_id
                    || value.last_sequence != sequence
                    || value.output_bytes != bytes
            })
        {
            return self.reject("the selected trace receipt differs from its identity or limits");
        }
        Ok(super::TraceOutputReceiptV1 {
            identity: stored,
            last_sequence: sequence,
            output_bytes: bytes,
            terminal,
            retained_floor: floor,
            commit_revision: revision,
        })
    }

    pub(super) const TRACE_SCHEMA: &'static str = "CREATE TABLE traces (
        tenant_id BLOB NOT NULL,
        request_id BLOB NOT NULL,
        source BLOB NOT NULL,
        source_sha256 BLOB NOT NULL,
        bindings VARCHAR NOT NULL,
        authority BLOB NOT NULL,
        accepted_unix_ns UBIGINT NOT NULL,
        deadline_unix_ns UBIGINT NOT NULL,
        host_sensitive BOOLEAN NOT NULL,
        revision UBIGINT NOT NULL,
        cancel_requested BOOLEAN NOT NULL,
        read_revoked BOOLEAN NOT NULL,
        PRIMARY KEY (tenant_id, request_id)
    )";

    pub fn accept_trace(&self, intent: &TraceIntentV1) -> Result<TraceStateV1> {
        intent.validate()?;
        let bindings =
            serde_json::to_string(&intent.bindings).context(JsonSnafu { path: &self.root })?;
        let mut writer = self.maintenance_writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin trace intent",
            })?;
        if let Some((state, stored)) = Self::read_trace_intent(
            &transaction,
            &self.root,
            intent.tenant_id,
            intent.request_id,
        )? {
            if &stored != intent {
                return AnalysisConflictSnafu.fail();
            }
            return Ok(state);
        }
        self.require_capacity(false)?;
        let (total, scoped): (u64, u64) = transaction.query_row(
            "SELECT COUNT(*)::UBIGINT, COUNT(*) FILTER (WHERE tenant_id = ?)::UBIGINT FROM traces",
            params![intent.tenant_id.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).context(AnalysisDatabaseSnafu { operation: "count retained trace requests" })?;
        if total >= 1024 || scoped >= 256 {
            return crate::StorageCapacitySnafu {
                resource: "retained trace requests",
            }
            .fail();
        }
        let revision = Self::read_meta_from(&transaction, &self.root)?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the trace intent revision is exhausted"))?;
        transaction
            .execute(
                "INSERT INTO traces VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, false)",
                params![
                    intent.tenant_id.as_slice(),
                    intent.request_id.as_slice(),
                    intent.source.bytes.as_slice(),
                    intent.source.sha256.as_slice(),
                    bindings,
                    intent.authority.as_slice(),
                    intent.accepted_unix_ns,
                    intent.deadline_unix_ns,
                    intent.host_sensitive,
                    revision,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert immutable trace intent",
            })?;
        super::quota::UsageChange::from(
            (256 + intent.source.bytes.len() + bindings.len() + intent.authority.len()) as i64,
        )
        .apply(&transaction, &intent.tenant_id)?;
        self.reserve_trace(&transaction, intent)?;
        self.check_logical(&transaction, intent.tenant_id, false)?;
        Self::record_revision(&transaction, revision, &["traces"])?;
        self.commit_metadata(transaction, "commit trace intent")?;
        self.revision.send_replace(revision);
        Ok(TraceStateV1 {
            tenant_id: intent.tenant_id,
            request_id: intent.request_id,
            revision,
            cancel_requested: false,
            read_revoked: false,
        })
    }

    pub fn trace_intent(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
    ) -> Result<Option<(TraceStateV1, TraceIntentV1)>> {
        Self::check_trace_key(tenant, request)?;
        let control = AnalysisReadControl::default();
        // Intent reads must not publish the pending raw catalogue before an upload ACK.
        let writer = self.raw_coordinator(&control)?;
        let reader = writer.get()?;
        control.query_run(reader, || {
            Self::read_trace_intent(reader, &self.root, tenant, request)
        })
    }

    pub fn trace_intents(
        &self,
        tenant: [u8; 16],
        after: Option<[u8; 16]>,
    ) -> Result<TraceIntentPageV1> {
        ensure!(
            tenant != [0; 16] && after.is_none_or(|id| id != [0; 16]),
            TraceInvalidSnafu {
                reason: "trace intent page identity is invalid",
            }
        );
        let control = AnalysisReadControl::default();
        let writer = self.raw_coordinator(&control)?;
        let reader = writer.get()?;
        control.query_run(reader, || {
            let mut statement = reader
                .prepare(
                    "SELECT request_id, source, source_sha256, bindings, authority,
                     accepted_unix_ns, deadline_unix_ns, host_sensitive,
                     revision, cancel_requested, read_revoked FROM traces WHERE tenant_id = ?
                     AND (CAST(? AS BLOB) IS NULL OR request_id > ?)
                     ORDER BY request_id LIMIT ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare trace intent page",
                })?;
            let mut rows = statement
                .query(params![
                    tenant.as_slice(),
                    after.as_ref().map(|id| id.as_slice()),
                    after.as_ref().map(|id| id.as_slice()),
                    TRACE_PAGE_ROWS as u32,
                ])
                .context(AnalysisDatabaseSnafu {
                    operation: "read trace intent page",
                })?;
            let mut intents = Vec::with_capacity(TRACE_PAGE_ROWS);
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "read trace intent row",
            })? {
                control.check()?;
                intents.push(Self::read_trace_row(row, &self.root, tenant)?);
            }
            let next_request = (intents.len() == TRACE_PAGE_ROWS)
                .then(|| intents.last().map(|(state, _)| state.request_id))
                .flatten();
            Ok(TraceIntentPageV1 {
                intents,
                next_request,
            })
        })
    }

    pub fn update_trace(&self, next: &TraceStateV1) -> Result<TraceStateV1> {
        Self::check_trace_key(next.tenant_id, next.request_id)?;
        let expected = next.revision;
        ensure!(
            expected > 0 && (!next.read_revoked || next.cancel_requested),
            TraceInvalidSnafu {
                reason: "trace state revision or cancellation is invalid",
            }
        );
        let mut writer = self.maintenance_writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin trace state",
            })?;
        let Some((stored, _)) =
            Self::read_trace_intent(&transaction, &self.root, next.tenant_id, next.request_id)?
        else {
            return self.reject("the trace request is absent");
        };
        if stored.revision != expected
            || (stored.cancel_requested && !next.cancel_requested)
            || (stored.read_revoked && !next.read_revoked)
        {
            return AnalysisConflictSnafu.fail();
        }
        if &stored == next {
            return Ok(stored);
        }
        let revision = Self::read_meta_from(&transaction, &self.root)?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the trace state revision is exhausted"))?;
        transaction
            .execute(
                "UPDATE traces SET revision = ?, cancel_requested = ?, read_revoked = ?
             WHERE tenant_id = ? AND request_id = ? AND revision = ?",
                params![
                    revision,
                    next.cancel_requested,
                    next.read_revoked,
                    next.tenant_id.as_slice(),
                    next.request_id.as_slice(),
                    expected
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "update trace state",
            })?;
        Self::record_revision(&transaction, revision, &["traces"])?;
        self.commit_metadata(transaction, "commit trace state")?;
        self.revision.send_replace(revision);
        Ok(TraceStateV1 {
            revision,
            ..next.clone()
        })
    }

    fn check_trace_key(tenant: [u8; 16], request: [u8; 16]) -> Result<()> {
        ensure!(
            tenant != [0; 16] && request != [0; 16],
            TraceInvalidSnafu {
                reason: "trace request key is invalid"
            }
        );
        Ok(())
    }

    pub(super) fn read_trace_intent(
        reader: &Connection,
        root: &Path,
        tenant: [u8; 16],
        request: [u8; 16],
    ) -> Result<Option<(TraceStateV1, TraceIntentV1)>> {
        let mut statement = reader
            .prepare(
                "SELECT request_id, source, source_sha256, bindings, authority,
             accepted_unix_ns, deadline_unix_ns, host_sensitive, revision,
             cancel_requested, read_revoked FROM traces WHERE tenant_id = ? AND request_id = ?",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare trace intent",
            })?;
        let mut rows = statement
            .query(params![tenant.as_slice(), request.as_slice()])
            .context(AnalysisDatabaseSnafu {
                operation: "read trace intent",
            })?;
        rows.next()
            .context(AnalysisDatabaseSnafu {
                operation: "read trace intent row",
            })?
            .map(|row| Self::read_trace_row(row, root, tenant))
            .transpose()
    }

    fn read_trace_row(
        row: &duckdb::Row<'_>,
        root: &Path,
        tenant: [u8; 16],
    ) -> Result<(TraceStateV1, TraceIntentV1)> {
        let row = row
            .get::<_, Vec<u8>>(0)
            .and_then(|request| {
                Ok((
                    request,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, bool>(7)?,
                    row.get::<_, u64>(8)?,
                    row.get::<_, bool>(9)?,
                    row.get::<_, bool>(10)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "decode trace intent row",
            })?;
        let (
            request,
            bytes,
            digest,
            bindings,
            authority,
            accepted,
            deadline,
            host,
            revision,
            cancel,
            revoked,
        ) = row;
        let request = request.try_into().map_err(|_| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the stored trace request key is invalid",
            }
            .build()
        })?;
        let sha256 = digest.try_into().map_err(|_| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the stored trace source digest is invalid",
            }
            .build()
        })?;
        let source = TraceSourceV1 { bytes, sha256 };
        if revision == 0 || (revoked && !cancel) {
            return Self::reject_path(root, "the stored trace source or state changed");
        }
        let intent = TraceIntentV1 {
            tenant_id: tenant,
            request_id: request,
            source,
            bindings: serde_json::from_str(&bindings).context(JsonSnafu { path: root })?,
            authority,
            accepted_unix_ns: accepted,
            deadline_unix_ns: deadline,
            host_sensitive: host,
        };
        if intent.validate().is_err() {
            return Self::reject_path(root, "the stored trace intent is invalid");
        }
        Ok((
            TraceStateV1 {
                tenant_id: tenant,
                request_id: request,
                revision,
                cancel_requested: cancel,
                read_revoked: revoked,
            },
            intent,
        ))
    }

    pub(super) fn validate_traces(reader: &Connection, root: &Path) -> Result<()> {
        let meta = Self::read_meta_from(reader, root)?;
        let revision: u64 = reader
            .query_row(
                "SELECT COALESCE(MAX(last_changed_revision), 0)::UBIGINT FROM relation_revisions
             WHERE relation_name = 'traces'",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read trace relation revision",
            })?;
        let mut after = -1_i64;
        loop {
            let mut statement = reader
                .prepare(
                    "SELECT rowid, tenant_id, request_id, revision FROM traces
                 WHERE rowid > ? ORDER BY rowid LIMIT 16",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare trace recovery page",
                })?;
            let rows = statement
                .query_map(params![after], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read trace recovery page",
                })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode trace recovery page",
                })?;
            if rows.is_empty() {
                break;
            }
            for (row, tenant, request, changed) in rows {
                let tenant = tenant.try_into().map_err(|_| {
                    crate::AnalysisStateSnafu {
                        path: root,
                        reason: "the retained trace tenant is invalid",
                    }
                    .build()
                })?;
                let request = request.try_into().map_err(|_| {
                    crate::AnalysisStateSnafu {
                        path: root,
                        reason: "the retained trace request is invalid",
                    }
                    .build()
                })?;
                if changed > meta.commit_revision
                    || changed > revision
                    || Self::read_trace_intent(reader, root, tenant, request)?.is_none()
                {
                    return Self::reject_path(root, "the retained trace revision is invalid");
                }
                after = row;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(request: u8) -> Result<TraceIntentV1> {
        let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
        Ok(TraceIntentV1 {
            tenant_id: [1; 16],
            request_id: [request; 16],
            bindings: vec![TraceBindingV1 {
                binding_id: [9; 16],
                identity: TraceIdentityV1 {
                    tenant_id: [1; 16],
                    node_id: "node-a".into(),
                    node_boot_id: [2; 16],
                    request_id: [request; 16],
                    execution_id: [request; 16],
                    source_sha256: source.sha256,
                },
                namespace_uid: "namespace-a".into(),
            }],
            source,
            authority: b"authorized-input".to_vec(),
            accepted_unix_ns: 100,
            deadline_unix_ns: 10_000,
            host_sensitive: false,
        })
    }

    #[test]
    fn observability_intent_recovery() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = AnalysisStore::open(&root)?;
        let input = intent(3)?;
        let state = store.accept_trace(&input)?;
        assert_eq!(store.accept_trace(&input)?, state);
        let mut changed = input.clone();
        changed.authority.push(b'!');
        assert!(matches!(
            store.accept_trace(&changed),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        let cancelled = store.update_trace(&TraceStateV1 {
            cancel_requested: true,
            read_revoked: true,
            ..state.clone()
        })?;
        assert_eq!(store.update_trace(&cancelled)?, cancelled);
        assert!(matches!(
            store.update_trace(&state),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert!(matches!(
            store.update_trace(&TraceStateV1 {
                cancel_requested: false,
                read_revoked: false,
                ..cancelled.clone()
            }),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(
            store.trace_intent(input.tenant_id, input.request_id)?,
            Some((cancelled, input))
        );
        assert!(store.trace_intent([4; 16], [3; 16])?.is_none());
        Ok(())
    }

    #[test]
    fn observability_intent_pages() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("data"))?;
        for request in 1..=16 {
            store.accept_trace(&intent(request)?)?;
        }
        let first = store.trace_intents([1; 16], None)?;
        assert_eq!(first.intents.len(), 16);
        assert_eq!(first.next_request, Some([16; 16]));
        for (request, (state, input)) in (1..=16).zip(&first.intents) {
            assert_eq!(state.request_id, [request; 16]);
            assert_eq!(input, &intent(request)?);
            assert_eq!(
                store.trace_intent([1; 16], state.request_id)?,
                Some((state.clone(), input.clone()))
            );
        }
        let end = store.trace_intents([1; 16], first.next_request)?;
        assert!(end.intents.is_empty());
        assert!(end.next_request.is_none());
        let state = store.accept_trace(&intent(17)?)?;
        let state = store.update_trace(&TraceStateV1 {
            cancel_requested: true,
            read_revoked: true,
            ..state
        })?;
        let last = store.trace_intents([1; 16], first.next_request)?;
        assert_eq!(last.intents.len(), 1);
        assert_eq!(last.intents, vec![(state, intent(17)?)]);
        assert!(last.next_request.is_none());
        assert!(store.trace_intents([2; 16], None)?.intents.is_empty());
        let mut invalid = intent(18)?;
        invalid.bindings.push(invalid.bindings[0].clone());
        assert!(store.accept_trace(&invalid).is_err());
        Ok(())
    }

    #[test]
    fn observability_intent_corruption() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = AnalysisStore::open(&root)?;
        store.accept_trace(&intent(3)?)?;
        store
            .writer()?
            .get_mut()?
            .execute("UPDATE traces SET authority = ?", params![b"".as_slice()])?;
        assert!(store.trace_intent([1; 16], [3; 16]).is_err());
        assert!(store.trace_intents([1; 16], None).is_err());
        drop(store);
        assert!(AnalysisStore::open(&root).is_err());
        Ok(())
    }

    #[test]
    fn observability_intent_pressure() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = AnalysisStore::open(&root)?;
        let input = intent(3)?;
        let state = store.accept_trace(&input)?;
        let padding = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("quota-test"))?;
        padding.set_len(store.storage.disk_max_bytes)?;
        assert!(matches!(
            store.accept_trace(&intent(4)?),
            Err(crate::Error::StorageCapacity { .. })
        ));
        assert_eq!(store.accept_trace(&input)?, state);
        let cancelled = store.update_trace(&TraceStateV1 {
            cancel_requested: true,
            read_revoked: true,
            ..state
        })?;
        assert_eq!(
            store
                .trace_intent([1; 16], [3; 16])?
                .map(|(state, _)| state),
            Some(cancelled)
        );
        Ok(())
    }

    #[test]
    fn observability_intent_quota() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let limits = super::super::StorageLimitsV1 {
            logical_max_bytes: 256 * 1024,
            tenant_max_bytes: 256 * 1024,
            ..Default::default()
        };
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        let input = intent(3)?;
        store.accept_trace(&input)?;
        assert!(matches!(
            store.accept_trace(&intent(4)?),
            Err(crate::Error::StorageCapacity {
                resource: "diagnostic logical bytes",
                ..
            })
        ));
        assert!(store.trace_intent([1; 16], [4; 16])?.is_none());
        store.accept_validated_batch(
            crate::EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "node-a".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            crate::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 100,
                framed_records: vec![1, 2, 3].into(),
                frame_ends: vec![3],
            },
        )?;
        let identity = &input.bindings[0].identity;
        store.append_trace(
            identity,
            &crate::TraceBatchV1 {
                execution_id: identity.execution_id,
                frames: Vec::new(),
                terminal: Some(crate::TraceTerminalV1 {
                    execution_id: identity.execution_id,
                    reason: crate::TraceTerminalReasonV1::Completed,
                    last_sequence: 0,
                    output_bytes: 0,
                    output_incomplete: false,
                    kernel_lost_events: None,
                    ready_at_unix_ns: None,
                    exit_code: Some(0),
                    forced_kill: false,
                    cleanup: crate::TraceCleanupV1::Unknown,
                }),
            },
            100,
        )?;
        store.accept_trace(&intent(4)?)?;
        drop(store);
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        assert!(store
            .trace_receipt(identity)?
            .is_some_and(|receipt| receipt.terminal.is_some()));
        assert!(store.trace_intent([1; 16], [4; 16])?.is_some());
        Ok(())
    }

    #[test]
    fn observability_intent_raw_pending() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::Ordering;
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("data"))?;
        store.accept_trace(&intent(3)?)?;
        store.accept_validated_batch(
            crate::EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "node-a".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            crate::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 100,
                framed_records: vec![1, 2, 3].into(),
                frame_ends: vec![3],
            },
        )?;
        for _ in 0..2 {
            assert!(store.trace_intent([1; 16], [3; 16])?.is_some());
            assert_eq!(store.trace_intents([1; 16], None)?.intents.len(), 1);
            assert!(store.raw_pending.load(Ordering::Acquire));
            assert!(!store.raw_dirty.load(Ordering::Acquire));
        }
        Ok(())
    }
}
