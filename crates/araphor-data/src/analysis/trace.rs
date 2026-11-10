use std::collections::BTreeSet;


use serde::{Deserialize, Serialize};
use snafu::ensure;

use crate :: { Result , TraceIdentityV1 , TraceInvalidSnafu , TraceSourceV1 } ;

const TRACE_PAGE_ROWS: usize = 16;

mod history;

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
    /// Control owns this record. It does not contain source bytes.
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
                && self
                    .bindings
                    .len()
                    .checked_sub(1)
                    .is_some_and(|index| u16::try_from(index).is_ok())
                && !self.authority.is_empty()
                && self.accepted_unix_ns > 0
                && self.deadline_unix_ns > self.accepted_unix_ns,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

pub struct TraceReadPermit(pub(in crate::analysis) super::read::ReadPermit);



#[cfg(test)]
pub(in crate::analysis) mod tests {
    use super::*;

    pub(in crate::analysis) fn intent(request: u8) -> Result<TraceIntentV1> {
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
        store.writer()?.get_mut()?.execute(
            "UPDATE trace_intents SET authority = ?",
            params![b"".as_slice()],
        )?;
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
        let store = AnalysisStore::open_with_limits(
            &root,
            Default::default(),
            super::super::StorageLimitsV1::fixture(),
        )?;
        let input = intent(3)?;
        let state = store.accept_trace(&input)?;
        let padding = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("quota-test"))?;
        padding.set_len(
            store
                .storage
                .disk_max_bytes
                .ok_or("configured disk limit")?,
        )?;
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
    fn diagnostic_sources_are_optional() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let limits = super::super::StorageLimitsV1 {
            diagnostic_sources: Some(1),
            tenant_diagnostic_sources: Some(1),
            ..Default::default()
        };
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        let first = intent(3)?;
        let state = store.accept_trace(&first)?;
        let before = store.meta()?;
        assert!(matches!(
            store.accept_trace(&intent(4)?),
            Err(crate::Error::StorageCapacity {
                resource: "diagnostic sources",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        assert!(store.trace_intent([1; 16], [4; 16])?.is_none());
        assert_eq!(store.accept_trace(&first)?, state);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        store.accept_trace(&intent(4)?)?;
        assert!(store.trace_intent([1; 16], [3; 16])?.is_some());
        assert!(store.trace_intent([1; 16], [4; 16])?.is_some());
        Ok(())
    }

    #[test]
    fn context_preserves_raw_state() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::analysis::tests::{batch, identity};
        use crate::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1};
        use std::sync::atomic::Ordering;

        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("data"))?;
        let source = identity();
        let mut changes = store.subscribe_revision();
        store.accept_validated_batch(source.clone(), batch(1, &[b"one"]))?;
        assert!(!store.raw_dirty.load(Ordering::Acquire));
        let receipt = store.source_receipt(&source)?.ok_or("evidence receipt")?;
        assert_eq!(receipt.contiguous_cursor, 1);
        let before = *changes.borrow_and_update();
        let mut context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: source.tenant_id,
                owner_id: "p".into(),
                entity_key: vec![1],
                lifetime_key: vec![1],
                owner_revision: 1,
            },
            valid_from_utc_ns: Some(1),
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: vec![1],
        };
        let first = store.commit_context_checked(&context, 0)?;
        assert!(!store.raw_dirty.load(Ordering::Acquire));
        assert!(first > before);
        assert_eq!(*changes.borrow_and_update(), first);
        assert_eq!(store.source_receipt(&source)?.as_ref(), Some(&receipt));
        assert_eq!(
            store.context_version(&context.key)?.as_ref(),
            Some(&context)
        );
        {
            let raw = store.raw.lock().map_err(|_| "raw owner lock")?;
            assert_eq!((raw.budget.trace_reserve, raw.budget.trace_slots), (0, 0));
        }

        let trace = intent(3)?;
        store.accept_trace(&trace)?;
        assert!(store.raw_dirty.load(Ordering::Acquire));
        let admitted = *changes.borrow_and_update();
        assert!(admitted > first);
        context.key.owner_revision = 2;
        context.body = vec![2];
        let second = store.commit_context_checked(&context, 1)?;
        assert!(store.raw_dirty.load(Ordering::Acquire));
        assert!(second > admitted);
        assert_eq!(*changes.borrow_and_update(), second);

        store.accept_validated_batch(source.clone(), batch(2, &[b"two"]))?;
        assert!(!store.raw_dirty.load(Ordering::Acquire));
        {
            let raw = store.raw.lock().map_err(|_| "raw owner lock")?;
            assert_eq!(
                (raw.budget.trace_reserve, raw.budget.trace_slots),
                (crate::analysis::quota::TRACE_RESERVE, 2)
            );
        }
        assert_eq!(
            store.source_receipt(&source)?,
            Some(crate::AnalysisSourceReceiptV1 {
                contiguous_cursor: 2,
                ..receipt
            })
        );
        assert!(*changes.borrow_and_update() > second);
        let output = store
            .trace_receipt(&trace.bindings[0].identity)?
            .ok_or("admitted trace receipt")?;
        assert_eq!(output.identity, trace.bindings[0].identity);
        assert_eq!(output.last_sequence, 0);
        assert_eq!(output.output_bytes, 0);
        assert!(output.terminal.is_none());
        assert_eq!(
            store.context_version(&context.key)?.as_ref(),
            Some(&context)
        );
        Ok(())
    }

    #[test]
    fn observability_intent_raw_pending() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::Ordering;
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("data"))?;
        store.accept_trace(&intent(3)?)?;
        store.accept_validated_batch(
            crate::analysis::tests::identity(),
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

    #[test]
    fn trace_selection_default_unbounded() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::{
            AnalysisExtractLimits, AnalysisReadModeV1, AnalysisSelectionV1, AnalysisTableRead,
            Selection,
        };

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = AnalysisStore::open(&root)?;
        let mut input = intent(1)?;
        let mut requests = Vec::new();
        let mut last = None;
        for number in 1_u128..=1025 {
            let request = number.to_be_bytes();
            input.request_id = request;
            input.bindings[0].identity.request_id = request;
            input.bindings[0].identity.execution_id = request;
            if number == 1025 {
                input.bindings[0].identity.node_id = "node-last".into();
                input.bindings[0].binding_id = [10; 16];
            }
            last = Some(store.accept_trace(&input)?);
            requests.push(request);
        }
        let committed = store.meta()?.commit_revision;
        drop(store);
        let store = AnalysisStore::open(&root)?;
        let before = store.meta()?;
        assert_eq!(before.commit_revision, committed);
        let control = AnalysisReadControl::default();
        store.check_trace_reads([1; 16], &requests, &control, store.reserve_trace_read()?)?;
        let column = crate::AnalysisStore::table_schemas()["traces"].index_of("request_id")?;
        let columns =
            std::collections::BTreeMap::from([("traces".into(), Some(BTreeSet::from([column])))]);
        let read = |selection: &AnalysisSelectionV1, limits: AnalysisExtractLimits| {
            store.read_tables(
                selection,
                AnalysisTableRead {
                    requests: &columns,
                    event_ranges: None,
                    mode: AnalysisReadModeV1::Metadata,
                    now: 100,
                },
                limits,
                &control,
            )
        };
        let mut all = AnalysisSelectionV1::new([1; 16], Vec::new());
        all.traces = Selection::All;
        let page = read(&all, AnalysisExtractLimits::default())?;
        assert_eq!(page.extraction.trace_reads(), requests.as_slice());
        assert_eq!(
            page.tables
                .get("traces")
                .ok_or("trace table absent")?
                .iter()
                .map(|batch| batch.num_rows())
                .sum::<usize>(),
            1025
        );
        assert_eq!(page.extraction.trace_reads().last(), requests.last());
        assert!(all.traces.is_all());
        for binding in [false, true] {
            let mut selected = all.clone();
            if binding {
                selected.binding_ids.push([10; 16]);
            } else {
                selected.nodes.push("node-last".into());
            }
            let original = selected.clone();
            let page = read(&selected, AnalysisExtractLimits::default())?;
            assert_eq!(page.extraction.trace_reads(), &requests[1024..]);
            let keys = if binding { 2 } else { 1 };
            let page = read(
                &selected,
                AnalysisExtractLimits {
                    keys: Some(keys),
                    ..Default::default()
                },
            )?;
            assert_eq!(page.extraction.trace_reads(), &requests[1024..]);
            assert!(matches!(
                read(
                    &selected,
                    AnalysisExtractLimits {
                        keys: Some(keys - 1),
                        ..Default::default()
                    },
                ),
                Err(crate::Error::AnalysisInputTooLarge {
                    resource: "selected input keys",
                    ..
                })
            ));
            assert_eq!(selected, original);
            assert_eq!(store.meta()?, before);
        }
        assert!(matches!(
            read(
                &all,
                AnalysisExtractLimits {
                    keys: Some(1024),
                    ..Default::default()
                },
            ),
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
        for tenant in [[0; 16], [2; 16]] {
            assert!(matches!(
                store.check_trace_reads(tenant, &requests, &control, store.reserve_trace_read()?),
                Err(crate::Error::AnalysisReadDenied { .. })
            ));
        }
        for request in [[0; 16], 1026_u128.to_be_bytes()] {
            assert!(matches!(
                store.check_trace_reads([1; 16], &[request], &control, store.reserve_trace_read()?),
                Err(crate::Error::AnalysisReadDenied { .. })
            ));
        }
        let cancelled = AnalysisReadControl::default();
        cancelled.cancel()?;
        assert!(matches!(
            store.check_trace_reads([1; 16], &requests, &cancelled, store.reserve_trace_read()?),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, before);
        store.update_trace(&TraceStateV1 {
            cancel_requested: true,
            read_revoked: true,
            ..last.ok_or("last trace absent")?
        })?;
        assert!(matches!(
            store.check_trace_reads([1; 16], &requests, &control, store.reserve_trace_read()?),
            Err(crate::Error::AnalysisReadDenied { .. })
        ));
        Ok(())
    }
}
