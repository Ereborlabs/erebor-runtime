use serde::{Deserialize, Serialize};

use super::AnalysisContextKeyV1;
use crate::{AnalysisStreamIdentityV1, Result};

mod notices;
mod profile;
mod schema;

pub use profile::{DiscoveryProducer, PreparedProfile, ProfileCommit};

pub const MAX_RESULT_BYTES: usize = usize::MAX;
pub const MAX_RESULT_REFS: usize = usize::MAX;
const MAX_WITNESS_AGE_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProcessorClassV1 {
    Optional,
    Required,
}

impl ProcessorClassV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }
}

impl TryFrom<&str> for ProcessorClassV1 {
    type Error = ();

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            _ => Err(()),
        }
    }
}

pub use araphor_analysis_builtins::discovery::ProcessorScopeV1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisWitnessV1 {
    pub identity: AnalysisStreamIdentityV1,
    pub cursor: u64,
    pub expires_utc_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisContextRefV1 {
    pub key: AnalysisContextKeyV1,
    pub commit_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisResultCommitV1 {
    pub scope: ProcessorScopeV1,
    pub expected_cursor: u64,
    pub consumed_cursor: u64,
    pub coverage_revision: u64,
    pub context_revision: u64,
    pub result_id: String,
    pub body: Vec<u8>,
    pub created_utc_ns: u64,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub context_refs: Vec<AnalysisContextRefV1>,
}

impl AnalysisResultCommitV1 {
    pub(in crate::analysis) fn check(
        &self,
        profile: Option<&crate::DiscoveryProfileV1>,
        contexts: &[super::AnalysisContextVersionV1],
        root: &std::path::Path,
    ) -> Result<()> {
        let input = self;
        if profile.is_some_and(|profile| {
            profile.scope != input.scope
                || profile.profile_id != input.result_id
                || profile.coverage_revision != input.coverage_revision
                || profile.context_refs != input.context_refs
        }) {
            return crate::Error::reject_path(
                root,
                "the profile header or references differ from its commit",
            );
        }
        if !input.scope.valid()
            || input.result_id.is_empty()
            || (input.body.is_empty() && (profile.is_none() || contexts.is_empty()))
            || input.created_utc_ns == 0
            || input.consumed_cursor < input.expected_cursor
            || input.witnesses.windows(2).any(|pair| {
                (&pair[0].identity, pair[0].cursor) >= (&pair[1].identity, pair[1].cursor)
            })
            || input
                .context_refs
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || input.context_refs.iter().any(|reference| {
                !reference.key.valid()
                    || reference.key.tenant_id != input.scope.identity.tenant_id
                    || reference.commit_revision == 0
            })
        {
            return crate::Error::reject_path(
                root,
                "the analysis result or progress bounds are invalid",
            );
        }
        if (profile.is_none() && !contexts.is_empty())
            || contexts.windows(2).any(|pair| pair[0].key >= pair[1].key)
            || contexts.iter().any(|context| {
                !context.valid() || context.key.tenant_id != input.scope.identity.tenant_id
            })
        {
            return crate::Error::reject_path(root, "the result contexts are invalid");
        }
        let witness_deadline = input
            .created_utc_ns
            .checked_add(MAX_WITNESS_AGE_NS)
            .ok_or_else(|| {
                crate::AnalysisStateSnafu {
                    path: root.to_path_buf(),
                    reason: "the witness deadline is exhausted".to_owned(),
                }
                .build()
            })?;
        if input.witnesses.iter().any(|witness| {
            witness.identity.tenant() != input.scope.identity.tenant_id
                || !witness.identity.valid()
                || witness.cursor == 0
                || witness.expires_utc_ns < input.created_utc_ns
                || witness.expires_utc_ns > witness_deadline
        }) {
            return crate::Error::reject_path(root, "the result has a foreign or invalid witness");
        }
        Ok(())
    }

    pub(super) fn request_meta(&self) -> std::result::Result<Vec<u8>, serde_json::Error> {
        self.request_meta_refs(self.context_revision, &self.context_refs, &[])
    }

    fn request_meta_refs(
        &self,
        context_revision: u64,
        references: &[AnalysisContextRefV1],
        sources: &[(String, u64)],
    ) -> std::result::Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&(
            &self.scope,
            self.expected_cursor,
            self.consumed_cursor,
            self.coverage_revision,
            context_revision,
            &self.result_id,
            self.created_utc_ns,
            &self.witnesses,
            references,
            sources,
        ))
    }

    pub(super) fn request_refs(
        bytes: &[u8],
    ) -> std::result::Result<(Vec<AnalysisWitnessV1>, Vec<AnalysisContextRefV1>), serde_json::Error>
    {
        type Metadata = (
            ProcessorScopeV1,
            u64,
            u64,
            u64,
            u64,
            String,
            u64,
            Vec<AnalysisWitnessV1>,
            Vec<AnalysisContextRefV1>,
            Vec<(String, u64)>,
        );
        let (_, _, _, _, _, _, _, witnesses, contexts, _sources): Metadata =
            serde_json::from_slice(bytes)?;
        Ok((witnesses, contexts))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisResultReceiptV1 {
    pub commit_revision: u64,
    pub consumed_cursor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisProcessorResultV1 {
    pub result_id: String,
    pub body: Vec<u8>,
    pub commit_revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisGapV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub commit_revision: u64,
}

#[derive(Clone, Copy)]
pub(in crate::analysis) enum ResultHead<'a> {
    Unchecked,
    Current(Option<&'a super::PackageResultRefV1>),
}

pub(in crate::analysis) struct ProgressWrite {
    pub(in crate::analysis) receipt: AnalysisResultReceiptV1,
    pub(in crate::analysis) relations: Vec<&'static str>,
    pub(in crate::analysis) commit: bool,
    pub(in crate::analysis) contexts: Vec<AnalysisContextRefV1>,
}

#[derive(Default, Deserialize, Serialize)]
pub(in crate::analysis) struct ProfileHeader {
    pub(in crate::analysis) stream_key: Option<Vec<u8>>,
    pub(in crate::analysis) method_version: Option<u64>,
    pub(in crate::analysis) interval_id: Option<String>,
    pub(in crate::analysis) profile_revision: Option<u64>,
    pub(in crate::analysis) facts_revision: Option<u64>,
    pub(in crate::analysis) coverage_revision: Option<u64>,
    pub(in crate::analysis) first_cursor: Option<u64>,
}

impl From<&crate::DiscoveryProfileV1> for ProfileHeader {
    fn from(profile: &crate::DiscoveryProfileV1) -> Self {
        Self {
            stream_key: Some(profile.scope.identity.key()),
            method_version: Some(profile.scope.method_version),
            interval_id: Some(profile.interval_id.clone()),
            profile_revision: Some(profile.revision),
            facts_revision: Some(profile.facts_revision),
            coverage_revision: Some(profile.coverage_revision),
            first_cursor: Some(
                profile
                    .snapshot
                    .coverage
                    .first()
                    .map_or(0, |range| range.first_cursor),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisContextVersionV1, ContextSensitivityV1, EvidenceStoreOutcomeV1,
        ValidatedEvidenceBatchV1,
    };

    fn identity(tenant: u8) -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            ..crate::analysis::tests::identity()
        }
    }

    #[test]
    fn registration_guard_rolls_back() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let scope = ProcessorScopeV1 {
            processor_id: "guarded-processor".into(),
            method_version: 1,
            identity: identity(1),
        };
        let before = store.meta()?;
        let mut notices = store.subscribe_revision();
        let control = std::sync::Arc::new(crate::AnalysisReadControl::default());
        control.check()?;
        let cancelled = std::sync::Arc::clone(&control);
        store.set_commit_hook(
            super::super::AnalysisCommitStage::BeforeResultCommit,
            move || cancelled.cancel(),
        )?;
        assert!(matches!(
            store.register_processor_guarded(&scope, ProcessorClassV1::Required, 1, || {
                control.check()
            }),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, before);
        assert!(store.processor_health(&scope)?.is_none());
        assert!(!notices.has_changed()?);
        let revision =
            store.register_processor_guarded(&scope, ProcessorClassV1::Optional, 1, || Ok(()))?;
        assert!(revision > before.commit_revision);
        notices.borrow_and_update();
        let committed = store.meta()?;
        assert!(matches!(
            store.register_processor_guarded(&scope, ProcessorClassV1::Optional, 1, || {
                control.check()
            }),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, committed);
        assert!(!notices.has_changed()?);
        let health = store.processor_health(&scope)?;
        drop(store);
        let reopened = AnalysisStore::open(root)?;
        assert_eq!(reopened.processor_health(&scope)?, health);
        assert_eq!(
            reopened.register_processor(&scope, ProcessorClassV1::Optional, 1)?,
            revision
        );
        assert_eq!(reopened.meta()?, committed);
        Ok(())
    }

    #[test]
    fn optional_registration_preserves_state() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let scope = ProcessorScopeV1 {
            processor_id: "existing-required".into(),
            method_version: 1,
            identity: identity(1),
        };
        store.accept_validated_batch(
            scope.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        let revision = store.register_processor(&scope, ProcessorClassV1::Required, 2)?;
        let health = store.processor_health(&scope)?;
        let before = store.meta()?;
        let mut notices = store.subscribe_revision();
        assert_eq!(
            store.ensure_optional_processor_guarded(&scope, || Ok(()))?,
            revision
        );
        assert_eq!(store.processor_health(&scope)?, health);
        assert_eq!(store.meta()?, before);
        assert!(!notices.has_changed()?);
        assert_eq!(
            store.register_processor(&scope, ProcessorClassV1::Required, 2)?,
            revision
        );
        assert!(matches!(
            store.register_processor(&scope, ProcessorClassV1::Optional, 1),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        let control = crate::AnalysisReadControl::default();
        control.cancel()?;
        assert!(matches!(
            store.ensure_optional_processor_guarded(&scope, || control.check()),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.processor_health(&scope)?, health);
        assert_eq!(store.meta()?, before);
        assert!(!notices.has_changed()?);
        let missing = ProcessorScopeV1 {
            processor_id: "missing-optional".into(),
            ..scope.clone()
        };
        assert!(matches!(
            store.ensure_optional_processor_guarded(&missing, || control.check()),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert!(store.processor_health(&missing)?.is_none());
        assert_eq!(store.meta()?, before);
        assert!(!notices.has_changed()?);
        let registered = store.ensure_optional_processor_guarded(&missing, || Ok(()))?;
        assert!(registered > revision);
        assert_eq!(
            store
                .processor_health(&missing)?
                .ok_or("optional registration absent")?
                .class,
            ProcessorClassV1::Optional
        );
        let committed = store.meta()?;
        notices.borrow_and_update();
        assert_eq!(
            store.ensure_optional_processor_guarded(&missing, || Ok(()))?,
            registered
        );
        assert_eq!(
            store.register_processor(&missing, ProcessorClassV1::Optional, 1)?,
            registered
        );
        assert_eq!(store.meta()?, committed);
        assert!(!notices.has_changed()?);
        store.retire_required(&crate::ProcessorRetirementV1 {
            scope: scope.clone(),
            change_id: "retire-existing".into(),
            reason: "Stop this required processor.".into(),
            expected_cursor: 1,
            cutoff_cursor: 1,
        })?;
        let retired = store.meta()?;
        let retirement = store.processor_retirement(&scope)?;
        notices.borrow_and_update();
        assert!(matches!(
            store.ensure_optional_processor_guarded(&scope, || Ok(())),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(store.meta()?, retired);
        assert_eq!(store.processor_retirement(&scope)?, retirement);
        assert!(!notices.has_changed()?);
        drop(store);
        let reopened = AnalysisStore::open(root)?;
        assert_eq!(reopened.processor_retirement(&scope)?, retirement);
        assert!(matches!(
            reopened.ensure_optional_processor_guarded(&scope, || Ok(())),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        Ok(())
    }

    #[test]
    fn resume_guard_rolls_back() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        };
        let store = AnalysisStore::open_with_retention(&root, limits)?;
        let scope = ProcessorScopeV1 {
            processor_id: "guarded-processor".into(),
            method_version: 1,
            identity: identity(1),
        };
        store.accept_validated_batch(
            scope.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        assert_eq!(
            crate::EvidenceRetentionOwner::new(&store)
                .step(100)?
                .removed_records,
            1
        );
        let before = store.meta()?;
        let health = store.processor_health(&scope)?;
        let mut notices = store.subscribe_revision();
        let control = std::sync::Arc::new(crate::AnalysisReadControl::default());
        control.check()?;
        let cancelled = std::sync::Arc::clone(&control);
        store.set_commit_hook(
            super::super::AnalysisCommitStage::BeforeResultCommit,
            move || cancelled.cancel(),
        )?;
        assert!(matches!(
            store.resume_optional_guarded(&scope, || control.check()),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, before);
        assert_eq!(store.processor_health(&scope)?, health);
        assert!(store.processor_gaps(&scope, 0)?.is_empty());
        assert!(!notices.has_changed()?);
        let gap = store
            .resume_optional_guarded(&scope, || Ok(()))?
            .ok_or("resume gap absent")?;
        assert_eq!((gap.first_cursor, gap.last_cursor), (1, 1));
        assert_eq!(store.processor_gaps(&scope, 0)?, [gap]);
        notices.borrow_and_update();
        let committed = store.meta()?;
        assert!(matches!(
            store.resume_optional_guarded(&scope, || control.check()),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, committed);
        assert!(!notices.has_changed()?);
        drop(store);
        let reopened = AnalysisStore::open_with_retention(root, limits)?;
        assert_eq!(reopened.processor_gaps(&scope, 0)?, [gap]);
        assert_eq!(reopened.resume_optional(&scope)?, None);
        assert_eq!(reopened.meta()?, committed);
        Ok(())
    }

    #[test]
    fn analysis_store_result_progress() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let source = identity(1);
        let scope = ProcessorScopeV1 {
            processor_id: "security-file".into(),
            method_version: 1,
            identity: source.clone(),
        };
        assert_eq!(
            store.register_processor(&scope, ProcessorClassV1::Required, 1)?,
            1
        );
        assert_eq!(
            store.register_processor(&scope, ProcessorClassV1::Required, 1)?,
            1
        );
        assert!(matches!(
            store.register_processor(&scope, ProcessorClassV1::Optional, 1),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(
            store.accept_validated_batch(
                source.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 1,
                    last_cursor: 1,
                    intake_utc_ns: 1_000_000_000,
                    framed_records: b"frame".to_vec().into(),
                    frame_ends: vec![5],
                },
            )?,
            EvidenceStoreOutcomeV1::Accepted
        );
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: source.tenant_id,
                owner_id: "policy".into(),
                entity_key: b"workload".to_vec(),
                lifetime_key: b"pod".to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: Some(1),
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"verified-context".to_vec(),
        };
        let context_revision = store.commit_context(&context)?;
        let mut input = AnalysisResultCommitV1 {
            context_revision,
            body: b"result".to_vec(),
            created_utc_ns: 1_000_000_000,
            witnesses: vec![AnalysisWitnessV1 {
                identity: source.into(),
                cursor: 1,
                expires_utc_ns: 1_000_000_001,
            }],
            context_refs: vec![AnalysisContextRefV1 {
                key: context.key.clone(),
                commit_revision: context_revision,
            }],
            ..crate::analysis::tests::result(scope, "finding-1".into())
        };
        let mut invalid = input.clone();
        assert!(store.processor_result(&input.scope)?.is_none());
        invalid.body.clear();
        assert!(store.commit_result(&invalid).is_err());
        invalid = input.clone();
        invalid.context_refs[0].commit_revision = 0;
        let before = store.meta()?;
        assert!(matches!(
            store.commit_result(&invalid),
            Err(crate::Error::AnalysisState { .. })
        ));
        assert_eq!(store.meta()?, before);
        let receipt = store.commit_result(&input)?;
        assert_eq!(receipt.commit_revision, 4);
        assert_eq!(receipt.consumed_cursor, 1);
        let head = AnalysisProcessorResultV1 {
            result_id: input.result_id.clone(),
            body: input.body.clone(),
            commit_revision: receipt.commit_revision,
        };
        assert_eq!(store.processor_result(&input.scope)?, Some(head.clone()));
        let mut foreign = input.scope.clone();
        foreign.identity.tenant_id = [4; 16];
        assert!(store.processor_result(&foreign)?.is_none());
        assert_eq!(
            store.read_result([1; 16], "finding-1")?,
            Some(b"result".to_vec())
        );
        assert_eq!(store.read_result([4; 16], "finding-1")?, None);
        assert_eq!(store.read_result([1; 16], "missing")?, None);
        assert_eq!(store.commit_result(&input)?, receipt);
        assert_eq!(store.meta()?.commit_revision, 4);
        {
            let reader = store.reader()?;
            let (request, body): (Vec<u8>, Vec<u8>) = reader.get()?.query_row(
                "SELECT request_meta, body FROM analysis_results WHERE result_id = ?",
                params![input.result_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(request, input.request_meta()?);
            assert_eq!(body, input.body);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&request)?,
                serde_json::json!([
                    input.scope,
                    input.expected_cursor,
                    input.consumed_cursor,
                    input.coverage_revision,
                    input.context_revision,
                    input.result_id,
                    input.created_utc_ns,
                    input.witnesses,
                    input.context_refs,
                    [],
                ])
            );
        }
        for change in 0..16 {
            let mut changed = input.clone();
            match change {
                0 => changed.scope.processor_id.push('x'),
                1 => changed.scope.method_version += 1,
                2 => changed.scope.identity.node_id.push('x'),
                3 => changed.expected_cursor += 1,
                4 => changed.consumed_cursor += 1,
                5 => changed.coverage_revision += 1,
                6 => changed.context_revision += 1,
                7 => changed.body.push(0),
                8 => changed.created_utc_ns += 1,
                9 => changed.witnesses[0].expires_utc_ns += 1,
                10 => changed.witnesses[0].cursor += 1,
                11 => changed.witnesses.clear(),
                12 => changed.context_refs[0].commit_revision += 1,
                13 => changed.context_refs[0].key.owner_revision += 1,
                14 => changed.context_refs.clear(),
                _ => {
                    changed.scope.identity.tenant_id = [4; 16];
                    changed.witnesses.clear();
                    changed.context_refs.clear();
                }
            }
            assert!(
                matches!(
                    store.commit_result(&changed),
                    Err(crate::Error::AnalysisConflict { .. })
                ),
                "changed request component {change}"
            );
            assert_eq!(store.meta()?.commit_revision, 4);
        }
        let path = directory.path().join("analysis");
        drop(store);
        let store = AnalysisStore::open(path)?;
        assert_eq!(store.processor_result(&input.scope)?, Some(head));
        assert_eq!(store.commit_result(&input)?, receipt);
        input.result_id = "finding-2".into();
        assert!(matches!(
            store.commit_result(&input),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(store.meta()?.commit_revision, 4);
        input.expected_cursor = 1;
        input.context_refs[0].commit_revision += 1;
        assert!(store.commit_result(&input).is_err());
        input.context_refs[0].commit_revision -= 1;
        input.witnesses[0].identity = identity(4).into();
        assert!(store.commit_result(&input).is_err());
        assert_eq!(store.meta()?.commit_revision, 4);
        store.writer()?.get()?.execute(
            "UPDATE analysis_results SET body = ? WHERE result_id = ?",
            params![b"".as_slice(), "finding-1"],
        )?;
        assert!(matches!(
            store.read_result([1; 16], "finding-1"),
            Err(crate::Error::AnalysisState { .. })
        ));
        Ok(())
    }

    #[test]
    fn observability_recovery_mixed_witnesses()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::{
            AnalysisReadControl, EvidenceRetentionOwner, RetentionLimitsV1, TraceBatchV1,
            TraceBindingV1, TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
            TraceIntentV1, TraceSourceV1, TraceTerminalReasonV1, TraceTerminalV1,
        };

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(100),
            raw_max_bytes: Some(64 * 1024 * 1024),
        };
        let store = AnalysisStore::open_with_retention(&root, limits)?;
        let evidence = identity(1);
        store.accept_validated_batch(
            evidence.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 100,
                framed_records: b"event".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        let scope = ProcessorScopeV1 {
            processor_id: "mixed-witness".into(),
            method_version: 1,
            identity: evidence.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
        let diagnostic = TraceIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            request_id: [7; 16],
            execution_id: [8; 16],
            source_sha256: source.sha256,
        };
        store.accept_trace(&TraceIntentV1 {
            tenant_id: [1; 16],
            request_id: diagnostic.request_id,
            source,
            bindings: vec![TraceBindingV1 {
                binding_id: [9; 16],
                identity: diagnostic.clone(),
                namespace_uid: "namespace-a".into(),
            }],
            authority: b"Control-owned inputs".to_vec(),
            accepted_unix_ns: 100,
            deadline_unix_ns: 1_000_000_000,
            host_sensitive: true,
        })?;
        let frame = TraceFrameV1 {
            execution_id: diagnostic.execution_id,
            sequence: 1,
            kind: TraceFrameKindV1::Data,
            bytes: b"raw\n".to_vec(),
        };
        let terminal = TraceTerminalV1 {
            execution_id: diagnostic.execution_id,
            reason: TraceTerminalReasonV1::Completed,
            last_sequence: 1,
            output_bytes: 4,
            output_incomplete: false,
            kernel_lost_events: None,
            ready_at_unix_ns: None,
            exit_code: Some(0),
            forced_kill: false,
            cleanup: TraceCleanupV1::Unknown,
        };
        store.append_trace(
            &diagnostic,
            &TraceBatchV1 {
                execution_id: diagnostic.execution_id,
                frames: vec![frame.clone()],
                terminal: Some(terminal.clone()),
            },
            100,
        )?;
        let input = AnalysisResultCommitV1 {
            body: b"result".to_vec(),
            created_utc_ns: 101,
            witnesses: vec![
                AnalysisWitnessV1 {
                    identity: evidence.into(),
                    cursor: 1,
                    expires_utc_ns: 300,
                },
                AnalysisWitnessV1 {
                    identity: diagnostic.clone().into(),
                    cursor: 2,
                    expires_utc_ns: 300,
                },
            ],
            ..crate::analysis::tests::result(scope, "mixed-result".into())
        };
        let mut invalid = input.clone();
        invalid.witnesses[1].cursor = 3;
        assert!(store.commit_result(&invalid).is_err());
        invalid.witnesses[1].cursor = 2;
        invalid.witnesses[1].identity = TraceIdentityV1 {
            source_sha256: [9; 32],
            ..diagnostic.clone()
        }
        .into();
        assert!(store.commit_result(&invalid).is_err());
        invalid.witnesses[1].identity = TraceIdentityV1 {
            tenant_id: [9; 16],
            ..diagnostic.clone()
        }
        .into();
        assert!(store.commit_result(&invalid).is_err());
        assert!(store.read_result([1; 16], "mixed-result")?.is_none());
        let receipt = store.commit_result(&input)?;
        let retained = EvidenceRetentionOwner::new(&store).retain_trace(&diagnostic, 201)?;
        assert_eq!(retained.removed_records, 0);
        assert_eq!(retained.retained_floor, 0);
        drop(store);

        let store = AnalysisStore::open_with_retention(&root, limits)?;
        assert_eq!(store.commit_result(&input)?, receipt);
        assert_eq!(
            store.read_result([1; 16], "mixed-result")?,
            Some(b"result".to_vec())
        );
        let output = store.read_trace(&diagnostic, 1, &AnalysisReadControl::default())?;
        assert_eq!(output.frames, vec![frame]);
        assert_eq!(output.terminal, Some(terminal));
        let expired = EvidenceRetentionOwner::new(&store).retain_trace(&diagnostic, 301)?;
        assert_eq!(expired.removed_records, 2);
        assert_eq!(expired.retained_floor, 2);
        assert!(matches!(
            store.read_trace(&diagnostic, 1, &AnalysisReadControl::default()),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert_eq!(store.commit_result(&input)?, receipt);
        Ok(())
    }
}

impl AnalysisContextRefV1 {
    pub(in crate::analysis) fn join(
        before: &[AnalysisContextRefV1],
        after: &[AnalysisContextRefV1],
    ) -> Result<Vec<AnalysisContextRefV1>> {
        let mut values = std::collections::BTreeMap::new();
        for value in before.iter().chain(after) {
            if values
                .insert(value.key.clone(), value.clone())
                .is_some_and(|prior| prior != *value)
            {
                return Err(crate::PackageErrorCodeV1::Conflict.error("derived immutable context"));
            }
        }
        Ok(values.into_values().collect())
    }
}
