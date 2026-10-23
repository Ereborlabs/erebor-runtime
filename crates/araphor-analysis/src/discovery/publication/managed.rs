use std::collections::BTreeMap;

use araphor_data::analysis::{PackageResultRefV1, PreparedProfile, ProfileCommit};
use araphor_data::{
    AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisGapV1, AnalysisReadControl,
    AnalysisResultCommitV1, DiscoveryHistoryRowV1, DiscoveryProfileV1, DiscoverySnapshotRowV1,
    EvidenceIntakeIdentityV1, ManagedDestination, PackageBundleRef, PackageErrorCodeV1 as Code,
    ProcessorScopeV1, DISCOVERY_PROCESSOR, DISCOVERY_SCHEMA_VERSION,
};
use araphor_query::definition::{ExecutionReceipt, PackageCall, PreparedDefinition};
use araphor_query::follow::WindowSource;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;

use super::Publication;
use crate::DiscoveryOwner;

pub(crate) struct ProfileConversion {
    pub(crate) packet: Option<ProfileCommit>,
    pub(crate) replan: bool,
    _memory: MemoryReservation,
}

#[derive(serde::Deserialize)]
struct ProfileState {
    #[serde(with = "serde_bytes")]
    tenant_id: [u8; 16],
    node_id: String,
    #[serde(with = "serde_bytes")]
    node_boot_id: [u8; 16],
    label_epoch: u64,
    #[serde(with = "serde_bytes")]
    source_id: [u8; 16],
    source_epoch: u64,
    retained_floor: u64,
    coverage_revision: Option<u64>,
    processor_present: bool,
    consumed_cursor: Option<u64>,
    resume_floor: Option<u64>,
    retired: Option<bool>,
    current_result_id: Option<String>,
    result_commit_revision: Option<u64>,
    current_compatible: bool,
    interval_id: Option<String>,
    profile_revision: Option<u64>,
    facts_revision: Option<u64>,
    created_utc_ns: Option<u64>,
    updated_utc_ns: Option<u64>,
    sealed: Option<bool>,
    input_bytes: Option<u64>,
    incomplete: Option<bool>,
    gaps: Option<Vec<AnalysisGapV1>>,
    context_refs: Option<Vec<AnalysisContextRefV1>>,
    snapshot: Option<DiscoverySnapshotRowV1>,
    #[serde(default)]
    history: Vec<DiscoveryHistoryRowV1>,
}

impl DiscoveryOwner {
    pub(crate) fn convert_profile(
        session: &araphor_query::execution::Session,
        prepared: &PreparedDefinition,
        destination: &ManagedDestination,
        receipt: &ExecutionReceipt,
        context: &TaskContext,
        control: &AnalysisReadControl,
    ) -> araphor_query::Result<ProfileConversion> {
        let ManagedDestination::DiscoveryProfile {
            source,
            call,
            output,
        } = destination
        else {
            return Err(Code::Invalid.error("profile destination").into());
        };
        control.check()?;
        let mut selected = None;
        PackageCall::any(&prepared.plan, &mut |candidate| {
            if candidate.id() == *call && candidate.output() == output {
                selected = Some(candidate.clone());
            }
            Ok(false)
        })
        .map_err(|source| araphor_query::Error::Sql { source })?;
        let selected = selected.ok_or_else(|| Code::Invalid.error("profile selected call"))?;
        let returned = receipt
            .calls()
            .get(call)
            .filter(|returned| returned.belongs_to(&selected))
            .ok_or_else(|| Code::Denied.error("profile returned call"))?;
        if receipt.calls().values().any(|returned| {
            let output = returned.output();
            output.checkpoint.is_some() || !output.reasons.is_empty() || !output.evidence.is_empty()
        }) {
            return Err(Code::Unsupported.error("discovery auxiliary return").into());
        }
        let data = returned
            .output()
            .datasets
            .iter()
            .find(|data| data.name == *output)
            .ok_or_else(|| Code::Invalid.error("profile returned output"))?;
        let source_capture = context
            .session_config()
            .get_extension::<araphor_query::sources::SourceSnapshot>()
            .ok_or_else(|| Code::Incomplete.error("profile captured source"))?;
        let memory = session
            .memory()
            .reserve_input(
                data.allocated_bytes()
                    .checked_mul(2)
                    .ok_or_else(|| Code::Limit.error("profile decoded bytes"))?,
            )
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let mut rows = Vec::new();
        for batch in &data.batches {
            rows.extend(Publication::decode::<Publication>(batch)?);
        }
        if rows.len() > 1 || rows.first().is_some_and(|row| &row.source != source) {
            return Err(Code::Invalid.error("profile output source").into());
        }
        let mut contexts = Vec::new();
        for (bundle, digest) in prepared.images().filter(|(bundle, digest)| {
            bundle.root == selected.image().image && *digest == selected.image().digest
        }) {
            contexts.push(PackageBundleRef::retained(bundle, digest).context(
                source.tenant_id,
                selected.package(),
                selected.export(),
                output,
            )?);
        }
        if contexts.len() != 1 {
            return Err(Code::Denied.error("profile image attribution").into());
        }
        let mut captured = source_capture
            .with_table("discovery_state", |_, batches| {
                let bytes = batches.iter().try_fold(0usize, |bytes, batch| {
                    bytes
                        .checked_add(batch.get_array_memory_size().saturating_mul(2))
                        .ok_or_else(|| {
                            datafusion::common::DataFusionError::ResourcesExhausted(
                                "profile state bytes".into(),
                            )
                        })
                })?;
                memory.try_grow(bytes)?;
                batches
                    .iter()
                    .map(Publication::decode::<ProfileState>)
                    .collect::<araphor_query::Result<Vec<_>>>()
                    .map(|rows| rows.into_iter().flatten().collect::<Vec<_>>())
                    .map_err(|source| {
                        datafusion::common::DataFusionError::External(Box::new(source))
                    })
            })
            .map_err(|source| araphor_query::Error::Sql { source })?;
        if captured.len() != 1 {
            return Err(Code::Invalid.error("profile captured state count").into());
        }
        let mut state = captured
            .pop()
            .ok_or_else(|| Code::Incomplete.error("profile captured state"))?;
        let head = Publication::previous(&state, source)?;
        let history = std::mem::take(&mut state.history);
        let code_changed = state.sealed == Some(false)
            && state.current_result_id.is_some()
            && !state.current_compatible;
        let completed = receipt
            .completed_windows()
            .iter()
            .any(|window| match window.source {
                WindowSource::Query => true,
                WindowSource::Input { call: owner, .. } => owner == *call,
            });
        let close_current = completed
            && state.sealed != Some(true)
            && (rows.is_empty()
                || rows
                    .first()
                    .is_some_and(|row| row.repair || row.notice_only));
        let row = if code_changed || close_current {
            Publication::from_state(state, source)?
        } else {
            rows.pop()
        };
        let repairing = row.as_ref().is_some_and(|row| row.repair);
        let pending = row.as_ref().is_some_and(|row| {
            history.iter().any(|prior| {
                !(row.repair && row.current_result_id.as_deref() == Some(prior.result_id.as_str()))
                    && (prior.notice_facts_revision < row.notice_facts_revision
                        || prior.notice_coverage_revision < row.notice_coverage_revision)
            })
        });
        let packet = row
            .map(|row| {
                let prior = if row.repair {
                    Some(
                        history
                            .iter()
                            .find(|prior| {
                                row.current_result_id.as_deref() == Some(prior.result_id.as_str())
                                    && row.result_commit_revision == Some(prior.commit_revision)
                            })
                            .ok_or_else(|| Code::Denied.error("profile captured history"))?,
                    )
                } else {
                    None
                };
                row.prepare(
                    source,
                    head,
                    prior,
                    receipt.snapshot(),
                    completed || code_changed || repairing,
                    if code_changed { Vec::new() } else { contexts },
                )
            })
            .transpose()?;
        Ok(ProfileConversion {
            packet,
            replan: code_changed || close_current || pending,
            _memory: memory,
        })
    }
}

impl Publication {
    pub(in crate::discovery) fn replay_snapshot(
        data: &araphor_analysis_sdk::Dataset,
        source: &EvidenceIntakeIdentityV1,
    ) -> araphor_query::Result<araphor_data::BehaviorSnapshotV1> {
        let mut rows = Vec::new();
        for batch in &data.batches {
            rows.extend(Self::decode::<Self>(batch)?);
        }
        if rows.len() != 1 || rows[0].source != *source {
            return Err(Code::Invalid.error("discovery replay source").into());
        }
        rows.pop()
            .ok_or_else(|| Code::Missing.error("discovery replay snapshot"))?
            .snapshot
            .into_snapshot()
            .map_err(Into::into)
    }

    fn decode<T: serde::de::DeserializeOwned>(
        batch: &araphor_analysis_sdk::RecordBatch,
    ) -> araphor_query::Result<Vec<T>> {
        serde_arrow::from_record_batch(batch).map_err(|source| {
            araphor_data::Error::DiscoveryContext {
                source: Box::new(source),
                location: snafu::location!(),
            }
            .into()
        })
    }

    fn previous(
        state: &ProfileState,
        source: &EvidenceIntakeIdentityV1,
    ) -> araphor_query::Result<Option<PackageResultRefV1>> {
        if state.tenant_id != source.tenant_id
            || state.node_id != source.node_id
            || state.node_boot_id != source.node_boot_id
            || state.label_epoch != source.label_epoch
            || state.source_id != source.source_id
            || state.source_epoch != source.source_epoch
        {
            return Err(Code::Denied
                .error("profile captured source identity")
                .into());
        }
        match (&state.current_result_id, state.result_commit_revision) {
            (Some(id), Some(revision)) => Ok(Some(PackageResultRefV1 {
                result_id: id.clone(),
                commit_revision: revision,
            })),
            (None, None) => Ok(None),
            _ => Err(Code::Invalid.error("profile captured head").into()),
        }
    }

    fn from_state(
        mut state: ProfileState,
        source: &EvidenceIntakeIdentityV1,
    ) -> araphor_query::Result<Option<Self>> {
        let Some(snapshot) = state.snapshot.take().filter(|_| state.sealed != Some(true)) else {
            return Ok(None);
        };
        let cursor = state
            .consumed_cursor
            .unwrap_or(0)
            .max(state.resume_floor.unwrap_or(0));
        Ok(Some(Self {
            source: source.clone(),
            current_result_id: state.current_result_id,
            result_commit_revision: state.result_commit_revision,
            repair: false,
            notice_only: false,
            notice_facts_revision: 0,
            notice_coverage_revision: 0,
            expected_cursor: cursor,
            consumed_cursor: cursor,
            processor_present: state.processor_present,
            retired: state.retired,
            retained_floor: state.retained_floor,
            coverage_revision: state
                .coverage_revision
                .ok_or_else(|| Code::Invalid.error("prior profile coverage"))?,
            interval_id: state.interval_id,
            profile_revision: state.profile_revision,
            facts_revision: state.facts_revision,
            created_utc_ns: state.created_utc_ns,
            updated_utc_ns: state.updated_utc_ns,
            sealed: state.sealed,
            input_bytes: state.input_bytes,
            incomplete: state.incomplete,
            gaps: state.gaps,
            context_refs: state.context_refs,
            snapshot,
        }))
    }

    fn prepare(
        self,
        source: &EvidenceIntakeIdentityV1,
        head: Option<PackageResultRefV1>,
        prior: Option<&DiscoveryHistoryRowV1>,
        snapshot: &araphor_query::sources::ArrowSnapshot,
        sealed: bool,
        contexts: Vec<AnalysisContextVersionV1>,
    ) -> araphor_query::Result<ProfileCommit> {
        let now = snapshot.time_utc_ns();
        let previous = if let Some(prior) = prior {
            Some(PackageResultRefV1 {
                result_id: prior.result_id.clone(),
                commit_revision: prior.commit_revision,
            })
        } else {
            head.clone()
        };
        if self.source != *source
            || !self.processor_present
            || self.retired == Some(true)
            || self.expected_cursor < self.retained_floor
            || self.consumed_cursor < self.expected_cursor
            || previous
                .as_ref()
                .is_some_and(|previous| !snapshot.results().any(|reference| reference == previous))
        {
            return Err(Code::Conflict.error("profile captured progress").into());
        }
        if let Some(prior) = prior {
            if (!self.notice_only && !prior.compatible)
                || self.interval_id.as_ref() != Some(&prior.interval_id)
                || self.profile_revision != Some(prior.profile_revision)
                || self.created_utc_ns != Some(prior.created_utc_ns)
                || self.updated_utc_ns != Some(prior.updated_utc_ns)
                || self.input_bytes != Some(prior.input_bytes)
                || self.incomplete != Some(prior.incomplete)
                || self.gaps.as_ref() != Some(&prior.gaps)
                || self.context_refs.as_ref() != Some(&prior.context_refs)
                || self.expected_cursor != self.consumed_cursor
                || (self.notice_only
                    && (self.snapshot != prior.snapshot
                        || self.facts_revision != Some(prior.facts_revision)))
            {
                return Err(Code::Conflict.error("profile historical transition").into());
            }
        }
        let scope = ProcessorScopeV1 {
            processor_id: DISCOVERY_PROCESSOR.into(),
            method_version: u64::from(DISCOVERY_SCHEMA_VERSION),
            identity: source.clone(),
        };
        let continuing = previous.is_some()
            && (self.notice_only || prior.is_some() || self.sealed != Some(true));
        let notice = self
            .notice_only
            .then_some((self.notice_facts_revision, self.notice_coverage_revision));
        let contexts = if self.notice_only {
            Vec::new()
        } else {
            contexts
        };
        let captured = if contexts.is_empty() {
            Vec::new()
        } else {
            snapshot.contexts().cloned().collect()
        };
        let mut refs = BTreeMap::new();
        for reference in self.context_refs.into_iter().flatten().chain(captured) {
            if refs
                .insert(reference.key.clone(), reference.clone())
                .is_some_and(|previous| previous != reference)
            {
                return Err(Code::Conflict.error("profile context identity").into());
            }
        }
        let refs = refs.into_values().collect::<Vec<_>>();
        let id = if self.notice_only {
            previous
                .as_ref()
                .ok_or_else(|| Code::Invalid.error("profile notice reference"))?
                .result_id
                .clone()
        } else {
            format!("discovery:{}", uuid::Uuid::new_v4())
        };
        let profile = DiscoveryProfileV1 {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            scope: scope.clone(),
            profile_id: id.clone(),
            interval_id: if continuing {
                self.interval_id
                    .ok_or_else(|| Code::Invalid.error("profile interval"))?
            } else {
                id.clone()
            },
            revision: if self.notice_only {
                self.profile_revision
                    .ok_or_else(|| Code::Invalid.error("profile notice revision"))?
            } else if continuing {
                self.profile_revision
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| Code::Invalid.error("profile revision"))?
            } else {
                1
            },
            facts_revision: if self.notice_only {
                self.facts_revision.unwrap_or(0)
            } else {
                refs.iter()
                    .filter(|reference| reference.key.owner_id.starts_with("mithril-control/"))
                    .map(|reference| reference.commit_revision)
                    .max()
                    .unwrap_or(self.facts_revision.unwrap_or(0))
            },
            coverage_revision: if self.notice_only {
                prior.map_or(self.coverage_revision, |prior| prior.coverage_revision)
            } else {
                self.coverage_revision
            },
            created_utc_ns: if continuing {
                self.created_utc_ns
                    .ok_or_else(|| Code::Invalid.error("profile creation time"))?
            } else {
                now
            },
            updated_utc_ns: if self.notice_only {
                self.updated_utc_ns
                    .ok_or_else(|| Code::Invalid.error("profile notice time"))?
            } else {
                now.max(self.updated_utc_ns.unwrap_or(0))
            },
            sealed,
            input_bytes: self.input_bytes.unwrap_or(0),
            incomplete: self.incomplete.unwrap_or(false),
            gaps: self.gaps.unwrap_or_default(),
            snapshot: self.snapshot.into_snapshot()?,
            context_refs: refs.clone(),
        };
        let request = AnalysisResultCommitV1 {
            scope,
            expected_cursor: self.expected_cursor,
            consumed_cursor: self.consumed_cursor,
            coverage_revision: self.coverage_revision,
            context_revision: refs
                .iter()
                .map(|reference| reference.commit_revision)
                .max()
                .unwrap_or(0),
            result_id: id,
            body: Vec::new(),
            created_utc_ns: now,
            witnesses: Vec::new(),
            context_refs: refs,
        };
        Ok(ProfileCommit {
            request,
            profile: PreparedProfile::captured(profile, contexts)?,
            previous,
            head,
            notice,
        })
    }
}
