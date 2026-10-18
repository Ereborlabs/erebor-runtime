use std::collections::BTreeMap;

use araphor_data::analysis::PreparedProfile;
use araphor_data::{
    AnalysisContextRefV1, AnalysisGapV1, AnalysisResultCommitV1, DiscoveryProfileV1,
    DiscoverySnapshotRowV1, EvidenceIntakeIdentityV1, PackageErrorCodeV1 as Code, ProcessorClassV1,
    ProcessorScopeV1, DISCOVERY_PROCESSOR, DISCOVERY_SCHEMA_VERSION,
};
use araphor_query::follow::Update;
use serde::Deserialize;

use crate::{Package, Result};

#[derive(Deserialize)]
pub(super) struct Publication {
    source: EvidenceIntakeIdentityV1,
    expected_cursor: u64,
    consumed_cursor: u64,
    current_result_id: Option<String>,
    result_commit_revision: Option<u64>,
    processor_present: bool,
    retired: Option<bool>,
    retained_floor: u64,
    coverage_revision: u64,
    interval_id: Option<String>,
    profile_revision: Option<u64>,
    facts_revision: Option<u64>,
    created_utc_ns: Option<u64>,
    sealed: Option<bool>,
    input_bytes: Option<u64>,
    incomplete: Option<bool>,
    gaps: Option<Vec<AnalysisGapV1>>,
    context_refs: Option<Vec<AnalysisContextRefV1>>,
    snapshot: DiscoverySnapshotRowV1,
}

impl Publication {
    pub(super) fn commit(self, package: &Package, update: &Update) -> Result<usize> {
        package.selection(Some(&self.source))?;
        let selection = &update.snapshot.selection;
        if self.source.tenant_id != selection.tenant_id
            || (!selection.sources.is_all() && !selection.sources.as_slice().contains(&self.source))
            || (!selection.nodes.is_empty() && !selection.nodes.contains(&self.source.node_id))
        {
            return Err(Code::Denied.error("captured discovery source").into());
        }

        let scope = ProcessorScopeV1 {
            processor_id: DISCOVERY_PROCESSOR.into(),
            method_version: u64::from(DISCOVERY_SCHEMA_VERSION),
            identity: self.source.clone(),
        };
        let store = package.query.store();
        if self.retired == Some(true) {
            return Ok(0);
        }
        if !self.processor_present {
            package.commit(|| {
                store.register_processor_guarded(&scope, ProcessorClassV1::Optional, 1, || {
                    package.grant.remaining().map(|_| ())
                })
            })?;
            return Ok(0);
        }
        if self.expected_cursor < self.retained_floor {
            package.commit(|| {
                store.resume_optional_guarded(&scope, || package.grant.remaining().map(|_| ()))
            })?;
            return Ok(0);
        }
        let snapshot = self.snapshot.into_snapshot()?;
        if snapshot.tenant_id != self.source.tenant_id
            || snapshot
                .coverage
                .iter()
                .any(|range| range.stream != self.source)
            || self.consumed_cursor < self.expected_cursor
        {
            return Err(Code::Invalid.error("SQL discovery publication").into());
        }
        let now = update.evaluated_utc_ns;
        let mut refs = BTreeMap::new();
        for reference in self
            .context_refs
            .into_iter()
            .flatten()
            .chain(update.snapshot.contexts().cloned())
            .chain(std::iter::once(package.context.clone()))
        {
            if let Some(previous) = refs.insert(reference.key.clone(), reference.clone()) {
                if previous != reference {
                    return Err(Code::Conflict.error("captured context revision").into());
                }
            }
        }
        let context_refs = refs.into_values().collect::<Vec<_>>();
        let facts = context_refs
            .iter()
            .filter(|reference| reference.key.owner_id.starts_with("mithril-control/"))
            .map(|reference| reference.commit_revision)
            .max()
            .unwrap_or(self.facts_revision.unwrap_or(0));
        let continuing = self.current_result_id.is_some() && self.sealed != Some(true);
        let profile_id = if continuing {
            self.current_result_id
                .ok_or_else(|| Code::Invalid.error("SQL current result"))?
        } else {
            format!("discovery:{}", uuid::Uuid::new_v4())
        };
        let revision = if continuing {
            self.profile_revision
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| Code::Invalid.error("profile revision"))?
        } else {
            1
        };
        let profile = DiscoveryProfileV1 {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            scope: scope.clone(),
            interval_id: if continuing {
                self.interval_id.unwrap_or_else(|| profile_id.clone())
            } else {
                profile_id.clone()
            },
            profile_id: profile_id.clone(),
            revision,
            facts_revision: facts,
            coverage_revision: self.coverage_revision,
            created_utc_ns: if continuing {
                self.created_utc_ns.unwrap_or(now)
            } else {
                now
            },
            updated_utc_ns: now,
            sealed: false,
            input_bytes: self.input_bytes.unwrap_or(0),
            incomplete: self.incomplete.unwrap_or(false),
            gaps: self.gaps.unwrap_or_default(),
            snapshot,
            context_refs: context_refs.clone(),
        };
        let commit = AnalysisResultCommitV1 {
            scope,
            expected_cursor: self.expected_cursor,
            consumed_cursor: self.consumed_cursor,
            coverage_revision: self.coverage_revision,
            context_revision: context_refs
                .iter()
                .map(|reference| reference.commit_revision)
                .max()
                .unwrap_or(0),
            result_id: profile_id,
            body: Vec::new(),
            created_utc_ns: now,
            witnesses: Vec::new(),
            context_refs,
        };
        let prepared = PreparedProfile::new(profile)?;
        package.commit(|| {
            store.commit_working_profile_guarded(
                commit,
                prepared,
                continuing.then_some(self.result_commit_revision).flatten(),
                || package.grant.remaining().map(|_| ()),
            )
        })?;
        usize::try_from(self.consumed_cursor - self.expected_cursor)
            .map_err(|_| Code::Invalid.error("discovery consumed count").into())
    }
}
