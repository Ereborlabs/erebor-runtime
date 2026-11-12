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
