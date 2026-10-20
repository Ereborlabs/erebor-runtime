use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::*;
use araphor_query::execution::Engine;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::Result;

mod codec;
mod selection;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContextLimits {
    pub document_bytes: Option<usize>,
    pub evidence: Option<usize>,
    pub owner_facts: Option<usize>,
    pub source_documents: Option<usize>,
    pub handles: Option<usize>,
    pub conflict_handles: Option<usize>,
    pub packet_bytes: Option<usize>,
    pub documents: Option<usize>,
    pub revisions: Option<usize>,
}

pub struct Context {
    query: Arc<Engine>,
    limits: ContextLimits,
}

impl Context {
    pub fn new(query: Arc<Engine>) -> Self {
        Self {
            query,
            limits: ContextLimits::default(),
        }
    }

    pub fn set_limits(&mut self, limits: ContextLimits) {
        self.limits = limits;
    }

    pub fn import_context(
        &self,
        access: &DiscoveryContextAccessV1,
        revision: &DiscoveryContextRevisionV1,
    ) -> Result<AnalysisContextRefV1> {
        access.validate()?;
        revision.validate()?;
        self.document_bytes(revision)?;
        Self::require(
            access.can_import
                && access.permits(&revision.document)
                && (revision.document.trust() != DiscoveryContextTrustV1::Reviewed
                    || (access.can_review
                        && revision.document.approver.as_deref()
                            == Some(access.principal.as_str()))),
            "context import authorization",
        )?;
        let context = AnalysisContextVersionV1::try_from(revision)?;
        let commit_revision = self.query.store().commit_context(&context)?;
        Ok(AnalysisContextRefV1 {
            key: context.key,
            commit_revision,
        })
    }

    fn require(valid: bool, field: &'static str) -> araphor_data::Result<()> {
        if valid {
            Ok(())
        } else {
            DiscoveryInvalidSnafu { field }.fail()
        }
    }

    fn document_bytes(&self, revision: &DiscoveryContextRevisionV1) -> Result<()> {
        if let Some(limit) = self.limits.document_bytes {
            serde_json::to_writer(InputByteLimit(limit), revision)
                .context(DiscoveryEncodingSnafu)?;
        }
        Ok(())
    }

    fn json(value: &impl Serialize) -> araphor_data::Result<String> {
        serde_json::to_string(value).context(DiscoveryEncodingSnafu)
    }

    fn decode<T: serde::de::DeserializeOwned>(value: &str) -> araphor_data::Result<T> {
        serde_json::from_str(value).context(DiscoveryEncodingSnafu)
    }

    fn missing(view: &mut DiscoveryContextViewV1) {
        for (kind, reason) in [
            (
                DiscoveryContextFactKindV1::SourceHealth,
                "SOURCE_HEALTH_UNAVAILABLE",
            ),
            (
                DiscoveryContextFactKindV1::PolicyProvenance,
                "POLICY_PROVENANCE_UNAVAILABLE",
            ),
        ] {
            if !view.owner_facts.iter().any(|fact| fact.kind == kind) {
                view.missing_facts.push(reason.into());
            }
        }
        if view.records.is_empty() {
            view.missing_facts
                .push("NO_QUALIFIED_SUBJECT_EVIDENCE".into());
        }
        view.missing_facts.sort();
        view.missing_facts.dedup();
    }

    fn packet(&self, view: &mut DiscoveryContextViewV1) -> Result<()> {
        Self::missing(view);
        let Some(limit) = self.limits.packet_bytes else {
            return Ok(());
        };
        while serde_json::to_writer(InputByteLimit(limit), &view).is_err() {
            let reason = if view.documents.pop().is_some() {
                "PACKET_DOCUMENT_BYTES"
            } else if view.records.pop().is_some() {
                "PACKET_EVIDENCE_BYTES"
            } else {
                Self::require(view.owner_facts.pop().is_some(), "context packet bytes")?;
                "PACKET_OWNER_FACT_BYTES"
            };
            let count = view.omissions.entry(reason.into()).or_default();
            *count = count
                .checked_add(1)
                .ok_or_else(|| DiscoveryInvalidSnafu { field: "count" }.build())?;
            Self::missing(view);
        }
        Ok(())
    }
}
