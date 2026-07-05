use std::collections::{BTreeMap, BTreeSet};

use erebor_runtime_core::{AuditRecord, SessionRegistryRecord};
use erebor_runtime_events::RiskLevel;
use erebor_runtime_policy::Decision;
use serde::Serialize;

use crate::{
    error::{ReviewNoSessionRecordsSnafu, ReviewUnknownSessionSnafu},
    read_audit_records, SessionReviewError,
};

use super::{
    artifacts::SessionReviewArtifacts,
    record::{risk_name, surface_name},
};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub status: String,
    pub actor: String,
    pub runner: String,
    pub surfaces: Vec<String>,
    pub allowed: usize,
    pub denied: usize,
    pub require_approval: usize,
    pub mediated: usize,
    pub max_risk: String,
    pub start: String,
    pub end: String,
    pub record_count: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct SessionSummaryBuilder<'a> {
    records: &'a [AuditRecord],
    artifacts: &'a SessionReviewArtifacts,
}

impl<'a> SessionSummaryBuilder<'a> {
    #[must_use]
    pub const fn new(records: &'a [AuditRecord], artifacts: &'a SessionReviewArtifacts) -> Self {
        Self { records, artifacts }
    }

    pub fn build_all(self) -> Result<Vec<SessionSummary>, SessionReviewError> {
        if self.records.is_empty() {
            return ReviewNoSessionRecordsSnafu.fail();
        }

        let mut sessions = BTreeMap::<String, SessionAccumulator>::new();
        for record in self.records {
            sessions
                .entry(record.event.session_id.as_str().to_owned())
                .or_default()
                .observe(record);
        }

        let mut summaries = sessions
            .into_iter()
            .map(|(session_id, accumulator)| accumulator.into_summary(session_id, self.artifacts))
            .collect::<Vec<_>>();
        summaries.sort_by(|left, right| {
            right
                .start
                .cmp(&left.start)
                .then_with(|| left.session_id.cmp(&right.session_id))
        });
        Ok(summaries)
    }

    pub(crate) fn build_for_session(self, records: &[&AuditRecord]) -> SessionSummary {
        let Some(first) = records.first() else {
            return SessionSummary::unknown(self.artifacts);
        };
        let mut accumulator = SessionAccumulator::default();
        for record in records {
            accumulator.observe(record);
        }
        accumulator.into_summary(first.event.session_id.as_str().to_owned(), self.artifacts)
    }
}

#[derive(Default)]
struct SessionAccumulator {
    actors: BTreeMap<String, usize>,
    surfaces: BTreeSet<String>,
    allowed: usize,
    denied: usize,
    require_approval: usize,
    mediated: usize,
    max_risk: Option<RiskLevel>,
    start: Option<String>,
    end: Option<String>,
    record_count: usize,
}

impl SessionAccumulator {
    fn observe(&mut self, record: &AuditRecord) {
        *self
            .actors
            .entry(record.event.actor.id.clone())
            .or_default() += 1;
        self.surfaces
            .insert(surface_name(&record.event.surface).to_owned());
        self.record_count += 1;
        match &record.final_decision {
            Decision::Allow { .. } => self.allowed += 1,
            Decision::Deny { .. } => self.denied += 1,
            Decision::RequireApproval { .. } => self.require_approval += 1,
            Decision::Mediate { .. } => self.mediated += 1,
        }
        if self
            .max_risk
            .as_ref()
            .is_none_or(|risk| record.event.risk.level.severity() > risk.severity())
        {
            self.max_risk = Some(record.event.risk.level.clone());
        }
        self.update_time_bounds(&record.event.timestamp);
    }

    fn into_summary(
        self,
        session_id: String,
        artifacts: &SessionReviewArtifacts,
    ) -> SessionSummary {
        SessionSummary {
            session_id,
            status: String::from("recorded"),
            actor: Self::dominant_actor(&self.actors),
            runner: artifacts.runner().unwrap_or("unknown").to_owned(),
            surfaces: self.surfaces.into_iter().collect(),
            allowed: self.allowed,
            denied: self.denied,
            require_approval: self.require_approval,
            mediated: self.mediated,
            max_risk: self
                .max_risk
                .as_ref()
                .map_or("unknown", risk_name)
                .to_owned(),
            start: self.start.unwrap_or_else(|| String::from("unknown")),
            end: self.end.unwrap_or_else(|| String::from("unknown")),
            record_count: self.record_count,
        }
    }

    fn update_time_bounds(&mut self, timestamp: &str) {
        if self
            .start
            .as_ref()
            .is_none_or(|start| timestamp < start.as_str())
        {
            self.start = Some(timestamp.to_owned());
        }
        if self.end.as_ref().is_none_or(|end| timestamp > end.as_str()) {
            self.end = Some(timestamp.to_owned());
        }
    }

    fn dominant_actor(actors: &BTreeMap<String, usize>) -> String {
        actors
            .iter()
            .max_by_key(|(actor, count)| (*count, std::cmp::Reverse((*actor).clone())))
            .map_or_else(|| String::from("unknown"), |(actor, _count)| actor.clone())
    }
}

impl SessionSummary {
    fn unknown(artifacts: &SessionReviewArtifacts) -> Self {
        Self {
            session_id: String::from("unknown"),
            status: String::from("recorded"),
            actor: String::from("unknown"),
            runner: artifacts.runner().unwrap_or("unknown").to_owned(),
            surfaces: Vec::new(),
            allowed: 0,
            denied: 0,
            require_approval: 0,
            mediated: 0,
            max_risk: String::from("unknown"),
            start: String::from("unknown"),
            end: String::from("unknown"),
            record_count: 0,
        }
    }

    pub(crate) fn from_registry_record(record: &SessionRegistryRecord) -> Self {
        Self {
            session_id: record.session_id.clone(),
            status: record.status.as_str().to_owned(),
            actor: record.actor_id.clone(),
            runner: record.runner.clone(),
            surfaces: record.surfaces.clone(),
            allowed: 0,
            denied: 0,
            require_approval: 0,
            mediated: 0,
            max_risk: String::from("unknown"),
            start: record.started_at_unix_ms.to_string(),
            end: record
                .ended_at_unix_ms
                .map_or_else(|| String::from("unknown"), |time| time.to_string()),
            record_count: 0,
        }
    }
}

pub(crate) struct SessionRecordSelector<'a> {
    records: &'a [AuditRecord],
    session_id: &'a str,
}

impl<'a> SessionRecordSelector<'a> {
    pub(crate) const fn new(records: &'a [AuditRecord], session_id: &'a str) -> Self {
        Self {
            records,
            session_id,
        }
    }

    pub(crate) fn select(self) -> Result<Vec<&'a AuditRecord>, SessionReviewError> {
        if self.records.is_empty() {
            return ReviewNoSessionRecordsSnafu.fail();
        }
        let session_records = self
            .records
            .iter()
            .filter(|record| record.event.session_id.as_str() == self.session_id)
            .collect::<Vec<_>>();
        if session_records.is_empty() {
            ReviewUnknownSessionSnafu {
                session_id: self.session_id.to_owned(),
            }
            .fail()
        } else {
            Ok(session_records)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RegistrySessionSummaryBuilder<'a> {
    records: &'a [SessionRegistryRecord],
}

impl<'a> RegistrySessionSummaryBuilder<'a> {
    pub(crate) const fn new(records: &'a [SessionRegistryRecord]) -> Self {
        Self { records }
    }

    pub(crate) fn build(self) -> Vec<SessionSummary> {
        self.records.iter().map(Self::summary).collect()
    }

    fn summary(record: &SessionRegistryRecord) -> SessionSummary {
        let artifacts = SessionReviewArtifacts::new(Some(record.runner.clone()));
        read_audit_records(record.audit_path())
            .ok()
            .and_then(|audit_records| {
                SessionSummaryBuilder::new(&audit_records, &artifacts)
                    .build_all()
                    .ok()
            })
            .and_then(|summaries| {
                summaries
                    .into_iter()
                    .find(|summary| summary.session_id == record.session_id)
            })
            .map(|mut summary| {
                summary.status = record.status.as_str().to_owned();
                summary
            })
            .unwrap_or_else(|| SessionSummary::from_registry_record(record))
    }
}
