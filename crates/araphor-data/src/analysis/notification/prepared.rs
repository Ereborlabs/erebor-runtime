use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;
use crate::analysis::graph_rows::GraphRows;
use crate::analysis::managed::{OwnerRead, PreparedMemory};
use crate::{
    AnalysisReadControl, ApprovedNotificationRouteV1, FindingV1, GraphRevisionV1, ManagedBudget,
    NotificationErrorCodeV1 as Code, NotificationFindingRefV1, NotificationKeyV1,
    NotificationRouteRefV1, NOTIFICATION_ROUTE_OWNER,
};

#[cfg(feature = "native-store")]
mod native;

type FindingKey = (String, String);

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum ReadOwner {
    Heads,
    Routes,
    Finding,
    Basis,
    Related,
    State,
    Subject,
    Route,
}

struct FindingValue {
    finding: FindingV1,
    revision: Option<GraphRevisionV1>,
    canonical: Option<u64>,
}

pub struct PreparedNotificationBatch<'a> {
    memory: PreparedMemory<'a>,
    failed: bool,
    errors: BTreeMap<(ReadOwner, String, String), Arc<crate::Error>>,
    comparisons: BTreeMap<(FindingKey, FindingKey), bool>,
    comparison_errors: BTreeMap<(FindingKey, FindingKey), Arc<crate::Error>>,
    heads: BTreeMap<String, String>,
    findings: BTreeMap<FindingKey, FindingValue>,
    routes: Vec<ApprovedNotificationRouteV1>,
    versions: BTreeMap<String, BTreeMap<u64, ApprovedNotificationRouteV1>>,
    states: BTreeMap<NotificationKeyV1, (NotificationObligationV1, usize)>,
    subjects: BTreeMap<(NotificationKeyV1, u64), NotificationObligationV1>,
}

impl<'a> PreparedNotificationBatch<'a> {
    fn new(control: &'a AnalysisReadControl, budget: &'a dyn ManagedBudget) -> Result<Self> {
        Ok(Self {
            memory: PreparedMemory::new(control, budget)?,
            failed: false,
            errors: BTreeMap::new(),
            comparisons: BTreeMap::new(),
            comparison_errors: BTreeMap::new(),
            heads: BTreeMap::new(),
            findings: BTreeMap::new(),
            routes: Vec::new(),
            versions: BTreeMap::new(),
            states: BTreeMap::new(),
            subjects: BTreeMap::new(),
        })
    }

    fn charge_inputs(
        &mut self,
        references: &[NotificationFindingRefV1],
        keys: &[NotificationKeyV1],
    ) -> Result<()> {
        let bytes = references
            .iter()
            .try_fold(0usize, |bytes, reference| {
                bytes
                    .checked_add(
                        reference
                            .finding_id
                            .len()
                            .saturating_add(reference.result_id.len())
                            .saturating_mul(12),
                    )
                    .and_then(|bytes| bytes.checked_add(12 * size_of::<FindingKey>()))
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    keys.len()
                        .saturating_mul(12 * size_of::<NotificationKeyV1>()),
                )
            })
            .ok_or_else(|| crate::PackageErrorCodeV1::Limit.error("notification request memory"))?;
        self.charge(bytes)
    }

    fn insert_state(&mut self, context: AnalysisContextVersionV1) -> Result<()> {
        let state = NotificationObligationV1::try_from(&context)?;
        self.states.insert(state.key, (state, context.body.len()));
        Ok(())
    }

    pub fn charge(&mut self, bytes: usize) -> Result<()> {
        let result = self.memory.charge(bytes);
        self.failed |= result.is_err();
        result
    }

    pub fn check_related(&self, reference: &NotificationFindingRefV1) -> Result<()> {
        self.failure(
            ReadOwner::Related,
            &reference.result_id,
            &reference.finding_id,
        )
    }

    pub fn check_state(&self, key: NotificationKeyV1) -> Result<()> {
        self.failure(
            ReadOwner::State,
            &uuid::Uuid::from_bytes(key.notification_id).to_string(),
            "",
        )
    }

    pub fn heads(&self) -> &BTreeMap<String, String> {
        &self.heads
    }

    fn failure(&self, kind: ReadOwner, owner: &str, id: &str) -> Result<()> {
        if let Some((_, error)) = self
            .errors
            .iter()
            .find(|((tag, key, value), _)| *tag == kind && key == owner && value == id)
        {
            return Err(crate::Error::PreparedNotification {
                source: Arc::clone(error),
            });
        }
        Ok(())
    }

    fn capture<T>(
        &mut self,
        result: Result<T>,
        kind: ReadOwner,
        owner: &str,
        id: &str,
    ) -> Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) => {
                let source = self.share(error, owner, id)?;
                self.errors.insert((kind, owner.into(), id.into()), source);
                Ok(None)
            }
        }
    }

    fn share(&mut self, error: crate::Error, owner: &str, id: &str) -> Result<Arc<crate::Error>> {
        self.memory.check()?;
        if self.failed
            || matches!(
                error.unprepared(),
                crate::Error::AnalysisReadCancelled { .. }
                    | crate::Error::AnalysisReadDeadline { .. }
                    | crate::Error::AnalysisInputTooLarge { .. }
                    | crate::Error::StorageCapacity { .. }
                    | crate::Error::ProtectedInputCapacity { .. }
                    | crate::Error::Package {
                        code: crate::PackageErrorCodeV1::Limit,
                        ..
                    }
                    | crate::Error::Notification {
                        code: Code::Limit,
                        ..
                    }
            )
        {
            return Err(error);
        }
        self.charge(
            owner
                .len()
                .saturating_add(id.len())
                .saturating_add(8 * size_of::<Arc<crate::Error>>()),
        )?;
        Ok(match error {
            crate::Error::PreparedNotification { source } => source,
            error => Arc::new(error),
        })
    }

    fn value(&self, reference: &NotificationFindingRefV1) -> Option<&FindingValue> {
        self.findings
            .iter()
            .find(|((result, id), _)| result == &reference.result_id && id == &reference.finding_id)
            .map(|(_, value)| value)
    }

    pub fn finding(&self, reference: &NotificationFindingRefV1) -> Result<&FindingV1> {
        Code::Invalid.require(
            NotificationGrantV1::identifier(&reference.finding_id, usize::MAX)
                && NotificationGrantV1::identifier(&reference.result_id, usize::MAX),
            "finding reference",
        )?;
        self.failure(ReadOwner::Heads, "", "")?;
        let current = self.heads.get(&reference.finding_id).ok_or_else(|| {
            crate::NotificationSnafu {
                code: Code::Denied,
                field: "current finding scope",
            }
            .build()
        })?;
        Code::Conflict.require(current == &reference.result_id, "current finding reference")?;
        self.failure(
            ReadOwner::Finding,
            &reference.result_id,
            &reference.finding_id,
        )?;
        self.value(reference)
            .map(|value| &value.finding)
            .ok_or_else(|| {
                crate::NotificationSnafu {
                    code: Code::Denied,
                    field: "current finding scope",
                }
                .build()
                .into()
            })
    }

    pub fn historical(
        &self,
        reference: &NotificationFindingRefV1,
    ) -> Result<Option<(&FindingV1, &GraphRevisionV1)>> {
        self.failure(
            ReadOwner::Finding,
            &reference.result_id,
            &reference.finding_id,
        )?;
        self.failure(
            ReadOwner::Basis,
            &reference.result_id,
            &reference.finding_id,
        )?;
        Ok(self.value(reference).and_then(|value| {
            value
                .revision
                .as_ref()
                .map(|revision| (&value.finding, revision))
        }))
    }

    pub fn changed(
        &self,
        reference: &NotificationFindingRefV1,
        prior: &NotificationFindingRefV1,
    ) -> Result<bool> {
        Code::Invalid.require(
            prior.finding_id == reference.finding_id
                && NotificationGrantV1::identifier(&prior.result_id, usize::MAX),
            "finding reference",
        )?;
        self.finding(reference)?;
        if prior.result_id == reference.result_id {
            return Ok(false);
        }
        let key = (
            (reference.result_id.clone(), reference.finding_id.clone()),
            (prior.result_id.clone(), prior.finding_id.clone()),
        );
        if let Some(error) = self.comparison_errors.get(&key) {
            return Err(crate::Error::PreparedNotification {
                source: Arc::clone(error),
            });
        }
        self.comparisons.get(&key).copied().ok_or_else(|| {
            crate::NotificationSnafu {
                code: Code::Denied,
                field: "prepared finding comparison",
            }
            .build()
            .into()
        })
    }

    pub fn routes(&self) -> Result<&[ApprovedNotificationRouteV1]> {
        self.failure(ReadOwner::Routes, "", "")?;
        Ok(&self.routes)
    }

    pub fn route(
        &self,
        reference: &NotificationRouteRefV1,
    ) -> Result<Option<&ApprovedNotificationRouteV1>> {
        self.failure(
            ReadOwner::Route,
            &reference.route_id,
            &reference.revision.to_string(),
        )?;
        Ok(self
            .versions
            .get(&reference.route_id)
            .and_then(|versions| versions.get(&reference.revision)))
    }

    pub fn states(&self) -> impl Iterator<Item = (&NotificationObligationV1, usize)> {
        self.states.values().map(|(state, bytes)| (state, *bytes))
    }

    pub fn subject(
        &self,
        key: NotificationKeyV1,
        revision: u64,
    ) -> Result<&NotificationObligationV1> {
        self.failure(
            ReadOwner::Subject,
            &uuid::Uuid::from_bytes(key.notification_id).to_string(),
            &revision.to_string(),
        )?;
        self.subjects.get(&(key, revision)).ok_or_else(|| {
            crate::NotificationSnafu {
                code: Code::Unavailable,
                field: "attempt finding revision",
            }
            .build()
            .into()
        })
    }
}

impl AnalysisStore {
    pub fn prepare_notifications<'a>(
        &self,
        tenant: [u8; 16],
        references: &[NotificationFindingRefV1],
        keys: &[NotificationKeyV1],
        control: &'a AnalysisReadControl,
        budget: &'a dyn ManagedBudget,
    ) -> Result<PreparedNotificationBatch<'a>> {
        Code::Invalid.require(tenant != [0; 16], "notification tenant")?;
        let mut batch = PreparedNotificationBatch::new(control, budget)?;
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            batch.charge_inputs(references, keys)?;
            let valid = references.iter().filter(|reference| NotificationGrantV1::identifier(&reference.finding_id, usize::MAX)
                && NotificationGrantV1::identifier(&reference.result_id, usize::MAX)).collect::<Vec<_>>();
            let ids = valid.iter().map(|reference| &reference.finding_id).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
            let mut owners = OwnerRead::with_budget(self, reader, tenant, control, budget)?;
            let heads = owners.finding_heads(&self.graph_engine, reader, tenant, &ids, &mut |_, bytes| batch.charge(bytes));
            if owners.memory_failed() {
                return Err(heads.err().unwrap_or_else(|| crate::PackageErrorCodeV1::Limit.error("notification owner memory")));
            }
            if let Some(heads) = batch.capture(heads, ReadOwner::Heads, "", "")? { batch.heads = heads; }
            let active = valid.iter().copied().filter(|reference| batch.heads.get(&reference.finding_id) == Some(&reference.result_id)).collect::<Vec<_>>();
            let route_read = (|| {
                let limit = self.storage.notification_routes.unwrap_or(usize::MAX).max(1);
                Self::bound_notice_contexts(reader, tenant, NOTIFICATION_ROUTE_OWNER, &mut batch)?;
                let contexts = self.context_heads_from(reader, tenant, NOTIFICATION_ROUTE_OWNER,
                    limit, limit.checked_add(1).and_then(|n| i64::try_from(n).ok()))?;
                Code::Limit.require(self.storage.notification_routes.is_none_or(|n| contexts.len() <= n), "route count")?;
                contexts.iter().map(ApprovedNotificationRouteV1::try_from).map(|value| value.map_err(Into::into)).collect::<Result<Vec<_>>>()
            })();
            if let Some(routes) = batch.capture(route_read, ReadOwner::Routes, "", "")? { batch.routes = routes; }
            for route in &batch.routes {
                batch.versions.entry(route.policy.route_id.clone()).or_default().insert(route.policy.revision, route.clone());
            }
            let mut wanted = active.iter().map(|reference|
                (reference.result_id.clone(), reference.finding_id.clone())).collect::<BTreeSet<_>>();
            self.prepare_notice_findings(reader, tenant, &wanted, &mut owners, control, &mut batch)?;
            for reference in &active {
                let Some(value) = batch.findings.get(&(reference.result_id.clone(), reference.finding_id.clone())) else { continue; };
                let id = value.finding.finding_id.clone();
                let action = value.finding.required_action.clone();
                let lookup = NotificationLookup::Finding(&id, action.as_deref());
                let lookup_key = NotificationKeys::lookup(tenant, lookup)?;
                let read = (|| {
                    Self::bound_notice_states(reader, &lookup_key, None, &mut batch)?;
                    let states = self.notification_states_from(reader, tenant, lookup,
                        "SELECT entity_key,owner_revision,commit_revision,state_key FROM notification_heads WHERE finding_key=? ORDER BY entity_key LIMIT ?",
                        self.storage.notification_routes.and_then(|n| n.checked_add(2)).and_then(|n| i64::try_from(n).ok()), &lookup_key)?;
                    Code::Limit.require(self.storage.notification_routes.is_none_or(|n| states.len() <= n.saturating_add(1)), "related obligation count")?;
                    for context in states { batch.insert_state(context)?; }
                    Ok(())
                })();
                batch.capture(read, ReadOwner::Related, &reference.result_id, &reference.finding_id)?;
            }
            for key in keys {
                let identity = uuid::Uuid::from_bytes(key.notification_id).to_string();
                let read = (|| {
                    Code::Invalid.require(key.tenant_id == tenant && key.notification_id != [0;16], "notification key")?;
                    if batch.states.contains_key(key) { return Ok(()); }
                    let state_key = NotificationKeys::state(tenant, &key.notification_id)?;
                    Self::bound_notice_states(reader, &[], Some(&state_key), &mut batch)?;
                    if let Some(context) = self.notification_head_from(reader, tenant, &key.notification_id, &state_key)? { batch.insert_state(context)?; }
                    Ok(())
                })();
                batch.capture(read, ReadOwner::State, &identity, "")?;
            }
            let pending = batch.states.values().flat_map(|(state, _)| state.attempts.iter()
                .filter(|attempt| attempt.result.is_none()).map(|attempt| (state.key, attempt.context_revision)))
                .collect::<BTreeSet<_>>();
            for (key, revision) in pending {
                let read = (|| {
                    let context = self.notice_context(reader, &AnalysisContextKeyV1 {
                        tenant_id: tenant, owner_id: NOTIFICATION_STATE_OWNER.into(), entity_key: key.notification_id.to_vec(),
                        lifetime_key: b"obligation".to_vec(), owner_revision: revision,
                    }, &mut batch)?.ok_or_else(|| crate::NotificationSnafu { code: Code::Unavailable, field: "attempt finding revision" }.build())?;
                    NotificationObligationV1::try_from(&context).map_err(Into::into)
                })();
                if let Some(subject) = batch.capture(read, ReadOwner::Subject, &uuid::Uuid::from_bytes(key.notification_id).to_string(), &revision.to_string())? {
                    batch.subjects.insert((key, revision), subject);
                }
            }
            let subjects = batch.states.values().map(|(state, _)| state).chain(batch.subjects.values());
            let mut routes = BTreeSet::new();
            for state in subjects {
                if let Some(reference) = &state.finding { wanted.insert((reference.result_id.clone(), reference.finding_id.clone())); }
                for reference in state.route.iter().chain(state.escalation.iter()) {
                    routes.insert((reference.route_id.clone(), reference.revision));
                }
            }
            for (id, revision) in routes {
                if batch.versions.get(&id).is_some_and(|versions| versions.contains_key(&revision)) { continue; }
                let read = (|| {
                    self.notice_context(reader, &AnalysisContextKeyV1 { tenant_id: tenant, owner_id: NOTIFICATION_ROUTE_OWNER.into(),
                        entity_key: id.as_bytes().to_vec(), lifetime_key: b"route".to_vec(), owner_revision: revision }, &mut batch)?
                        .as_ref().map(ApprovedNotificationRouteV1::try_from).transpose().map_err(Into::into)
                })();
                if let Some(Some(route)) = batch.capture(read, ReadOwner::Route, &id, &revision.to_string())? {
                    batch.versions.entry(id).or_default().insert(revision, route);
                }
            }
            self.prepare_notice_findings(reader, tenant, &wanted, &mut owners, control, &mut batch)?;
            batch.memory.check()
        })?;
        Ok(batch)
    }

    fn notice_context(
        &self,
        reader: &Connection,
        key: &AnalysisContextKeyV1,
        batch: &mut PreparedNotificationBatch<'_>,
    ) -> Result<Option<AnalysisContextVersionV1>> {
        let bytes: Option<u64> = reader
            .query_row(
                "SELECT octet_length(body) FROM context_versions WHERE version_key=?",
                params![crate::analysis::context::version_key(key)?],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "bound prepared notification context",
            })?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        Self::charge_notice(bytes, batch)?;
        Ok(Self::read_context_from(reader, &self.root, key)?.map(|(context, _)| context))
    }

    fn bound_notice_contexts(
        reader: &Connection,
        tenant: [u8; 16],
        owner: &str,
        batch: &mut PreparedNotificationBatch<'_>,
    ) -> Result<()> {
        let bytes: u64 = reader.query_row("SELECT coalesce(sum(octet_length(body)+octet_length(entity_key)+octet_length(lifetime_key)),0)
            FROM context_versions c WHERE tenant_id=? AND owner_id=? AND owner_revision=(
                SELECT max(h.owner_revision) FROM context_versions h WHERE h.tenant_id=c.tenant_id AND h.owner_id=c.owner_id
                    AND h.entity_key=c.entity_key AND h.lifetime_key=c.lifetime_key)",
            params![tenant.as_slice(),owner], |row| row.get(0))
            .context(AnalysisDatabaseSnafu { operation: "bound prepared notification routes" })?;
        Self::charge_notice(bytes, batch)
    }

    fn bound_notice_states(
        reader: &Connection,
        finding: &[u8],
        key: Option<&[u8]>,
        batch: &mut PreparedNotificationBatch<'_>,
    ) -> Result<()> {
        let bytes: u64 = reader
            .query_row(
                "SELECT coalesce(sum(octet_length(c.body)+octet_length(c.entity_key)),0)
            FROM notification_heads h JOIN context_versions c ON c.tenant_id=h.tenant_id
                AND c.owner_id=? AND c.entity_key=h.entity_key AND c.lifetime_key='obligation'::BLOB
                AND c.owner_revision=h.owner_revision WHERE h.finding_key=? OR h.state_key=?",
                params![NOTIFICATION_STATE_OWNER, finding, key],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "bound prepared notification states",
            })?;
        Self::charge_notice(bytes, batch)
    }

    fn charge_notice(bytes: u64, batch: &mut PreparedNotificationBatch<'_>) -> Result<()> {
        let bytes = usize::try_from(bytes)
            .ok()
            .and_then(|n| n.checked_mul(12))
            .and_then(|n| n.checked_add(8 * size_of::<NotificationObligationV1>()))
            .ok_or_else(|| {
                crate::PackageErrorCodeV1::Limit.error("prepared notification memory")
            })?;
        batch.charge(bytes)
    }

    fn prepare_notice_findings(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        wanted: &BTreeSet<FindingKey>,
        owners: &mut OwnerRead<'_>,
        control: &AnalysisReadControl,
        batch: &mut PreparedNotificationBatch<'_>,
    ) -> Result<()> {
        for (result, id) in wanted {
            control.check()?;
            if batch.findings.contains_key(&(result.clone(), id.clone()))
                || batch
                    .errors
                    .contains_key(&(ReadOwner::Finding, result.clone(), id.clone()))
            {
                continue;
            }
            let value = (|| {
                let native = owners.finding(
                    &self.graph_engine,
                    reader,
                    tenant,
                    result,
                    id,
                    &mut |_, bytes| batch.charge(bytes),
                )?;
                let source: bool = reader.query_row(
                    "SELECT EXISTS(SELECT 1 FROM managed_source_publications WHERE tenant_id=? AND result_id=?)",
                    params![tenant.as_slice(), result], |row| row.get(0),
                ).context(AnalysisDatabaseSnafu { operation: "read prepared finding publication kind" })?;
                let definition = if source {
                    None
                } else {
                    owners
                        .publication(reader, tenant, result, &mut |_, bytes| batch.charge(bytes))?
                };
                if let Some((canonical, member)) = native {
                    return Ok(Some((member.value, Some(canonical), definition.is_some())));
                }
                let bytes: Option<u64> = reader.query_row("SELECT octet_length(body) FROM analysis_results WHERE tenant_id=? AND result_id=?",
                    params![tenant.as_slice(),result], |row| row.get(0)).optional().context(AnalysisDatabaseSnafu { operation: "bound legacy notification header" })?;
                if let Some(bytes) = bytes {
                    Self::charge_notice(bytes, batch)?;
                }
                let Some(header) = GraphRows::read_finding_header(reader, tenant, result)? else {
                    return Ok(None);
                };
                GraphRows::bound_findings(
                    self,
                    reader,
                    result,
                    Some(id),
                    &header.snapshot.scope.identity,
                    &mut |_, bytes| batch.charge(bytes),
                )?;
                Ok(
                    GraphRows::read_finding(self, reader, result, id, &header, Some(control))?
                        .map(|finding| (finding, None, false)),
                )
            })();
            if owners.memory_failed() {
                return Err(value.err().unwrap_or_else(|| {
                    crate::PackageErrorCodeV1::Limit.error("notification owner memory")
                }));
            }
            let Some(Some((finding, canonical, definition))) =
                batch.capture(value, ReadOwner::Finding, result, id)?
            else {
                continue;
            };
            let basis = (|| {
                let revision = if definition {
                    Self::finding_basis_on(
                        &self.graph_engine,
                        reader,
                        tenant,
                        result,
                        &BTreeSet::from([id.clone()]),
                        control,
                        &mut |_, bytes| batch.charge(bytes),
                        true,
                        owners,
                    )?
                    .2
                } else {
                    let header = GraphRows::read_finding_header(reader, tenant, result)?
                        .ok_or_else(|| self.state_error("the Graph header is absent"))?;
                    Self::native_source_revision(reader, tenant, result, &mut |_, bytes| {
                        batch.charge(bytes)
                    })?
                    .unwrap_or(header.snapshot.input_manifest)
                };
                revision.validate_finding(&finding)?;
                Ok(revision)
            })();
            if owners.memory_failed() {
                return Err(basis.err().unwrap_or_else(|| {
                    crate::PackageErrorCodeV1::Limit.error("notification owner memory")
                }));
            }
            let revision = batch.capture(basis, ReadOwner::Basis, result, id)?;
            batch.findings.insert(
                (result.clone(), id.clone()),
                FindingValue {
                    finding,
                    revision,
                    canonical,
                },
            );
        }
        let comparisons = batch
            .findings
            .iter()
            .filter(|((result, id), _)| batch.heads.get(id) == Some(result))
            .flat_map(|(current, value)| {
                batch.states.values().filter_map(move |(state, _)| {
                    let prior = state.finding.as_ref()?;
                    (prior.finding_id == current.1
                        && state.required_action == value.finding.required_action)
                        .then(|| {
                            (
                                current.clone(),
                                (prior.result_id.clone(), prior.finding_id.clone()),
                            )
                        })
                })
            })
            .collect::<Vec<_>>();
        for (current, prior) in comparisons {
            if batch
                .comparisons
                .contains_key(&(current.clone(), prior.clone()))
            {
                continue;
            }
            let compare = (|| {
                let value = &batch.findings[&current];
                let finding = value.finding.clone();
                let canonical = value.canonical;
                let reference = NotificationFindingRefV1 {
                    result_id: current.0.clone(),
                    finding_id: current.1.clone(),
                };
                let previous = NotificationFindingRefV1 {
                    result_id: prior.0.clone(),
                    finding_id: prior.1.clone(),
                };
                if let Some(canonical) = canonical {
                    owners.finding_changed(
                        &self.graph_engine,
                        reader,
                        tenant,
                        &reference,
                        Some(&previous),
                        canonical,
                        &mut |_, bytes| batch.charge(bytes),
                    )
                } else {
                    let header = GraphRows::read_summary(reader, tenant, &current.0, None)?
                        .ok_or_else(|| self.state_error("the current Graph header is absent"))?;
                    Self::legacy_finding_changed(
                        self,
                        reader,
                        tenant,
                        &reference,
                        Some(&previous),
                        &finding,
                        &header,
                    )
                }
            })();
            match compare {
                Ok(changed) => {
                    batch.comparisons.insert((current, prior), changed);
                }
                Err(error) => {
                    let source = batch.share(error, &current.0, &current.1)?;
                    batch.comparison_errors.insert((current, prior), source);
                }
            }
        }
        Ok(())
    }
}
