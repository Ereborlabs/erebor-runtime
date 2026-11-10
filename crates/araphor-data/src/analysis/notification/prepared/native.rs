use std::cell::RefCell;

use super::*;
use crate::analysis::native::{DataView, FindingRead, NativeStore};

impl NativeStore {
    pub fn prepare_notifications<'a>(
        &self,
        tenant: [u8; 16],
        references: &[NotificationFindingRefV1],
        keys: &[NotificationKeyV1],
        control: &'a AnalysisReadControl,
        budget: &'a dyn ManagedBudget,
    ) -> Result<PreparedNotificationBatch<'a>> {
        Code::Invalid.require(tenant != [0; 16], "notification tenant")?;
        let view = self.view()?;
        let batch = RefCell::new(PreparedNotificationBatch::new(control, budget)?);
        batch.borrow_mut().charge_inputs(references, keys)?;
        let mut charge = |bytes| {
            let mut batch = batch.borrow_mut();
            if bytes == 0 {
                batch.memory.check()
            } else {
                batch.charge(bytes)
            }
        };
        let mut findings = FindingRead::new(self, &view, tenant, control, &mut charge);
        let valid = references
            .iter()
            .filter(|reference| {
                NotificationGrantV1::identifier(&reference.finding_id, usize::MAX)
                    && NotificationGrantV1::identifier(&reference.result_id, usize::MAX)
            })
            .collect::<Vec<_>>();
        let ids = valid
            .iter()
            .map(|reference| reference.finding_id.as_str())
            .collect::<BTreeSet<_>>();
        let read = findings.heads(&ids);
        let heads = batch.borrow_mut().capture(read, ReadOwner::Heads, "", "")?;
        if let Some(heads) = heads {
            batch.borrow_mut().heads = heads;
        }
        let active = valid
            .into_iter()
            .filter(|reference| {
                batch.borrow().heads.get(&reference.finding_id) == Some(&reference.result_id)
            })
            .collect::<Vec<_>>();
        let read = view
            .head_versions(tenant, NOTIFICATION_ROUTE_OWNER, None,
                self.storage_limits().notification_routes.map_or(usize::MAX, |limit| limit.saturating_add(1)), false, &mut |bytes| {
                Self::charge_notice(&batch, bytes)
            })
            .and_then(|contexts| {
                Code::Limit.require(self.storage_limits().notification_routes.is_none_or(|limit| contexts.len() <= limit), "route count")?;
                contexts
                    .iter()
                    .map(ApprovedNotificationRouteV1::try_from)
                    .collect::<Result<Vec<_>>>()
            });
        let routes = batch
            .borrow_mut()
            .capture(read, ReadOwner::Routes, "", "")?;
        if let Some(routes) = routes {
            for route in &routes {
                batch
                    .borrow_mut()
                    .versions
                    .entry(route.policy.route_id.clone())
                    .or_default()
                    .insert(route.policy.revision, route.clone());
            }
            batch.borrow_mut().routes = routes;
        }
        let mut wanted = active
            .iter()
            .map(|reference| (reference.result_id.clone(), reference.finding_id.clone()))
            .collect::<BTreeSet<_>>();
        Self::prepare_notice_findings(&mut findings, &wanted, &batch)?;
        for reference in active {
            let lookup = {
                let batch = batch.borrow();
                batch.value(reference).map(|value| {
                    (
                        value.finding.finding_id.clone(),
                        value.finding.required_action.clone(),
                    )
                })
            };
            let Some((id, action)) = lookup else {
                continue;
            };
            let read = view
                .notification_states_charged(
                    tenant,
                    NotificationLookup::Finding(&id, action.as_deref()),
                    self.storage_limits().notification_routes.and_then(|limit| limit.checked_add(2)).unwrap_or(usize::MAX),
                    &mut |bytes| Self::charge_notice(&batch, bytes),
                )
                .and_then(|contexts| {
                    Code::Limit.require(self.storage_limits().notification_routes.is_none_or(|limit| contexts.len() <= limit.saturating_add(1)), "related obligation count")?;
                    for context in contexts {
                        batch.borrow_mut().insert_state(context)?;
                    }
                    Ok(())
                });
            batch.borrow_mut().capture(
                read,
                ReadOwner::Related,
                &reference.result_id,
                &reference.finding_id,
            )?;
        }
        for &key in keys {
            let identity = uuid::Uuid::from_bytes(key.notification_id).to_string();
            let read = (|| {
                Code::Invalid.require(
                    key.tenant_id == tenant && key.notification_id != [0; 16],
                    "notification key",
                )?;
                if batch.borrow().states.contains_key(&key) {
                    return Ok(());
                }
                let context = view.context_latest(
                    &AnalysisContextKeyV1 {
                        tenant_id: tenant,
                        owner_id: NOTIFICATION_STATE_OWNER.into(),
                        entity_key: key.notification_id.to_vec(),
                        lifetime_key: b"obligation".to_vec(),
                        owner_revision: 0,
                    },
                    &mut |bytes| Self::charge_notice(&batch, bytes),
                )?;
                if let Some(context) = context {
                    batch.borrow_mut().insert_state(context)?;
                }
                Ok(())
            })();
            batch
                .borrow_mut()
                .capture(read, ReadOwner::State, &identity, "")?;
        }
        let pending = batch
            .borrow()
            .states
            .values()
            .flat_map(|(state, _)| {
                state
                    .attempts
                    .iter()
                    .filter(|attempt| attempt.result.is_none())
                    .map(|attempt| (state.key, attempt.context_revision))
            })
            .collect::<BTreeSet<_>>();
        for (key, revision) in pending {
            let read = (|| {
                let context = Self::notice_context(
                    &view,
                    &AnalysisContextKeyV1 {
                        tenant_id: tenant,
                        owner_id: NOTIFICATION_STATE_OWNER.into(),
                        entity_key: key.notification_id.to_vec(),
                        lifetime_key: b"obligation".to_vec(),
                        owner_revision: revision,
                    },
                    &batch,
                )?
                .ok_or_else(|| {
                    crate::NotificationSnafu {
                        code: Code::Unavailable,
                        field: "attempt finding revision",
                    }
                    .build()
                })?;
                NotificationObligationV1::try_from(&context)
            })();
            let subject = batch.borrow_mut().capture(
                read,
                ReadOwner::Subject,
                &uuid::Uuid::from_bytes(key.notification_id).to_string(),
                &revision.to_string(),
            )?;
            if let Some(subject) = subject {
                batch.borrow_mut().subjects.insert((key, revision), subject);
            }
        }
        let mut routes = BTreeSet::new();
        {
            let batch = batch.borrow();
            for state in batch
                .states
                .values()
                .map(|(state, _)| state)
                .chain(batch.subjects.values())
            {
                if let Some(reference) = &state.finding {
                    wanted.insert((reference.result_id.clone(), reference.finding_id.clone()));
                }
                for reference in state.route.iter().chain(state.escalation.iter()) {
                    routes.insert((reference.route_id.clone(), reference.revision));
                }
            }
        }
        for (id, revision) in routes {
            if batch
                .borrow()
                .versions
                .get(&id)
                .is_some_and(|versions| versions.contains_key(&revision))
            {
                continue;
            }
            let read = Self::notice_context(
                &view,
                &AnalysisContextKeyV1 {
                    tenant_id: tenant,
                    owner_id: NOTIFICATION_ROUTE_OWNER.into(),
                    entity_key: id.as_bytes().to_vec(),
                    lifetime_key: b"route".to_vec(),
                    owner_revision: revision,
                },
                &batch,
            )
            .and_then(|context| {
                context
                    .as_ref()
                    .map(ApprovedNotificationRouteV1::try_from)
                    .transpose()
            });
            let route =
                batch
                    .borrow_mut()
                    .capture(read, ReadOwner::Route, &id, &revision.to_string())?;
            if let Some(Some(route)) = route {
                batch
                    .borrow_mut()
                    .versions
                    .entry(id)
                    .or_default()
                    .insert(revision, route);
            }
        }
        Self::prepare_notice_findings(&mut findings, &wanted, &batch)?;
        let comparisons = {
            let batch = batch.borrow();
            batch
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
                .collect::<BTreeSet<_>>()
        };
        for (current, prior) in comparisons {
            let read = findings.changed(
                &NotificationFindingRefV1 {
                    result_id: current.0.clone(),
                    finding_id: current.1.clone(),
                },
                &NotificationFindingRefV1 {
                    result_id: prior.0.clone(),
                    finding_id: prior.1.clone(),
                },
            );
            let mut batch = batch.borrow_mut();
            match read {
                Ok(changed) => {
                    batch.comparisons.insert((current, prior), changed);
                }
                Err(error) => {
                    let error = batch.share(error, &current.0, &current.1)?;
                    batch.comparison_errors.insert((current, prior), error);
                }
            }
        }
        drop(findings);
        let batch = batch.into_inner();
        batch.memory.check()?;
        Ok(batch)
    }

    fn charge_notice(batch: &RefCell<PreparedNotificationBatch<'_>>, bytes: usize) -> Result<()> {
        let mut batch = batch.borrow_mut();
        if bytes == 0 {
            return batch.memory.check();
        }
        batch.charge(
            bytes
                .saturating_mul(12)
                .saturating_add(8 * size_of::<NotificationObligationV1>()),
        )
    }

    fn notice_context(
        view: &DataView,
        key: &AnalysisContextKeyV1,
        batch: &RefCell<PreparedNotificationBatch<'_>>,
    ) -> Result<Option<AnalysisContextVersionV1>> {
        let context = view
            .context_charged(key, &mut |bytes| Self::charge_notice(batch, bytes))?
            .map(|(context, _)| context);
        if let Some(context) = &context {
            view.verify_context(context)?;
        }
        Ok(context)
    }

    fn prepare_notice_findings(
        reader: &mut FindingRead<'_>,
        wanted: &BTreeSet<FindingKey>,
        batch: &RefCell<PreparedNotificationBatch<'_>>,
    ) -> Result<()> {
        for (result, id) in wanted {
            {
                let batch = batch.borrow();
                batch.memory.check()?;
                if batch.findings.contains_key(&(result.clone(), id.clone()))
                    || batch
                        .errors
                        .contains_key(&(ReadOwner::Finding, result.clone(), id.clone()))
                {
                    continue;
                }
            }
            let read = reader.value(result, id);
            let finding = batch
                .borrow_mut()
                .capture(read, ReadOwner::Finding, result, id)?;
            let Some(Some(finding)) = finding else {
                continue;
            };
            let read = reader.revision(result, id);
            let revision = batch
                .borrow_mut()
                .capture(read, ReadOwner::Basis, result, id)?;
            batch.borrow_mut().findings.insert(
                (result.clone(), id.clone()),
                FindingValue {
                    finding,
                    revision,
                    canonical: None,
                },
            );
        }
        Ok(())
    }
}
