use std::{cell::RefCell, collections::BTreeMap};

use super::{Capture, DataView, NativeStore};
use crate::analysis::native::FindingRead;
use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisExtractionV1, AnalysisReadControl,
    AnalysisReferenceOriginV1, AnalysisSelectionV1, AnalysisTableRead, ApprovedNotificationRouteV1,
    NotificationDeliveryKindV1, NotificationFindingRefV1, NotificationObligationV1,
    PackageErrorCodeV1 as Code, Result, NOTIFICATION_ROUTE_OWNER, NOTIFICATION_STATE_OWNER,
};

struct State {
    key: AnalysisContextKeyV1,
    revision: u64,
    obligation: NotificationObligationV1,
}

impl State {
    fn push(
        states: &mut Vec<Self>,
        context: AnalysisContextVersionV1,
        revision: u64,
        selection: &AnalysisSelectionV1,
        output: &mut AnalysisExtractionV1,
    ) -> Result<()> {
        if output.limits.keys.is_some_and(|limit| {
            selection
                .key_count()
                .saturating_sub(selection.notification_keys().len())
                + states.len()
                >= limit
        }) {
            return crate::AnalysisInputTooLargeSnafu {
                resource: "selected input keys",
            }
            .fail();
        }
        output.charge(AnalysisExtractionV1::grow(
            states,
            output.input_bytes,
            output.limits.input_bytes,
        )?)?;
        states.push(Self::capture(context, revision, output)?);
        Ok(())
    }

    fn capture(
        context: AnalysisContextVersionV1,
        revision: u64,
        output: &mut AnalysisExtractionV1,
    ) -> Result<Self> {
        output.scan(context.body.len())?;
        output.charge(context.body.len().saturating_mul(4) + size_of::<Self>())?;
        let obligation = NotificationObligationV1::try_from(&context)?;
        Ok(Self {
            key: context.key,
            revision,
            obligation,
        })
    }
}

impl NativeStore {
    fn notification_rows(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<Vec<State>> {
        let mut states = Vec::new();
        if selection.obligations.is_all() {
            let first = (
                selection.tenant_id,
                NOTIFICATION_STATE_OWNER.into(),
                Vec::new(),
                Vec::new(),
            );
            for (name, base) in view.contexts.range(first..).take_while(|(name, _)| {
                name.0 == selection.tenant_id && name.1 == NOTIFICATION_STATE_OWNER
            }) {
                control.check()?;
                let row = view.head_context_charged(name, *base, &mut |bytes| {
                    control.check()?;
                    output.charge(bytes)
                })?;
                if let Some((context, revision)) = row {
                    State::push(&mut states, context, revision, selection, output)?;
                }
            }
        } else {
            for key in selection.notification_keys() {
                control.check()?;
                let (context, revision) = view
                    .context_charged(key, &mut |bytes| {
                        control.check()?;
                        output.charge(bytes)
                    })?
                    .ok_or_else(|| Code::Missing.error("selected notification state"))?;
                State::push(&mut states, context, revision, selection, output)?;
            }
        }
        Ok(states)
    }

    pub(super) fn extract_notifications(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        unscoped: bool,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if read.projected("notifications").is_none() {
            return Ok(());
        }
        let states = self.notification_rows(view, selection, output, control)?;
        let current = read.projects_field("notifications", "current_finding_result_id")
            || read.projects_field("notifications", "same_graph_revision");
        let memory = RefCell::new(output);
        let mut charge = |bytes| memory.borrow_mut().charge(bytes);
        let mut reader = FindingRead::new(self, view, selection.tenant_id, control, &mut charge);
        memory
            .borrow_mut()
            .charge(states.len().saturating_mul(12 * size_of::<&str>()))?;
        let ids = states
            .iter()
            .filter_map(|state| {
                state
                    .obligation
                    .finding
                    .as_ref()
                    .map(|reference| reference.finding_id.as_str())
            })
            .collect();
        let heads = if current {
            reader.heads(&ids)?
        } else {
            BTreeMap::new()
        };
        let mut routes = BTreeMap::new();
        for state in states {
            control.check()?;
            let scalar = state
                .obligation
                .finding
                .as_ref()
                .map(|reference| reader.scalar(reference, selection, scope))
                .transpose()?
                .flatten();
            if scalar.as_ref().is_some_and(|value| !value.allowed) || scalar.is_none() && !unscoped
            {
                continue;
            }
            let mut latest = None;
            if let Some(reference) = &state.obligation.finding {
                if let Some(scalar) = &scalar {
                    memory.borrow_mut().reference_result(
                        &reference.result_id,
                        scalar.revision,
                        AnalysisReferenceOriginV1::Notification,
                    )?;
                    if scalar.value.is_some() {
                        capture.record_finding(
                            &reference.result_id,
                            &reference.finding_id,
                            &mut memory.borrow_mut().sink(control),
                        )?;
                        if let Some(result) = heads.get(&reference.finding_id).filter(|result| {
                            selection.graphs.is_empty() || selection.graphs().contains(result)
                        }) {
                            let reference = NotificationFindingRefV1 {
                                finding_id: reference.finding_id.clone(),
                                result_id: result.clone(),
                            };
                            if let Some(value) = reader
                                .scalar(&reference, selection, scope)?
                                .filter(|value| value.allowed && value.value.is_some())
                            {
                                memory.borrow_mut().reference_result(
                                    result,
                                    value.revision,
                                    AnalysisReferenceOriginV1::Graph,
                                )?;
                                capture.record_finding(
                                    result,
                                    &reference.finding_id,
                                    &mut memory.borrow_mut().sink(control),
                                )?;
                                latest = Some(result.as_str());
                            }
                        }
                    }
                }
            }
            let mut retry = None;
            for kind in [
                NotificationDeliveryKindV1::Finding,
                NotificationDeliveryKindV1::FailureEscalation,
                NotificationDeliveryKindV1::AcknowledgementEscalation,
            ] {
                let Some(reference) = state.obligation.delivery_route(kind) else {
                    continue;
                };
                let identity = (reference.route_id.clone(), reference.revision);
                if !routes.contains_key(&identity) {
                    memory
                        .borrow_mut()
                        .charge(identity.0.len() + 12 * size_of::<ApprovedNotificationRouteV1>())?;
                    let key = AnalysisContextKeyV1 {
                        tenant_id: selection.tenant_id,
                        owner_id: NOTIFICATION_ROUTE_OWNER.into(),
                        entity_key: reference.route_id.as_bytes().to_vec(),
                        lifetime_key: b"route".to_vec(),
                        owner_revision: reference.revision,
                    };
                    let route = view
                        .context_charged(&key, &mut |bytes| memory.borrow_mut().charge(bytes))?
                        .map(|(context, revision)| {
                            memory.borrow_mut().scan(context.body.len())?;
                            memory
                                .borrow_mut()
                                .charge(context.body.len().saturating_mul(4))?;
                            memory.borrow_mut().reference_context(
                                &key,
                                revision,
                                AnalysisReferenceOriginV1::Notification,
                            )?;
                            ApprovedNotificationRouteV1::try_from(&context)
                        })
                        .transpose()?;
                    routes.insert(identity.clone(), route);
                }
                if let Some(deadline) = routes[&identity]
                    .as_ref()
                    .and_then(|route| state.obligation.retry_utc_ns(kind, &route.policy))
                {
                    retry = Some(retry.map_or(deadline, |old: u64| old.min(deadline)));
                }
            }
            let mut output = memory.borrow_mut();
            output.reference_context(
                &state.key,
                state.revision,
                AnalysisReferenceOriginV1::Notification,
            )?;
            let value = scalar.and_then(|scalar| scalar.value);
            capture.notification(
                &state.obligation,
                value.is_some(),
                value,
                latest,
                state
                    .obligation
                    .finding
                    .as_ref()
                    .is_some_and(|reference| latest == Some(reference.result_id.as_str())),
                state.revision,
                retry,
                &mut output.sink(control),
            )?;
        }
        Ok(())
    }
}
