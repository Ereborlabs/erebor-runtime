use std::{collections::BTreeMap, ops::RangeBounds as _};

use snafu::ResultExt as _;

use super::{results::ResultBody, Records};
use crate::analysis::managed::{Attempt, Record, Step};
use crate::analysis::native::{DataView, NativeStore};
use crate::{
    AnalysisContextRefV1, AnalysisReadControl, AnalysisWitnessV1, ManagedDestination,
    NativeStorageSnafu, PackageErrorCodeV1 as Code, Result,
};

impl DataView {
    pub(super) fn validate_success(&self, attempt: &Attempt) -> Result<()> {
        let receipt = attempt
            .receipt
            .as_ref()
            .ok_or_else(|| Code::Missing.error("managed success receipt"))?;
        let tenant = attempt.capture.tenant;
        let control = AnalysisReadControl::default();
        let (_, selected, owner) =
            self.result_owner(tenant, &receipt.selected.result_id, &control, &mut |_| {
                Ok(())
            })?;
        let ResultBody::Selected(step) = &selected.body else {
            return Err(Code::Invalid.error("managed success selected body"));
        };
        let spec = &owner.1.spec;
        if owner.0 != *attempt {
            return Err(Code::Invalid.error("managed success owner"));
        }
        match &spec.destination {
            ManagedDestination::Selected | ManagedDestination::DiscoveryProfile { .. }
                if receipt.graph.is_none() && step.source.is_none() => {}
            ManagedDestination::Graph {
                operation: crate::ManagedGraphOperation::Evaluate,
                ..
            } if receipt.graph.as_ref() == Some(&receipt.selected) && step.source.is_some() => {}
            ManagedDestination::Graph {
                operation: crate::ManagedGraphOperation::Evaluate,
                ..
            } if receipt.graph.is_none()
                && step.source.is_none()
                && step.rows == 0
                && receipt.results.is_empty() => {}
            _ => return Err(Code::Invalid.error("managed success destination")),
        }
        self.check_step_evidence(attempt, step, spec)?;
        let mut expected = attempt.capture.dependencies.clone();
        expected.extend(receipt.results.values().cloned());
        expected.sort_by(|left, right| left.result_id.cmp(&right.result_id));
        expected.dedup();
        if step.dependencies != expected {
            return Err(Code::Invalid.error("managed selected dependencies"));
        }
        let mut derived = Vec::new();
        let mut origins = BTreeMap::new();
        let mut proofs = BTreeMap::new();
        for (call, reference) in &receipt.results {
            let (id, stored, saved) =
                self.result_owner(tenant, &reference.result_id, &control, &mut |_| Ok(()))?;
            let ResultBody::Call(record) = &stored.body else {
                return Err(Code::Invalid.error("managed success call body"));
            };
            if saved.0 != *attempt
                || record.call != *call
                || stored.revision != receipt.commit_revision
            {
                return Err(Code::Invalid.error("managed selected call binding"));
            }
            self.check_call_record(id, attempt, record, step, spec)?;
            derived = crate::AnalysisStore::join_contexts(&derived, &record.derived)?;
            for origin in &record.origins {
                origins.insert(origin.result_id.clone(), origin.clone());
            }
            for (record, reference) in &record.proofs {
                if proofs
                    .insert((record.clone(), reference.key.clone()), reference.clone())
                    .is_some_and(|prior| prior != *reference)
                {
                    return Err(Code::Conflict.error("selected call proof identity"));
                }
            }
        }
        if let Some(source) = &step.source {
            derived = crate::AnalysisStore::join_contexts(&derived, &source.derived)?;
            for origin in &source.origins {
                if origins
                    .insert(origin.result_id.clone(), origin.clone())
                    .is_some_and(|prior| prior != *origin)
                {
                    return Err(Code::Conflict.error("selected source origin identity"));
                }
            }
            for (record, reference) in &source.proofs {
                if proofs
                    .insert((record.clone(), reference.key.clone()), reference.clone())
                    .is_some_and(|prior| prior != *reference)
                {
                    return Err(Code::Conflict.error("selected source proof identity"));
                }
            }
        }
        if derived != step.derived
            || origins.into_values().collect::<Vec<_>>() != step.origins
            || proofs
                .into_iter()
                .map(|((record, _), reference)| (record, reference))
                .collect::<Vec<_>>()
                != step.proofs
        {
            return Err(Code::Invalid.error("managed derived evidence union"));
        }
        Ok(())
    }

    fn check_step_evidence(
        &self,
        attempt: &Attempt,
        step: &Step,
        spec: &crate::ManagedSpec,
    ) -> Result<()> {
        let capture = &attempt.capture;
        let scope = spec.destination.selection(&capture.grant.selection)?;
        let witnessed = |value: &AnalysisWitnessV1| {
            step.witnesses
                .binary_search_by(|wanted| {
                    (&wanted.identity, wanted.cursor).cmp(&(&value.identity, value.cursor))
                })
                .ok()
                .is_some_and(|i| step.witnesses[i] == *value)
        };
        let contextual = |value: &AnalysisContextRefV1| {
            step.contexts
                .binary_search_by(|wanted| wanted.key.cmp(&value.key))
                .ok()
                .is_some_and(|i| step.contexts[i] == *value)
        };
        if step
            .witnesses
            .windows(2)
            .any(|pair| (&pair[0].identity, pair[0].cursor) >= (&pair[1].identity, pair[1].cursor))
            || step
                .contexts
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || capture.witnesses.iter().any(|value| !witnessed(value))
            || capture.contexts.iter().any(|value| !contextual(value))
        {
            return Err(Code::Invalid.error("managed source evidence order"));
        }
        for witness in &step.witnesses {
            if !capture.witnesses.contains(witness) {
                let valid = match &witness.identity {
                    crate::AnalysisStreamIdentityV1::Evidence(source) => {
                        source.valid()
                            && scope.includes_source(source)
                            && witness.cursor != 0
                            && (scope.cursor_from, scope.cursor_until).contains(&witness.cursor)
                    }
                    crate::AnalysisStreamIdentityV1::Diagnostic(_) => false,
                };
                if !valid || witness.expires_utc_ns != attempt.request.witness_expiry {
                    return Err(Code::Invalid.error("managed source witness expiry"));
                }
            }
        }
        for reference in &step.contexts {
            if reference.commit_revision > capture.revision
                || (!capture.contexts.contains(reference)
                    && (!reference.key.valid()
                        || reference.key.tenant_id != scope.tenant_id
                        || (!scope.contexts.is_all()
                            && !scope.contexts.as_slice().contains(&reference.key))
                        || reference.commit_revision == 0))
            {
                return Err(Code::Invalid.error("managed source context scope"));
            }
        }
        Ok(())
    }

    fn check_call_record(
        &self,
        id: u64,
        attempt: &Attempt,
        record: &Record,
        step: &Step,
        spec: &crate::ManagedSpec,
    ) -> Result<()> {
        if record
            .witnesses
            .windows(2)
            .any(|pair| (&pair[0].identity, pair[0].cursor) >= (&pair[1].identity, pair[1].cursor))
            || record
                .contexts
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || record
                .witnesses
                .iter()
                .any(|value| !step.witnesses.contains(value))
            || record
                .contexts
                .iter()
                .any(|value| !step.contexts.contains(value))
            || record
                .derived
                .iter()
                .any(|value| !step.derived.contains(value))
            || record
                .origins
                .iter()
                .any(|value| !step.origins.contains(value))
        {
            return Err(Code::Invalid.error("managed result source evidence"));
        }
        let declaration = &spec.manifest.calls[&record.call];
        let descriptor = self.managed_contract(spec, declaration)?;
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == declaration.export)
            .ok_or_else(|| Code::Missing.error("retained managed model"))?;
        if record.context.inputs.len() != model.inputs.len()
            || record.context.input_coverage.len() != model.inputs.len()
            || record.context.coverage
                != crate::ResultContext::coverage(&record.context.input_coverage)
        {
            return Err(Code::Invalid.error("retained managed evaluation context"));
        }
        self.check_change_record(record, attempt, declaration, model, &mut |_| Ok(()))?;
        if model.graph.is_some() {
            let mapping = self
                .managed_graph(spec.tenant, &spec.id, &AnalysisReadControl::default())?
                .ok_or_else(|| Code::Missing.error("managed Graph result mapping"))?;
            let writer = *mapping
                .writers
                .get(&record.call)
                .ok_or_else(|| Code::Missing.error("managed Graph result writer"))?;
            let receipt = attempt
                .receipt
                .as_ref()
                .ok_or_else(|| Code::Missing.error("managed Graph result receipt"))?;
            let origin = self.graph_origin(writer, receipt.commit_revision)?;
            if origin.layer != id || receipt.results.get(&record.call) != Some(&origin.reference) {
                return Err(Code::Invalid.error("managed Graph result authority"));
            }
        }
        if model.graph.is_none() && record.graph_proof.is_some() {
            return Err(Code::Invalid.error("Graph proof order"));
        }
        let mut dependencies = attempt.capture.dependencies.clone();
        dependencies.extend(declaration.dependencies.iter().filter_map(|call| {
            attempt
                .receipt
                .as_ref()
                .and_then(|receipt| receipt.results.get(call))
                .cloned()
        }));
        dependencies.sort_by(|left, right| left.result_id.cmp(&right.result_id));
        dependencies.dedup();
        if dependencies != record.dependencies {
            return Err(Code::Invalid.error("retained managed dependencies"));
        }
        let packet = self.result_checkpoint(id, &mut |_| Ok(()))?;
        let checkpoint = packet
            .as_ref()
            .map(|packet| packet.decode_model(model))
            .transpose()
            .context(crate::AnalysisContractSnafu)?;
        model
            .validate_checkpoint(checkpoint.as_ref(), true)
            .context(crate::AnalysisContractSnafu)?;
        Ok(())
    }
}

impl NativeStore {
    pub(in crate::analysis::native) fn validate_result_recovery(&self) -> Result<()> {
        let current = self.view()?;
        let control = AnalysisReadControl::default();
        let mut expected_results = BTreeMap::new();
        let mut checkpoints = std::collections::BTreeSet::new();
        for entry in current.snapshot.prefix(b"\0data/a") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate successful result owners",
            })?;
            if key.len() != 15 {
                continue;
            }
            let bytes = Records::payload(&key, |key| Records::read(key, &current.snapshot))?
                .ok_or_else(|| Code::Missing.error("managed recovery attempt"))?;
            let attempt: Attempt = Records::decode(&bytes)?;
            self.check_captured_progress(&attempt.capture)?;
            let historical = self.read_at(attempt.capture.revision)?;
            let target = current.managed_version(
                attempt.capture.tenant,
                &attempt.capture.instance,
                attempt.capture.generation,
                &control,
            )?;
            let captured = historical
                .managed_instance(attempt.capture.tenant, &attempt.capture.instance, &control)?
                .ok_or_else(|| Code::Missing.error("managed captured instance"))?;
            let owner = Records::find(
                &super::InstanceRecord::identity(
                    attempt.capture.tenant,
                    &attempt.capture.instance,
                )?,
                |key| Records::read(key, &historical.snapshot),
            )?
            .ok_or_else(|| Code::Missing.error("managed captured instance"))?;
            attempt
                .capture
                .check_native_heads(&captured, &target, owner, |key| {
                    Records::read(key, &historical.snapshot)
                })?;
            if let Some(receipt) = &attempt.receipt {
                for reference in receipt.results.values().chain([&receipt.selected]) {
                    let (id, result, _) = current.result_owner(
                        attempt.capture.tenant,
                        &reference.result_id,
                        &control,
                        &mut |_| Ok(()),
                    )?;
                    if let ResultBody::Call(record) = &result.body {
                        let declaration = &target.manifest.calls[&record.call];
                        let package = current.managed_contract(&target, declaration)?;
                        let model = package
                            .exports
                            .iter()
                            .find(|model| model.name == declaration.export)
                            .ok_or_else(|| Code::Missing.error("managed proof model"))?;
                        record.check_graph_proof(
                            &attempt,
                            model.graph.is_some(),
                            &mut |_, _| Ok(()),
                            |source, charge| {
                                historical.source_proof_coverage(
                                    &source.source,
                                    source.cpu,
                                    source.report,
                                    &mut |bytes| charge(0, bytes),
                                )
                            },
                        )?;
                    }
                    if expected_results.insert(id, result).is_some() {
                        return Err(Code::Invalid.error("managed result owner set"));
                    }
                }
            }
        }
        for entry in current.snapshot.prefix(b"\0data/X") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate managed result set",
            })?;
            if key.len() == 23 {
                continue;
            }
            if key.len() != 15 {
                return Err(Code::Invalid.error("managed result key"));
            }
            let id = Self::number(&key[7..])?;
            let result = expected_results
                .remove(&id)
                .ok_or_else(|| Code::Invalid.error("managed result owner set"))?;
            if matches!(result.body, ResultBody::Call(_)) {
                checkpoints.insert(id);
            }
        }
        if !expected_results.is_empty() {
            return Err(Code::Missing.error("managed result owner set"));
        }
        for entry in current.snapshot.prefix(b"\0data/U") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate managed checkpoint set",
            })?;
            if key.len() == 23 {
                continue;
            }
            if key.len() != 15 || !checkpoints.remove(&Self::number(&key[7..])?) {
                return Err(Code::Invalid.error("managed checkpoint owner set"));
            }
        }
        if !checkpoints.is_empty() {
            return Err(Code::Missing.error("managed checkpoint owner set"));
        }
        self.validate_result_references()?;
        Ok(())
    }
}
