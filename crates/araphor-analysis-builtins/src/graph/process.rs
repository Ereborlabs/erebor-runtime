use std::collections::BTreeSet;

use super::*;

impl Computation {
    pub(super) fn process(&mut self) -> sdk::Result<()> {
        for row in 0..self.records.len() {
            self.process_record(row as u32)?;
        }
        for index in 0..self.facts.len() {
            let FactValue::Context { classification, .. } = self.facts[index].value else {
                continue;
            };
            let row = self.facts[index].record;
            self.context_finding(
                row,
                Some(index as u32),
                match classification {
                    ContextClass::OutsideAuthority => "OUTSIDE_AUTHORITY",
                    ContextClass::InMemory => "IN_MEMORY_ONLY",
                    ContextClass::PayloadUnobservable => "PAYLOAD_UNOBSERVABLE",
                },
                false,
                vec![row],
                vec!["CONTEXT_ANCHOR_HAS_NO_PHYSICAL_ACTION_PROOF".into()],
            )?;
        }
        Ok(())
    }

    fn process_record(&mut self, row: u32) -> sdk::Result<()> {
        let record = self.record(row)?.clone();
        self.subject(row, None)?;
        let cause = if record.exact_identity() {
            Cause::Direct
        } else {
            Cause::Contextual
        };
        for (present, kind) in [
            (record.process_instance_id.is_some(), EdgeKind::Process),
            (
                record.effect.execution_set_id.iter().any(|byte| *byte != 0),
                EdgeKind::ExecutionSet,
            ),
            (
                record.effect.exact_object_id.iter().any(|byte| *byte != 0),
                EdgeKind::Object,
            ),
        ] {
            if present {
                self.edge(row, None, kind, cause, vec![row])?;
            }
        }
        let mut ancestry = false;
        let mut deviations = BTreeSet::new();
        let mut baseline_unproved = false;
        let mut parents = Vec::new();
        for (index, fact) in self.facts(row) {
            match &fact.value {
                FactValue::NativeParent {
                    child,
                    proof_quality,
                    ..
                } => {
                    if proof_quality.parent_qualified()
                        && child
                            .matches_local(record.effect.task_cookie, record.process_instance_id)
                    {
                        parents.push(index as u32);
                        ancestry = true;
                    }
                }
                FactValue::Baseline {
                    role_id,
                    state_id,
                    outside_reviewed_baseline,
                    ..
                } if record.role_id == Some(*role_id) && record.state_id == Some(*state_id) => {
                    if self.reviewed(fact)? {
                        deviations.insert(*outside_reviewed_baseline);
                    } else if *outside_reviewed_baseline {
                        baseline_unproved = true;
                    }
                }
                _ => {}
            }
        }
        for index in parents {
            self.edge(row, Some(index), EdgeKind::Parent, Cause::Direct, vec![row])?;
        }
        let mut limits = Vec::new();
        for (present, limit) in [
            (baseline_unproved, "REVIEWED_BASELINE_PROVENANCE_MISSING"),
            (!ancestry, "NATIVE_ANCESTRY_UNAVAILABLE"),
            (!record.complete(), "SOURCE_COVERAGE_INSUFFICIENT"),
            (record.network(), "TLS_PAYLOAD_UNOBSERVABLE"),
            (record.network(), "REMOTE_OPERATION_UNPROVEN"),
            (
                record.physical() == Physical::Unknown,
                "PHYSICAL_EFFECT_UNPROVEN",
            ),
            (
                record.physical() == Physical::PacketDropped,
                "LOCAL_PACKET_DROP_ONLY",
            ),
            (
                record.physical() == Physical::PacketDropped,
                "SYSCALL_COMPLETION_UNPROVEN",
            ),
            (
                record.physical() == Physical::PacketDropped,
                "PROVIDER_WRITE_AND_CONTENT_UNPROVEN",
            ),
            (
                record.physical() == Physical::TerminationQueued,
                "TERMINATION_COMPLETION_UNPROVEN",
            ),
        ] {
            if present {
                limits.push(limit.into());
            }
        }
        let enforced = record.denied()
            || matches!(
                record.physical(),
                Physical::PacketDropped | Physical::TerminationQueued
            );
        if deviations.len() > 1 || self.policy_conflict(row)? {
            self.state.value = "CONTRADICTED".into();
            self.finding(row, "CONTRADICTION", false, vec![row], limits)?;
        } else if !record.exact_identity()
            || enforced
            || deviations.contains(&true)
            || baseline_unproved
        {
            self.state.value = "NATIVE_EFFECT".into();
            let reason = if !record.exact_identity() {
                "LINEAGE_COVERAGE_GAP"
            } else if enforced {
                "UNEXPECTED_EFFECT"
            } else {
                "AUDITED_ROLE_DEVIATION"
            };
            self.finding(
                row,
                reason,
                record.exact_identity() && !baseline_unproved && record.complete(),
                vec![row],
                limits,
            )?;
        }
        Ok(())
    }
}
