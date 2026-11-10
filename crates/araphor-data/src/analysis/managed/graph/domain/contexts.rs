use super::*;
use crate::{AnalysisContextKeyV1, AnalysisContextVersionV1};

type Values = std::collections::BTreeMap<
    AnalysisContextKeyV1,
    (AnalysisContextVersionV1, AnalysisContextRefV1),
>;

pub(in crate::analysis) struct ContextInputs {
    pub(in crate::analysis) values: Values,
}

impl ContextInputs {
    pub(in crate::analysis) fn capture(
        root: &std::path::Path,
        attempt: &crate::ManagedAttempt,
        call: u64,
        captured: &[(AnalysisContextVersionV1, AnalysisContextRefV1)],
        evidence: &super::super::super::source::SourceEvidence,
        derived: &super::super::super::source::import::PreparedDerived,
        memory: &mut super::super::super::budget::PreparedMemory<'_>,
    ) -> Result<Self> {
        let calls = attempt.1.spec.manifest.input_calls(call)?;
        let frame = attempt.5.as_ref();
        let refs = frame.map(|frame| frame.call_contexts(&calls)).transpose()?;
        let wanted = crate::AnalysisContextRefV1::join(
            refs.as_deref().unwrap_or(&evidence.contexts),
            &derived.contexts(call),
        )?;
        let mut result = Self {
            values: frame
                .map(|frame| {
                    frame.canonical_contexts(&calls, root, &mut |bytes| memory.charge(bytes))
                })
                .transpose()?
                .unwrap_or_default(),
        };
        for (value, reference) in captured {
            result.insert(value, reference, &wanted, memory)?;
        }
        if let Some(frame) = frame {
            for handle in frame.call_derived(&calls)? {
                for value in &handle.contexts {
                    if let Some(reference) = handle.references.get(&value.key) {
                        result.insert(value, reference, &wanted, memory)?;
                    }
                }
                if let Some(history) = &handle.history {
                    for (value, reference) in history.contexts() {
                        result.insert(value, reference, &wanted, memory)?;
                    }
                }
            }
        }
        for value in derived.values(call) {
            if let Ok(index) = wanted.binary_search_by(|reference| reference.key.cmp(&value.key)) {
                result.insert(value, &wanted[index], &wanted, memory)?;
            }
        }
        result.finish(&wanted)?;
        Ok(result)
    }

    pub(in crate::analysis) fn insert(
        &mut self,
        value: &AnalysisContextVersionV1,
        reference: &AnalysisContextRefV1,
        wanted: &[AnalysisContextRefV1],
        memory: &mut super::super::super::budget::PreparedMemory<'_>,
    ) -> Result<()> {
        if wanted
            .binary_search_by(|wanted| wanted.key.cmp(&reference.key))
            .ok()
            .is_none_or(|index| wanted[index] != *reference)
        {
            return Ok(());
        }
        if value.key != reference.key {
            return Err(Code::Denied.error("canonical Graph context authority"));
        }
        if let Some(prior) = self.values.get(&value.key) {
            if prior.0 != *value || prior.1 != *reference {
                return Err(Code::Conflict.error("canonical context cells"));
            }
            return Ok(());
        }
        memory.charge(
            value
                .body
                .len()
                .saturating_mul(8)
                .saturating_add(value.key.allocated_bytes().saturating_mul(4))
                .saturating_add(12 * size_of::<(AnalysisContextVersionV1, AnalysisContextRefV1)>()),
        )?;
        self.values
            .insert(value.key.clone(), (value.clone(), reference.clone()));
        Ok(())
    }

    pub(in crate::analysis) fn finish(&mut self, wanted: &[AnalysisContextRefV1]) -> Result<()> {
        self.values.retain(|key, (_, reference)| {
            wanted
                .binary_search_by(|wanted| wanted.key.cmp(key))
                .ok()
                .is_some_and(|index| wanted[index] == *reference)
        });
        if self.values.len() != wanted.len() {
            return Err(Code::Denied.error("Graph disclosure context"));
        }
        Ok(())
    }

    pub(in crate::analysis) fn restricted(&self) -> bool {
        self.values
            .values()
            .any(|(value, _)| value.sensitivity == crate::ContextSensitivityV1::HostRestricted)
    }
}
