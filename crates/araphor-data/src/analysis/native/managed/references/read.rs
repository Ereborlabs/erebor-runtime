use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::analysis::native::{DataView, NativeStore};

impl DataView {
    pub(in crate::analysis::native) fn check_dependencies(
        &self,
        result: u64,
        tenant: [u8; 16],
        references: &[PackageResultRefV1],
        control: &crate::AnalysisReadControl,
    ) -> Result<()> {
        if references
            .windows(2)
            .any(|pair| pair[0].result_id >= pair[1].result_id)
        {
            return Err(Code::Conflict.error("managed change owner"));
        }
        let mut expected = std::collections::BTreeMap::new();
        for reference in references {
            control.check()?;
            let (target, revision) = self
                .result_reference(tenant, &reference.result_id, &mut |_| control.check())?
                .ok_or_else(|| Code::Missing.error("managed result dependency"))?;
            if revision != reference.commit_revision {
                return Err(Code::Conflict.error("managed change owner"));
            }
            expected.insert(
                References::key(References::DEPENDENCY, &[result, target]),
                reference.commit_revision.to_be_bytes(),
            );
        }
        for entry in self
            .snapshot
            .prefix(References::key(References::DEPENDENCY, &[result]))
        {
            control.check()?;
            let (key, value) = entry.context(crate::NativeStorageSnafu {
                operation: "read managed dependencies",
            })?;
            if expected
                .remove(key.as_ref())
                .as_ref()
                .map(|revision| revision.as_slice())
                != Some(value.as_ref())
            {
                return Err(Code::Conflict.error("managed change owner"));
            }
        }
        if !expected.is_empty() {
            return Err(Code::Conflict.error("managed change owner"));
        }
        Ok(())
    }

    pub(in crate::analysis::native) fn check_result_pins(
        &self,
        result: u64,
        witnesses: &[AnalysisWitnessV1],
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<()> {
        charge(
            crate::analysis::managed::source::SourceEvidence::metadata_bytes(
                witnesses.iter(),
                std::iter::empty::<&AnalysisContextRefV1>(),
            )?,
        )?;
        let mut expected = BTreeMap::<(PinTarget, u64), BTreeSet<u64>>::new();
        let mut unresolved = Vec::new();
        for witness in witnesses {
            charge(0)?;
            let segment = self.witness_target(witness, self.revision)?;
            if let Some(segment) = segment {
                expected
                    .entry((segment, witness.expires_utc_ns))
                    .or_default()
                    .insert(witness.cursor);
            } else {
                unresolved.push(witness.expires_utc_ns);
            }
        }
        for prefix in [References::RAW, References::EVIDENCE] {
            let prefix = References::key(prefix, &[result]);
            for entry in self.snapshot.prefix(&prefix) {
                charge(0)?;
                let (key, value) = entry.context(crate::NativeStorageSnafu {
                    operation: "read managed witness pins",
                })?;
                let pin = WitnessPin::decode(&key, &value)?;
                let cursors = expected
                    .get_mut(&(pin.target, pin.expires))
                    .ok_or_else(|| Code::Invalid.error("managed witness pin value"))?;
                for (first, last) in &pin.ranges {
                    if cursors.range(*first..=*last).count() as u128 != u128::from(last - first) + 1
                    {
                        return Err(Code::Invalid.error("managed witness pin value"));
                    }
                    for cursor in *first..=*last {
                        cursors.remove(&cursor);
                    }
                }
                let reverse = Records::read(&pin.reverse(), &self.snapshot)?;
                if reverse
                    .map(|value| NativeStore::number(&value))
                    .transpose()?
                    != Some(pin.expires)
                {
                    return Err(Code::Invalid.error("managed witness pin value"));
                }
            }
        }
        if expected.values().any(|cursors| !cursors.is_empty()) || !unresolved.is_empty() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Code::Invalid.error("source witness expiry clock"))?
                .as_nanos();
            if expected
                .iter()
                .any(|((_, expires), cursors)| !cursors.is_empty() && u128::from(*expires) > now)
                || unresolved.iter().any(|expires| u128::from(*expires) > now)
            {
                return Err(Code::Missing.error("managed source witness binding"));
            }
        }
        Ok(())
    }
}
