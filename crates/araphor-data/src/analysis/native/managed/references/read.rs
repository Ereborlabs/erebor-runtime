use std::collections::BTreeSet;

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
            let (target, stored) = StoredResult::read(
                tenant,
                &reference.result_id,
                self.metadata_revision,
                |key| Records::read(key, &self.snapshot),
                &mut |_| control.check(),
            )?
            .ok_or_else(|| Code::Missing.error("managed result dependency"))?;
            if stored.revision != reference.commit_revision {
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
        let prefix = References::key(References::RAW, &[result]);
        let mut present = BTreeSet::new();
        for entry in self.snapshot.prefix(&prefix) {
            charge(0)?;
            let (key, value) = entry.context(crate::NativeStorageSnafu {
                operation: "read managed witness pins",
            })?;
            if key.len() != prefix.len() + 8 || value.len() != 16 {
                return Err(Code::Invalid.error("managed witness pin value"));
            }
            let ordinal = usize::try_from(NativeStore::number(&key[prefix.len()..])?)
                .map_err(|_| Code::Invalid.error("extra managed witness pin"))?;
            let witness = witnesses
                .get(ordinal)
                .ok_or_else(|| Code::Invalid.error("extra managed witness pin"))?;
            let segment = NativeStore::number(&value[..8])?;
            let expires = NativeStore::number(&value[8..])?;
            let stream = witness.identity.key();
            let live = self
                .raw
                .ranges
                .range((stream.clone(), 0)..=(stream, witness.cursor))
                .next_back()
                .is_some_and(|(_, &(revision, slot))| {
                    let entry = &self.raw.entries[&revision];
                    entry.identity == witness.identity
                        && revision <= self.revision
                        && entry.reference.id == segment
                        && entry.commit.spans[slot].last >= witness.cursor
                });
            let reverse = Records::read(
                &References::key(References::SEGMENT, &[segment, result, ordinal as u64]),
                &self.snapshot,
            )?;
            if witness.expires_utc_ns != expires
                || !live
                || reverse
                    .map(|value| NativeStore::number(&value))
                    .transpose()?
                    != Some(expires)
            {
                return Err(Code::Invalid.error("managed witness pin value"));
            }
            present.insert(ordinal);
        }
        if present.len() != witnesses.len() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Code::Invalid.error("source witness expiry clock"))?
                .as_nanos();
            if witnesses.iter().enumerate().any(|(ordinal, witness)| {
                !present.contains(&ordinal) && u128::from(witness.expires_utc_ns) > now
            }) {
                return Err(Code::Missing.error("managed source witness binding"));
            }
        }
        Ok(())
    }
}
