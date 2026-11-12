use std::ops::Bound::{Excluded, Included};

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::super::{DataView, DataWrite, NativeStore};
use super::Records;
use crate::{
    AnalysisExtractionV1, AnalysisGapV1, AnalysisReadControl, AnalysisRecoveryStatusV1,
    EvidenceIntakeIdentityV1, NativeStateSnafu, NativeStorageSnafu, Result,
};

#[derive(Deserialize, Serialize)]
struct RecoveryRange {
    source: EvidenceIntakeIdentityV1,
    gap: AnalysisGapV1,
}

impl RecoveryRange {
    const PREFIX: &'static [u8] = b"\0data/@source-recovery/";

    fn prefix(source: &EvidenceIntakeIdentityV1) -> Vec<u8> {
        [Self::PREFIX, &source.key()].concat()
    }

    fn key(source: &EvidenceIntakeIdentityV1, last: u64) -> Vec<u8> {
        [Self::prefix(source).as_slice(), &last.to_be_bytes()].concat()
    }

    fn bounds(
        source: &EvidenceIntakeIdentityV1,
        after: u64,
    ) -> (std::ops::Bound<Vec<u8>>, std::ops::Bound<Vec<u8>>) {
        (
            Excluded(Self::key(source, after)),
            Included(Self::key(source, u64::MAX)),
        )
    }

    fn decode(key: &[u8], value: &[u8], revision: u64) -> Result<Self> {
        let bytes = value.strip_prefix(&[0]).ok_or_else(|| {
            NativeStateSnafu {
                field: "source recovery encoding",
            }
            .build()
        })?;
        let record: Self = Records::decode(bytes)?;
        if !record.source.valid()
            || record.gap.first_cursor == 0
            || record.gap.last_cursor < record.gap.first_cursor
            || record.gap.commit_revision == 0
            || record.gap.commit_revision > revision
            || Self::key(&record.source, record.gap.last_cursor) != key
        {
            return NativeStateSnafu {
                field: "source recovery identity",
            }
            .fail();
        }
        Ok(record)
    }
}

impl NativeStore {
    pub fn record_recovery_floor(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        node_floor: u64,
    ) -> Result<AnalysisRecoveryStatusV1> {
        let mut write = self.maintenance_write()?;
        let status = write.record_recovery_floor(identity, node_floor)?;
        write.commit([])?;
        Ok(status)
    }

    pub fn recovery_gaps(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        after_cursor: u64,
    ) -> Result<Vec<AnalysisGapV1>> {
        self.view()?.recovery_gaps(identity, after_cursor)
    }
}

impl DataView {
    pub(in crate::analysis::native) fn recovery_bound(&self, mut bound: u64) -> Result<u64> {
        if bound == 0 {
            return Ok(0);
        }
        for row in self.snapshot.prefix(RecoveryRange::PREFIX) {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "read retained recovery history",
            })?;
            bound = bound.min(
                RecoveryRange::decode(&key, &value, self.metadata_revision)?
                    .gap
                    .commit_revision,
            );
        }
        Ok(bound)
    }
}

impl DataWrite<'_> {
    fn record_recovery_floor(
        &mut self,
        identity: &EvidenceIntakeIdentityV1,
        node_floor: u64,
    ) -> Result<AnalysisRecoveryStatusV1> {
        if !identity.valid() {
            return NativeStateSnafu {
                field: "source recovery identity",
            }
            .fail();
        }
        let accepted = self
            .raw
            .sources
            .get(&identity.key())
            .map_or(0, |source| source.receipt.cursor());
        if node_floor <= accepted {
            return Ok(AnalysisRecoveryStatusV1::Complete);
        }
        let first = accepted + 1;
        let prior = self
            .transaction
            .prefix(RecoveryRange::prefix(identity))
            .next_back()
            .transpose()
            .context(NativeStorageSnafu {
                operation: "read source recovery floor",
            })?
            .map(|(key, value)| RecoveryRange::decode(&key, &value, self.metadata_revision))
            .transpose()?;
        if prior
            .as_ref()
            .is_none_or(|record| record.gap.last_cursor < node_floor)
        {
            let next = prior.map_or(first, |record| first.max(record.gap.last_cursor + 1));
            let record = RecoveryRange {
                source: identity.clone(),
                gap: AnalysisGapV1 {
                    first_cursor: next,
                    last_cursor: node_floor,
                    commit_revision: self.revision,
                },
            };
            self.transaction.insert(
                RecoveryRange::key(identity, node_floor),
                Records::encode(&record)?,
            );
            self.note_relation("recovery_gaps", self.revision)?;
        }
        Ok(AnalysisRecoveryStatusV1::Partial {
            first_cursor: first,
            last_cursor: node_floor,
        })
    }
}

impl DataView {
    pub fn recovery_gaps(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        after_cursor: u64,
    ) -> Result<Vec<AnalysisGapV1>> {
        if !identity.valid() {
            return NativeStateSnafu {
                field: "source recovery identity",
            }
            .fail();
        }
        self.snapshot
            .range::<Vec<u8>, _>(RecoveryRange::bounds(identity, after_cursor))
            .take(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS)
            .map(|row| {
                let (key, value) = row.context(NativeStorageSnafu {
                    operation: "read source recovery gaps",
                })?;
                Ok(RecoveryRange::decode(&key, &value, self.metadata_revision)?.gap)
            })
            .collect()
    }

    pub(super) fn source_recovery(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<Vec<AnalysisGapV1>> {
        let mut gaps = Vec::new();
        for row in self
            .snapshot
            .range::<Vec<u8>, _>(RecoveryRange::bounds(identity, 0))
        {
            control.check()?;
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "read selected source recovery",
            })?;
            let saved = output.input_bytes;
            output.charge(value.len().saturating_mul(2))?;
            let record = RecoveryRange::decode(&key, &value, self.metadata_revision)?;
            let gap = record.gap;
            drop(record);
            drop(value);
            output.input_bytes = saved;
            output.charge(AnalysisExtractionV1::grow(
                &mut gaps,
                output.input_bytes,
                output.limits.input_bytes,
            )?)?;
            gaps.push(gap);
        }
        Ok(gaps)
    }

    pub(in crate::analysis::native) fn input_recovery_key(key: &[u8]) -> bool {
        key.starts_with(RecoveryRange::PREFIX)
    }

    pub(in crate::analysis::native) fn input_recovery(
        &self,
        key: &[u8],
    ) -> Result<Option<(EvidenceIntakeIdentityV1, AnalysisGapV1)>> {
        if !Self::input_recovery_key(key) {
            return Ok(None);
        }
        let value = NativeStore::required(&self.snapshot, key)?;
        let record = RecoveryRange::decode(key, &value, self.metadata_revision)?;
        if record.gap.commit_revision != self.metadata_revision {
            return NativeStateSnafu {
                field: "input recovery revision",
            }
            .fail();
        }
        Ok(Some((record.source, record.gap)))
    }

    pub(in crate::analysis::native) fn validate_recovery_ranges(&self) -> Result<()> {
        let notice = self
            .snapshot
            .get(NativeStore::relation_key("recovery_gaps"))
            .context(NativeStorageSnafu {
                operation: "read source recovery notice",
            })?
            .map(|value| NativeStore::number(&value))
            .transpose()?
            .unwrap_or(0);
        if notice > self.metadata_revision {
            return NativeStateSnafu {
                field: "source recovery notice",
            }
            .fail();
        }
        let mut prior: Option<RecoveryRange> = None;
        for row in self.snapshot.prefix(RecoveryRange::PREFIX) {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "validate source recovery gaps",
            })?;
            let record = RecoveryRange::decode(&key, &value, self.metadata_revision)?;
            if record.gap.commit_revision > notice {
                return NativeStateSnafu {
                    field: "source recovery notice",
                }
                .fail();
            }
            if prior.as_ref().is_some_and(|previous| {
                previous.source == record.source
                    && (previous.gap.last_cursor >= record.gap.first_cursor
                        || previous.gap.commit_revision >= record.gap.commit_revision)
            }) {
                return NativeStateSnafu {
                    field: "source recovery order",
                }
                .fail();
            }
            prior = Some(record);
        }
        Ok(())
    }
}
