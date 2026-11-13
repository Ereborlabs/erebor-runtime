use super::*;
use crate::analysis::native::source::Sources;

impl DataView {
    pub(in crate::analysis::native) fn validate_events(&self, root: &Path) -> Result<()> {
        let events = Events::new(self);
        let mut expected_payloads = 0_usize;
        let mut expected_spans = 0_usize;
        for row in self.snapshot.prefix(Events::POSITION) {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "validate evidence positions",
            })?;
            let batch = events.decode_batch(&key, &value)?;
            let receipt = self.source_receipt(&batch.source)?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "evidence batch source",
                }
                .build()
            })?;
            if batch.meta.kind.cpu() != Some(receipt.cpu_id) {
                return NativeStateSnafu {
                    field: "evidence batch CPU",
                }
                .fail();
            }
            expected_spans = expected_spans
                .checked_add(batch.meta.spans.len())
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "evidence index count",
                    }
                    .build()
                })?;
            if events.expiry(batch.meta.revision)?.is_none() {
                expected_payloads = expected_payloads.checked_add(1).ok_or_else(|| {
                    NativeStateSnafu {
                        field: "evidence payload count",
                    }
                    .build()
                })?;
            }
        }
        let mut payloads = 0_usize;
        for row in self.snapshot.prefix(Events::PAYLOAD) {
            let (key, bytes) = row.context(NativeStorageSnafu {
                operation: "validate original evidence payloads",
            })?;
            let commit = RawCommit::from_frame(&bytes, root)?;
            let batch = events.batch(commit.revision)?;
            batch.check_commit(&commit, bytes.len())?;
            if key.as_ref() != Events::key(Events::PAYLOAD, &batch.source, batch.first)
                || events.expiry(commit.revision)?.is_some()
            {
                return NativeStateSnafu {
                    field: "evidence payload key",
                }
                .fail();
            }
            payloads = payloads.checked_add(1).ok_or_else(|| {
                NativeStateSnafu {
                    field: "evidence payload count",
                }
                .build()
            })?;
        }
        let mut spans = 0_usize;
        for row in self.snapshot.prefix(Events::SPANS) {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "validate accepted evidence indexes",
            })?;
            let span: EventSpan = Records::decode(value.strip_prefix(&[0]).ok_or_else(|| {
                NativeStateSnafu {
                    field: "evidence span value",
                }
                .build()
            })?)?;
            let batch = events.batch(span.revision)?;
            let (first, span) = Events::decode_span(&batch.source, &key, &value)?;
            batch.check_span(&batch.source, first, &span)?;
            spans = spans.checked_add(1).ok_or_else(|| {
                NativeStateSnafu {
                    field: "evidence span count",
                }
                .build()
            })?;
        }
        if payloads != expected_payloads || spans != expected_spans {
            return NativeStateSnafu {
                field: "missing native evidence index or payload",
            }
            .fail();
        }
        for row in self.snapshot.prefix(Events::EXPIRED) {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "validate evidence expiry markers",
            })?;
            let revision = NativeStore::number(&key[Events::EXPIRED.len()..])?;
            events.batch(revision)?;
            events.expiry(revision)?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "evidence expiry marker",
                }
                .build()
            })?;
        }
        for row in self.snapshot.prefix(Sources::RECEIPTS) {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "validate native source receipts",
            })?;
            let receipt = Sources::decode_receipt(&key, &value)?;
            if self
                .source_binding(
                    receipt.identity.tenant_id,
                    &receipt.identity.node_id,
                    receipt.identity.source_id,
                    receipt.identity.source_epoch,
                )?
                .as_ref()
                != Some(&receipt.identity)
            {
                return NativeStateSnafu {
                    field: "source epoch receipt binding",
                }
                .fail();
            }
            let mut contiguous = 0_u64;
            let mut previous = 0;
            let mut gap = false;
            for row in events.spans(&receipt.identity, 1, u64::MAX)? {
                let (key, value) = row.context(NativeStorageSnafu {
                    operation: "validate original evidence prefix",
                })?;
                let (first, span) = Events::decode_span(&receipt.identity, &key, &value)?;
                if first <= previous {
                    return NativeStateSnafu {
                        field: "overlapping accepted evidence spans",
                    }
                    .fail();
                }
                previous = span.last;
                gap |= first > contiguous.saturating_add(1);
                if !gap {
                    contiguous = span.last;
                }
            }
            if contiguous != receipt.contiguous_cursor {
                return NativeStateSnafu {
                    field: "source original evidence prefix",
                }
                .fail();
            }
            self.source_status(&receipt.identity)?;
        }
        for row in self.snapshot.prefix(Sources::EPOCHS) {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "validate source epoch mappings",
            })?;
            let identity: EvidenceIntakeIdentityV1 =
                Records::decode(value.strip_prefix(&[0]).ok_or_else(|| {
                    NativeStateSnafu {
                        field: "source epoch value",
                    }
                    .build()
                })?)?;
            if !identity.valid()
                || key.as_ref() != Sources::key(Sources::EPOCHS, &identity.epoch_key())
                || self.source_receipt(&identity)?.is_none()
            {
                return NativeStateSnafu {
                    field: "source epoch identity",
                }
                .fail();
            }
        }
        Ok(())
    }
}
