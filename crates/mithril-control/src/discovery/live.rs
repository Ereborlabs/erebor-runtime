use std::sync::Mutex;

use prost::Message as _;
use serde::{Deserialize, Serialize};

use super::*;
use crate::{
    error::DiscoverySnafu, ControlStore, DiscoveryContextJoinV1, DiscoveryContextUnavailableV1,
    DiscoveryHeadKeyV1, DiscoveryHeadV1, EvidenceIntakeIdentityV1, Result,
};

pub(super) struct DiscoveryLive {
    store: ControlStore,
    index: DiscoveryIndex,
    operation: Mutex<()>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum DiscoveryAdvanceV1 {
    Idle {
        next_cursor: u64,
    },
    Applied {
        export: DiscoveryHeadV1,
        progress: DiscoveryIndexProgressV1,
    },
}

impl DiscoveryOwner {
    pub fn open(store: ControlStore) -> Result<Self> {
        let index = DiscoveryIndex::open(store.clone())?;
        store.recover_discovery_artifacts()?;
        Ok(Self {
            live: Some(DiscoveryLive {
                store,
                index,
                operation: Mutex::new(()),
            }),
        })
    }

    fn live(&self) -> Result<&DiscoveryLive> {
        self.live.as_ref().ok_or_else(|| {
            DiscoverySnafu {
                code: "DISCOVERY_DISABLED",
                reason: "live discovery is not open",
            }
            .build()
        })
    }

    pub fn advance(
        &self,
        stream: &EvidenceIntakeIdentityV1,
        interval_first_cursor: u64,
    ) -> Result<DiscoveryAdvanceV1> {
        let live = self.live()?;
        // ponytail: one interval operation runs at a time; add per-interval locks if throughput requires them.
        let _operation = live.operation.try_lock().map_err(|_| {
            DiscoverySnafu {
                code: "DISCOVERY_BUSY",
                reason: "another interval operation is active",
            }
            .build()
        })?;
        DiscoveryInputManifestV1::require(interval_first_cursor > 0, "INTERVAL_START")?;
        let key = DiscoveryHeadKeyV1 {
            tenant_id: stream.tenant_id,
            id: DiscoveryDigestV1::of(&("evidence-export-v1", stream, interval_first_cursor))?,
        };
        let previous = live.store.discovery_head(&key)?;
        let (first_cursor, remaining_records, remaining_bytes) = if let Some(head) = &previous {
            let indexed = live.index.progress(key.tenant_id, &key.id)?;
            let progress = if indexed
                .as_ref()
                .is_some_and(|progress| progress.commit_index == head.commit_index)
            {
                live.index.apply_export(head)?
            } else {
                live.index.replay_interval(head)?
            };
            DiscoveryInputManifestV1::require(
                progress.accepted_records < MAX_DISCOVERY_RECORDS as u64
                    && progress.input_bytes < MAX_DISCOVERY_INPUT_BYTES as u64,
                "INTERVAL_SEAL_REQUIRED",
            )?;
            (
                progress.next_cursor,
                MAX_DISCOVERY_RECORDS - progress.accepted_records as usize,
                MAX_DISCOVERY_INPUT_BYTES as u64 - progress.input_bytes,
            )
        } else {
            (
                interval_first_cursor,
                MAX_DISCOVERY_RECORDS,
                MAX_DISCOVERY_INPUT_BYTES as u64,
            )
        };
        let read = live.store.begin_evidence_read(stream, first_cursor)?;
        let metadata = read.metadata();
        if first_cursor > metadata.last_cursor {
            return Ok(DiscoveryAdvanceV1::Idle {
                next_cursor: first_cursor,
            });
        }
        let mut exported = DiscoveryExportPageV1 {
            schema_version: 1,
            stream: stream.clone(),
            cpu_binding: metadata.cpu_binding,
            first_cursor,
            expired_through: None,
            coverage_record: metadata
                .coverage
                .as_ref()
                .map(|coverage| coverage.encode_to_vec()),
            previous,
            records: Vec::new(),
        };
        match live.store.read_evidence_page(&read, first_cursor) {
            Ok(page) => {
                for (ordinal, wire) in page.records.into_iter().take(remaining_records).enumerate()
                {
                    let cursor = first_cursor + ordinal as u64;
                    let mut context = if let Some(cpu) = exported
                        .cpu_binding
                        .filter(|cpu| cursor >= cpu.first_cursor)
                    {
                        live.store.discovery_context(&DiscoveryRecordV1::from_wire(
                            stream, cpu.cpu_id, cursor, &wire,
                        )?)?
                    } else {
                        DiscoveryContextJoinV1::Unresolved(
                            DiscoveryContextUnavailableV1::MissingSourceCpu,
                        )
                    };
                    if serde_json::to_writer(
                        super::model::InputByteLimit(MAX_DISCOVERY_PIN_BYTES),
                        &context,
                    )
                    .is_err()
                    {
                        context = DiscoveryContextJoinV1::Unresolved(
                            DiscoveryContextUnavailableV1::ContextLimit,
                        );
                    }
                    exported.records.push(DiscoveryExportRecordV1 {
                        wire_record: wire.encode_to_vec(),
                        context,
                    });
                }
            }
            Err(crate::Error::RetainedRangeExpired { last_cursor, .. }) => {
                exported.expired_through = Some(last_cursor);
            }
            Err(error) => return Err(error),
        }
        let artifact = loop {
            if exported.input_bytes()? <= remaining_bytes {
                match exported.artifact() {
                    Ok(artifact) => break artifact,
                    Err(crate::Error::Discovery {
                        code: "EXPORT_LIMIT",
                        ..
                    }) => {}
                    Err(error) => return Err(error),
                }
            }
            DiscoveryInputManifestV1::require(
                exported.records.len() > 1,
                "INTERVAL_SEAL_REQUIRED",
            )?;
            exported.records.truncate(exported.records.len() / 2);
        };
        let artifact = live.store.put_discovery_artifact(&artifact)?;
        let export = live
            .store
            .commit_discovery_head(key, exported.previous.as_ref(), artifact)?;
        let progress = live.index.apply_export(&export)?;
        Ok(DiscoveryAdvanceV1::Applied { export, progress })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_derivation_exports_retained_input_and_exact_gaps_then_rebuilds(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let input = DiscoveryInputManifestV1::from_json(include_bytes!(
            "../../../mithril-e2e/fixtures/discovery/manifest.json"
        ))?;
        let record = &input.records[0];
        let stream = &record.id.stream;
        let wire = record.observation.to_wire_record()?.encode_to_vec();
        let mut frames = Vec::new();
        for _ in 0..10 {
            let start = frames.len();
            frames.extend_from_slice(&u32::try_from(wire.len())?.to_be_bytes());
            frames.extend_from_slice(&wire);
            let checksum = crc32c::crc32c(&frames[start..]);
            frames.extend_from_slice(&checksum.to_be_bytes());
        }
        for first_cursor in [1, 11] {
            crate::EvidenceIntakeOwner::from_store(store.clone()).receive(
                &crate::AuthenticatedEvidenceNodeV1 {
                    tenant_id: stream.tenant_id,
                    node_id: stream.node_id.clone(),
                    node_boot_id: stream.node_boot_id,
                    label_epoch: stream.label_epoch,
                },
                crate::EvidenceBatch {
                    node_boot_id: stream.node_boot_id.to_vec(),
                    source_id: stream.source_id.to_vec(),
                    source_epoch: stream.source_epoch,
                    cpu_id: record.id.cpu_id,
                    first_cursor,
                    framed_records: frames.clone().into(),
                    commit_group_tail: true,
                },
            )?;
        }
        let retention = crate::EvidenceRetentionOwner::from_store(store.clone());
        retention.acknowledge(crate::EvidenceConsumptionWatermarkV1 {
            identity: stream.clone(),
            evidence_cursor: 10,
            coverage_revision: 0,
        })?;
        let before = retention.watermark(stream)?;
        assert!(DiscoveryOwner::default().advance(stream, 1).is_err());
        let owner = DiscoveryOwner::open(store.clone())?;
        assert!(DiscoveryOwner::open(store.clone()).is_err());
        {
            let _busy = owner
                .live()?
                .operation
                .lock()
                .map_err(|_| "operation poisoned")?;
            assert!(owner.advance(stream, 1).is_err());
        }
        let DiscoveryAdvanceV1::Applied {
            export: gap,
            progress,
        } = owner.advance(stream, 1)?
        else {
            return Err("the expired range was not exported".into());
        };
        assert_eq!(
            (
                progress.next_cursor,
                progress.accepted_records,
                progress.atom_count
            ),
            (11, 0, 0)
        );
        let gap_page = owner.live()?.index.export(&gap)?;
        assert_eq!(
            (gap_page.first_cursor, gap_page.expired_through),
            (1, Some(10))
        );
        assert!(gap_page.records.is_empty());
        let DiscoveryAdvanceV1::Applied { export, progress } = owner.advance(stream, 1)? else {
            return Err("the retained records were not exported".into());
        };
        assert_eq!(
            (
                progress.next_cursor,
                progress.accepted_records,
                progress.atom_count
            ),
            (21, 10, 0)
        );
        let page = owner.live()?.index.export(&export)?;
        assert_eq!(page.previous, Some(gap));
        assert_eq!(page.records.len(), 10);
        assert!(page.records.iter().all(|record| matches!(
            record.context,
            DiscoveryContextJoinV1::Unresolved(
                DiscoveryContextUnavailableV1::MissingDecisionCatalog
            )
        )));
        assert_eq!(retention.watermark(stream)?, before);
        assert_eq!(
            owner.advance(stream, 1)?,
            DiscoveryAdvanceV1::Idle { next_cursor: 21 }
        );
        retention.acknowledge(crate::EvidenceConsumptionWatermarkV1 {
            identity: stream.clone(),
            evidence_cursor: 20,
            coverage_revision: 0,
        })?;
        drop(owner);
        drop(retention);
        drop(store);
        std::fs::remove_file(directory.path().join("discovery-index.sqlite"))?;
        let reopened = DiscoveryOwner::open(ControlStore::open(directory.path())?)?;
        assert_eq!(
            reopened.advance(stream, 1)?,
            DiscoveryAdvanceV1::Idle { next_cursor: 21 }
        );
        assert_eq!(
            reopened
                .live()?
                .index
                .progress(stream.tenant_id, &export.key.id)?,
            Some(progress)
        );
        assert_eq!(reopened.live()?.index.export(&export)?, page);
        Ok(())
    }
}
