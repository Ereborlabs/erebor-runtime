use std::{collections::BTreeSet, sync::Mutex};

use prost::Message as _;
use serde::{Deserialize, Serialize};

use super::*;
use crate::{
    error::DiscoverySnafu, ControlStore, DiscoveryArtifactRefV1, DiscoveryArtifactV1,
    DiscoveryContextJoinV1, DiscoveryContextUnavailableV1, DiscoveryHeadKeyV1, DiscoveryHeadV1,
    EvidenceIntakeIdentityV1, Result,
};

pub(super) struct DiscoveryLive {
    store: ControlStore,
    index: DiscoveryIndex,
    operation: Mutex<()>,
}

impl DiscoveryLive {
    fn write_profile_artifact(
        &self,
        artifact: DiscoveryArtifactV1,
        used: &mut u64,
    ) -> Result<DiscoveryArtifactRefV1> {
        let remaining = (128 * 1024 * 1024_u64).checked_sub(*used).ok_or_else(|| {
            DiscoverySnafu {
                code: "PROFILE_LIMIT",
                reason: "the profile byte budget is exhausted",
            }
            .build()
        })?;
        DiscoveryInputManifestV1::require(
            artifact
                .serialize(
                    &mut rmp_serde::Serializer::new(super::model::InputByteLimit(
                        remaining as usize,
                    ))
                    .with_struct_map(),
                )
                .is_ok(),
            "PROFILE_LIMIT",
        )?;
        let reference = self.store.put_discovery_artifact(&artifact)?;
        *used += reference.bytes;
        Ok(reference)
    }

    fn resume(&self, export: &DiscoveryHeadV1) -> Result<DiscoveryIndexProgressV1> {
        if self
            .index
            .progress(export.key.tenant_id, &export.key.id)?
            .is_some_and(|progress| progress.commit_index == export.commit_index)
        {
            self.index.apply_export(export)
        } else {
            self.index.replay_interval(export)
        }
    }
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryProfileV1 {
    pub schema_version: u32,
    pub transformation_version: u32,
    pub proof_kind: DiscoveryProofKindV1,
    pub state: DiscoveryProfileStateV1,
    pub export: DiscoveryHeadV1,
    pub stream: EvidenceIntakeIdentityV1,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub accepted_records: u64,
    pub included_records: u64,
    pub unresolved_records: u64,
    pub missing_records: u64,
    pub atom_count: u64,
    pub partial_reasons: Vec<String>,
    pub segments: Vec<DiscoveryProfileSegmentV1>,
    pub content_digest: DiscoveryDigestV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryProfileStateV1 {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryProfileSegmentV1 {
    pub artifact: DiscoveryArtifactRefV1,
    pub first: DiscoveryDigestV1,
    pub last: DiscoveryDigestV1,
    pub atoms: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySnapshotPageV1 {
    pub snapshot: DiscoveryHeadV1,
    pub profile: DiscoveryProfileV1,
    pub atoms: Vec<BehaviorAtomV1>,
    pub next: Option<DiscoveryDigestV1>,
}

impl DiscoveryProfileV1 {
    fn digest(&self) -> Result<DiscoveryDigestV1> {
        let mut content = self.clone();
        content.content_digest = DiscoveryDigestV1([0; 32]);
        DiscoveryDigestV1::of(&content)
    }

    fn dependencies(&self) -> Vec<DiscoveryArtifactRefV1> {
        self.segments
            .iter()
            .map(|segment| segment.artifact.clone())
            .chain(std::iter::once(self.export.artifact.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn head_key(export: &DiscoveryHeadV1) -> Result<DiscoveryHeadKeyV1> {
        Ok(DiscoveryHeadKeyV1 {
            tenant_id: export.key.tenant_id,
            id: DiscoveryDigestV1::of(&("behavior-snapshot-v1", export))?,
        })
    }
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
            let progress = live.resume(head)?;
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

    pub fn seal_interval(&self, export: &DiscoveryHeadV1) -> Result<DiscoveryHeadV1> {
        let live = self.live()?;
        let _operation = live.operation.try_lock().map_err(|_| {
            DiscoverySnafu {
                code: "DISCOVERY_BUSY",
                reason: "another interval operation is active",
            }
            .build()
        })?;
        let key = DiscoveryProfileV1::head_key(export)?;
        if let Some(snapshot) = live.store.discovery_head(&key)? {
            self.profile(&snapshot)?;
            live.index.publish_snapshot(&snapshot)?;
            return Ok(snapshot);
        }
        let progress = live.resume(export)?;
        let mut current = Some(export.clone());
        let mut expected_next = progress.next_cursor;
        let mut accepted = 0_u64;
        let mut missing = 0_u64;
        let mut pages = 0;
        let mut stream = None;
        let mut reasons = BTreeSet::new();
        while let Some(head) = current {
            DiscoveryInputManifestV1::require(pages < 8192, "EXPORT_CHAIN_LIMIT")?;
            pages += 1;
            let page = live.index.export(&head)?;
            DiscoveryInputManifestV1::require(
                page.next_cursor()? == expected_next,
                "EXPORT_PROGRESS_GAP",
            )?;
            if let Some(known) = &stream {
                DiscoveryInputManifestV1::require(known == &page.stream, "EXPORT_STREAM_CONFLICT")?;
            } else {
                stream = Some(page.stream.clone());
            }
            expected_next = page.first_cursor;
            accepted += page.records.len() as u64;
            if let Some(last) = page.expired_through {
                missing = missing
                    .checked_add(last - page.first_cursor + 1)
                    .ok_or_else(|| {
                        DiscoverySnafu {
                            code: "EXPORT_LIMIT",
                            reason: "the missing-record count is exhausted",
                        }
                        .build()
                    })?;
                reasons.insert("SOURCE_RANGE_EXPIRED".to_owned());
            }
            let coverage = page
                .coverage_record
                .as_ref()
                .map(|bytes| crate::CoverageReport::decode(bytes.as_slice()))
                .transpose()
                .map_err(|error| {
                    DiscoverySnafu {
                        code: "EXPORT_COVERAGE",
                        reason: error.to_string(),
                    }
                    .build()
                })?;
            for retained in &page.records {
                let wire = crate::EvidenceRecord::decode(retained.wire_record.as_slice()).map_err(
                    |error| {
                        DiscoverySnafu {
                            code: "EXPORT_RECORD",
                            reason: error.to_string(),
                        }
                        .build()
                    },
                )?;
                if wire.temporal_coverage != crate::EvidenceTemporalCoverage::Complete as i32 {
                    reasons.insert("OBSERVATION_COVERAGE_INCOMPLETE".to_owned());
                }
                let healthy = coverage.as_ref().is_some_and(|report| {
                    page.cpu_binding
                        .is_some_and(|cpu| cpu.cpu_id == report.cpu_id)
                        && report.intervals.iter().any(|interval| {
                            interval.interval_id == wire.coverage_interval_id
                                && interval.state == "HEALTHY"
                                && interval.gap_reasons.is_empty()
                                && wire.decision_context.as_ref().is_some_and(|context| {
                                    context.original_kernel_sequence >= interval.first_sequence
                                        && interval.last_sequence.is_some_and(|last| {
                                            context.original_kernel_sequence <= last
                                        })
                                })
                        })
                });
                if !healthy {
                    reasons.insert("SOURCE_COVERAGE_UNPROVEN".to_owned());
                }
            }
            current = page.previous;
        }
        DiscoveryInputManifestV1::require(
            accepted == progress.accepted_records,
            "INDEX_COUNT_MISMATCH",
        )?;
        let (indexed, unresolved) = live.index.input_counts(export)?;
        DiscoveryInputManifestV1::require(indexed == accepted, "INDEX_COUNT_MISMATCH")?;
        if unresolved > 0 {
            reasons.insert("UNRESOLVED_INPUT".to_owned());
        }
        if accepted == 0 {
            reasons.insert("EMPTY_INPUT".to_owned());
        }
        let mut profile = DiscoveryProfileV1 {
            schema_version: 1,
            transformation_version: 1,
            proof_kind: DiscoveryProofKindV1::RecordedInput,
            state: if reasons.is_empty() {
                DiscoveryProfileStateV1::Complete
            } else {
                DiscoveryProfileStateV1::Partial
            },
            export: export.clone(),
            stream: stream.ok_or_else(|| {
                DiscoverySnafu {
                    code: "EXPORT_CHAIN",
                    reason: "the export chain is empty",
                }
                .build()
            })?,
            first_cursor: expected_next,
            last_cursor: progress.next_cursor - 1,
            accepted_records: accepted,
            included_records: 0,
            unresolved_records: unresolved,
            missing_records: missing,
            atom_count: 0,
            partial_reasons: reasons.into_iter().collect(),
            segments: Vec::new(),
            content_digest: DiscoveryDigestV1([0; 32]),
        };
        let mut after = None;
        let mut artifact_bytes = 0_u64;
        loop {
            let page = live.index.atoms(export, after.as_ref())?;
            if !page.atoms.is_empty() {
                let payload = rmp_serde::to_vec_named(&page.atoms).map_err(|error| {
                    DiscoverySnafu {
                        code: "PROFILE_ENCODING",
                        reason: error.to_string(),
                    }
                    .build()
                })?;
                DiscoveryInputManifestV1::require(
                    payload.len() <= 1024 * 1024,
                    "PROFILE_SEGMENT_LIMIT",
                )?;
                DiscoveryInputManifestV1::require(profile.segments.len() < 8191, "PROFILE_LIMIT")?;
                let artifact = live.write_profile_artifact(
                    DiscoveryArtifactV1 {
                        schema_version: 1,
                        tenant_id: export.key.tenant_id,
                        dependencies: Vec::new(),
                        payload,
                    },
                    &mut artifact_bytes,
                )?;
                profile.segments.push(DiscoveryProfileSegmentV1 {
                    artifact,
                    first: page.atoms[0].id.clone(),
                    last: page.atoms[page.atoms.len() - 1].id.clone(),
                    atoms: page.atoms.len() as u32,
                });
                profile.atom_count += page.atoms.len() as u64;
                profile.included_records += page.atoms.iter().map(|atom| atom.count).sum::<u64>();
            }
            after = page.next;
            if after.is_none() {
                break;
            }
        }
        DiscoveryInputManifestV1::require(
            profile.atom_count == progress.atom_count
                && profile.included_records.checked_add(unresolved) == Some(accepted),
            "INDEX_COUNT_MISMATCH",
        )?;
        profile.content_digest = profile.digest()?;
        let payload = rmp_serde::to_vec_named(&profile).map_err(|error| {
            DiscoverySnafu {
                code: "PROFILE_ENCODING",
                reason: error.to_string(),
            }
            .build()
        })?;
        let artifact = live.write_profile_artifact(
            DiscoveryArtifactV1 {
                schema_version: 1,
                tenant_id: export.key.tenant_id,
                dependencies: profile.dependencies(),
                payload,
            },
            &mut artifact_bytes,
        )?;
        let snapshot = live.store.commit_discovery_head(key, None, artifact)?;
        live.index.publish_snapshot(&snapshot)?;
        Ok(snapshot)
    }

    fn profile(&self, head: &DiscoveryHeadV1) -> Result<DiscoveryProfileV1> {
        let live = self.live()?;
        DiscoveryInputManifestV1::require(
            live.store.discovery_head(&head.key)?.as_ref() == Some(head),
            "SNAPSHOT_NOT_COMMITTED",
        )?;
        let artifact = live.store.read_discovery_artifact(&head.artifact)?;
        let profile: DiscoveryProfileV1 =
            rmp_serde::from_slice(&artifact.payload).map_err(|error| {
                DiscoverySnafu {
                    code: "PROFILE_ENCODING",
                    reason: error.to_string(),
                }
                .build()
            })?;
        DiscoveryInputManifestV1::require(
            profile.schema_version == 1
                && profile.transformation_version == 1
                && profile.proof_kind == DiscoveryProofKindV1::RecordedInput
                && (profile.state == DiscoveryProfileStateV1::Complete)
                    == profile.partial_reasons.is_empty()
                && profile.stream.tenant_id == head.key.tenant_id
                && profile.export.key.tenant_id == head.key.tenant_id
                && DiscoveryProfileV1::head_key(&profile.export)? == head.key
                && head.revision == 1
                && head.commit_index > profile.export.commit_index
                && profile.content_digest == profile.digest()?
                && profile.segments.len() <= 8191
                && profile
                    .segments
                    .iter()
                    .try_fold(head.artifact.bytes, |sum, segment| {
                        sum.checked_add(segment.artifact.bytes)
                    })
                    .is_some_and(|bytes| bytes <= 128 * 1024 * 1024)
                && profile.segments.iter().all(|segment| {
                    segment.atoms > 0 && segment.atoms <= 200 && segment.first <= segment.last
                })
                && profile
                    .segments
                    .windows(2)
                    .all(|pair| pair[0].last < pair[1].first)
                && profile
                    .segments
                    .iter()
                    .map(|segment| u64::from(segment.atoms))
                    .sum::<u64>()
                    == profile.atom_count
                && profile.partial_reasons.len() <= 32
                && profile
                    .partial_reasons
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && profile
                    .partial_reasons
                    .iter()
                    .all(|reason| !reason.is_empty() && reason.len() <= 128)
                && profile.atom_count <= MAX_DISCOVERY_ATOMS as u64
                && profile.accepted_records <= MAX_DISCOVERY_RECORDS as u64
                && profile
                    .included_records
                    .checked_add(profile.unresolved_records)
                    == Some(profile.accepted_records)
                && profile.first_cursor > 0
                && profile.last_cursor >= profile.first_cursor
                && profile
                    .accepted_records
                    .checked_add(profile.missing_records)
                    == Some(profile.last_cursor - profile.first_cursor + 1)
                && artifact.dependencies == profile.dependencies(),
            "PROFILE_INTEGRITY",
        )?;
        Ok(profile)
    }

    pub fn read_snapshot(
        &self,
        snapshot: &DiscoveryHeadV1,
        after: Option<&DiscoveryDigestV1>,
    ) -> Result<DiscoverySnapshotPageV1> {
        let live = self.live()?;
        let profile = self.profile(snapshot)?;
        DiscoveryInputManifestV1::require(
            live.index.snapshot_visible(snapshot)?,
            "SNAPSHOT_INDEX_UNAVAILABLE",
        )?;
        let mut atoms = Vec::new();
        let mut more = false;
        for segment in &profile.segments {
            if after.is_some_and(|after| &segment.last <= after) {
                continue;
            }
            let artifact = live.store.read_discovery_artifact(&segment.artifact)?;
            DiscoveryInputManifestV1::require(
                artifact.payload.len() <= 1024 * 1024 && artifact.dependencies.is_empty(),
                "PROFILE_SEGMENT_LIMIT",
            )?;
            let page: Vec<BehaviorAtomV1> =
                rmp_serde::from_slice(&artifact.payload).map_err(|error| {
                    DiscoverySnafu {
                        code: "PROFILE_ENCODING",
                        reason: error.to_string(),
                    }
                    .build()
                })?;
            DiscoveryInputManifestV1::require(
                !page.is_empty()
                    && page.len() == segment.atoms as usize
                    && page[0].id == segment.first
                    && page[page.len() - 1].id == segment.last
                    && page.windows(2).all(|pair| pair[0].id < pair[1].id),
                "PROFILE_ATOM_ORDER",
            )?;
            for atom in page {
                if after.is_some_and(|after| &atom.id <= after) {
                    continue;
                }
                if atoms.len() == 200 {
                    more = true;
                    break;
                }
                DiscoveryInputManifestV1::require(
                    atom.key.stream == profile.stream
                        && atom.id == DiscoveryDigestV1::of(&atom.key)?,
                    "ATOM_DIGEST_MISMATCH",
                )?;
                atoms.push(atom);
            }
            if more {
                break;
            }
        }
        let next = if more {
            atoms.last().map(|atom| atom.id.clone())
        } else {
            None
        };
        let mut page = DiscoverySnapshotPageV1 {
            snapshot: snapshot.clone(),
            profile,
            atoms,
            next,
        };
        while serde_json::to_writer(super::model::InputByteLimit(1024 * 1024), &page).is_err() {
            DiscoveryInputManifestV1::require(page.atoms.len() > 1, "SNAPSHOT_ROW_LIMIT")?;
            page.atoms.truncate(page.atoms.len() / 2);
            page.next = page.atoms.last().map(|atom| atom.id.clone());
        }
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_derivation_reserves_encoded_profile_bytes_before_write(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = DiscoveryOwner::open(ControlStore::open(directory.path())?)?;
        let artifact = DiscoveryArtifactV1 {
            schema_version: 1,
            tenant_id: [1; 16],
            dependencies: Vec::new(),
            payload: vec![255; 4096],
        };
        let bytes = rmp_serde::to_vec_named(&artifact)?.len() as u64;
        assert!(bytes > artifact.payload.len() as u64 + 4096);
        let mut used = 128 * 1024 * 1024 - bytes;
        let reference = owner
            .live()?
            .write_profile_artifact(artifact.clone(), &mut used)?;
        assert_eq!(reference.bytes, bytes);
        assert_eq!(used, 128 * 1024 * 1024);
        let mut used = 128 * 1024 * 1024 - bytes + 1;
        assert!(owner
            .live()?
            .write_profile_artifact(artifact, &mut used)
            .is_err());
        assert_eq!(used, 128 * 1024 * 1024 - bytes + 1);
        Ok(())
    }

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
        let snapshot = owner.seal_interval(&export)?;
        assert_eq!(owner.seal_interval(&export)?, snapshot);
        let sealed = owner.read_snapshot(&snapshot, None)?;
        assert_eq!(sealed.profile.state, DiscoveryProfileStateV1::Partial);
        assert_eq!(
            (
                sealed.profile.accepted_records,
                sealed.profile.unresolved_records,
                sealed.profile.missing_records
            ),
            (10, 10, 10)
        );
        assert_eq!(
            sealed.profile.partial_reasons,
            vec![
                "SOURCE_COVERAGE_UNPROVEN",
                "SOURCE_RANGE_EXPIRED",
                "UNRESOLVED_INPUT"
            ]
        );
        assert!(sealed.atoms.is_empty());
        assert!(sealed.next.is_none());
        let mut foreign = snapshot.clone();
        foreign.key.tenant_id = [9; 16];
        assert!(owner.read_snapshot(&foreign, None).is_err());
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
        assert!(reopened.read_snapshot(&snapshot, None).is_err());
        assert_eq!(reopened.seal_interval(&export)?, snapshot);
        assert_eq!(reopened.read_snapshot(&snapshot, None)?, sealed);
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
