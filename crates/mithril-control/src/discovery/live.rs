use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Mutex, MutexGuard},
};

use prost::Message as _;
use serde::{Deserialize, Serialize};

use super::*;
use crate::{
    error::DiscoverySnafu, ControlStore, DiscoveryArtifactRefV1, DiscoveryArtifactV1,
    DiscoveryHeadKeyV1, DiscoveryHeadV1, EvidenceIntakeIdentityV1, Result,
};

pub(super) struct DiscoveryLive {
    pub(super) store: ControlStore,
    pub(super) index: DiscoveryIndex,
    pub(super) operation: Mutex<()>,
}

impl DiscoveryLive {
    pub(super) fn admit(&self) -> Result<MutexGuard<'_, ()>> {
        // ponytail: one operation runs at a time; add per-interval locks if throughput requires them.
        self.operation.try_lock().map_err(|_| {
            DiscoverySnafu {
                code: "DISCOVERY_BUSY",
                reason: "another interval operation is active",
            }
            .build()
        })
    }

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
#[serde(deny_unknown_fields)]
pub struct DiscoveryProfileV1 {
    pub schema_version: u32,
    pub transformation_version: u32,
    pub proof_kind: DiscoveryProofKindV1,
    pub state: DiscoveryProfileStateV1,
    pub export: DiscoveryHeadV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<DiscoveryHeadV1>,
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
    fn interval_has_gap(interval: &crate::CoverageInterval) -> bool {
        interval.state == "GAPPED"
            || !interval.gap_reasons.is_empty()
            || interval
                .opening_counters
                .as_ref()
                .zip(interval.closing_counters.as_ref())
                .is_some_and(|(before, after)| {
                    after.lost != before.lost
                        || after.suppressed != before.suppressed
                        || after.unresolved != before.unresolved
                        || after.classifier_miss_count != before.classifier_miss_count
                        || after.attempted < before.attempted
                        || after.requested < before.requested
                        || after.emitted < before.emitted
                        || after.next_sequence < before.next_sequence
                })
    }

    fn interval_complete(interval: &crate::CoverageInterval) -> bool {
        matches!(interval.state.as_str(), "HEALTHY" | "CLOSED")
            && !Self::interval_has_gap(interval)
            && interval
                .opening_counters
                .as_ref()
                .zip(interval.closing_counters.as_ref())
                .is_some_and(|(before, after)| {
                    [before, after].into_iter().all(|counters| {
                        counters.suppressed.checked_add(counters.requested)
                            == Some(counters.attempted)
                            && counters.emitted.checked_add(counters.lost)
                                == Some(counters.requested)
                    }) && before.next_sequence <= interval.first_sequence
                        && interval
                            .last_sequence
                            .is_some_and(|last| after.next_sequence > last)
                })
    }

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
            .chain(self.replaces.iter().map(|head| head.artifact.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub(super) fn head_key(export: &DiscoveryHeadV1) -> Result<DiscoveryHeadKeyV1> {
        Ok(DiscoveryHeadKeyV1 {
            tenant_id: export.key.tenant_id,
            id: DiscoveryDigestV1::of(&("behavior-snapshot-v1", export))?,
        })
    }
}

impl DiscoveryOwner {
    pub fn resource_usage(&self) -> Result<DiscoveryResourceUsageV1> {
        self.live.index.resource_usage()
    }

    pub fn open(store: ControlStore) -> Result<Self> {
        let index = match DiscoveryIndex::open(store.clone()) {
            Ok(index) => index,
            Err(crate::Error::DiscoveryDatabase { source, .. })
                if matches!(source.as_ref(), rusqlite::Error::SqliteFailure(error, _)
                    if matches!(error.code, rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase)) =>
            {
                store.recover_discovery_artifacts()?;
                return Self::rebuild_index(store);
            }
            Err(error) => return Err(error),
        };
        store.recover_discovery_artifacts()?;
        Ok(Self {
            live: DiscoveryLive {
                store,
                index,
                operation: Mutex::new(()),
            },
        })
    }

    pub fn seal_interval(&self, export: &DiscoveryHeadV1) -> Result<DiscoveryHeadV1> {
        let live = &self.live;
        let _operation = live.admit()?;
        let key = DiscoveryProfileV1::head_key(export)?;
        if let Some(snapshot) = live.store.discovery_head(&key)? {
            self.profile(&snapshot)?;
            live.index.publish_snapshot(&snapshot)?;
            return Ok(snapshot);
        }
        let progress = live.resume(export)?;
        let tip = live.index.export(export)?;
        let replaces = if tip.records.is_empty() && tip.expired_through.is_none() {
            let previous = tip.previous.as_ref().ok_or_else(|| {
                DiscoverySnafu {
                    code: "SNAPSHOT_PREDECESSOR_MISSING",
                    reason: "a coverage correction needs its prior export",
                }
                .build()
            })?;
            Some(
                live.store
                    .discovery_head(&DiscoveryProfileV1::head_key(previous)?)?
                    .ok_or_else(|| {
                        DiscoverySnafu {
                            code: "SNAPSHOT_PREDECESSOR_MISSING",
                            reason: "a coverage correction needs its prior snapshot",
                        }
                        .build()
                    })?,
            )
        } else {
            None
        };
        let latest_coverage = tip
            .coverage_record
            .map(|bytes| crate::CoverageReport::decode(bytes.as_slice()))
            .transpose()
            .map_err(|error| {
                DiscoverySnafu {
                    code: "EXPORT_COVERAGE",
                    reason: error.to_string(),
                }
                .build()
            })?;
        let latest_intervals: BTreeMap<_, _> = latest_coverage
            .as_ref()
            .into_iter()
            .flat_map(|report| {
                report
                    .intervals
                    .iter()
                    .map(|interval| (interval.interval_id.as_slice(), interval))
            })
            .collect();
        let mut current = Some(export.clone());
        let mut expected_next = progress.next_cursor;
        let mut accepted = 0_u64;
        let mut missing = 0_u64;
        let mut pages = 0;
        let mut stream = None;
        let mut reasons = BTreeSet::new();
        if let Some(previous) = &replaces {
            let previous = self.profile(previous)?;
            if previous
                .partial_reasons
                .iter()
                .any(|reason| reason == "SOURCE_COVERAGE_GAPPED")
            {
                reasons.insert("SOURCE_COVERAGE_GAPPED".to_owned());
            }
        }
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
                let effective = latest_coverage
                    .as_ref()
                    .and_then(|report| {
                        latest_intervals
                            .get(wire.coverage_interval_id.as_ref())
                            .map(|interval| (report, *interval))
                    })
                    .or_else(|| {
                        coverage.as_ref().and_then(|report| {
                            report
                                .intervals
                                .iter()
                                .find(|interval| interval.interval_id == wire.coverage_interval_id)
                                .map(|interval| (report, interval))
                        })
                    });
                let recorded_gap = coverage
                    .as_ref()
                    .and_then(|report| {
                        report
                            .intervals
                            .iter()
                            .find(|interval| interval.interval_id == wire.coverage_interval_id)
                    })
                    .is_some_and(DiscoveryProfileV1::interval_has_gap);
                if recorded_gap
                    || effective
                        .is_some_and(|(_, interval)| DiscoveryProfileV1::interval_has_gap(interval))
                {
                    reasons.insert("SOURCE_COVERAGE_GAPPED".to_owned());
                }
                let healthy = !recorded_gap
                    && effective.is_some_and(|(report, interval)| {
                        page.cpu_binding
                            .is_some_and(|cpu| cpu.cpu_id == report.cpu_id)
                            && interval.source_epoch == page.stream.source_epoch
                            && DiscoveryProfileV1::interval_complete(interval)
                            && wire.decision_context.as_ref().is_some_and(|context| {
                                context.original_kernel_sequence >= interval.first_sequence
                                    && interval.last_sequence.is_some_and(|last| {
                                        context.original_kernel_sequence <= last
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
            transformation_version: 2,
            proof_kind: DiscoveryProofKindV1::RecordedInput,
            state: if reasons.is_empty() {
                DiscoveryProfileStateV1::Complete
            } else {
                DiscoveryProfileStateV1::Partial
            },
            export: export.clone(),
            replaces,
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
        #[cfg(test)]
        super::test_crash_boundary("snapshot-head");
        live.index.publish_snapshot(&snapshot)?;
        #[cfg(test)]
        super::test_crash_boundary("snapshot-visible");
        Ok(snapshot)
    }

    pub(super) fn profile(&self, head: &DiscoveryHeadV1) -> Result<DiscoveryProfileV1> {
        let live = &self.live;
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
                && (1..=2).contains(&profile.transformation_version)
                && profile.replaces.as_ref().is_none_or(|previous| {
                    previous.key.tenant_id == head.key.tenant_id
                        && previous.commit_index < head.commit_index
                        && previous.key != head.key
                })
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
        let live = &self.live;
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
    fn discovery_derivation_requires_counter_proof_for_complete_coverage() {
        let interval = crate::CoverageInterval {
            state: "HEALTHY".into(),
            first_sequence: 1,
            last_sequence: Some(1),
            opening_counters: Some(crate::CoverageCounters::default()),
            closing_counters: Some(crate::CoverageCounters {
                attempted: 1,
                requested: 1,
                emitted: 1,
                next_sequence: 2,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(DiscoveryProfileV1::interval_complete(&interval));
        for field in 0..4 {
            let mut gap = interval.clone();
            if let Some(counters) = &mut gap.closing_counters {
                match field {
                    0 => {
                        counters.lost = 1;
                        counters.requested += 1;
                        counters.attempted += 1;
                    }
                    1 => {
                        counters.suppressed = 1;
                        counters.attempted += 1;
                    }
                    2 => counters.unresolved = 1,
                    _ => counters.classifier_miss_count = 1,
                }
            }
            assert!(DiscoveryProfileV1::interval_has_gap(&gap));
            assert!(!DiscoveryProfileV1::interval_complete(&gap));
        }
        let mut absent = interval;
        absent.closing_counters = None;
        assert!(!DiscoveryProfileV1::interval_has_gap(&absent));
        assert!(!DiscoveryProfileV1::interval_complete(&absent));
    }

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
            .live
            .write_profile_artifact(artifact.clone(), &mut used)?;
        assert_eq!(reference.bytes, bytes);
        assert_eq!(used, 128 * 1024 * 1024);
        let mut used = 128 * 1024 * 1024 - bytes + 1;
        assert!(owner
            .live
            .write_profile_artifact(artifact, &mut used)
            .is_err());
        assert_eq!(used, 128 * 1024 * 1024 - bytes + 1);
        Ok(())
    }
}
