use super::*;
use crate::evidence_segment::EvidenceSegmentReadV1;
use prost::Message as _;

pub const MAX_EVIDENCE_READ_RECORDS: usize = 256;
pub const MAX_EVIDENCE_READ_BYTES: usize = 1024 * 1024;
pub const MAX_EVIDENCE_READ_HANDLES: usize = 4;

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceReadMetadataV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub cpu_binding: Option<EvidenceCpuBindingV1>,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub retained_floor: u64,
    pub control_commit_index: u64,
    pub coverage_revision: u64,
    pub coverage: Option<CoverageReport>,
}

pub struct EvidenceReadV1 {
    store: ControlStore,
    metadata: EvidenceReadMetadataV1,
    coverage_bytes: Option<Vec<u8>>,
}

impl EvidenceReadV1 {
    pub fn metadata(&self) -> &EvidenceReadMetadataV1 {
        &self.metadata
    }

    pub(crate) fn coverage_bytes(&self) -> Option<&[u8]> {
        self.coverage_bytes.as_deref()
    }
}

#[derive(Debug, PartialEq)]
pub struct EvidenceReadPageV1 {
    pub first_cursor: u64,
    pub records: Vec<EvidenceRecord>,
    pub encoded_bytes: usize,
    pub next_cursor: Option<u64>,
}

#[derive(Debug, PartialEq)]
pub(crate) struct EvidenceFramePageV1 {
    pub first_cursor: u64,
    pub framed_records: Vec<u8>,
    pub frame_ends: Vec<usize>,
    pub next_cursor: Option<u64>,
}

struct OpenEvidencePage {
    first_cursor: u64,
    segments: Vec<EvidenceSegmentReadV1>,
    encoded_bytes: usize,
    next_cursor: Option<u64>,
}

impl OpenEvidencePage {
    fn decode(self) -> Result<EvidenceReadPageV1> {
        let mut records = Vec::new();
        for segment in self.segments {
            records.extend(segment.decode::<EvidenceRecord>()?);
        }
        Ok(EvidenceReadPageV1 {
            first_cursor: self.first_cursor,
            records,
            encoded_bytes: self.encoded_bytes,
            next_cursor: self.next_cursor,
        })
    }

    fn frames(self) -> Result<EvidenceFramePageV1> {
        let mut framed_records = Vec::with_capacity(self.encoded_bytes);
        let mut frame_ends = Vec::new();
        for segment in self.segments {
            let (bytes, ends) = segment.frames()?;
            let offset = framed_records.len();
            frame_ends.extend(ends.into_iter().map(|end| end + offset));
            framed_records.extend_from_slice(&bytes);
        }
        Ok(EvidenceFramePageV1 {
            first_cursor: self.first_cursor,
            framed_records,
            frame_ends,
            next_cursor: self.next_cursor,
        })
    }
}

impl ControlStore {
    pub(crate) fn discovery_sources(
        &self,
        after: Option<&EvidenceIntakeIdentityV1>,
    ) -> Result<Vec<EvidenceIntakeIdentityV1>> {
        use std::ops::Bound;
        Ok(self
            .evidence_lock()?
            .state
            .evidence_cursors
            .range((
                after.map_or(Bound::Unbounded, Bound::Excluded),
                Bound::Unbounded,
            ))
            .take(32)
            .map(|(identity, _)| identity.clone())
            .collect())
    }

    pub(crate) fn legacy_sources(
        &self,
        after: Option<&EvidenceIntakeIdentityV1>,
    ) -> Result<Vec<EvidenceIntakeIdentityV1>> {
        use std::ops::Bound;
        let inner = self.evidence_lock()?;
        let range = (
            after.map_or(Bound::Unbounded, Bound::Excluded),
            Bound::Unbounded,
        );
        let mut sources = BTreeSet::new();
        sources.extend(
            inner
                .state
                .evidence_cursors
                .range(range)
                .take(32)
                .map(|(identity, _)| identity.clone()),
        );
        sources.extend(
            inner
                .state
                .coverage_cursors
                .range(range)
                .take(32)
                .map(|(identity, _)| identity.clone()),
        );
        Ok(sources.into_iter().take(32).collect())
    }

    pub fn begin_evidence_read(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
    ) -> Result<EvidenceReadV1> {
        let (mut metadata, coverage) = {
            let inner = self.evidence_lock()?;
            validate_evidence_identity(identity, &inner.root)?;
            let last_cursor = inner
                .state
                .evidence_cursors
                .get(identity)
                .map_or(0, |state| state.contiguous_cursor);
            if first_cursor == 0 || first_cursor > last_cursor.saturating_add(1) {
                return ControlStoreSnafu {
                    path: inner.root.clone(),
                    reason: "the evidence read start is zero or ahead of accepted input".to_owned(),
                }
                .fail();
            }
            let retained_floor = inner
                .state
                .evidence_consumption
                .get(identity)
                .map_or(1, |state| state.evidence_cursor.saturating_add(1));
            let coverage = inner
                .state
                .coverage_cursors
                .get(identity)
                .and_then(|cursor| {
                    inner.state.coverage_reports.get(&CoverageReportKeyV1 {
                        identity: identity.clone(),
                        revision: cursor.revision,
                    })
                })
                .map(|stored| {
                    inner.evidence_segments.open_read(
                        stored.segment.id,
                        EvidenceSegmentKindV1::Coverage {
                            stream_id: inner.stream_id(identity)?,
                            first_revision: stored.state.revision,
                            last_revision: stored.state.revision,
                        },
                        1,
                        crate::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES + 8,
                    )
                })
                .transpose()?
                .flatten();
            (
                EvidenceReadMetadataV1 {
                    identity: identity.clone(),
                    cpu_binding: inner.state.evidence_cpu_bindings.get(identity).copied(),
                    first_cursor,
                    last_cursor,
                    retained_floor,
                    control_commit_index: inner.state.commit_index,
                    coverage_revision: inner
                        .state
                        .coverage_cursors
                        .get(identity)
                        .map_or(0, |cursor| cursor.revision),
                    coverage: None,
                },
                coverage,
            )
        };
        let mut coverage_bytes = None;
        if let Some(coverage) = coverage {
            let revision = coverage.first;
            let (frames, ends) = coverage.frames()?;
            if ends != [frames.len()] || frames.len() < 8 {
                return crate::error::DiscoverySnafu {
                    code: "COVERAGE_READ",
                    reason: "the frozen coverage report does not contain one frame",
                }
                .fail();
            }
            let length = u32::from_be_bytes(frames[..4].try_into().unwrap_or_default()) as usize;
            if length != frames.len() - 8 {
                return crate::error::DiscoverySnafu {
                    code: "COVERAGE_READ",
                    reason: "the frozen coverage frame length differs from its payload",
                }
                .fail();
            }
            let bytes = frames[4..4 + length].to_vec();
            let report = CoverageReport::decode(bytes.as_slice())
                .ok()
                .filter(|report| {
                    report.revision == revision
                        && report.source_id.as_slice() == identity.source_id
                        && report.source_epoch == identity.source_epoch
                });
            let Some(report) = report else {
                return crate::error::DiscoverySnafu {
                    code: "COVERAGE_READ",
                    reason: "the frozen coverage reference differs from its payload",
                }
                .fail();
            };
            metadata.coverage = Some(report);
            coverage_bytes = Some(bytes);
        }
        Ok(EvidenceReadV1 {
            store: self.clone(),
            metadata,
            coverage_bytes,
        })
    }

    pub fn read_evidence_page(
        &self,
        read: &EvidenceReadV1,
        first_cursor: u64,
    ) -> Result<EvidenceReadPageV1> {
        self.open_evidence_page(read, first_cursor)?.decode()
    }

    pub(crate) fn read_evidence_frames_page(
        &self,
        read: &EvidenceReadV1,
        first_cursor: u64,
    ) -> Result<EvidenceFramePageV1> {
        self.open_evidence_page(read, first_cursor)?.frames()
    }

    fn open_evidence_page(
        &self,
        read: &EvidenceReadV1,
        first_cursor: u64,
    ) -> Result<OpenEvidencePage> {
        let metadata = &read.metadata;
        if !Arc::ptr_eq(&self.inner, &read.store.inner)
            || first_cursor < metadata.first_cursor
            || first_cursor > metadata.last_cursor.saturating_add(1)
        {
            return crate::error::DiscoverySnafu {
                code: "READ_SCOPE",
                reason: "the evidence read belongs to another store or cursor range",
            }
            .fail();
        }
        let inner = self.evidence_lock()?;
        let floor = inner
            .state
            .evidence_consumption
            .get(&metadata.identity)
            .map_or(1, |state| state.evidence_cursor.saturating_add(1));
        if first_cursor < floor && first_cursor <= metadata.last_cursor {
            return crate::error::RetainedRangeExpiredSnafu {
                identity: Box::new(metadata.identity.clone()),
                first_cursor,
                last_cursor: (floor - 1).min(metadata.last_cursor),
            }
            .fail();
        }
        let mut cursor = first_cursor;
        let mut segments = Vec::new();
        let mut records = 0;
        let mut encoded_bytes = 0;
        while cursor <= metadata.last_cursor
            && segments.len() < MAX_EVIDENCE_READ_HANDLES
            && records < MAX_EVIDENCE_READ_RECORDS
        {
            let key = EvidenceBatchKeyV1 {
                identity: metadata.identity.clone(),
                first_cursor: cursor,
                last_cursor: u64::MAX,
            };
            let batch = inner
                .state
                .evidence_batches
                .range(..=key)
                .next_back()
                .filter(|(key, batch)| {
                    key.identity == metadata.identity && batch.last_cursor >= cursor
                })
                .map(|(_, batch)| batch)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: inner.root.clone(),
                        reason: "an accepted evidence read has no retained segment".to_owned(),
                    }
                    .build()
                })?;
            let Some(segment) = inner.evidence_segments.open_read(
                batch.segment.id,
                EvidenceSegmentKindV1::Records {
                    stream_id: inner.stream_id(&metadata.identity)?,
                    first_cursor: cursor,
                    last_cursor: metadata.last_cursor,
                },
                MAX_EVIDENCE_READ_RECORDS - records,
                MAX_EVIDENCE_READ_BYTES - encoded_bytes,
            )?
            else {
                break;
            };
            records += segment.len();
            encoded_bytes += segment.encoded_bytes;
            cursor = checked_store_increment(
                cursor + (segment.len() as u64 - 1),
                &inner.root,
                "the evidence page cursor is exhausted",
            )?;
            segments.push(segment);
        }
        if records == 0 && first_cursor <= metadata.last_cursor {
            return ControlStoreSnafu {
                path: inner.root.clone(),
                reason: "an evidence record exceeds the export page bound".to_owned(),
            }
            .fail();
        }
        Ok(OpenEvidencePage {
            first_cursor,
            segments,
            encoded_bytes,
            next_cursor: (cursor <= metadata.last_cursor).then_some(cursor),
        })
    }
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::*;

    type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[derive(prost::Message)]
    struct FutureField {
        #[prost(bytes = "vec", tag = "99")]
        padding: Vec<u8>,
    }

    struct ReadFixture {
        directory: tempfile::TempDir,
        store: ControlStore,
        identity: EvidenceIntakeIdentityV1,
        record: EvidenceRecord,
    }

    impl ReadFixture {
        fn new() -> TestResult<Self> {
            let directory = tempfile::tempdir()?;
            let store = ControlStore::open(directory.path())?;
            let input = crate::DiscoveryInputManifestV1::from_json(include_bytes!(
                "../../../mithril-e2e/fixtures/discovery/manifest.json"
            ))?;
            Ok(Self {
                directory,
                store,
                identity: input.records[0].id.stream.clone(),
                record: input.records[0].observation.to_wire_record()?,
            })
        }

        fn append(&self, first: u64, count: u64, frame_bytes: Option<usize>) -> TestResult<()> {
            let mut frames = Vec::new();
            for cursor in first..first + count {
                let mut record = self.record.clone();
                record.observed_boottime_ns = cursor;
                let mut payload = record.encode_to_vec();
                if let Some(target) = frame_bytes {
                    let field = FutureField {
                        padding: vec![0; target - payload.len() - 8 - 5],
                    };
                    field.encode(&mut payload)?;
                    assert_eq!(payload.len() + 8, target);
                }
                let start = frames.len();
                frames.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
                frames.extend_from_slice(&payload);
                let checksum = crc32c::crc32c(&frames[start..]);
                frames.extend_from_slice(&checksum.to_be_bytes());
            }
            crate::EvidenceIntakeOwner::from_store(self.store.clone()).receive(
                &crate::AuthenticatedEvidenceNodeV1 {
                    tenant_id: self.identity.tenant_id,
                    node_id: self.identity.node_id.clone(),
                    node_boot_id: self.identity.node_boot_id,
                    label_epoch: self.identity.label_epoch,
                },
                crate::EvidenceBatch {
                    node_boot_id: self.identity.node_boot_id.to_vec(),
                    source_id: self.identity.source_id.to_vec(),
                    source_epoch: self.identity.source_epoch,
                    cpu_id: 7,
                    first_cursor: first,
                    framed_records: frames.into(),
                    commit_group_tail: true,
                },
            )?;
            Ok(())
        }

        fn coverage(&self, revision: u64, gapped: bool) -> TestResult<()> {
            let count = self.store.evidence_cursor(&self.identity)?;
            let report = CoverageReport {
                source_id: self.identity.source_id.to_vec(),
                source_epoch: self.identity.source_epoch,
                cpu_id: 7,
                revision,
                intervals: vec![crate::CoverageInterval {
                    interval_id: self.record.coverage_interval_id.to_vec(),
                    source_epoch: self.identity.source_epoch,
                    revision,
                    state: if gapped { "GAPPED" } else { "HEALTHY" }.into(),
                    first_sequence: 1,
                    last_sequence: Some(count),
                    opening_counters: Some(crate::CoverageCounters::default()),
                    closing_counters: Some(crate::CoverageCounters {
                        attempted: count,
                        requested: count,
                        emitted: count - u64::from(gapped),
                        lost: u64::from(gapped),
                        next_sequence: count + 1,
                        ..crate::CoverageCounters::default()
                    }),
                    gap_reasons: if gapped {
                        vec!["RING_LOSS".into()]
                    } else {
                        vec![]
                    },
                    current: true,
                }],
            };
            crate::EvidenceIntakeOwner::from_store(self.store.clone()).receive_coverage(
                &crate::AuthenticatedEvidenceNodeV1 {
                    tenant_id: self.identity.tenant_id,
                    node_id: self.identity.node_id.clone(),
                    node_boot_id: self.identity.node_boot_id,
                    label_epoch: self.identity.label_epoch,
                },
                &report,
            )?;
            Ok(())
        }
    }

    #[test]
    fn evidence_frame_export_preserves_checked_original_bytes() -> TestResult<()> {
        let fixture = ReadFixture::new()?;
        fixture.append(1, 2, None)?;
        fixture.append(3, 1, None)?;
        let read = fixture.store.begin_evidence_read(&fixture.identity, 1)?;
        let page = fixture.store.read_evidence_frames_page(&read, 1)?;
        let mut expected = Vec::new();
        let mut ends = Vec::new();
        for cursor in 1..=3 {
            let mut record = fixture.record.clone();
            record.observed_boottime_ns = cursor;
            let payload = record.encode_to_vec();
            let start = expected.len();
            expected.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
            expected.extend_from_slice(&payload);
            expected.extend_from_slice(&crc32c::crc32c(&expected[start..]).to_be_bytes());
            ends.push(expected.len());
        }
        assert_eq!(page.first_cursor, 1);
        assert_eq!(page.framed_records, expected);
        assert_eq!(page.frame_ends, ends);
        assert_eq!(page.next_cursor, None);
        Ok(())
    }

    #[test]
    fn evidence_coverage_export_keeps_checked_payload_bytes() -> TestResult<()> {
        let fixture = ReadFixture::new()?;
        fixture.append(1, 1, None)?;
        fixture.coverage(1, false)?;
        let read = fixture.store.begin_evidence_read(&fixture.identity, 1)?;
        let bytes = read.coverage_bytes().ok_or("coverage bytes are absent")?;
        let decoded = CoverageReport::decode(bytes)?;
        assert_eq!(read.metadata().coverage.as_ref(), Some(&decoded));
        Ok(())
    }

    #[test]
    fn discovery_read_freezes_coverage_and_record_bounds_without_consumption() -> TestResult<()> {
        let fixture = ReadFixture::new()?;
        fixture.append(1, 257, None)?;
        fixture.coverage(1, false)?;
        let retention = crate::EvidenceRetentionOwner::from_store(fixture.store.clone());
        let before = retention.watermark(&fixture.identity)?;
        let read = fixture.store.begin_evidence_read(&fixture.identity, 1)?;
        fixture.append(258, 1, None)?;
        fixture.coverage(2, true)?;
        assert_eq!(
            read.metadata()
                .coverage
                .as_ref()
                .ok_or("coverage is absent")?
                .revision,
            1
        );
        assert_eq!(read.metadata().last_cursor, 257);
        assert_eq!(
            read.metadata().cpu_binding.ok_or("CPU is absent")?.cpu_id,
            7
        );
        let page = fixture.store.read_evidence_page(&read, 1)?;
        assert_eq!(page.records.len(), 256);
        assert_eq!(page.next_cursor, Some(257));
        assert_eq!(fixture.store.read_evidence_page(&read, 1)?, page);
        let last = fixture.store.read_evidence_page(&read, 257)?;
        assert_eq!(last.records.len(), 1);
        assert_eq!(last.records[0].observed_boottime_ns, 257);
        assert_eq!(last.next_cursor, None);
        assert_eq!(retention.watermark(&fixture.identity)?, before);
        let current = fixture.store.begin_evidence_read(&fixture.identity, 1)?;
        assert_eq!(
            current
                .metadata()
                .coverage
                .as_ref()
                .ok_or("coverage is absent")?
                .revision,
            2
        );
        assert_eq!(current.metadata().last_cursor, 258);
        Ok(())
    }

    #[test]
    fn discovery_read_empty_input_has_no_cpu_or_coverage_claim() -> TestResult<()> {
        let fixture = ReadFixture::new()?;
        let read = fixture.store.begin_evidence_read(&fixture.identity, 1)?;
        assert_eq!(read.metadata().last_cursor, 0);
        assert_eq!(read.metadata().cpu_binding, None);
        assert_eq!(read.metadata().coverage, None);
        assert!(fixture
            .store
            .read_evidence_page(&read, 1)?
            .records
            .is_empty());
        assert!(fixture
            .store
            .begin_evidence_read(&fixture.identity, 0)
            .is_err());
        assert!(fixture
            .store
            .begin_evidence_read(&fixture.identity, 2)
            .is_err());
        Ok(())
    }

    #[test]
    fn discovery_read_byte_limit_preserves_the_next_record() -> TestResult<()> {
        let fixture = ReadFixture::new()?;
        fixture.append(1, 9, Some(MAX_EVIDENCE_READ_BYTES / 8))?;
        let read = fixture.store.begin_evidence_read(&fixture.identity, 1)?;
        let page = fixture.store.read_evidence_page(&read, 1)?;
        assert_eq!(page.records.len(), 8);
        assert_eq!(page.encoded_bytes, MAX_EVIDENCE_READ_BYTES);
        assert_eq!(page.next_cursor, Some(9));
        let last = fixture.store.read_evidence_page(&read, 9)?;
        assert_eq!(last.records.len(), 1);
        assert_eq!(last.records[0].observed_boottime_ns, 9);
        assert_eq!(last.next_cursor, None);
        Ok(())
    }

    #[test]
    fn discovery_read_bounds_handles_across_out_of_order_segments() -> TestResult<()> {
        let fixture = ReadFixture::new()?;
        for cursor in [3, 5, 7] {
            assert!(fixture.append(cursor, 1, None).is_err());
        }
        for cursor in [1, 2, 4, 6] {
            fixture.append(cursor, 1, None)?;
        }
        let read = fixture.store.begin_evidence_read(&fixture.identity, 1)?;
        let opened = fixture.store.open_evidence_page(&read, 1)?;
        assert_eq!(opened.segments.len(), MAX_EVIDENCE_READ_HANDLES);
        let page = opened.decode()?;
        assert_eq!(
            page.records
                .iter()
                .map(|record| record.observed_boottime_ns)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(page.next_cursor, Some(6));
        let last = fixture.store.read_evidence_page(&read, 6)?;
        assert_eq!(
            last.records
                .iter()
                .map(|record| record.observed_boottime_ns)
                .collect::<Vec<_>>(),
            vec![6, 7]
        );
        assert_eq!(last.next_cursor, None);
        Ok(())
    }

    #[test]
    fn discovery_read_open_handles_survive_reclaim_without_holding_the_store_lock() -> TestResult<()>
    {
        let fixture = ReadFixture::new()?;
        fixture.append(1, 257, None)?;
        let read = fixture.store.begin_evidence_read(&fixture.identity, 1)?;
        let opened = fixture.store.open_evidence_page(&read, 1)?;
        assert_eq!(opened.segments.len(), 1);
        assert!(fixture.store.inner.inner.try_lock().is_ok());
        crate::EvidenceRetentionOwner::from_store(fixture.store.clone()).acknowledge(
            EvidenceConsumptionWatermarkV1 {
                identity: fixture.identity.clone(),
                evidence_cursor: 257,
                coverage_revision: 0,
            },
        )?;
        assert_eq!(
            std::fs::read_dir(fixture.directory.path().join("evidence/segments-v2"))?.count(),
            0
        );
        assert_eq!(opened.decode()?.records.len(), 256);
        match fixture.store.read_evidence_page(&read, 257) {
            Err(crate::Error::RetainedRangeExpired {
                identity,
                first_cursor,
                last_cursor,
                ..
            }) => {
                assert_eq!(*identity, fixture.identity);
                assert_eq!((first_cursor, last_cursor), (257, 257));
            }
            result => return Err(format!("expected exact expiry, got {result:?}").into()),
        }
        match fixture.store.read_evidence_page(&read, 1) {
            Err(crate::Error::RetainedRangeExpired {
                first_cursor,
                last_cursor,
                ..
            }) => assert_eq!((first_cursor, last_cursor), (1, 257)),
            result => return Err(format!("expected prefix expiry, got {result:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn discovery_read_rejects_foreign_handles_and_changed_frames() -> TestResult<()> {
        use std::os::unix::fs::FileExt as _;
        let fixture = ReadFixture::new()?;
        fixture.append(1, 1, None)?;
        let read = fixture.store.begin_evidence_read(&fixture.identity, 1)?;
        let foreign = ReadFixture::new()?;
        assert!(foreign.store.read_evidence_page(&read, 1).is_err());
        assert!(fixture.store.read_evidence_page(&read, 0).is_err());
        assert!(fixture.store.read_evidence_page(&read, 3).is_err());
        let opened = fixture.store.open_evidence_page(&read, 1)?;
        let path = std::fs::read_dir(fixture.directory.path().join("evidence/segments-v2"))?
            .next()
            .ok_or("segment is absent")??
            .path();
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let offset = file.metadata()?.len() - 1;
        let mut byte = [0];
        file.read_exact_at(&mut byte, offset)?;
        byte[0] ^= 1;
        file.write_all_at(&byte, offset)?;
        assert!(opened.decode().is_err());
        Ok(())
    }
}
