use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use prost::Message as _;
use snafu::ResultExt as _;

use super::raw::{RawCommit, RawEntry, RawIdentity, RawJournal, RawKind, RawLocation, RawMeta};
use super::{AnalysisStore, SegmentFile, StorageUsageV1, EVIDENCE_SEGMENT_BYTES};
use crate::{AnalysisStateSnafu, IoSnafu, Result};

pub(super) type DirectoryStamp = (u64, u64, i64, i64, i64, i64);

pub(super) struct RawSegment {
    pub(super) source: Vec<u8>,
    pub(super) path: PathBuf,
    pub(super) end: u64,
    pub(super) usage: StorageUsageV1,
}

pub(super) struct RawAppend {
    pub(super) id: u64,
    pub(super) offset: u64,
    pub(super) header: Option<Vec<u8>>,
    pub(super) frame: Vec<u8>,
    pub(super) commit: RawCommit,
}

impl RawAppend {
    pub(super) fn added(&self) -> u64 {
        (self.frame.len() + self.header.as_ref().map_or(0, Vec::len)) as u64
    }
}

impl RawCommit {
    pub(super) fn from_frame(bytes: &[u8], path: &Path) -> Result<Self> {
        if bytes.len() < 8 {
            return AnalysisStore::reject_path(path, "the raw commit frame size is invalid");
        }
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap_or_default()) as usize;
        let checksum = u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().unwrap_or_default());
        if length != bytes.len() - 8 || crc32c::crc32c(&bytes[..bytes.len() - 4]) != checksum {
            return AnalysisStore::reject_path(
                path,
                "the raw commit frame length or checksum is invalid",
            );
        }
        let payload = &bytes[4..bytes.len() - 4];
        let commit = Self::decode(payload).map_err(|source| {
            AnalysisStateSnafu {
                path,
                reason: format!("the raw commit failed decoding: {source}"),
            }
            .build()
        })?;
        if commit.encode_to_vec() != payload {
            return AnalysisStore::reject_path(path, "the raw commit encoding is not canonical");
        }
        commit.validate(path)?;
        Ok(commit)
    }

    pub(super) fn read(file: &SegmentFile, start: u64, bytes: usize) -> Result<Self> {
        Self::from_frame(&file.read(start, bytes)?, file.path())
    }
}

impl RawJournal {
    fn directory_stamp(&self) -> Result<DirectoryStamp> {
        let path = self.root.join("segments");
        let metadata = fs::symlink_metadata(&path).context(IoSnafu { path: &path })?;
        Ok((
            metadata.dev(),
            metadata.ino(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ))
    }

    pub(super) fn directory_current(&self) -> Result<bool> {
        Ok(self.directory.get() == Some(self.directory_stamp()?))
    }

    pub(super) fn directory_changed(&self, current: bool) -> Result<()> {
        self.directory.set(if current {
            Some(self.directory_stamp()?)
        } else {
            None
        });
        Ok(())
    }

    pub(super) fn storage_summary(&self) -> Result<Option<(StorageUsageV1, usize, usize)>> {
        Ok(self.directory_current()?.then_some((
            self.usage,
            self.segments.len() - self.diagnostics,
            self.diagnostics,
        )))
    }

    pub(super) fn segment_path(&self, id: u64) -> Result<&Path> {
        self.segments
            .get(&id)
            .map(|segment| segment.path.as_path())
            .ok_or_else(|| self.invalid("the raw segment is absent"))
    }

    fn seal_segment(&mut self, id: u64) -> Result<()> {
        let segment = self.segments.get_mut(&id).ok_or_else(|| {
            AnalysisStateSnafu {
                path: &self.root,
                reason: "the active raw segment is absent",
            }
            .build()
        })?;
        let path = segment
            .path
            .with_extension(format!("{:016x}.seg", segment.end));
        fs::rename(&segment.path, &path).context(IoSnafu {
            path: &segment.path,
        })?;
        segment.path = path;
        if let Some(source) = self.sources.get_mut(&segment.source) {
            source.active = None;
        }
        Ok(())
    }

    pub(super) fn seal_all(&mut self) -> Result<()> {
        let current = self.directory_current()?;
        let active = self
            .sources
            .values()
            .filter_map(|source| source.active)
            .collect::<Vec<_>>();
        for id in active {
            self.seal_segment(id)?;
        }
        let path = self.root.join("segments");
        File::open(&path)
            .and_then(|file| file.sync_all())
            .context(IoSnafu { path: &path })?;
        self.directory_changed(current)
    }

    pub(super) fn forget_segment(&mut self, id: u64) -> Result<()> {
        if let Some(segment) = self.segments.remove(&id) {
            self.usage.subtract(segment.usage, &self.root)?;
            if segment.source.first() == Some(&1) {
                self.diagnostics = self
                    .diagnostics
                    .checked_sub(1)
                    .ok_or_else(|| self.invalid("the diagnostic segment count underflows"))?;
            }
            if let Some(source) = self.sources.get_mut(&segment.source) {
                if source.active == Some(id) {
                    source.active = None;
                }
            }
        }
        Ok(())
    }

    pub(super) fn prepare_append(
        &self,
        identity: &RawIdentity,
        commit: RawCommit,
    ) -> Result<RawAppend> {
        commit.validate(&self.root)?;
        let length = u32::try_from(commit.encoded_len())
            .map_err(|_| self.invalid("the raw commit is too large"))?;
        let capacity = (length as usize)
            .checked_add(8)
            .ok_or_else(|| self.invalid("the raw commit size is not representable"))?;
        let mut frame = Vec::with_capacity(capacity);
        frame.extend_from_slice(&length.to_be_bytes());
        commit
            .encode(&mut frame)
            .map_err(|_| self.invalid("the raw commit encoding failed"))?;
        frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
        let terminal = matches!(&commit.kind, Some(RawKind::Diagnostic(progress))
            if progress.terminal && commit.spans.len() == 1 && commit.spans[0].first == progress.last_sequence + 1);
        if let Some((id, segment)) = self
            .sources
            .get(&identity.key())
            .and_then(|source| source.active)
            .and_then(|id| self.segments.get(&id).map(|segment| (id, segment)))
            .filter(|(id, segment)| {
                segment
                    .end
                    .checked_add(frame.len() as u64)
                    .is_some_and(|end| end <= EVIDENCE_SEGMENT_BYTES as u64)
                    && !(terminal
                        && self
                            .budget
                            .pins
                            .get(id)
                            .is_some_and(|(_, expiry)| *expiry > commit.intake))
            })
        {
            return Ok(RawAppend {
                id,
                offset: segment.end,
                header: None,
                frame,
                commit,
            });
        }
        self.next_segment
            .checked_add(1)
            .ok_or_else(|| self.invalid("the evidence segment sequence is exhausted"))?;
        let header = SegmentFile::encode_raw(identity)?;
        header
            .len()
            .checked_add(frame.len())
            .ok_or_else(|| self.invalid("the raw segment size is not representable"))?;
        Ok(RawAppend {
            id: self.next_segment,
            offset: header.len() as u64,
            header: Some(header),
            frame,
            commit,
        })
    }

    pub(super) fn append(&mut self, identity: &RawIdentity, append: RawAppend) -> Result<()> {
        let current = self.directory_current()?;
        let path = if let Some(header) = &append.header {
            if let Some(id) = self
                .sources
                .get(&identity.key())
                .and_then(|source| source.active)
            {
                self.seal_segment(id)?;
            }
            self.next_segment = append
                .id
                .checked_add(1)
                .ok_or_else(|| self.invalid("the evidence segment sequence is exhausted"))?;
            let kind = if identity.evidence().is_some() {
                "r"
            } else {
                "d"
            };
            let path = self
                .root
                .join("segments")
                .join(format!("{:016x}.{kind}.open", append.id));
            let file = SegmentFile::create(&path, header)?;
            #[cfg(test)]
            AnalysisStore::crash_path(&self.root, "segment.reserved");
            file.append(append.offset, &append.frame)?;
            path
        } else {
            let segment = self
                .segments
                .get(&append.id)
                .ok_or_else(|| self.invalid("the selected evidence segment is missing"))?;
            if segment.source != identity.key()
                || segment.end != append.offset
                || self
                    .sources
                    .get(&segment.source)
                    .is_none_or(|source| source.active != Some(append.id))
            {
                return Err(self.invalid("the selected evidence segment changed"));
            }
            SegmentFile::open(&segment.path)?.append(append.offset, &append.frame)?;
            segment.path.clone()
        };
        #[cfg(test)]
        AnalysisStore::crash_path(&self.root, "segment.appended");
        let directory = self.root.join("segments");
        rustix::fs::syncfs(&File::open(&directory).context(IoSnafu { path: &directory })?)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: &directory })?;
        let metadata = fs::symlink_metadata(&path).context(IoSnafu { path: &path })?;
        if !metadata.is_file() {
            return Err(self.invalid("the synced evidence segment is not a file"));
        }
        let usage = StorageUsageV1::from_metadata(&path, &metadata)?;
        if let Some(segment) = self.segments.get(&append.id) {
            self.usage.subtract(segment.usage, &self.root)?;
        } else if identity.evidence().is_none() {
            self.diagnostics += 1;
        }
        self.usage.add(usage, &self.root)?;
        let end = append.offset + append.frame.len() as u64;
        self.segments.insert(
            append.id,
            RawSegment {
                source: identity.key(),
                path,
                end,
                usage,
            },
        );
        self.directory_changed(current)?;
        #[cfg(test)]
        AnalysisStore::crash_path(&self.root, "segment.synced");
        self.publish(
            RawEntry {
                identity: identity.clone(),
                commit: RawMeta::try_from(&append.commit)?,
                reference: RawLocation {
                    id: append.id,
                    offset: end,
                },
                body_start: end - 4 - append.commit.body.len() as u64,
                body_bytes: append.commit.body.len(),
                frame_bytes: append.frame.len(),
            },
            &append.commit,
        )?;
        self.sources
            .get_mut(&identity.key())
            .ok_or_else(|| {
                AnalysisStateSnafu {
                    path: &self.root,
                    reason: "the appended raw source is absent",
                }
                .build()
            })?
            .active = Some(append.id);
        self.refresh_source(&identity.key())
    }

    pub(super) fn open(root: &Path, committed: &BTreeMap<u64, u64>) -> Result<Self> {
        AnalysisStore::segment_directory(root)?;
        Self::read_segments(root, committed, false)
    }

    pub(super) fn read_sealed(root: &Path, committed: &BTreeMap<u64, u64>) -> Result<Self> {
        Self::read_segments(root, committed, true)
    }

    fn read_segments(
        root: &Path,
        committed: &BTreeMap<u64, u64>,
        sealed_only: bool,
    ) -> Result<Self> {
        let mut journal = Self {
            root: root.to_path_buf(),
            sources: BTreeMap::new(),
            entries: BTreeMap::new(),
            ranges: BTreeMap::new(),
            revision: 0,
            budget: Default::default(),
            segments: BTreeMap::new(),
            next_segment: 1,
            usage: Default::default(),
            diagnostics: 0,
            directory: Cell::new(None),
        };
        let directory = root.join("segments");
        let mut paths = BTreeMap::new();
        for entry in fs::read_dir(&directory).context(IoSnafu { path: &directory })? {
            let path = entry.context(IoSnafu { path: &directory })?.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| journal.invalid("the evidence segment name is invalid"))?;
            let fields = name.split('.').collect::<Vec<_>>();
            let (id, kind, sealed) = match fields.as_slice() {
                [id, kind @ ("r" | "d"), "open"] => (*id, *kind, None),
                [id, kind @ ("r" | "d"), end, "seg"] => {
                    let value = u64::from_str_radix(end, 16)
                        .map_err(|_| journal.invalid("the sealed segment length is invalid"))?;
                    if *end != format!("{value:016x}") {
                        return Err(journal.invalid("the sealed segment length is invalid"));
                    }
                    (*id, *kind, Some(value))
                }
                _ => return Err(journal.invalid("the evidence segment name is invalid")),
            };
            let value = u64::from_str_radix(id, 16)
                .map_err(|_| journal.invalid("the evidence segment name is invalid"))?;
            if value == 0 || id != format!("{value:016x}") || (sealed_only && sealed.is_none()) {
                return Err(journal.invalid("the evidence segment name or state is invalid"));
            }
            let kind = if kind == "r" { "records" } else { "diagnostic" };
            if paths.insert(value, (path, kind, sealed)).is_some() {
                return Err(journal.invalid("the evidence segment sequence is duplicated"));
            }
        }
        let mut changed = false;
        for (id, (path, kind, sealed)) in paths {
            let active = sealed.is_none();
            journal.next_segment =
                journal.next_segment.max(id.checked_add(1).ok_or_else(|| {
                    journal.invalid("the evidence segment sequence is exhausted")
                })?);
            let file = if active {
                SegmentFile::open(&path)?
            } else {
                SegmentFile::reader(&path)?
            };
            let length = file.length()?;
            if sealed.is_some_and(|end| end != length) {
                return Err(journal.invalid("the sealed segment length differs from its name"));
            }
            let bytes = file.read(
                0,
                usize::try_from(length)
                    .map_err(|_| journal.invalid("the segment size is not representable"))?,
            )?;
            let (identity, mut offset) = SegmentFile::decode_raw(kind, &bytes, &path)?;
            if !identity.valid() {
                return Err(journal.invalid("the raw source identity is invalid"));
            }
            let first = offset;
            while offset < bytes.len() {
                let Some(length) = bytes.get(offset..offset + 4) else {
                    break;
                };
                let length = u32::from_be_bytes(length.try_into().unwrap_or_default()) as usize;
                if length == 0 {
                    return Err(journal
                        .invalid("the evidence segment contains a record outside its size bound"));
                }
                let Some(end) = offset
                    .checked_add(length)
                    .and_then(|end| end.checked_add(8))
                    .filter(|end| *end <= bytes.len())
                else {
                    break;
                };
                let commit = RawCommit::from_frame(&bytes[offset..end], &path)?;
                journal.publish(
                    RawEntry {
                        identity: identity.clone(),
                        commit: RawMeta::try_from(&commit)?,
                        reference: RawLocation {
                            id,
                            offset: end as u64,
                        },
                        body_start: end as u64 - 4 - commit.body.len() as u64,
                        body_bytes: commit.body.len(),
                        frame_bytes: end - offset,
                    },
                    &commit,
                )?;
                offset = end;
            }
            if (offset as u64) < committed.get(&id).copied().unwrap_or(0) {
                return Err(journal.invalid("the raw segment lost a catalogued commit"));
            }
            if offset != bytes.len() {
                if !active {
                    return Err(journal
                        .invalid("the sealed evidence segment has an incomplete record tail"));
                }
                file.discard_tail(offset as u64)?;
            }
            if offset == first {
                if !active {
                    return Err(journal.invalid("a sealed evidence segment is empty"));
                }
                fs::remove_file(&path).context(IoSnafu { path: &path })?;
                changed = true;
                continue;
            }
            if active {
                let source = journal.sources.get_mut(&identity.key()).ok_or_else(|| {
                    AnalysisStateSnafu {
                        path: root,
                        reason: "the raw source is absent",
                    }
                    .build()
                })?;
                if source.active.replace(id).is_some() {
                    return Err(journal.invalid("one evidence stream has multiple active segments"));
                }
            }
            let usage = file.storage_usage()?;
            journal.usage.add(usage, root)?;
            journal.diagnostics += usize::from(identity.evidence().is_none());
            journal.segments.insert(
                id,
                RawSegment {
                    source: identity.key(),
                    path,
                    end: offset as u64,
                    usage,
                },
            );
        }
        if changed {
            File::open(&directory)
                .and_then(|file| file.sync_all())
                .context(IoSnafu { path: &directory })?;
        }
        journal.directory.set(Some(journal.directory_stamp()?));
        journal.refresh_receipts()?;
        Ok(journal)
    }
}
