use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use super::{native::events::EventRead, raw::RawRead, AnalysisRecordV1, StorePositionV1};
use crate::Result;

#[derive(Clone)]
enum Reader {
    Diagnostic {
        read: RawRead,
        first: u64,
        last: u64,
    },
    Evidence(EventRead),
}

#[derive(Clone)]
pub(super) struct InputRange {
    pub(super) first_cursor: u64,
    pub(super) scan_bytes: usize,
    pub(super) intake: u64,
    reader: Reader,
}

impl InputRange {
    pub(super) fn diagnostic(
        read: RawRead,
        first: u64,
        last: u64,
        bytes: usize,
        intake: u64,
    ) -> Self {
        Self {
            first_cursor: read.first(),
            scan_bytes: bytes,
            intake,
            reader: Reader::Diagnostic { read, first, last },
        }
    }

    pub(super) fn native(read: EventRead) -> Self {
        Self {
            first_cursor: read.first(),
            scan_bytes: read.bytes(),
            intake: read.intake(),
            reader: Reader::Evidence(read),
        }
    }

    pub(super) fn window(&self, after: Option<StorePositionV1>, limit: usize) -> Option<Self> {
        match &self.reader {
            Reader::Diagnostic { read, first, last } => Some(Self::diagnostic(
                read.window(after, limit)?,
                *first,
                *last,
                self.scan_bytes,
                self.intake,
            )),
            Reader::Evidence(read) => Some(Self::native(read.window(after, limit)?)),
        }
    }

    pub(super) fn end(&self) -> StorePositionV1 {
        match &self.reader {
            Reader::Diagnostic { read, .. } => read.end(),
            Reader::Evidence(read) => read.end(),
        }
    }

    pub(super) fn metadata_bytes(&self) -> usize {
        match &self.reader {
            Reader::Diagnostic { read, .. } => read.metadata_bytes(),
            Reader::Evidence(read) => read.metadata_bytes(),
        }
    }

    pub(super) fn read(&self, root: &Path) -> Result<(Vec<AnalysisRecordV1>, usize, usize)> {
        match &self.reader {
            Reader::Evidence(read) => read.read(root),
            Reader::Diagnostic { read, first, last } => {
                if last
                    .checked_sub(*first)
                    .is_none_or(|bytes| bytes == 0 || bytes > self.scan_bytes as u64)
                {
                    return crate::Error::reject_path(
                        root,
                        "the selected raw byte range is invalid",
                    );
                }
                read.read(root)
            }
        }
    }

    #[cfg(test)]
    pub(super) fn path(root: &Path, segment_id: u64) -> PathBuf {
        std::fs::read_dir(root.join("segments"))
            .ok()
            .into_iter()
            .flatten()
            .filter_map(std::result::Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{segment_id:016x}."))
            })
            .map_or_else(
                || {
                    root.join("segments")
                        .join(format!("{segment_id:016x}.missing"))
                },
                |entry| entry.path(),
            )
    }
}
