use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use super::AnalysisRecordV1;
use crate::Result;

#[derive(Clone)]
pub(super) struct SegmentRange {
    pub(super) segment_id: u64,
    pub(super) byte_start: u64,
    pub(super) byte_end: u64,
    pub(super) first_cursor: u64,
    pub(super) reader: super::raw::RawRead,
    pub(super) scan_bytes: usize,
    pub(super) intake: u64,
}

impl SegmentRange {
    pub(super) fn window(
        &self,
        after: Option<super::StorePositionV1>,
        limit: usize,
    ) -> Option<Self> {
        let mut next = self.clone();
        next.reader = self.reader.window(after, limit)?;
        next.first_cursor = next.reader.first();
        Some(next)
    }

    pub(super) fn end(&self) -> super::StorePositionV1 {
        self.reader.end()
    }

    pub(super) fn metadata_bytes(&self) -> usize {
        self.reader.metadata_bytes()
    }

    pub(super) fn read(&self, root: &Path) -> Result<(Vec<AnalysisRecordV1>, usize, usize)> {
        if self
            .byte_end
            .checked_sub(self.byte_start)
            .is_none_or(|bytes| bytes == 0 || bytes > self.scan_bytes as u64)
        {
            return crate::Error::reject_path(root, "the selected raw byte range is invalid");
        }
        self.reader.read(root)
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
