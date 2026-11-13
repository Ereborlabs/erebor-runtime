use std::fs::File;
use std::sync::{atomic::AtomicBool, Arc};

use super::{RawEntry, RawIdentity, RawJournal, RawLocation, RawMeta, Result};
use crate::analysis::raw_segments::{RawAppend, RawSegment};
use crate::analysis::SegmentFile;

#[derive(Default)]
pub(super) struct Segments {
    active: Option<(u64, SegmentFile)>,
}

impl Segments {
    pub fn append(
        &mut self,
        journal: &mut RawJournal,
        identity: &RawIdentity,
        append: RawAppend,
    ) -> Result<()> {
        let end = append
            .offset
            .checked_add(append.frame.len() as u64)
            .ok_or("benchmark segment end overflow")?;
        let mut index = journal.prepare_index(
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
        index
            .sources
            .get_mut(&identity.key())
            .ok_or("benchmark source missing")?
            .active = Some(append.id);
        index.refresh_source(&identity.key())?;
        let current = journal.directory_current()?;
        let directory = journal.root.join("segments");
        if let Some(header) = &append.header {
            journal.seal_all()?;
            let path = directory.join(format!("{:016x}.r.open", append.id));
            self.active = Some((append.id, SegmentFile::create(&path, header)?));
        } else {
            let segment = journal
                .segments
                .get(&append.id)
                .ok_or("benchmark segment missing")?;
            if segment.source != identity.key()
                || segment.end != append.offset
                || journal.index.sources[&identity.key()].active != Some(append.id)
            {
                return Err("benchmark active segment changed".into());
            }
            if self.active.as_ref().is_none_or(|(id, _)| *id != append.id) {
                self.active = Some((append.id, SegmentFile::open(&segment.path)?));
            }
        }
        let (_, file) = self.active.as_ref().ok_or("benchmark file missing")?;
        file.append(append.offset, &append.frame)?;
        file.sync()?;
        if append.header.is_some() {
            File::open(&directory)?.sync_all()?;
        }
        let usage = file.storage_usage()?;
        let previous = journal.segments.get(&append.id);
        if let Some(segment) = previous {
            journal.usage.subtract(segment.usage, &journal.root)?;
        }
        journal.usage.add(usage, &journal.root)?;
        let live = previous.map_or_else(
            || Arc::new(AtomicBool::new(true)),
            |segment| Arc::clone(&segment.live),
        );
        journal.segments.insert(
            append.id,
            RawSegment {
                source: identity.key(),
                path: file.path().to_owned(),
                end,
                usage,
                live,
            },
        );
        journal.next_segment = journal.next_segment.max(
            append
                .id
                .checked_add(1)
                .ok_or("benchmark segment sequence overflow")?,
        );
        journal.directory_changed(current)?;
        journal.index = index;
        Ok(())
    }
}
