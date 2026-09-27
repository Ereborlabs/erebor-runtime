use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use snafu::ResultExt as _;

use crate::{AnalysisStateSnafu, IoSnafu, Result};

pub const MAX_EVIDENCE_SEGMENT_BYTES: usize = 16 * 1024 * 1024;
const IDENTITY_FIXED_BYTES: usize = 70;

/// Bounded segment I/O. The caller owns the directory lease and commit catalog.
pub struct SegmentFile {
    file: File,
    path: PathBuf,
}

impl SegmentFile {
    pub fn encode_identity(identity: &crate::EvidenceIntakeIdentityV1) -> Result<Vec<u8>> {
        let node_id_bytes = identity.node_id.as_bytes();
        let node_id_len = u16::try_from(node_id_bytes.len()).map_err(|error| {
            AnalysisStateSnafu {
                path: PathBuf::from("<evidence-stream-identity>"),
                reason: format!("the evidence stream node identity is too long: {error}"),
            }
            .build()
        })?;
        let mut bytes = Vec::with_capacity(IDENTITY_FIXED_BYTES + node_id_bytes.len());
        bytes.extend_from_slice(&identity.tenant_id);
        bytes.extend_from_slice(&identity.node_boot_id);
        bytes.extend_from_slice(&identity.source_id);
        bytes.extend_from_slice(&identity.label_epoch.to_be_bytes());
        bytes.extend_from_slice(&identity.source_epoch.to_be_bytes());
        bytes.extend_from_slice(&node_id_len.to_be_bytes());
        bytes.extend_from_slice(node_id_bytes);
        let checksum = crc32c::crc32c(&bytes);
        bytes.extend_from_slice(&checksum.to_be_bytes());
        Ok(bytes)
    }

    pub fn decode_identity(
        bytes: &[u8],
        path: &Path,
    ) -> Result<(crate::EvidenceIntakeIdentityV1, usize)> {
        if bytes.len() < IDENTITY_FIXED_BYTES {
            return AnalysisStateSnafu {
                path: path.to_owned(),
                reason: "the evidence segment stream identity is truncated".to_owned(),
            }
            .fail();
        }
        let node_id_len = u16::from_be_bytes(bytes[64..66].try_into().unwrap_or_default()) as usize;
        let header_bytes = IDENTITY_FIXED_BYTES
            .checked_add(node_id_len)
            .ok_or_else(|| {
                AnalysisStateSnafu {
                    path: path.to_owned(),
                    reason: "the evidence segment stream identity size overflowed".to_owned(),
                }
                .build()
            })?;
        if bytes.len() < header_bytes {
            return AnalysisStateSnafu {
                path: path.to_owned(),
                reason: "the evidence segment stream identity is incomplete".to_owned(),
            }
            .fail();
        }
        let checksum_start = header_bytes - 4;
        let expected = u32::from_be_bytes(
            bytes[checksum_start..header_bytes]
                .try_into()
                .unwrap_or_default(),
        );
        if crc32c::crc32c(&bytes[..checksum_start]) != expected {
            return AnalysisStateSnafu {
                path: path.to_owned(),
                reason: "the evidence segment stream identity checksum is invalid".to_owned(),
            }
            .fail();
        }
        let node_id = std::str::from_utf8(&bytes[66..checksum_start])
            .map_err(|error| {
                AnalysisStateSnafu {
                    path: path.to_owned(),
                    reason: format!("the evidence segment node identity is invalid: {error}"),
                }
                .build()
            })?
            .to_owned();
        Ok((
            crate::EvidenceIntakeIdentityV1 {
                tenant_id: bytes[..16].try_into().unwrap_or_default(),
                node_id,
                node_boot_id: bytes[16..32].try_into().unwrap_or_default(),
                label_epoch: u64::from_be_bytes(bytes[48..56].try_into().unwrap_or_default()),
                source_id: bytes[32..48].try_into().unwrap_or_default(),
                source_epoch: u64::from_be_bytes(bytes[56..64].try_into().unwrap_or_default()),
            },
            header_bytes,
        ))
    }

    pub fn create(path: &Path, header: &[u8]) -> Result<Self> {
        if header.is_empty() || header.len() > MAX_EVIDENCE_SEGMENT_BYTES {
            return Self::invalid(path, "the segment header is outside its size bound");
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .context(IoSnafu { path })?;
        let owner = Self {
            file,
            path: path.to_owned(),
        };
        owner.append(0, header)?;
        Ok(owner)
    }

    pub fn open(path: &Path) -> Result<Self> {
        Self::open_file(path, true)
    }

    pub fn reader(path: &Path) -> Result<Self> {
        Self::open_file(path, false)
    }

    fn open_file(path: &Path, writable: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(writable)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)
            .context(IoSnafu { path })?;
        let metadata = file.metadata().context(IoSnafu { path })?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > MAX_EVIDENCE_SEGMENT_BYTES as u64
        {
            return Self::invalid(path, "the segment is not a private bounded file");
        }
        Ok(Self {
            file,
            path: path.to_owned(),
        })
    }

    pub fn append(&self, expected_end: u64, bytes: &[u8]) -> Result<u64> {
        let end = expected_end.checked_add(bytes.len() as u64);
        if bytes.is_empty() || end.is_none_or(|end| end > MAX_EVIDENCE_SEGMENT_BYTES as u64) {
            return Self::invalid(&self.path, "the segment append exceeds its size bound");
        }
        let length = self
            .file
            .metadata()
            .context(IoSnafu { path: &self.path })?
            .len();
        if length != expected_end {
            return Self::invalid(
                &self.path,
                "the segment end differs from the expected position",
            );
        }
        self.file
            .write_all_at(bytes, expected_end)
            .context(IoSnafu { path: &self.path })?;
        Ok(end.unwrap_or_default())
    }

    pub fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        if offset
            .checked_add(length as u64)
            .is_none_or(|end| end > MAX_EVIDENCE_SEGMENT_BYTES as u64)
        {
            return Self::invalid(&self.path, "the segment read exceeds its size bound");
        }
        let mut bytes = vec![0; length];
        self.file
            .read_exact_at(&mut bytes, offset)
            .context(IoSnafu { path: &self.path })?;
        Ok(bytes)
    }

    pub(super) fn length(&self) -> Result<u64> {
        Ok(self
            .file
            .metadata()
            .context(IoSnafu { path: &self.path })?
            .len())
    }

    pub(super) fn sync(&self) -> Result<()> {
        self.file.sync_all().context(IoSnafu { path: &self.path })
    }

    pub(super) fn discard_tail(&self, committed_end: u64) -> Result<()> {
        if committed_end == 0 || committed_end > self.length()? {
            return Self::invalid(&self.path, "the committed segment end is unavailable");
        }
        self.file
            .set_len(committed_end)
            .context(IoSnafu { path: &self.path })?;
        self.sync()
    }

    fn invalid<T>(path: &Path, reason: &str) -> Result<T> {
        AnalysisStateSnafu { path, reason }.fail()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_identity_checks_integrity() -> Result<()> {
        let identity = crate::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "segment-node".to_owned(),
            node_boot_id: [2; 16],
            label_epoch: 3,
            source_id: [4; 16],
            source_epoch: 5,
        };
        let path = Path::new("/test/segment");
        let encoded = SegmentFile::encode_identity(&identity)?;
        for length in 0..encoded.len() {
            assert!(SegmentFile::decode_identity(&encoded[..length], path).is_err());
        }
        let mut input = encoded.clone();
        input.extend_from_slice(b"frame");
        let (decoded, consumed) = SegmentFile::decode_identity(&input, path)?;
        assert_eq!(decoded, identity);
        assert_eq!(consumed, encoded.len());
        input[0] ^= 1;
        assert!(SegmentFile::decode_identity(&input, path).is_err());
        Ok(())
    }

    #[test]
    fn segment_append_checks_position() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("1.seg");
        let file = SegmentFile::create(&path, b"header")?;
        assert_eq!(file.append(6, b"frame")?, 11);
        assert_eq!(file.read(6, 5)?, b"frame");
        assert!(file.read(6, 6).is_err());
        assert!(file.read(u64::MAX, 1).is_err());
        assert!(file.read(0, MAX_EVIDENCE_SEGMENT_BYTES + 1).is_err());
        assert!(file.append(6, b"second").is_err());
        assert_eq!(std::fs::read(&path)?, b"headerframe");
        drop(file);
        assert_eq!(SegmentFile::open(&path)?.append(11, b"next")?, 15);
        Ok(())
    }

    #[test]
    fn segment_append_checks_bound() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("1.seg");
        let file = SegmentFile::create(&path, b"h")?;
        file.file.set_len(MAX_EVIDENCE_SEGMENT_BYTES as u64 - 1)?;
        assert_eq!(
            file.append(MAX_EVIDENCE_SEGMENT_BYTES as u64 - 1, b"x")?,
            MAX_EVIDENCE_SEGMENT_BYTES as u64
        );
        assert!(file
            .append(MAX_EVIDENCE_SEGMENT_BYTES as u64, b"x")
            .is_err());
        assert!(file.append(u64::MAX, b"x").is_err());
        assert!(file.append(MAX_EVIDENCE_SEGMENT_BYTES as u64, b"").is_err());
        Ok(())
    }

    #[test]
    fn segment_rejects_foreign_files() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let path = root.path().join("1.seg");
        SegmentFile::create(&path, b"h")?;
        assert!(SegmentFile::create(&path, b"replacement").is_err());
        let link = root.path().join("link.seg");
        symlink(&path, &link)?;
        assert!(SegmentFile::open(&link).is_err());
        assert!(SegmentFile::create(&link, b"replacement").is_err());
        assert!(SegmentFile::open(root.path()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert!(SegmentFile::open(&path).is_err());
        assert_eq!(std::fs::read(&path)?, b"h");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        let reader = SegmentFile::reader(&path)?;
        assert_eq!(reader.read(0, 1)?, b"h");
        assert!(reader.append(1, b"x").is_err());
        Ok(())
    }
}
