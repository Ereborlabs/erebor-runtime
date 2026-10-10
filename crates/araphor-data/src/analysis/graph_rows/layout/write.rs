use minicbor::Encoder;

use super::*;

enum Piece {
    Copy(Range<usize>),
    Spelling(Vec<u8>),
}

pub(super) struct LayoutWriter<'a> {
    canonical: &'a [u8],
    bytes: Vec<u8>,
    pending: Option<Piece>,
}

impl<'a> LayoutWriter<'a> {
    pub(super) fn new(canonical: &'a [u8]) -> Self {
        Self {
            canonical,
            bytes: Vec::new(),
            pending: None,
        }
    }

    pub(super) fn copy(&mut self, span: Range<usize>) -> Result<()> {
        let canonical = self.canonical;
        if self.extend(&canonical[span.clone()]) {
            return Ok(());
        }
        self.flush()?;
        self.pending = Some(Piece::Copy(span));
        Ok(())
    }

    pub(super) fn spelling(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || self.extend(bytes) {
            return Ok(());
        }
        if !matches!(self.pending, Some(Piece::Spelling(_))) {
            self.flush()?;
            self.pending = Some(Piece::Spelling(Vec::new()));
        }
        if let Some(Piece::Spelling(pending)) = &mut self.pending {
            Self::reserve(pending, bytes.len(), super::super::super::MAX_RESULT_BYTES)?;
            pending.extend_from_slice(bytes);
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<Vec<u8>> {
        self.flush()?;
        Ok(self.bytes)
    }

    fn extend(&mut self, bytes: &[u8]) -> bool {
        if let Some(Piece::Copy(span)) = &mut self.pending {
            if self.canonical.get(span.end..span.end + bytes.len()) == Some(bytes) {
                span.end += bytes.len();
                return true;
            }
        }
        false
    }

    fn flush(&mut self) -> Result<()> {
        let Some(piece) = self.pending.take() else {
            return Ok(());
        };
        let maximum = match &piece {
            Piece::Copy(_) => 11,
            Piece::Spelling(bytes) => bytes.len() + 5,
        };
        Self::reserve(&mut self.bytes, maximum, JsonLayout::MAX_BYTES)?;
        let mut encoder = Encoder::new(&mut self.bytes);
        match piece {
            Piece::Copy(span) => encoder
                .array(2)
                .and_then(|e| e.u32(span.start as u32))
                .and_then(|e| e.u32(span.len() as u32)),
            Piece::Spelling(bytes) => encoder.bytes(&bytes),
        }
        .map_err(JsonLayout::error)?;
        Ok(())
    }

    fn reserve(bytes: &mut Vec<u8>, additional: usize, limit: usize) -> Result<()> {
        let needed = bytes
            .len()
            .checked_add(additional)
            .filter(|needed| *needed <= limit)
            .ok_or_else(|| JsonLayout::error("allocation bound"))?;
        if needed > bytes.capacity() {
            let capacity = bytes.capacity().saturating_mul(2).max(needed).min(limit);
            bytes
                .try_reserve_exact(capacity - bytes.len())
                .map_err(JsonLayout::error)?;
        }
        Ok(())
    }
}
