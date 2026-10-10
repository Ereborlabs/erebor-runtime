use std::collections::HashMap;
use std::ops::Range;

use minicbor::Decoder;

use super::GraphRows;
use crate::{GraphInvalidSnafu, GraphSnapshotV1, Result};

pub(super) struct JsonLayout;

mod write;

struct JsonTokens<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl JsonLayout {
    pub(super) const MAX_BYTES: usize = 17 * super::super::MAX_RESULT_BYTES + 8;

    pub(super) fn encode(
        snapshot: &GraphSnapshotV1,
        source: &[u8],
        canonical: &[u8],
    ) -> Result<Vec<u8>> {
        if source.is_empty()
            || source.len() > super::super::MAX_RESULT_BYTES
            || canonical.len() > GraphRows::MAX_CANONICAL_BYTES
        {
            return GraphInvalidSnafu {
                field: "graph source encoding",
            }
            .fail();
        }
        if source == canonical {
            return Ok(Vec::new());
        }
        if GraphRows::decode::<GraphSnapshotV1>(source)? != *snapshot {
            return GraphInvalidSnafu {
                field: "graph source encoding",
            }
            .fail();
        }
        let mut dictionary = HashMap::new();
        for span in JsonTokens::new(canonical) {
            let span = span?;
            let token = &canonical[span.clone()];
            if !dictionary.contains_key(token) {
                dictionary.try_reserve(1).map_err(Self::error)?;
                dictionary.insert(token, span.start as u32);
            }
        }
        let mut writer = write::LayoutWriter::new(canonical);
        let mut position = 0;
        for span in JsonTokens::new(source) {
            let span = span?;
            writer.spelling(&source[position..span.start])?;
            let token = &source[span.clone()];
            if let Some(start) = dictionary.get(token) {
                let start = *start as usize;
                writer.copy(start..start + token.len())?;
            } else {
                writer.spelling(token)?;
            }
            position = span.end;
        }
        writer.spelling(&source[position..])?;
        writer.finish()
    }

    pub(super) fn replay(layout: &[u8], canonical: &[u8], expected: usize) -> Result<Vec<u8>> {
        if layout.len() > Self::MAX_BYTES || expected > super::super::MAX_RESULT_BYTES {
            return GraphInvalidSnafu {
                field: "graph encoding layout bytes",
            }
            .fail();
        }
        if layout.is_empty() {
            if canonical.len() != expected {
                return GraphInvalidSnafu {
                    field: "graph encoding output bytes",
                }
                .fail();
            }
            return Ok(canonical.to_vec());
        }
        let mut decoder = Decoder::new(layout);
        let mut body = Vec::with_capacity(expected);
        while decoder.position() < layout.len() {
            let chunk = match decoder.datatype().map_err(Self::error)? {
                minicbor::data::Type::Bytes => decoder.bytes().map_err(Self::error)?,
                minicbor::data::Type::Array => {
                    if decoder.array().map_err(Self::error)? != Some(2) {
                        return GraphInvalidSnafu {
                            field: "graph encoding span",
                        }
                        .fail();
                    }
                    let start = decoder.u32().map_err(Self::error)? as usize;
                    let length = decoder.u32().map_err(Self::error)? as usize;
                    let end = start
                        .checked_add(length)
                        .ok_or_else(|| Self::error("overflow"))?;
                    canonical
                        .get(start..end)
                        .ok_or_else(|| Self::error("span"))?
                }
                _ => {
                    return GraphInvalidSnafu {
                        field: "graph encoding layout type",
                    }
                    .fail()
                }
            };
            if chunk.len() > expected.saturating_sub(body.len()) {
                return GraphInvalidSnafu {
                    field: "graph encoding output bytes",
                }
                .fail();
            }
            body.extend_from_slice(chunk);
        }
        if body.len() != expected {
            return GraphInvalidSnafu {
                field: "graph encoding output bytes",
            }
            .fail();
        }
        Ok(body)
    }

    fn separator(byte: u8) -> bool {
        b"{}[],: \t\r\n".contains(&byte)
    }
    fn error(_: impl std::fmt::Display) -> crate::Error {
        GraphInvalidSnafu {
            field: "graph encoding layout",
        }
        .build()
    }
}

impl<'a> JsonTokens<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
}

impl Iterator for JsonTokens<'_> {
    type Item = Result<Range<usize>>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.position < self.bytes.len() && JsonLayout::separator(self.bytes[self.position]) {
            self.position += 1;
        }
        if self.position == self.bytes.len() {
            return None;
        }
        let start = self.position;
        if self.bytes[self.position] == b'"' {
            self.position += 1;
            while self.position < self.bytes.len() && self.bytes[self.position] != b'"' {
                self.position += if self.bytes[self.position] == b'\\' {
                    2
                } else {
                    1
                };
            }
            if self.position >= self.bytes.len() {
                self.position = self.bytes.len();
                return Some(Err(JsonLayout::error("string span")));
            }
            self.position += 1;
        } else {
            while self.position < self.bytes.len()
                && !JsonLayout::separator(self.bytes[self.position])
            {
                self.position += 1;
            }
        }
        Some(Ok(start..self.position))
    }
}
