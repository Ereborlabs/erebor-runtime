use arrow_ipc::{Message, MessageHeader};

use crate::{Error, ErrorCode, Limits, Model, Result};

pub(super) struct IpcFrames<'a> {
    bytes: &'a [u8],
    rows: u64,
    batches: u32,
}

impl<'a> IpcFrames<'a> {
    pub(super) fn validate_envelope(bytes: &'a [u8]) -> Result<()> {
        let mut frames = Self {
            bytes,
            rows: 0,
            batches: 0,
        };
        while let Some((message, _, _)) = frames.next()? {
            match message.header_type() {
                MessageHeader::RecordBatch => {
                    Self::uncompressed(message.header_as_record_batch().ok_or_else(Self::invalid)?)?
                }
                MessageHeader::DictionaryBatch => {
                    let dictionary = message
                        .header_as_dictionary_batch()
                        .ok_or_else(Self::invalid)?;
                    Self::uncompressed(dictionary.data().ok_or_else(Self::invalid)?)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(super) fn validate(bytes: &'a [u8], limits: Limits) -> Result<()> {
        let mut frames = Self {
            bytes,
            rows: 0,
            batches: 0,
        };
        while let Some((message, _, _)) = frames.next()? {
            match message.header_type() {
                MessageHeader::Schema => {
                    let schema = message.header_as_schema().ok_or_else(Self::invalid)?;
                    SchemaBudget::validate(schema, limits)?;
                    let schema =
                        std::panic::catch_unwind(|| arrow_ipc::convert::fb_to_schema(schema))
                            .map_err(|_| Self::invalid())?;
                    Model::schema(&schema)?;
                }
                MessageHeader::RecordBatch => {
                    let batch = message.header_as_record_batch().ok_or_else(Self::invalid)?;
                    frames.record(batch, limits)?;
                }
                _ => {
                    return Err(Error::contract(
                        ErrorCode::Incompatible,
                        "arrow message type",
                    ))
                }
            }
        }
        Ok(())
    }

    pub(super) fn decoding_bytes(bytes: &'a [u8], limits: Limits) -> Result<usize> {
        let mut frames = Self {
            bytes,
            rows: 0,
            batches: 0,
        };
        let mut buffers = DecodeBuffers::default();
        buffers.add_aligned(bytes.len())?;
        while let Some((message, body, metadata)) = frames.next()? {
            // StreamDecoder can copy the final message into its scratch buffer.
            buffers.add_aligned(metadata)?;
            match message.header_type() {
                MessageHeader::Schema => {
                    let schema = message.header_as_schema().ok_or_else(Self::invalid)?;
                    let fields = SchemaBudget::validate(schema, limits)?;
                    // An empty variable-size field has one offset buffer.
                    buffers.add(fields.checked_mul(64).ok_or_else(DecodeBuffers::limit)?)?;
                }
                MessageHeader::RecordBatch => {
                    let batch = message.header_as_record_batch().ok_or_else(Self::invalid)?;
                    frames.record(batch, limits)?;
                    for buffer in batch.buffers().ok_or_else(Self::invalid)? {
                        let offset =
                            usize::try_from(buffer.offset()).map_err(|_| Self::invalid())?;
                        let length =
                            usize::try_from(buffer.length()).map_err(|_| Self::invalid())?;
                        offset
                            .checked_add(length)
                            .filter(|end| *end <= body.len())
                            .ok_or_else(Self::invalid)?;
                        // The native reader can copy an unaligned IPC buffer.
                        buffers.add_aligned(length)?;
                        buffers.add_owned(length)?;
                    }
                    for node in batch.nodes().ok_or_else(Self::invalid)? {
                        let length = usize::try_from(node.length()).map_err(|_| Self::invalid())?;
                        // A nullable parent can require child validity storage.
                        buffers.add_aligned(length.div_ceil(8))?;
                    }
                }
                _ => {
                    return Err(Error::contract(
                        ErrorCode::Incompatible,
                        "arrow message type",
                    ))
                }
            }
        }
        Ok(buffers.bytes)
    }

    fn next(&mut self) -> Result<Option<(Message<'a>, &'a [u8], usize)>> {
        if self.bytes.is_empty() {
            return Ok(None);
        }
        let mut length = self.length()?;
        if length == u32::MAX {
            length = self.length()?;
        }
        if length == 0 {
            if !self.bytes.is_empty() {
                return Err(Self::invalid());
            }
            return Ok(None);
        }
        let metadata = self.take(length as usize)?;
        let message = arrow_ipc::root_as_message(metadata).map_err(|_| Self::invalid())?;
        let body =
            self.take(usize::try_from(message.bodyLength()).map_err(|_| Self::invalid())?)?;
        Ok(Some((message, body, metadata.len())))
    }

    fn uncompressed(batch: arrow_ipc::RecordBatch<'_>) -> Result<()> {
        if batch.compression().is_some() {
            return Err(Error::contract(
                ErrorCode::Incompatible,
                "compressed arrow stream",
            ));
        }
        Ok(())
    }

    fn record(&mut self, batch: arrow_ipc::RecordBatch<'_>, limits: Limits) -> Result<()> {
        Self::uncompressed(batch)?;
        self.rows = self
            .rows
            .checked_add(u64::try_from(batch.length()).map_err(|_| Self::invalid())?)
            .ok_or_else(|| Error::contract(ErrorCode::Limit, "stream rows"))?;
        self.batches = self.batches.saturating_add(1);
        if self.rows > limits.max_rows || self.batches > limits.max_batches {
            return Err(Error::contract(ErrorCode::Limit, "stream rows or batches"));
        }
        Ok(())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let value = self.bytes.get(..length).ok_or_else(Self::invalid)?;
        self.bytes = &self.bytes[length..];
        Ok(value)
    }

    fn length(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Self::invalid())?,
        ))
    }

    fn invalid() -> Error {
        Error::contract(ErrorCode::Invalid, "arrow framing")
    }
}

struct SchemaBudget {
    fields: usize,
    bytes: u64,
    limit: u64,
}

impl SchemaBudget {
    fn validate(schema: arrow_ipc::Schema<'_>, limits: Limits) -> Result<usize> {
        let mut budget = Self {
            fields: 0,
            bytes: 0,
            limit: limits.max_bytes,
        };
        budget.add(std::mem::size_of::<crate::Schema>())?;
        budget.metadata(schema.custom_metadata().into_iter().flatten())?;
        for field in schema.fields().into_iter().flatten() {
            budget.field(field, 0)?;
        }
        Ok(budget.fields)
    }

    fn field(&mut self, field: arrow_ipc::Field<'_>, depth: usize) -> Result<()> {
        self.fields = self.fields.saturating_add(1);
        if depth > 16 || self.fields > 1024 {
            return Err(Error::contract(ErrorCode::Limit, "schema depth or fields"));
        }
        if field.dictionary().is_some() {
            return Err(Error::contract(
                ErrorCode::Incompatible,
                "dictionary arrow stream",
            ));
        }
        self.add(std::mem::size_of::<crate::Field>())?;
        self.add(field.name().map_or(0, str::len))?;
        self.metadata(field.custom_metadata().into_iter().flatten())?;
        for child in field.children().into_iter().flatten() {
            self.field(child, depth + 1)?;
        }
        Ok(())
    }

    fn metadata<'a>(
        &mut self,
        metadata: impl IntoIterator<Item = arrow_ipc::KeyValue<'a>>,
    ) -> Result<()> {
        for entry in metadata {
            self.add(std::mem::size_of::<(String, String)>())?;
            self.add(entry.key().map_or(0, str::len))?;
            self.add(entry.value().map_or(0, str::len))?;
        }
        Ok(())
    }

    fn add(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self.bytes.saturating_add(bytes as u64);
        if self.bytes > self.limit {
            return Err(Error::contract(ErrorCode::Limit, "arrow schema bytes"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct DecodeBuffers {
    bytes: usize,
}

impl DecodeBuffers {
    fn add(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(Self::limit)?;
        Ok(())
    }

    fn add_aligned(&mut self, bytes: usize) -> Result<()> {
        self.add(Self::aligned(bytes)?)
    }

    fn add_owned(&mut self, bytes: usize) -> Result<()> {
        // MutableArrayData starts offsets with four bytes in a 64-byte buffer.
        let required = bytes.checked_add(4).ok_or_else(Self::limit)?;
        let capacity = if required <= 64 {
            64
        } else {
            Self::aligned(required)?.max(128)
        };
        // This also bounds a primitive buffer copied once from zero capacity.
        self.add(capacity)
    }

    fn aligned(bytes: usize) -> Result<usize> {
        bytes
            .checked_add(63)
            .map(|bytes| bytes & !63)
            .ok_or_else(Self::limit)
    }

    fn limit() -> Error {
        Error::contract(ErrorCode::Limit, "arrow decode buffers")
    }
}
