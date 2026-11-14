use super::*;

#[derive(Clone, Deserialize, Serialize)]
pub enum Payload {
    Frames {
        bytes: serde_bytes::ByteBuf,
        ends: Vec<usize>,
        intake: u64,
    },
    Packed(serde_bytes::ByteBuf),
    Columns(Vec<(usize, serde_bytes::ByteBuf)>),
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Packet {
    pub key: serde_bytes::ByteBuf,
    pub header: Header,
    pub payload: Payload,
}

impl Packet {
    pub fn frames(batch: ValidatedEvidenceBatchV1) -> Self {
        Self {
            key: Table::batch_key(batch.first_cursor, batch.cpu_id).into(),
            header: Header {
                first: batch.first_cursor,
                rows: batch.frame_ends.len(),
                cpu: Some(batch.cpu_id),
            },
            payload: Payload::Frames {
                bytes: batch.framed_records.to_vec().into(),
                ends: batch.frame_ends,
                intake: batch.intake_utc_ns,
            },
        }
    }

    pub fn arrow(
        key: Vec<u8>,
        header: Header,
        batch: &RecordBatch,
        layout: Layout,
    ) -> Result<Self> {
        let indices = (0..batch.num_columns())
            .filter(|&index| index != 0 || header.cpu.is_none())
            .collect::<Vec<_>>();
        let payload = match layout {
            Layout::Packed => Payload::Packed(Table::encode(&batch.project(&indices)?)?.into()),
            Layout::Columns => Payload::Columns(
                indices
                    .into_iter()
                    .map(|index| Ok((index, Table::encode(&batch.project(&[index])?)?.into())))
                    .collect::<Result<_>>()?,
            ),
            Layout::Frames => return Err("sender Arrow requires an Arrow layout".into()),
        };
        Ok(Self {
            key: key.into(),
            header,
            payload,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(rmp_serde::to_vec(self)?)
    }

    fn validate(&self, table: &Table) -> Result<()> {
        if self.header.cpu.is_some()
            && !table.schema.fields().first().is_some_and(|field| {
                field.name() == "cpu_id" && field.data_type() == &DataType::UInt32
            })
        {
            return Err("CPU constant has no matching schema column".into());
        }
        let expected = (0..table.schema.fields().len())
            .filter(|&index| index != 0 || self.header.cpu.is_none())
            .collect::<Vec<_>>();
        if self.header.first == 0
            || self.header.rows == 0
            || self
                .header
                .first
                .checked_add(self.header.rows as u64 - 1)
                .is_none()
        {
            return Err("invalid wire row range".into());
        }
        let source = self.header.cpu.unwrap_or(u32::from(
            *self.key.get(8).ok_or("invalid fixture source key")?,
        ));
        if self.key.as_ref() != Table::batch_key(self.header.first, source) {
            return Err("wire source key mismatch".into());
        }
        let batches = match (&self.payload, table.layout) {
            (Payload::Packed(bytes), Layout::Packed) => {
                let batch = Table::decode(bytes)?;
                if batch.schema().as_ref() != &table.schema.project(&expected)? {
                    return Err("wire packed schema mismatch".into());
                }
                vec![batch]
            }
            (Payload::Columns(values), Layout::Columns) => {
                let actual = values
                    .iter()
                    .map(|(index, _)| *index)
                    .collect::<std::collections::BTreeSet<_>>();
                if actual.len() != values.len() || actual != expected.iter().copied().collect() {
                    return Err("wire column set mismatch".into());
                }
                values
                    .iter()
                    .map(|(index, bytes)| {
                        let batch = Table::decode(bytes)?;
                        if batch.schema().as_ref() != &table.schema.project(&[*index])? {
                            return Err("wire column schema mismatch".into());
                        }
                        Ok(batch)
                    })
                    .collect::<Result<_>>()?
            }
            _ => return Err("wire payload layout mismatch".into()),
        };
        for batch in batches {
            if batch.num_rows() != self.header.rows {
                return Err("wire row count mismatch".into());
            }
            for (field, array) in batch.schema().fields().iter().zip(batch.columns()) {
                if !field.is_nullable() && array.null_count() != 0 {
                    return Err("null in required wire column".into());
                }
            }
            if let Some(array) = batch.column_by_name("source_cursor") {
                let cursors = array
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .ok_or("wire cursor type mismatch")?;
                if cursors
                    .values()
                    .iter()
                    .enumerate()
                    .any(|(row, &cursor)| cursor != self.header.first + row as u64)
                {
                    return Err("wire cursor range mismatch".into());
                }
            }
        }
        Ok(())
    }
}

impl Table {
    pub fn receive(&self, wire: &[u8]) -> Result<fjall::Commit> {
        let packet: Packet = rmp_serde::from_slice(wire)?;
        if let Payload::Frames {
            bytes,
            ends,
            intake,
        } = packet.payload
        {
            if ends.len() != packet.header.rows
                || ends.last().copied() != Some(bytes.len())
                || ends.windows(2).any(|ends| ends[0] >= ends[1])
                || ends.first() == Some(&0)
            {
                return Err("invalid wire frame boundaries".into());
            }
            let last = packet
                .header
                .first
                .checked_add(
                    packet
                        .header
                        .rows
                        .checked_sub(1)
                        .ok_or("empty wire frames")? as u64,
                )
                .ok_or("wire frame range overflow")?;
            let batch = ValidatedEvidenceBatchV1 {
                cpu_id: packet.header.cpu.ok_or("wire frame CPU missing")?,
                first_cursor: packet.header.first,
                last_cursor: last,
                intake_utc_ns: intake,
                framed_records: bytes.into_vec().into(),
                frame_ends: ends,
            };
            if packet.key.as_ref() != Self::batch_key(batch.first_cursor, batch.cpu_id) {
                return Err("wire source key mismatch".into());
            }
            return self.append(&batch);
        }
        packet.validate(self)?;
        let mut tx = self.database.write_tx();
        tx.insert(
            &self.events,
            Self::key(b'H', None, &packet.key),
            rmp_serde::to_vec(&packet.header)?,
        );
        match packet.payload {
            Payload::Packed(bytes) => tx.insert(
                &self.events,
                Self::key(b'P', None, &packet.key),
                bytes.as_ref(),
            ),
            Payload::Columns(values) => {
                for (index, bytes) in values {
                    tx.insert(
                        &self.events,
                        Self::key(b'C', Some(index), &packet.key),
                        bytes.as_ref(),
                    );
                }
            }
            Payload::Frames { .. } => unreachable!(),
        }
        tx.commit_receipt()?
            .ok_or_else(|| "missing wire input commit".into())
    }
}
