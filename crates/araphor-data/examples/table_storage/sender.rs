use super::*;
use araphor_data::{
    analysis::native::benchmark::columnar::{Header, Packet},
    ValidatedEvidenceBatchV1,
};

pub struct Sender {
    pub layout: Layout,
    pub arrow: bool,
}

impl Sender {
    pub fn encode(
        &self,
        template: &ValidatedEvidenceBatchV1,
        first_record: u64,
    ) -> Result<Vec<u8>> {
        let records = (first_record..first_record + template.frame_ends.len() as u64)
            .map(common::record)
            .collect::<Vec<_>>();
        let mut bytes = Vec::new();
        let mut ends = Vec::new();
        for record in &records {
            bytes.extend_from_slice(&Vec::<u8>::try_from(record)?);
            ends.push(bytes.len());
        }
        let batch = ValidatedEvidenceBatchV1 {
            cpu_id: template.cpu_id,
            first_cursor: template.first_cursor,
            last_cursor: template.last_cursor,
            intake_utc_ns: template.intake_utc_ns,
            framed_records: bytes.into(),
            frame_ends: ends,
        };
        let packet = if self.arrow {
            Packet::arrow(
                Table::batch_key(batch.first_cursor, batch.cpu_id),
                Header {
                    first: batch.first_cursor,
                    rows: records.len(),
                    cpu: Some(batch.cpu_id),
                },
                &Table::from_records(&batch, &records)?,
                self.layout,
            )?
        } else {
            Packet::frames(batch)
        };
        packet.encode()
    }
}
