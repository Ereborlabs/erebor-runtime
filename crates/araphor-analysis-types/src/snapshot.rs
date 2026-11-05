use crate::GraphSnapshotV1;

impl GraphSnapshotV1 {
    pub fn encode_native(&self) -> crate::Result<Vec<u8>> {
        use snafu::ResultExt as _;
        rmp_serde::to_vec_named(self).context(crate::error::EncodingSnafu)
    }

    pub fn decode_native(bytes: &[u8]) -> crate::Result<Self> {
        use serde::Deserialize as _;
        use snafu::ResultExt as _;

        let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
        let value = Self::deserialize(&mut decoder).context(crate::error::DecodingSnafu)?;
        if decoder.position() != bytes.len() as u64 {
            return crate::error::InvalidSnafu {
                field: "graph snapshot trailing bytes",
            }
            .fail();
        }
        value.validate()?;
        Ok(value)
    }

    pub fn retained_input_expired(&self) -> bool {
        self.missing_ranges
            .contains(&(self.first_cursor, self.last_cursor))
            && self.findings.iter().all(|finding| {
                finding
                    .limits
                    .iter()
                    .any(|limit| limit == "RETAINED_INPUT_EXPIRED")
            })
    }
}
