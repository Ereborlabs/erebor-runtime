use super::*;
use sha2::{Digest, Sha256};
impl FindingV1 {
    pub fn identity(
        package: &str,
        record: &crate::source::DiscoveryRecordIdV1,
        subject: &GraphSubjectKeyV1,
    ) -> sdk::Result<String> {
        let mut digest = Sha256::new();
        (package, record, subject)
            .serialize(&mut rmp_serde::Serializer::new(&mut digest))
            .map_err(|_| super::invalid("graph finding identity"))?;
        Ok(format!("{:x}", digest.finalize()))
    }
}
