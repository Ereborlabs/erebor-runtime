use super::*;

impl Graph<'_> {
    pub(super) fn require(valid: bool, field: &'static str) -> Result<()> {
        araphor_data::EvidenceBasis::require(valid, field)
    }

    fn evidence(&self) -> araphor_data::EvidenceBasis<'_> {
        araphor_data::EvidenceBasis::new(
            &self.input,
            &self.observations,
            &self.revision,
            &self.facts,
            self.restricted,
        )
    }

    pub(super) fn validate_subject(&self, row: &algorithm::Subject) -> Result<()> {
        self.evidence().validate_subject(row)
    }

    pub(super) fn validate_edge(
        &self,
        row: &algorithm::Relationship,
        subjects: &[algorithm::Subject],
    ) -> Result<()> {
        self.evidence().validate_edge(row, subjects)
    }

    pub(super) fn validate_finding(
        &self,
        record: u32,
        context: Option<u32>,
        finding: &FindingV1,
    ) -> Result<()> {
        self.evidence().validate_finding(record, context, finding)
    }
}
