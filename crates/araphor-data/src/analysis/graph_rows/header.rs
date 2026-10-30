use super::*;

pub(in crate::analysis) struct GraphHeader {
    pub snapshot: GraphSnapshotV1,
    pub finding_value_ids: BTreeMap<String, u64>,
    pub subject_count: usize,
    pub edge_count: usize,
    pub finding_count: usize,
    pub branch_count: usize,
    pub branches_loaded: bool,
    pub complete: bool,
    pub derive_branches: bool,
    pub evidence_count: usize,
    pub position_count: usize,
    pub fact_count: usize,
    pub notice: (u64, u64),
    pub expired: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeaderMetadata {
    metadata: GraphManifest,
    evidence_count: usize,
    position_count: usize,
    branch_count: usize,
    fact_count: usize,
}

impl GraphHeader {
    pub(super) fn encode(
        metadata: &GraphManifest,
        counts: (usize, usize, usize, usize),
    ) -> Result<Vec<u8>> {
        let mut stripped = metadata.clone();
        stripped.input_manifest.evidence.clear();
        stripped.input_positions.clear();
        stripped.facts.clear();
        let payload = GraphRows::encode_value(&HeaderMetadata {
            metadata: stripped,
            evidence_count: metadata.input_manifest.evidence.len(),
            position_count: metadata.input_positions.len(),
            branch_count: counts.3,
            fact_count: metadata.facts.len(),
        })?;
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(5)
            .and_then(|e| e.u32(2))
            .and_then(|e| e.u64(counts.0 as u64))
            .and_then(|e| e.u64(counts.1 as u64))
            .and_then(|e| e.u64(counts.2 as u64))
            .and_then(|e| e.bytes(&payload))
            .map_err(|_| GraphRows::invalid("graph header format"))?;
        Ok(encoder.into_writer())
    }

    pub(in crate::analysis) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let decoded = (|| {
            if decoder.array().ok()? != Some(5) || decoder.u32().ok()? != 2 {
                return None;
            }
            Some((
                usize::try_from(decoder.u64().ok()?).ok()?,
                usize::try_from(decoder.u64().ok()?).ok()?,
                usize::try_from(decoder.u64().ok()?).ok()?,
                decoder.bytes().ok()?,
            ))
        })()
        .ok_or_else(|| GraphRows::invalid("graph header format"))?;
        if decoder.position() != bytes.len() {
            return Err(GraphRows::invalid("graph header format"));
        }
        let payload: HeaderMetadata = GraphRows::decode_value(decoded.3)
            .map_err(|_| GraphRows::invalid("graph header format"))?;
        payload.metadata.validate()?;
        if !payload.metadata.input_manifest.evidence.is_empty()
            || !payload.metadata.input_positions.is_empty()
            || !payload.metadata.facts.is_empty()
        {
            return Err(GraphRows::invalid("graph header native fields"));
        }
        let notice = (
            payload.metadata.context_notice_revision,
            payload
                .metadata
                .input_manifest
                .coverage
                .iter()
                .map(|coverage| coverage.report_revision)
                .max()
                .unwrap_or(0),
        );
        Ok(Self {
            snapshot: payload.metadata.snapshot(),
            finding_value_ids: BTreeMap::new(),
            subject_count: decoded.0,
            edge_count: decoded.1,
            finding_count: decoded.2,
            branch_count: payload.branch_count,
            branches_loaded: false,
            complete: false,
            derive_branches: false,
            evidence_count: payload.evidence_count,
            position_count: payload.position_count,
            fact_count: payload.fact_count,
            notice,
            expired: false,
        })
    }

    pub(in crate::analysis) fn check_index(
        &self,
        tenant: [u8; 16],
        stream: &[u8],
        method: u64,
        first: u64,
    ) -> Result<()> {
        if self.snapshot.scope.identity.tenant_id != tenant
            || self.snapshot.scope.identity.key() != stream
            || self.snapshot.scope.method_version != method
            || self.snapshot.first_cursor != first
        {
            return Err(GraphRows::invalid("graph header index"));
        }
        Ok(())
    }

    pub(in crate::analysis) fn check_shape(
        &self,
        subjects: u64,
        edges: u64,
        findings: u64,
    ) -> Result<()> {
        if (self.subject_count, self.edge_count, self.finding_count)
            != (subjects as usize, edges as usize, findings as usize)
        {
            return Err(GraphRows::invalid("graph row counts"));
        }
        Ok(())
    }
}

impl GraphRows {
    #[cfg(test)]
    pub(in crate::analysis) fn encode(graph: &GraphSnapshotV1) -> Result<Vec<u8>> {
        graph.validate()?;
        GraphHeader::encode(
            &GraphManifest::from_snapshot(graph),
            (
                graph.graph.subjects.len(),
                graph.graph.edges.len(),
                graph.findings.len(),
                graph.graph.branches.len(),
            ),
        )
    }
}
