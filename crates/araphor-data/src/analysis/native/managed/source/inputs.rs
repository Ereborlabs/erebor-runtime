use super::*;

impl DataView {
    pub(in crate::analysis::native) fn input_source_key(key: &[u8]) -> bool {
        key.starts_with(SourceRecord::PREFIX) && key.len() == SourceRecord::PREFIX.len() + 8
    }

    pub(in crate::analysis::native) fn input_source(
        &self,
        key: &[u8],
        inputs: &crate::analysis::inputs::InputChanges,
        position: StorePositionV1,
    ) -> Result<()> {
        let id = NativeStore::number(&key[SourceRecord::PREFIX.len()..])?;
        let (header, result) = SourceRecord::publication(
            id,
            self.metadata_revision,
            |key| Records::read(key, &self.snapshot),
            &mut |_| Ok(()),
        )?;
        let (_, _, owner) = self.result_owner(
            result.tenant,
            &result.id,
            &AnalysisReadControl::default(),
            &mut |_| Ok(()),
        )?;
        let ManagedDestination::Graph { source, .. } = &owner.instance().spec.destination else {
            return Err(Code::Invalid.error("input source destination"));
        };
        if result.revision != position.commit_revision
            || header.captured.commit_revision != owner.captured_revision()
        {
            return Err(Code::Invalid.error("input source revision"));
        }
        let ResultBody::Selected(step) = &result.body else {
            return Err(Code::Invalid.error("input source kind"));
        };
        inputs.publish(
            position,
            crate::analysis::inputs::InputChange::Graph {
                tenant: result.tenant,
                result: &result.id,
                source: Some(source),
                witnesses: &step.witnesses,
            },
        );
        Ok(())
    }

    pub(in crate::analysis::native) fn source_progress(
        &self,
        scope: &crate::ProcessorScopeV1,
        reference: &PackageResultRefV1,
    ) -> Result<(SourceRecord, StoredResult)> {
        let (id, result, owner) = self.result_owner(
            scope.identity.tenant_id,
            &reference.result_id,
            &AnalysisReadControl::default(),
            &mut |_| Ok(()),
        )?;
        let header = SourceRecord::header(
            id,
            |key| Records::read(key, &self.snapshot),
            &mut |_| Ok(()),
        )?;
        if scope.processor_id != crate::GRAPH_PROCESSOR
            || scope.method_version != u64::from(crate::GRAPH_SCHEMA_VERSION)
            || result.revision != reference.commit_revision
            || !matches!(&owner.instance().spec.destination, ManagedDestination::Graph { source, .. } if *source == scope.identity)
            || owner.receipt().and_then(|receipt| receipt.graph.as_ref()) != Some(reference)
        {
            return Err(Code::Invalid.error("source processor head"));
        }
        Ok((header, result))
    }
}
