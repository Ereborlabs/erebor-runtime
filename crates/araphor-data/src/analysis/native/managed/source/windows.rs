use std::ops::Bound::{Excluded, Included};

use super::*;

impl NativeStore {
    pub fn graph_window_headers(
        &self,
        source: &EvidenceIntakeIdentityV1,
        after: Option<u64>,
    ) -> Result<Vec<(String, crate::GraphSnapshotV1, u64)>> {
        if !source.valid() {
            return Err(Code::Invalid.error("Graph source"));
        }
        let view = self.view()?;
        let Some(id) = Records::find(&SourceRecord::identity(source)?, |key| {
            Records::read(key, &view.snapshot)
        })?
        else {
            return Ok(Vec::new());
        };
        let prefix = SourceRecord::key(SourceRecord::WINDOW, &[id]);
        let first = after.map_or_else(
            || prefix.clone(),
            |after| SourceRecord::key(&prefix, &[after]),
        );
        let end = SourceRecord::key(&prefix, &[u64::MAX]);
        let mut headers = Vec::new();
        for entry in view
            .snapshot
            .range::<Vec<u8>, _>((Excluded(first), Included(end)))
            .take(32)
        {
            let (key, value) = entry.context(crate::NativeStorageSnafu {
                operation: "read source window heads",
            })?;
            if key.len() != prefix.len() + 8 {
                return Err(Code::Invalid.error("source window key"));
            }
            let (header, stored) = SourceRecord::publication(
                Self::number(&value)?,
                view.metadata_revision,
                |key| Records::read(key, &view.snapshot),
                &mut |_| Ok(()),
            )?;
            let (_, _, owner) = view.result_owner(
                source.tenant_id,
                &stored.id,
                &AnalysisReadControl::default(),
                &mut |_| Ok(()),
            )?;
            if !matches!(&owner.instance().spec.destination,ManagedDestination::Graph { source: actual, .. } if actual == source)
            {
                return Err(Code::Invalid.error("source window owner"));
            }
            let manifest = header.manifest(&stored, source)?;
            if manifest.first_cursor != Self::number(&key[prefix.len()..])? {
                return Err(Code::Invalid.error("source window start"));
            }
            headers.push((stored.id, manifest.snapshot(), stored.revision));
        }
        Ok(headers)
    }

    pub fn graph_source(
        &self,
        tenant: [u8; 16],
        name: &str,
    ) -> Result<Option<EvidenceIntakeIdentityV1>> {
        if tenant == [0; 16] || name.is_empty() || name.chars().any(char::is_control) {
            return Err(Code::Invalid.error("Graph result reference"));
        }
        let view = self.view()?;
        let Some(id) = Records::find(&StoredResult::identity(tenant, name)?, |key| {
            Records::read(key, &view.snapshot)
        })?
        else {
            return Ok(None);
        };
        if Records::read(
            &SourceRecord::key(SourceRecord::PREFIX, &[id]),
            &view.snapshot,
        )?
        .is_none()
        {
            return Ok(None);
        }
        let (_, stored) = SourceRecord::publication(
            id,
            view.metadata_revision,
            |key| Records::read(key, &view.snapshot),
            &mut |_| Ok(()),
        )?;
        if stored.tenant != tenant {
            return Ok(None);
        }
        let (_, _, owner) =
            view.result_owner(tenant, name, &AnalysisReadControl::default(), &mut |_| {
                Ok(())
            })?;
        match &owner.instance().spec.destination {
            ManagedDestination::Graph { source, .. } => Ok(Some(source.clone())),
            _ => Err(Code::Invalid.error("source result destination")),
        }
    }
}
