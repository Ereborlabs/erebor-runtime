use std::collections::BTreeSet;

use snafu::ResultExt as _;

use super::*;
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, ContextSensitivityV1, EvidenceIntakeIdentityV1,
    GraphEncodingSnafu, InstalledAnalysis, InstalledRefV1,
};

impl GraphAndFindingOwner {
    pub fn installed_refs(
        &self,
        tenant: [u8; 16],
        result_id: &str,
    ) -> Result<Option<Vec<InstalledRefV1>>> {
        let Some(source) = self.store.graph_source(tenant, result_id)? else {
            return Ok(None);
        };
        let key = Self::package_key(&source, result_id);
        let Some(context) = self.store.context_version(&key)? else {
            return Ok(None);
        };
        InstalledRefV1::context_refs(&context)
    }

    pub(super) fn analysis_refs(
        execution: &InstalledAnalysis,
        snapshot: &GraphSnapshotV1,
    ) -> Result<Vec<InstalledRefV1>> {
        Ok(
            Self::compatible_refs(execution, snapshot.scope.identity.tenant_id)?
                .into_iter()
                .filter(|reference| {
                    snapshot
                        .packages
                        .iter()
                        .any(|package| package.package_id == reference.package_id)
                })
                .collect(),
        )
    }

    fn compatible_refs(
        execution: &InstalledAnalysis,
        tenant: [u8; 16],
    ) -> Result<Vec<InstalledRefV1>> {
        let descriptors = execution.descriptors(tenant)?;
        Ok(execution
            .refs()?
            .into_iter()
            .filter(|reference| {
                descriptors.iter().any(|package| {
                    package.id == reference.package_id
                        && package.exports.iter().any(|model| {
                            model.name == reference.export && Self::supports_analysis(model)
                        })
                })
            })
            .collect())
    }

    pub(super) fn installed_current(
        &self,
        result_id: &str,
        snapshot: &GraphSnapshotV1,
    ) -> Result<bool> {
        let tenant = snapshot.scope.identity.tenant_id;
        let execution = self.execution.snapshot(tenant)?;
        let references = Self::compatible_refs(&execution, tenant)?;
        if self.installed_refs(tenant, result_id)?.as_ref() != Some(&references) {
            return Ok(false);
        }
        execution.authorize(tenant, &Self::package_revisions(&references), || Ok(true))
    }

    pub(super) fn package_revisions(references: &[InstalledRefV1]) -> Vec<(String, String)> {
        references
            .iter()
            .map(|reference| (reference.package_id.clone(), reference.revision.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub(super) fn package_context(
        &self,
        snapshot: &GraphSnapshotV1,
        result_id: &str,
        refs: &[InstalledRefV1],
    ) -> Result<AnalysisContextRefV1> {
        let context = AnalysisContextVersionV1 {
            key: Self::package_key(&snapshot.scope.identity, result_id),
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: serde_json::to_vec(&serde_json::json!({"installed_packages": refs}))
                .context(GraphEncodingSnafu)?,
        };
        Ok(AnalysisContextRefV1 {
            key: context.key.clone(),
            commit_revision: self.store.commit_context(&context)?,
        })
    }

    pub(crate) fn package_key(
        source: &EvidenceIntakeIdentityV1,
        result_id: &str,
    ) -> AnalysisContextKeyV1 {
        AnalysisContextKeyV1 {
            tenant_id: source.tenant_id,
            owner_id: "graph-packages-v1".into(),
            entity_key: result_id.as_bytes().to_vec(),
            lifetime_key: source.key(),
            owner_revision: GRAPH_SCHEMA_VERSION as u64,
        }
    }
}
