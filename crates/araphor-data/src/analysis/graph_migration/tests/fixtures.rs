use super::*;

impl AnalysisStore {
    pub(super) fn legacy_graph_fixture(&self) -> Result<()> {
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin legacy graph fixture",
            })?;
        let mut after = String::new();
        let mut bodies = Vec::new();
        while let Some((id, tenant, _)) = Self::next_graph(&transaction, &after, false)? {
            let tenant = tenant.try_into().map_err(|_| {
                crate::GraphInvalidSnafu {
                    field: "fixture tenant",
                }
                .build()
            })?;
            let header = GraphRows::read_header(&transaction, tenant, &id)?.ok_or_else(|| {
                crate::GraphInvalidSnafu {
                    field: "fixture graph header",
                }
                .build()
            })?;
            let snapshot = GraphRows::read(&transaction, &id, &header)?;
            bodies.push((
                id.clone(),
                GraphRows::read_body(&transaction, &id, &header, &snapshot)?,
            ));
            after = id;
        }
        transaction.execute_batch(
            "DROP TABLE graph_subjects; DROP TABLE graph_relationships; DROP TABLE graph_findings;
            ALTER TABLE analysis_results DROP COLUMN graph_encoding;
            DELETE FROM relation_revisions WHERE relation_name IN ('graph_subjects', 'graph_relationships', 'graph_findings');
            UPDATE store_meta SET schema_version = 17; DELETE FROM tenant_usage;"
        ).context(AnalysisDatabaseSnafu { operation: "set legacy graph fixture schema" })?;
        for (id, body) in bodies {
            transaction
                .execute(
                    "UPDATE analysis_results SET body = ? WHERE result_id = ?",
                    params![body, id],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "write legacy graph fixture",
                })?;
        }
        transaction
            .execute_batch(&format!(
                "INSERT INTO tenant_usage {}",
                Self::usage_projection(false)
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "set legacy graph fixture usage",
            })?;
        Self::validate_tables(&transaction)?;
        Self::validate_state(&transaction, &self.root)?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit legacy graph fixture",
        })
    }
}

struct NoAuthority;

impl NotificationAuthorization for NoAuthority {
    fn check(&self, _grant: &NotificationGrantV1, _now: u64) -> Result<()> {
        crate::NotificationSnafu {
            code: NotificationErrorCodeV1::Denied,
            field: "fixture grant",
        }
        .fail()
    }
}

pub(super) struct MigrationFixture {
    pub(super) directory: tempfile::TempDir,
    pub(super) store: Arc<AnalysisStore>,
    pub(super) first: AnalysisResultCommitV1,
    pub(super) second: AnalysisResultCommitV1,
    pub(super) notification: AnalysisContextVersionV1,
}

impl MigrationFixture {
    pub(super) fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let CommitFixture {
            directory,
            owner,
            store,
            mut snapshot,
            request,
        } = CommitFixture::new()?;
        store.commit_graph(&request, true)?;
        let router = NotificationRouter::new(store.clone(), Arc::new(NoAuthority))?;
        assert_eq!(router.route(&owner, 11)?, 1);
        let notification = store
            .notification_states(
                request.scope.identity.tenant_id,
                crate::analysis::NotificationLookup::Finding(
                    &snapshot.findings[0].finding_id,
                    snapshot.findings[0].required_action.as_deref(),
                ),
            )?
            .remove(0);
        let state: NotificationObligationV1 = serde_json::from_slice(&notification.body)?;
        state.validate()?;
        assert_eq!(
            state
                .finding
                .as_ref()
                .ok_or("notification finding")?
                .result_id,
            request.result_id
        );
        let mut second = request.clone();
        second.result_id = "graph:native-storage-replacement".into();
        second.expected_cursor = 1;
        second.created_utc_ns = 12;
        snapshot.findings.clear();
        second.body = serde_json::to_vec(&snapshot)?;
        store.commit_graph(&second, false)?;
        assert!(owner
            .current_findings(request.scope.identity.tenant_id)?
            .is_empty());
        drop(router);
        drop(owner);
        Ok(Self {
            directory,
            store,
            first: request,
            second,
            notification,
        })
    }

    pub(super) fn check(&self, store: &AnalysisStore) -> TestResult {
        let tenant = self.first.scope.identity.tenant_id;
        assert_eq!(
            store.read_result(tenant, &self.first.result_id)?,
            Some(self.first.body.clone())
        );
        assert_eq!(
            store.read_result(tenant, &self.second.result_id)?,
            Some(self.second.body.clone())
        );
        assert_eq!(
            store.context_version(&self.notification.key)?,
            Some(self.notification.clone())
        );
        let state: NotificationObligationV1 = serde_json::from_slice(&self.notification.body)?;
        let reference = state.finding.ok_or("notification finding")?;
        let historical = store
            .graph_result(tenant, &reference.result_id)?
            .ok_or("historical graph")?;
        assert!(historical
            .findings
            .iter()
            .any(|finding| finding.finding_id == reference.finding_id));
        let progress = store
            .processor_result(&self.first.scope)?
            .ok_or("processor result")?;
        assert_eq!(progress.result_id, self.first.result_id);
        assert_eq!(progress.body, self.first.body);
        AnalysisStore::validate_usage(store.writer()?.get()?, &store.root)?;
        Ok(())
    }
}
