use super::*;
use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, QueryAuthorization, QueryGrant,
    QueryLimits, QueryOwner, QueryPlan, QuerySql,
};
use std::sync::Arc;
use tokio::sync::watch;

struct QueryPermit {
    grant: QueryGrant,
    until: u64,
    changes: watch::Sender<u64>,
}

impl QueryAuthorization for QueryPermit {
    fn check(&self, grant: &QueryGrant) -> araphor_data::Result<()> {
        let expected = &self.grant;
        let selection = &grant.selection;
        let scope = &expected.selection;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_nanos()).ok());
        if now.is_none_or(|now| now >= self.until)
            || *self.changes.borrow() != expected.revision
            || grant.principal != expected.principal
            || grant.revision != expected.revision
            || selection.tenant_id != scope.tenant_id
            || selection.sources != scope.sources
            || selection.contexts != scope.contexts
            || selection.results != scope.results
            || selection.received_from != scope.received_from
            || selection.received_until != scope.received_until
        {
            return Err(araphor_data::Error::QueryDenied {
                location: snafu::Location::default(),
            });
        }
        Ok(())
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn expires_ns(&self) -> Option<u64> {
        Some(self.until)
    }
}

impl ObservabilityQualification {
    pub(super) fn trace_inputs(
        fact: mithril_control::WorkloadTargetFactV1,
        now: u64,
    ) -> ProofResult<(
        mithril_control::TraceRequestV1,
        mithril_control::TraceExecutionGrantV1,
    )> {
        use mithril_control::{
            DiscoveryDigestV1, TraceExecutionGrantV1, TraceRecipeV1, TraceRequestV1, TraceTargetV1,
        };

        let tenant = *uuid::Uuid::parse_str(crate::control_fixture::OUTAGE_TENANT_ID)?.as_bytes();
        let target = TraceTargetV1 {
            fact_digest: DiscoveryDigestV1::of(&fact)?,
            fact,
            runtime_container_id: "1".repeat(64),
            node_boot_id: [7; 16],
            cgroup_id: 17,
            binding_id: [3; 16],
            binding_nonce: [4; 16],
            root_cgroup_live_interval_id: [5; 16],
            container_generation: 1,
            label_epoch: 1,
        };
        let grant = TraceExecutionGrantV1 {
            tenant_id: tenant,
            grant_id: [7; 16],
            principal: "qualification".into(),
            namespace_uids: [target.fact.namespace_uid.clone()].into(),
            node_ids: ["node-a".into()].into(),
            recipe_digests: [TraceRecipeV1::FailedOpens.digest()?].into(),
            host_diagnostic: false,
            valid_until_unix_ns: now
                .checked_add(120_000_000_000)
                .ok_or("fixture grant overflows")?,
        };
        let request = TraceRequestV1 {
            tenant_id: tenant,
            request_id: [6; 16],
            source: TraceRecipeV1::FailedOpens.manifest()?.source,
            targets: vec![target],
            unresolved: Vec::new(),
            collection_seconds: 30,
        };
        Ok((request, grant))
    }

    pub fn query_upload(&self) -> ProofResult<()> {
        use crate::control_fixture::OutagePolicyFixture;

        fs::create_dir(&self.output)?;
        let fixture = OutagePolicyFixture::new(mithril_control::ControlStore::open(
            self.output.join("inventory"),
        )?);
        let fact = fixture
            .inventory(&fixture.resource(1)?)?
            .into_iter()
            .next()
            .ok_or("missing query case workload fact")?;
        drop(fixture);
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
        )?;
        let (request, grant) = Self::trace_inputs(fact, now)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        let mut record = runtime.block_on(self.owned_node(&key, request, grant, true))?;
        record["schema_version"] = serde_json::json!(1);
        record["case"] = serde_json::json!("query-upload");
        record["discovery_enabled"] = serde_json::json!(false);
        record["proof_boundary"] = serde_json::json!("Production QueryOwner runs admitted SQL in process through its asynchronous API. A catalog value causes a native conversion error. The same owner then completes a valid query. Production Node capture emits a new frame after the query error. Control commits that frame before its mTLS ACK. Cancellation, Node spool reopen, Control reopen, retained output and ACK replay use production owners. The backend and binding inputs are external fixtures. This case does not prove native interruption, process-crash isolation, BPF cleanup, enforcement or performance.");
        self.write("result.json", &record)
    }

    pub(super) async fn fail_query(
        data: Arc<AnalysisStore>,
        tenant: [u8; 16],
        now: u64,
        until: u64,
    ) -> ProofResult<serde_json::Value> {
        let grant = QueryGrant {
            principal: "query-qualification".into(),
            revision: 1,
            selection: AnalysisSelectionV1::new(tenant, Vec::new()),
        };
        let sql = QuerySql::admit(
            "SELECT CAST(relation AS BIGINT) AS value FROM catalog LIMIT 1",
            Vec::new(),
            false,
        )?;
        let plan = QueryPlan::client(grant.clone(), sql)?;
        let (changes, _) = watch::channel(grant.revision);
        let authority: Arc<dyn QueryAuthorization> = Arc::new(QueryPermit {
            grant: grant.clone(),
            until,
            changes,
        });
        let owner = Arc::new(QueryOwner::new(data, QueryLimits::default())?);
        let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(5))?);
        let (operation, error) = match owner
            .query_client(plan, authority.clone(), now, control)
            .await
        {
            Err(araphor_data::Error::AnalysisDatabase {
                operation: operation @ ("execute query evaluation" | "read query evaluation"),
                source,
                ..
            }) => (operation, source.to_string()),
            result => {
                return Err(
                    format!("native query returned an unexpected result: {result:?}").into(),
                )
            }
        };
        let sql = QuerySql::admit("SELECT relation FROM catalog LIMIT 1", Vec::new(), false)?;
        let plan = QueryPlan::client(grant, sql)?;
        let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(5))?);
        let result = owner.query_client(plan, authority, now, control).await?;
        if result.rows.len() != 1 || result.columns != ["relation"] || result.limited {
            return Err("the query owner did not recover after the native error".into());
        }
        Ok(serde_json::json!({
            "execution": "in-process", "query_failure": "AnalysisDatabase",
            "query_operation": operation, "query_error": error,
            "query_recovered": true, "catalog_rows": result.rows.len(),
            "native_interruption_proved": false, "process_isolation_proved": false,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_query_upload() -> ProofResult<()> {
        let directory = tempfile::tempdir()?;
        let owner = ObservabilityQualification::new(directory.path().join("query"));
        owner.query_upload()?;
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(owner.output.join("result.json"))?)?;
        assert_eq!(record["case"], "query-upload");
        assert_eq!(record["result"], "PASS");
        assert_eq!(record["physical"], false);
        assert_eq!(record["performance_claim"], false);
        assert_eq!(record["discovery_index_present"], false);
        assert_eq!(record["discovery_enabled"], false);
        let cases = record["cases"].as_array().ok_or("missing query case")?;
        assert_eq!(cases.len(), 1);
        let case = &cases[0];
        assert_eq!(case["initial_acknowledgement"]["last_sequence"], 2);
        assert!(case["initial_acknowledgement"]["terminal"].is_null());
        let failure = &case["query_failure"];
        for field in [
            "query_recovered",
            "capture_active",
            "prefix_unchanged",
            "writer_ready",
        ] {
            assert_eq!(failure[field], true, "{field}");
        }
        assert_eq!(failure["execution"], "in-process");
        assert_eq!(failure["query_failure"], "AnalysisDatabase");
        assert!(matches!(
            failure["query_operation"].as_str(),
            Some("execute query evaluation" | "read query evaluation")
        ));
        assert_eq!(failure["catalog_rows"], 1);
        assert_eq!(failure["native_interruption_proved"], false);
        assert_eq!(failure["process_isolation_proved"], false);
        assert_eq!(failure["prefix_sequence"], 2);
        assert_eq!(failure["post_failure_sequence"], 3);
        assert_eq!(failure["post_failure_ack"], failure["post_failure_replay"]);
        assert!(failure["post_failure_revision"].as_u64() > failure["prefix_revision"].as_u64());
        assert_eq!(case["launch_count"], 1);
        assert_eq!(case["process_reaped"], true);
        assert_eq!(case["terminal_reopen"], true);
        assert_eq!(case["control_reopen"], true);
        assert_eq!(case["acknowledgement"], case["replay_ack"]);
        assert_eq!(case["acknowledgement"]["last_sequence"], 3);
        assert_eq!(case["acknowledgement"]["terminal"]["reason"], "Cancelled");
        assert_eq!(case["acknowledgement"]["terminal"]["cleanup"], "Unknown");
        assert_eq!(
            case["acknowledgement"]["terminal"]["output_incomplete"],
            true
        );
        assert!(case["acknowledgement"]["terminal"]["kernel_lost_events"].is_null());
        assert_eq!(
            case["retained"][0]["frames"].as_array().map(Vec::len),
            Some(3)
        );
        assert_eq!(
            case["retained"][0]["frames"][2]["bytes"],
            serde_json::json!(b"output after query error\n")
        );
        Ok(())
    }
}
