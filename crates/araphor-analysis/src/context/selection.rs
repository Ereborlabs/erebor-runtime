use datafusion::catalog::TableProvider;
use datafusion::datasource::MemTable;
use futures_util::TryStreamExt as _;
use serde_arrow::schema::{SchemaLike as _, TracingOptions};

use super::*;

#[derive(Serialize, Deserialize)]
struct Scope {
    subject: String,
    method: String,
    from_ns: u64,
    cutoff_ns: u64,
    sensitivities: Vec<String>,
    evidence_limit: Option<u64>,
    fact_limit: Option<u64>,
    source_limit: Option<u64>,
    handle_limit: Option<u64>,
    conflict_limit: Option<u64>,
    document_limit: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct Evidence {
    id: DiscoveryRecordIdV1,
    subject: String,
    time: Option<u64>,
    payload: String,
}

impl Evidence {
    fn fields() -> Vec<Arc<sdk::Field>> {
        use sdk::DataType::*;
        vec![
            Arc::new(
                araphor_analysis_builtins::discovery::Record::port()
                    .schema
                    .field(0)
                    .clone(),
            ),
            Arc::new(sdk::Field::new("subject", Utf8, false)),
            Arc::new(sdk::Field::new("time", UInt64, true)),
            Arc::new(sdk::Field::new("payload", Utf8, false)),
        ]
    }
}

#[derive(Serialize, Deserialize)]
struct Fact {
    kind: u8,
    key: AnalysisContextKeyV1,
    subject: String,
    recorded: u64,
    valid_from: Option<u64>,
    valid_until: Option<u64>,
    sensitivity: String,
    payload: String,
}

impl Fact {
    fn fields() -> Vec<Arc<sdk::Field>> {
        use sdk::DataType::*;
        let key = AnalysisStore::table_schemas()["context_versions"].fields()[..5].to_vec();
        vec![
            Arc::new(sdk::Field::new("kind", UInt8, false)),
            Arc::new(sdk::Field::new("key", Struct(key.into()), false)),
            Arc::new(sdk::Field::new("subject", Utf8, false)),
            Arc::new(sdk::Field::new("recorded", UInt64, false)),
            Arc::new(sdk::Field::new("valid_from", UInt64, true)),
            Arc::new(sdk::Field::new("valid_until", UInt64, true)),
            Arc::new(sdk::Field::new("sensitivity", Utf8, false)),
            Arc::new(sdk::Field::new("payload", Utf8, false)),
        ]
    }
}

#[derive(Serialize, Deserialize)]
struct Document {
    id: String,
    revision: u64,
    imported: u64,
    subject: String,
    method: String,
    origin: String,
    kind: String,
    kind_rank: u8,
    sensitivity: String,
    valid_from: u64,
    valid_until: Option<u64>,
    text: String,
    version: String,
    payload: String,
}

#[derive(Deserialize)]
struct Count {
    key: String,
    count: u64,
}

#[derive(Deserialize)]
struct Conflict {
    kind: String,
    ids: Vec<String>,
}

#[derive(Deserialize)]
struct Selected {
    records: Vec<String>,
    facts: Vec<String>,
    documents: Vec<String>,
    available: u64,
    sources: Vec<Count>,
    omissions: Vec<Count>,
    conflicts: Vec<Conflict>,
    error: Option<String>,
}

impl Context {
    pub async fn select_context(
        &self,
        request: &DiscoveryContextRequestV1,
        control: &AnalysisReadControl,
    ) -> Result<DiscoveryContextViewV1> {
        control.check()?;
        Self::validate_request(request)?;
        let (plan, sources) = self
            .query
            .prepare(
                "SELECT named_struct('tenant_id',tenant_id,'owner_id',owner_id,\
                'entity_key',entity_key,'lifetime_key',lifetime_key,\
                'owner_revision',owner_revision) AS key, valid_from_utc_ns,\
                valid_until_utc_ns,CASE sensitivity WHEN 'public' THEN 'Public' \
                WHEN 'tenant' THEN 'Tenant' WHEN 'host_restricted' THEN 'HostRestricted' \
                ELSE sensitivity END AS sensitivity,body FROM context_versions \
                WHERE owner_id = 'discovery-context-v1'",
                Vec::new(),
            )
            .await?;
        let session = self.query.session(
            AnalysisSelectionV1::tenant(request.access.tenant_id),
            control,
            request.cutoff_utc_ns,
        )?;
        let (_, stream) = session
            .stream(&plan, &sources, araphor_query::execution::Read::Snapshot)
            .await?;
        let batches = stream.try_collect::<Vec<_>>().await.map_err(Self::sql)?;
        let mut revisions = Vec::new();
        for batch in &batches {
            let versions: Vec<AnalysisContextVersionV1> =
                serde_arrow::from_record_batch(batch).context(crate::error::ArrowSnafu)?;
            for version in versions {
                revisions.push(DiscoveryContextRevisionV1::try_from(&version)?);
            }
        }
        self.select_captured(request, &revisions, control).await
    }

    pub(super) async fn select_captured(
        &self,
        request: &DiscoveryContextRequestV1,
        revisions: &[DiscoveryContextRevisionV1],
        control: &AnalysisReadControl,
    ) -> Result<DiscoveryContextViewV1> {
        control.check()?;
        Self::validate_request(request)?;
        Self::require(
            self.limits
                .revisions
                .is_none_or(|limit| revisions.len() <= limit),
            "context request",
        )?;
        let scope = Scope {
            subject: Self::json(&request.access.subject)?,
            method: Self::json(&request.method)?,
            from_ns: request.from_utc_ns,
            cutoff_ns: request.cutoff_utc_ns,
            sensitivities: request
                .access
                .sensitivities
                .iter()
                .map(|value| <&str>::from(*value).to_owned())
                .collect(),
            evidence_limit: self.limits.evidence.map(|value| value as u64),
            fact_limit: self.limits.owner_facts.map(|value| value as u64),
            source_limit: self.limits.source_documents.map(|value| value as u64),
            handle_limit: self.limits.handles.map(|value| value as u64),
            conflict_limit: self.limits.conflict_handles.map(|value| value as u64),
            document_limit: self.limits.documents.map(|value| value as u64),
        };
        let evidence = request
            .records
            .iter()
            .map(|row| {
                row.record_id.validate()?;
                Self::require(
                    row.record_id.stream.tenant_id == request.access.tenant_id
                        && row.subject.tenant_id == request.access.tenant_id,
                    "context evidence tenant",
                )?;
                Ok(Evidence {
                    id: row.record_id.clone(),
                    subject: Self::json(&row.subject)?,
                    time: row.received_utc_ns,
                    payload: Self::json(row)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let facts = request
            .owner_facts
            .iter()
            .map(|row| {
                Self::require(
                    row.context.key.tenant_id == request.access.tenant_id
                        && row.subject.tenant_id == request.access.tenant_id,
                    "context fact tenant",
                )?;
                Self::require(
                    row.context.key.valid()
                        && row.context.key.owner_revision > 0
                        && row.subject.valid()
                        && row.subject.owner_revision > 0
                        && row.context.valid_until_utc_ns.is_none_or(|end| {
                            row.context
                                .valid_from_utc_ns
                                .is_some_and(|start| end > start)
                        })
                        && !row.context.body.is_empty(),
                    "context fact",
                )?;
                Ok(Fact {
                    kind: row.kind as u8,
                    key: row.context.key.clone(),
                    subject: Self::json(&row.subject)?,
                    recorded: row.recorded_utc_ns,
                    valid_from: row.context.valid_from_utc_ns,
                    valid_until: row.context.valid_until_utc_ns,
                    sensitivity: <&str>::from(row.context.sensitivity).into(),
                    payload: Self::json(row)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let documents = revisions
            .iter()
            .map(|row| {
                row.validate()?;
                self.document_bytes(row)?;
                let document = &row.document;
                Self::require(
                    document.tenant_id == request.access.tenant_id,
                    "context document tenant",
                )?;
                let handle = DiscoveryContextHandleV1 {
                    key: AnalysisContextVersionV1::try_from(row)?.key,
                    document_id: document.id.clone(),
                    document_revision: document.revision,
                    imported_utc_ns: row.imported_utc_ns,
                    origin: document.origin.clone(),
                    kind: document.kind,
                    sensitivity: document.sensitivity,
                    trust: document.trust(),
                };
                Ok(Document {
                    id: document.id.clone(),
                    revision: document.revision,
                    imported: row.imported_utc_ns,
                    subject: Self::json(&document.subject)?,
                    method: Self::json(&document.method)?,
                    origin: document.origin.clone(),
                    kind: Self::json(&document.kind)?,
                    kind_rank: document.kind as u8,
                    sensitivity: <&str>::from(document.sensitivity).into(),
                    valid_from: document.valid_from_utc_ns,
                    valid_until: document.valid_until_utc_ns,
                    text: document.text.clone(),
                    version: Self::json(row)?,
                    payload: Self::json(&handle)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let tables = [
            Self::table(
                "scope",
                Vec::<Arc<sdk::Field>>::from_type::<Scope>(TracingOptions::default())
                    .context(crate::error::ArrowSnafu)?,
                &[scope],
            )?,
            Self::table("evidence", Evidence::fields(), &evidence)?,
            Self::table("facts", Fact::fields(), &facts)?,
            Self::table(
                "documents",
                Vec::<Arc<sdk::Field>>::from_type::<Document>(TracingOptions::default())
                    .context(crate::error::ArrowSnafu)?,
                &documents,
            )?,
        ];
        let providers = tables
            .iter()
            .map(|(name, schema, batches)| {
                MemTable::try_new(Arc::clone(schema), vec![batches.clone()])
                    .map(|table| (name.clone(), Arc::new(table) as Arc<dyn TableProvider>))
                    .map_err(Self::sql)
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let state = self.query.catalog(providers)?;
        let statement = self
            .query
            .limits()
            .parser
            .parse(include_str!("selection.sql"))?;
        let plan = araphor_query::planner::Planner::new(&state)
            .build(statement, Vec::new())
            .await?;
        let mut session = self.query.session(
            AnalysisSelectionV1::tenant(request.access.tenant_id),
            control,
            request.cutoff_utc_ns,
        )?;
        for (name, schema, batches) in tables {
            session.register(&name, schema, &batches)?;
        }
        let permit = Arc::new(self.query.reserve_evaluation(request.access.tenant_id)?);
        let batches = session
            .stream_local(&plan, permit)
            .await?
            .try_collect::<Vec<_>>()
            .await
            .map_err(Self::sql)?;
        let mut selected = batches
            .iter()
            .map(|batch| {
                serde_arrow::from_record_batch::<Vec<Selected>>(batch)
                    .context(crate::error::ArrowSnafu)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        Self::require(selected.len() == 1, "context selection row")?;
        let selected = selected.remove(0);
        if let Some(kind) = selected.error {
            if kind == "context document count" {
                return Err(DiscoveryInvalidSnafu {
                    field: "context document count",
                }
                .build()
                .into());
            }
            let kind = match kind.as_str() {
                "context evidence" => "context evidence",
                "context fact" => "context fact",
                "context document revision" => "context document revision",
                _ => "context revision history",
            };
            return Err(DiscoveryConflictSnafu { kind }.build().into());
        }
        let decode = |rows: Vec<String>| {
            rows.into_iter()
                .map(|row| Self::decode(&row))
                .collect::<araphor_data::Result<Vec<_>>>()
        };
        let mut view = DiscoveryContextViewV1 {
            selector_version: 1,
            access: request.access.clone(),
            method: request.method.clone(),
            from_utc_ns: request.from_utc_ns,
            cutoff_utc_ns: request.cutoff_utc_ns,
            question: request.question.clone(),
            records: decode(selected.records)?,
            owner_facts: selected
                .facts
                .into_iter()
                .map(|row| Self::decode(&row))
                .collect::<araphor_data::Result<_>>()?,
            documents: selected
                .documents
                .into_iter()
                .map(|row| Self::decode(&row))
                .collect::<araphor_data::Result<_>>()?,
            missing_facts: request.missing_facts.clone(),
            available_documents: selected.available,
            source_counts: selected
                .sources
                .into_iter()
                .map(|count| (count.key, count.count))
                .collect(),
            omissions: selected
                .omissions
                .into_iter()
                .map(|count| (count.key, count.count))
                .collect(),
            conflicts: selected
                .conflicts
                .into_iter()
                .map(|row| {
                    Ok(DiscoveryContextConflictV1 {
                        kind: Self::decode(&row.kind)?,
                        document_ids: row.ids,
                    })
                })
                .collect::<araphor_data::Result<_>>()?,
        };
        self.packet(&mut view)?;
        control.check()?;
        Ok(view)
    }

    fn table<T: Serialize>(
        name: &str,
        fields: Vec<Arc<sdk::Field>>,
        rows: &[T],
    ) -> Result<(String, sdk::arrow_schema::SchemaRef, Vec<sdk::RecordBatch>)> {
        let batch =
            serde_arrow::to_record_batch(&fields, &rows).context(crate::error::ArrowSnafu)?;
        Ok((name.into(), batch.schema(), vec![batch]))
    }

    fn validate_request(request: &DiscoveryContextRequestV1) -> araphor_data::Result<()> {
        request.access.validate()?;
        request.method.validate()?;
        Self::require(
            request.from_utc_ns > 0
                && request.cutoff_utc_ns >= request.from_utc_ns
                && !request.question.is_empty()
                && request.missing_facts.iter().all(|fact| !fact.is_empty()),
            "context request",
        )
    }

    fn sql(source: datafusion::common::DataFusionError) -> crate::Error {
        araphor_query::Error::Sql { source }.into()
    }
}
