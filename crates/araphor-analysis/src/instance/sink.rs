use std::any::Any;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisReadControl, ManagedAttempt, ManagedCommit, ManagedDestination, ManagedGraphOperation,
    ManagedInstance, ManagedReceipt, ManagedRequest, ManagedResume, ManagedReturn, PackageActionV1,
    PackageErrorCodeV1 as Code, PackageGrantV1,
};
use araphor_query::definition::{ExecutionReceipt, PackageCall};
use async_trait::async_trait;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::{DFSchema, DataFusionError, Result};
use datafusion::datasource::sink::{DataSink, DataSinkExec};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{dml::InsertOp, Expr, TableType};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, SendableRecordBatchStream,
};
use futures_util::TryStreamExt as _;

use super::Instance;

#[derive(Default)]
pub(super) struct Step {
    pub(super) completed: u64,
    pub(super) admission: Option<ManagedResume>,
    pub(super) attempt: Option<Arc<ManagedAttempt>>,
    pub(super) receipt: Option<ManagedReceipt>,
}

#[derive(Clone)]
pub(super) enum Operation {
    Follow {
        lifecycle: u64,
    },
    Once {
        current: ManagedInstance,
        request: ManagedRequest,
        caller: Option<PackageGrantV1>,
    },
    Version {
        expected: ManagedInstance,
        rebuild: bool,
        action: PackageActionV1,
        caller: Option<PackageGrantV1>,
    },
}

impl Operation {
    pub(super) fn caller(&self) -> Option<(&PackageGrantV1, PackageActionV1)> {
        match self {
            Self::Follow { .. } => None,
            Self::Once { caller, .. } => caller.as_ref().map(|grant| (grant, PackageActionV1::Run)),
            Self::Version { caller, action, .. } => caller.as_ref().map(|grant| (grant, *action)),
        }
    }
}

#[derive(Clone)]
pub(super) enum Mode {
    Managed {
        operation: Box<Operation>,
        state: Arc<Mutex<Step>>,
        witness_expiry: u64,
    },
    Notification {
        router: Arc<crate::NotificationRouter>,
        sink: Arc<dyn araphor_data::NotificationSink>,
        lifecycle: u64,
    },
}

#[derive(Clone)]
pub(super) struct Publication {
    pub(super) owner: Arc<Instance>,
    pub(super) schema: sdk::arrow_schema::SchemaRef,
    pub(super) mode: Mode,
}

impl Publication {
    pub(super) fn managed(&self) -> araphor_data::Result<(&Arc<Mutex<Step>>, u64, &Operation)> {
        match &self.mode {
            Mode::Managed {
                state,
                witness_expiry,
                operation,
            } => Ok((state, *witness_expiry, operation.as_ref())),
            Mode::Notification { .. } => {
                Err(Code::Unsupported.error("notification managed publication"))
            }
        }
    }

    fn notify(
        &self,
        tenant: [u8; 16],
        now: u64,
        batches: &[sdk::RecordBatch],
        control: &AnalysisReadControl,
    ) -> crate::Result<()> {
        let Mode::Notification {
            router,
            sink,
            lifecycle,
        } = &self.mode
        else {
            return Err(Code::Invalid.error("notification publication mode").into());
        };
        let check = || self.owner.check_notification(*lifecycle, control);
        router
            .consume_rows(tenant, now, batches, &check, &mut |delivery| {
                Ok(sink.deliver(delivery))
            })
            .map(|_| ())
    }
}

impl fmt::Debug for Publication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedPublication")
    }
}

impl DisplayAs for Publication {
    fn fmt_as(&self, _: DisplayFormatType, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedPublication")
    }
}

#[async_trait]
impl TableProvider for Publication {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> sdk::arrow_schema::SchemaRef {
        Arc::clone(&self.schema)
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        _: &dyn Session,
        _: Option<&Vec<usize>>,
        _: &[Expr],
        _: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        Err(DataFusionError::External(Box::new(
            Code::Unsupported.error("managed publication scan"),
        )))
    }

    async fn insert_into(
        &self,
        _: &dyn Session,
        input: Arc<dyn ExecutionPlan>,
        operation: InsertOp,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let matches = match &self.mode {
            Mode::Notification { .. } => DFSchema::try_from(Arc::clone(&self.schema))?
                .logically_equivalent_names_and_types(&DFSchema::try_from(input.schema())?),
            Mode::Managed { .. } => input.schema() == self.schema,
        };
        if operation != InsertOp::Append || !matches {
            return Err(DataFusionError::External(Box::new(
                Code::Invalid.error("managed publication input"),
            )));
        }
        Ok(Arc::new(DataSinkExec::new(
            input,
            Arc::new(self.clone()),
            None,
        )))
    }
}

#[async_trait]
impl DataSink for Publication {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> &sdk::arrow_schema::SchemaRef {
        &self.schema
    }

    async fn write_all(
        &self,
        mut data: SendableRecordBatchStream,
        context: &Arc<TaskContext>,
    ) -> Result<u64> {
        let control = context
            .session_config()
            .get_extension::<AnalysisReadControl>()
            .ok_or_else(|| {
                DataFusionError::External(Box::new(
                    Code::Incomplete.error("managed execution control"),
                ))
            })?;
        let limits = self.owner.query.limits();
        let memory = self.owner.session.memory();
        let reservation = memory.reserve_output(0)?;
        let (mut rows, mut bytes) = (0usize, 0usize);
        let mut batches = Vec::new();
        while let Some(batch) = data.try_next().await? {
            control
                .check()
                .map_err(|source| DataFusionError::External(Box::new(source)))?;
            rows = rows.checked_add(batch.num_rows()).ok_or_else(|| {
                DataFusionError::ResourcesExhausted("managed selected rows".into())
            })?;
            bytes = bytes
                .checked_add(batch.get_array_memory_size())
                .ok_or_else(|| {
                    DataFusionError::ResourcesExhausted("managed selected bytes".into())
                })?;
            if rows > limits.output_rows || bytes > limits.output_bytes {
                return Err(DataFusionError::ResourcesExhausted(
                    "managed selected relation exceeds output limits".into(),
                ));
            }
            memory.retain_output(&batch, &reservation)?;
            batches.push(batch);
        }
        if batches.is_empty() {
            batches.push(sdk::RecordBatch::new_empty(Arc::clone(&self.schema)));
        }
        let receipt = ExecutionReceipt::from_context(context)?;
        for (id, returned) in receipt.calls() {
            if self
                .owner
                .calls
                .get(id)
                .and_then(|plan| match plan {
                    datafusion::logical_expr::LogicalPlan::Extension(extension) => {
                        extension.node.as_any().downcast_ref::<PackageCall>()
                    }
                    _ => None,
                })
                .is_none_or(|call| !returned.belongs_to(call))
            {
                return Err(DataFusionError::External(Box::new(
                    Code::Denied.error("managed returned call identity"),
                )));
            }
        }
        if matches!(&self.mode, Mode::Notification { .. }) {
            let snapshot = receipt.snapshot();
            if !receipt.calls().is_empty()
                || !snapshot.page.exhausted
                || snapshot.selection.tenant_id != self.owner.admitted.grant.selection.tenant_id
            {
                return Err(DataFusionError::External(Box::new(
                    Code::Invalid.error("notification complete native capture"),
                )));
            }
            let tenant = snapshot.selection.tenant_id;
            let now = snapshot.time_utc_ns();
            let publication = self.clone();
            return receipt
                .blocking(context, reservation, move |control| {
                    publication
                        .notify(tenant, now, &batches, control)
                        .map_err(|source| araphor_query::Error::Sql {
                            source: DataFusionError::External(Box::new(source)),
                        })?;
                    Ok(rows as u64)
                })
                .await;
        }
        let (state, _, mode) = self
            .managed()
            .map_err(|source| DataFusionError::External(Box::new(source)))?;
        let attempt = state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .attempt
            .clone()
            .ok_or_else(|| {
                DataFusionError::External(Box::new(
                    Code::Incomplete.error("managed execution attempt"),
                ))
            })?;
        let captured = receipt.clone();
        let acknowledgement = receipt.clone();
        let task = Arc::clone(context);
        let owner = Arc::clone(&self.owner);
        let state = Arc::clone(state);
        let schema = Arc::clone(&self.schema);
        let selected = sdk::Dataset {
            name: "selected".into(),
            batches,
        };
        let actions: &'static [_] = match mode {
            Operation::Version {
                action: PackageActionV1::Rollback,
                ..
            } => &[
                PackageActionV1::Run,
                PackageActionV1::Update,
                PackageActionV1::Rollback,
            ],
            Operation::Version { .. } => &[PackageActionV1::Run, PackageActionV1::Update],
            _ => &[PackageActionV1::Run],
        };
        let caller = mode.caller().map(|(grant, action)| (grant.clone(), action));
        let published = receipt
            .blocking(context, reservation, move |control| {
                let calls = captured.calls();
                let returns = calls
                    .iter()
                    .map(|(call, returned)| ManagedReturn {
                        call: *call,
                        evaluation: returned.evaluation(),
                        output: returned.output(),
                        retained: returned.retained(),
                    })
                    .collect::<Vec<_>>();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .and_then(|time| u64::try_from(time.as_nanos()).ok())
                    .ok_or_else(|| Code::Incomplete.error("managed publication time"))?;
                let profile = if matches!(
                    owner.admitted.spec.destination,
                    ManagedDestination::DiscoveryProfile { .. }
                ) {
                    Some(crate::DiscoveryOwner::convert_profile(
                        &owner.session,
                        &owner.prepared,
                        &owner.admitted.spec.destination,
                        &captured,
                        &task,
                        control,
                    )?)
                } else {
                    None
                };
                let graph = match &owner.admitted.spec.destination {
                    ManagedDestination::Graph {
                        operation: ManagedGraphOperation::Evaluate,
                        ..
                    } if calls.is_empty() && rows == 0 => None,
                    ManagedDestination::Graph {
                        operation: ManagedGraphOperation::Evaluate,
                        ..
                    } => Some(
                        owner
                            .graph
                            .as_ref()
                            .ok_or_else(|| Code::Incomplete.error("managed graph owner"))?
                            .convert_graph(
                                &task,
                                &captured,
                                format!("graph:{}", uuid::Uuid::new_v4()),
                                control,
                            )?,
                    ),
                    ManagedDestination::Graph {
                        operation: ManagedGraphOperation::Expire,
                        ..
                    } => crate::graph::GraphConversion::expiry(
                        &owner.session,
                        &task,
                        &captured,
                        &selected.batches,
                        control,
                    )?,
                    _ => None,
                };
                let completed = graph.as_ref().is_none_or(|converted| converted.completed)
                    && profile.as_ref().is_none_or(|converted| !converted.replan);
                Instance::authorize_actions_for(
                    owner.authority.as_ref(),
                    &owner.admitted.grant,
                    &owner.prepared,
                    actions,
                    caller
                        .as_ref()
                        .map(|(grant, action)| (grant, *action, control)),
                    || {
                        control.check()?;
                        let managed = ManagedCommit {
                            completed,
                            attempt: &attempt,
                            now_utc_ns: now,
                            returns: &returns,
                            selected: &selected,
                            selected_schema: schema.as_ref(),
                        };
                        let receipt = match &owner.admitted.spec.destination {
                            ManagedDestination::Notification => {
                                return Err(Code::Unsupported.error("notification managed commit"))
                            }
                            ManagedDestination::Selected => owner
                                .query
                                .store()
                                .commit_managed(&managed, || control.check())?,
                            ManagedDestination::DiscoveryProfile { .. } => {
                                let converted = profile.ok_or_else(|| {
                                    Code::Incomplete.error("managed profile conversion")
                                })?;
                                owner
                                    .query
                                    .store()
                                    .commit_managed_profile(&managed, converted.packet, || {
                                        control.check()
                                    })?
                                    .0
                            }
                            ManagedDestination::Graph { .. } => {
                                if let Some(converted) = graph {
                                    let evaluate = matches!(
                                        owner.admitted.spec.destination,
                                        ManagedDestination::Graph {
                                            operation: ManagedGraphOperation::Evaluate,
                                            ..
                                        }
                                    );
                                    let deadline = converted.deadline;
                                    if evaluate {
                                        crate::graph::GraphConversion::check_deadline(deadline)?;
                                    }
                                    owner
                                        .query
                                        .store()
                                        .commit_managed_graph(
                                            &managed,
                                            Some(converted.packet),
                                            || {
                                                control.check()?;
                                                if evaluate {
                                                    crate::graph::GraphConversion::check_deadline(
                                                        deadline,
                                                    )?;
                                                }
                                                Ok(())
                                            },
                                        )?
                                        .0
                                } else {
                                    owner
                                        .query
                                        .store()
                                        .commit_managed_graph(&managed, None, || control.check())?
                                        .0
                                }
                            }
                        };
                        let revision = receipt.commit_revision;
                        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
                        state.attempt = None;
                        state.completed = receipt.commit_revision;
                        if let Some(admission) = &mut state.admission {
                            admission.instance.progress = receipt.commit_revision;
                            admission.completed = receipt.commit_revision;
                        }
                        state.receipt = Some(receipt);
                        Ok(completed.then_some(revision))
                    },
                )
                .map_err(araphor_query::Error::from)
            })
            .await?;
        if let Some(revision) = published {
            acknowledgement.acknowledge(context, revision)?;
        }
        Ok(rows as u64)
    }
}
