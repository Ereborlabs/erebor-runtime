use std::sync::Arc;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, ManagedDestination, PackageGrantV1};
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_query::definition::PreparedDefinition;
use datafusion::arrow::datatypes::DataType;
use datafusion::datasource::provider_as_source;
use datafusion::logical_expr::{dml::InsertOp, LogicalPlanBuilder};

use super::{Code, Instance, InstanceHost};
use crate::instance::sink;
use crate::{NotificationRouter, Result};

#[derive(Clone)]
pub(super) struct Notifications {
    pub(super) router: Arc<NotificationRouter>,
    pub(super) sink: Arc<dyn araphor_data::NotificationSink>,
    pub(super) enabled: bool,
}

impl Notifications {
    pub(super) const ID: &str = "notifications";

    fn definition() -> Definition {
        Definition {
            name: "mithril-control-notifications".into(),
            description: "Route and deliver retained findings.".into(),
            labels: Default::default(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: NotificationRouter::SQL.into(),
                },
            },
        }
    }
}

impl InstanceHost {
    pub async fn admit_notifications(
        self: &Arc<Self>,
        grant: PackageGrantV1,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        if !self
            .notifications
            .as_ref()
            .is_some_and(|owner| owner.enabled)
        {
            return Err(Code::Denied.error("notification admission disabled").into());
        }
        let session = self.query.session(grant.selection.clone(), control, 0)?;
        let prepared = session
            .prepare_definition(&Notifications::definition())
            .await?;
        self.admit_prepared(
            session,
            grant,
            Notifications::ID.into(),
            prepared,
            ManagedDestination::Notification,
        )
        .await
    }
}

impl Instance {
    pub(in crate::instance) fn validate_notification(
        prepared: &PreparedDefinition,
        grant: &PackageGrantV1,
        id: &str,
    ) -> araphor_query::Result<()> {
        let fields = prepared.plan.schema().fields();
        let columns = [
            ("finding_id", DataType::Utf8),
            ("result_id", DataType::Utf8),
            ("notification_id", DataType::Binary),
        ];
        if id != Notifications::ID
            || grant.selection != AnalysisSelectionV1::tenant(grant.selection.tenant_id)
            || prepared.resolved().definition != Notifications::definition()
            || !prepared.resolved().images.is_empty()
            || fields.len() != columns.len()
            || fields.iter().zip(columns).any(|(field, (name, kind))| {
                field.name() != name || field.data_type() != &kind || !field.is_nullable()
            })
            || !Self::manifest(prepared)?.0.calls.is_empty()
        {
            return Err(Code::Invalid.error("notification native definition").into());
        }
        Ok(())
    }

    pub(in crate::instance) fn check_notification(
        &self,
        lifecycle: u64,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        control.check()?;
        if !self.current_lifecycle(lifecycle, control)?.running {
            return Err(Code::Conflict.error("notification running intent").into());
        }
        self.check()?;
        Ok(())
    }

    pub(super) fn subscribe_notifications(
        self: &Arc<Self>,
        owner: &Notifications,
        control: Arc<AnalysisReadControl>,
        lifecycle: u64,
    ) -> Result<araphor_query::follow::Subscription> {
        Self::validate_notification(&self.prepared, &self.admitted.grant, &self.admitted.spec.id)?;
        self.check_notification(lifecycle, &control)?;
        let target = Arc::new(sink::Publication {
            owner: Arc::clone(self),
            schema: Arc::clone(self.prepared.plan.schema().inner()),
            mode: sink::Mode::Notification {
                router: Arc::clone(&owner.router),
                sink: Arc::clone(&owner.sink),
                lifecycle,
            },
        });
        let plan = LogicalPlanBuilder::insert_into(
            self.prepared.plan.clone(),
            "__araphor_notifications",
            provider_as_source(target),
            InsertOp::Append,
        )
        .and_then(LogicalPlanBuilder::build)
        .map_err(|source| araphor_query::Error::Sql { source })?;
        let binding = self
            .admitted
            .spec
            .definition
            .digest()
            .map_err(araphor_data::Error::from)?;
        Ok(self
            .session
            .operation(&control, 0)?
            .subscribe(
                plan,
                self.prepared.sources().clone(),
                binding.as_bytes(),
                true,
            )?
            .until_change(self.authority.changes_for(&self.admitted.grant)))
    }
}

#[cfg(test)]
mod tests;
