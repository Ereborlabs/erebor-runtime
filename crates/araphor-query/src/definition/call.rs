use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_discovery_definition::{ImagePin, PackageCall as DefinitionCall};
use datafusion::common::{DFSchemaRef, DataFusionError, Result};
use datafusion::logical_expr::planner::{
    PlannedRelation, RelationPlanner, RelationPlannerContext, RelationPlanning,
};
use datafusion::logical_expr::{Expr, Extension, LogicalPlan, UserDefinedLogicalNodeCore};
use datafusion::sql::sqlparser::ast::{
    Expr as SqlExpr, FunctionArg, FunctionArgExpr, TableFactor, Value,
};

#[derive(Clone, Debug)]
pub struct PackageCall {
    pub(crate) call: DefinitionCall,
    pub(crate) pin: ImagePin,
    pub(crate) descriptor: Arc<sdk::Package>,
    pub(crate) output: String,
    pub(crate) identity: String,
    pub(crate) children: Vec<LogicalPlan>,
    pub(crate) schema: DFSchemaRef,
}

impl PackageCall {
    pub fn definition(&self) -> &DefinitionCall {
        &self.call
    }

    pub fn image(&self) -> &ImagePin {
        &self.pin
    }

    pub fn descriptor(&self) -> &sdk::Package {
        &self.descriptor
    }

    pub fn output(&self) -> &str {
        &self.output
    }

    pub(crate) fn sql(&self) -> String {
        let arguments = self
            .arguments()
            .map(|value| format!("'{}'", value.replace('\'', "''")))
            .join(", ");
        format!("SELECT * FROM araphor.package_call({arguments})")
    }

    fn arguments(&self) -> [&str; 4] {
        [
            &self.call.image.package_id,
            &self.call.image.revision,
            &self.call.export,
            &self.output,
        ]
    }

    pub(crate) fn plan(&self) -> LogicalPlan {
        LogicalPlan::Extension(Extension {
            node: Arc::new(self.clone()),
        })
    }
}

impl PartialEq for PackageCall {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.children == other.children
            && self.schema == other.schema
    }
}

impl Eq for PackageCall {}

impl Hash for PackageCall {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity.hash(state);
        self.children.hash(state);
        self.schema.hash(state);
    }
}

impl PartialOrd for PackageCall {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.identity.cmp(&other.identity) {
            Ordering::Equal => self.children.partial_cmp(&other.children),
            ordering => Some(ordering),
        }
        .filter(|ordering| *ordering != Ordering::Equal || self == other)
    }
}

impl UserDefinedLogicalNodeCore for PackageCall {
    fn name(&self) -> &str {
        "PackageCall"
    }

    fn inputs(&self) -> Vec<&LogicalPlan> {
        self.children.iter().collect()
    }

    fn schema(&self) -> &DFSchemaRef {
        &self.schema
    }

    fn expressions(&self) -> Vec<Expr> {
        Vec::new()
    }

    fn necessary_children_exprs(&self, _output_columns: &[usize]) -> Option<Vec<Vec<usize>>> {
        Some(
            self.children
                .iter()
                .map(|input| (0..input.schema().fields().len()).collect())
                .collect(),
        )
    }

    fn fmt_for_explain(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "PackageCall: {}@{} {}/{}",
            self.call.image.package_id, self.call.image.revision, self.call.export, self.output
        )
    }

    fn with_exprs_and_inputs(
        &self,
        expressions: Vec<Expr>,
        inputs: Vec<LogicalPlan>,
    ) -> Result<Self> {
        if !expressions.is_empty() || inputs.len() != self.children.len() {
            return Err(DataFusionError::Internal(
                "PackageCall inputs changed".into(),
            ));
        }
        Ok(Self {
            children: inputs,
            ..self.clone()
        })
    }
}

impl RelationPlanner for PackageCall {
    fn plan_relation(
        &self,
        relation: TableFactor,
        context: &mut dyn RelationPlannerContext,
    ) -> Result<RelationPlanning> {
        let TableFactor::Table {
            name,
            args: Some(_),
            ..
        } = &relation
        else {
            return Ok(RelationPlanning::Original(Box::new(relation)));
        };
        let name = context.object_name_to_table_reference(name.clone())?;
        if name.catalog().is_some()
            || name.schema() != Some("araphor")
            || name.table() != "package_call"
        {
            return Ok(RelationPlanning::Original(Box::new(relation)));
        }
        let TableFactor::Table {
            alias,
            args: Some(args),
            with_hints,
            version,
            with_ordinality,
            partitions,
            json_path,
            sample,
            index_hints,
            ..
        } = relation
        else {
            return Err(DataFusionError::Internal(
                "PackageCall relation changed".into(),
            ));
        };
        if args.settings.is_some()
            || !with_hints.is_empty()
            || version.is_some()
            || with_ordinality
            || !partitions.is_empty()
            || json_path.is_some()
            || sample.is_some()
            || !index_hints.is_empty()
            || args.args.len() != 4
        {
            return Err(DataFusionError::Plan(
                "PackageCall modifiers or arguments are invalid".into(),
            ));
        }
        for (argument, expected) in args.args.iter().zip(self.arguments()) {
            if !matches!(argument, FunctionArg::Unnamed(FunctionArgExpr::Expr(SqlExpr::Value(value))) if matches!(&value.value, Value::SingleQuotedString(actual) if actual == expected))
            {
                return Err(DataFusionError::Plan("PackageCall identity changed".into()));
            }
        }
        Ok(RelationPlanning::Planned(Box::new(PlannedRelation::new(
            self.plan(),
            alias,
        ))))
    }
}
