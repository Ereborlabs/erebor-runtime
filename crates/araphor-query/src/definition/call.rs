use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::inputs::Inputs;
use araphor_analysis_sdk as sdk;
use araphor_discovery_definition::ImagePin;
use araphor_package::{PackageBundleV1, PackageRefV1};
use datafusion::common::tree_node::{Transformed, TreeNodeRecursion};
use datafusion::common::{DFSchemaRef, DataFusionError, Result};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::{Expr, Extension, LogicalPlan, UserDefinedLogicalNodeCore};

#[derive(Clone)]
pub struct PackageCall {
    pub(crate) id: u64,
    pub(crate) admission: Arc<()>,
    pub(crate) tenant: [u8; 16],
    pub(crate) pin: ImagePin,
    pub(crate) package: PackageRefV1,
    pub(crate) export: String,
    pub(crate) output: String,
    pub(crate) arguments: Arc<[String]>,
    pub(crate) artifact: usize,
    pub(crate) bundle: Arc<PackageBundleV1>,
    pub(crate) sql: Option<SqlCall>,
    pub(crate) input_scope: Arc<Inputs>,
    pub(super) admitted: Arc<[LogicalPlan]>,
    pub(crate) children: Vec<LogicalPlan>,
    pub(crate) schema: DFSchemaRef,
    pub(crate) _metadata: Arc<MemoryReservation>,
    pub(crate) _image: Arc<MemoryReservation>,
}

impl fmt::Debug for PackageCall {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        <Self as UserDefinedLogicalNodeCore>::fmt_for_explain(self, formatter)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SqlCall {
    pub(crate) inputs: Vec<usize>,
    pub(crate) parameters: Option<usize>,
    pub(crate) prior: Vec<usize>,
    pub(crate) outputs: Vec<usize>,
    pub(crate) evidence: bool,
    pub(crate) reasons: Vec<(String, String)>,
    pub(crate) used: BTreeSet<usize>,
}

impl PackageCall {
    pub(super) fn metadata(
        memory: &crate::memory::Memory,
        model: &sdk::Model,
        input_scope: &Inputs,
        children: usize,
    ) -> crate::Result<Arc<MemoryReservation>> {
        use snafu::ResultExt as _;
        let plans = model
            .outputs
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(children))
            .and_then(|count| count.checked_mul(std::mem::size_of::<LogicalPlan>()))
            .ok_or_else(|| araphor_data::PackageErrorCodeV1::Limit.error("package call memory"))?;
        let bytes = input_scope
            .allocated_bytes()
            .checked_add(plans)
            .and_then(|bytes| {
                bytes.checked_add(
                    model
                        .outputs
                        .len()
                        .checked_mul(std::mem::size_of::<PackageCall>())?,
                )
            })
            .ok_or_else(|| araphor_data::PackageErrorCodeV1::Limit.error("package call memory"))?;
        Ok(Arc::new(
            memory.reserve_input(bytes).context(crate::SqlSnafu)?,
        ))
    }

    pub(super) fn seal(plan: LogicalPlan) -> Result<LogicalPlan> {
        plan.transform_up_with_subqueries(|plan| {
            if let LogicalPlan::Extension(extension) = &plan {
                if let Some(call) = extension.node.as_any().downcast_ref::<Self>() {
                    let mut call = call.clone();
                    call.admitted = call.children.clone().into();
                    return Ok(Transformed::yes(LogicalPlan::Extension(Extension {
                        node: Arc::new(call),
                    })));
                }
            }
            Ok(Transformed::no(plan))
        })
        .map(|plan| plan.data)
    }

    pub(crate) fn contains(plan: &LogicalPlan) -> Result<bool> {
        Self::any(plan, &mut |_| Ok(true))
    }

    pub(crate) fn check_admission(plan: &LogicalPlan) -> Result<()> {
        Self::any(plan, &mut |call| {
            let mut valid = call.children.as_slice() == call.admitted.as_ref();
            if valid {
                for (actual, admitted) in call.children.iter().zip(call.admitted.iter()) {
                    if !Self::same_sources(actual, admitted)? {
                        valid = false;
                        break;
                    }
                }
            }
            if !valid {
                return Err(DataFusionError::External(Box::new(
                    araphor_data::PackageErrorCodeV1::Invalid.error("package call admission"),
                )));
            }
            Ok(false)
        })?;
        Ok(())
    }

    fn same_sources(actual: &LogicalPlan, admitted: &LogicalPlan) -> Result<bool> {
        // Native TableScan equality does not compare the source provider.
        let mut sources = Vec::new();
        admitted.apply_with_subqueries(|plan| {
            if let LogicalPlan::TableScan(scan) = plan {
                sources.push(Arc::clone(&scan.source));
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        let mut sources = sources.into_iter();
        let mut same = true;
        actual.apply_with_subqueries(|plan| {
            if let LogicalPlan::TableScan(scan) = plan {
                same = sources
                    .next()
                    .is_some_and(|source| Arc::ptr_eq(&scan.source, &source));
            }
            Ok(if same {
                TreeNodeRecursion::Continue
            } else {
                TreeNodeRecursion::Stop
            })
        })?;
        Ok(same && sources.next().is_none())
    }

    pub fn any(plan: &LogicalPlan, test: &mut impl FnMut(&Self) -> Result<bool>) -> Result<bool> {
        let mut found = false;
        plan.apply_with_subqueries(|plan| {
            found |= match plan {
                LogicalPlan::Extension(extension) => extension
                    .node
                    .as_any()
                    .downcast_ref::<Self>()
                    .map(&mut *test)
                    .transpose()?
                    .unwrap_or(false),
                LogicalPlan::TableScan(scan) => scan
                    .source
                    .get_logical_plan()
                    .map(|plan| Self::any(plan.as_ref(), test))
                    .transpose()?
                    .unwrap_or(false),
                _ => false,
            };
            Ok(if found {
                TreeNodeRecursion::Stop
            } else {
                TreeNodeRecursion::Continue
            })
        })?;
        Ok(found)
    }

    pub fn tenant(&self) -> [u8; 16] {
        self.tenant
    }

    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn image(&self) -> &ImagePin {
        &self.pin
    }
    pub fn package(&self) -> &PackageRefV1 {
        &self.package
    }
    pub fn export(&self) -> &str {
        &self.export
    }
    pub fn descriptor(&self) -> &sdk::Package {
        &self.bundle.artifacts[self.artifact].descriptor
    }
    pub fn output(&self) -> &str {
        &self.output
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    fn key(&self) -> (&str, &str, &str, &str, &str, &str, &str) {
        (
            &self.pin.image.package_id,
            &self.pin.image.revision,
            &self.pin.digest,
            &self.package.package_id,
            &self.package.revision,
            &self.export,
            &self.output,
        )
    }
}

impl PartialEq for PackageCall {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.admission, &other.admission)
            && self.id == other.id
            && self.key() == other.key()
            && self.children == other.children
            && self.schema == other.schema
    }
}
impl Eq for PackageCall {}

impl Hash for PackageCall {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.key().hash(state);
        self.children.hash(state);
        self.schema.hash(state);
    }
}

impl PartialOrd for PackageCall {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.id, self.key()).cmp(&(other.id, other.key())) {
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
    fn necessary_children_exprs(&self, _: &[usize]) -> Option<Vec<Vec<usize>>> {
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
            self.package.package_id, self.package.revision, self.export, self.output
        )
    }
    fn with_exprs_and_inputs(
        &self,
        expressions: Vec<Expr>,
        children: Vec<LogicalPlan>,
    ) -> Result<Self> {
        if !expressions.is_empty() || children.len() != self.children.len() {
            return Err(DataFusionError::Internal(
                "PackageCall inputs changed".into(),
            ));
        }
        Ok(Self {
            children,
            ..self.clone()
        })
    }
}
