use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_discovery_definition::ImagePin;
use araphor_package::PackageRefV1;
use datafusion::common::{DFSchemaRef, DataFusionError, Result};
use datafusion::logical_expr::{Expr, LogicalPlan, UserDefinedLogicalNodeCore};

#[derive(Clone, Debug)]
pub struct PackageCall {
    pub(crate) pin: ImagePin,
    pub(crate) package: PackageRefV1,
    pub(crate) export: String,
    pub(crate) output: String,
    pub(crate) descriptor: Arc<sdk::Package>,
    pub(crate) children: Vec<LogicalPlan>,
    pub(crate) schema: DFSchemaRef,
}

impl PackageCall {
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
        &self.descriptor
    }
    pub fn output(&self) -> &str {
        &self.output
    }
}

impl PartialEq for PackageCall {
    fn eq(&self, other: &Self) -> bool {
        self.pin == other.pin
            && self.package == other.package
            && self.export == other.export
            && self.output == other.output
            && self.children == other.children
            && self.schema == other.schema
    }
}
impl Eq for PackageCall {}

impl Hash for PackageCall {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pin.image.package_id.hash(state);
        self.pin.image.revision.hash(state);
        self.pin.digest.hash(state);
        self.package.package_id.hash(state);
        self.package.revision.hash(state);
        self.export.hash(state);
        self.output.hash(state);
        self.children.hash(state);
        self.schema.hash(state);
    }
}

impl PartialOrd for PackageCall {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let identity = (
            &self.pin.image.package_id,
            &self.pin.image.revision,
            &self.pin.digest,
            &self.package.package_id,
            &self.package.revision,
            &self.export,
            &self.output,
        );
        let compared = (
            &other.pin.image.package_id,
            &other.pin.image.revision,
            &other.pin.digest,
            &other.package.package_id,
            &other.package.revision,
            &other.export,
            &other.output,
        );
        match identity.cmp(&compared) {
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
