use snafu::ResultExt as _;

use crate::{Package, Result};

const WIT: &str = include_str!("bindings/analysis.wit");
const NATIVE: &str = include_str!("bindings/analysis.h");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceDeclarations {
    pub descriptor_json: String,
    pub wit: String,
    pub native_header: String,
}

impl Package {
    pub fn interfaces(&self) -> Result<InterfaceDeclarations> {
        self.validate()?;
        let mut descriptor = serde_json::to_value(self).context(crate::EncodingSnafu)?;
        descriptor.sort_all_objects();
        let descriptor_json =
            serde_json::to_string_pretty(&descriptor).context(crate::EncodingSnafu)?;
        let descriptor = serde_json::to_string(&descriptor).context(crate::EncodingSnafu)?;
        Ok(InterfaceDeclarations {
            descriptor_json,
            wit: format!("// descriptor-json: {descriptor}\n{WIT}"),
            native_header: format!("// descriptor-json: {descriptor}\n{NATIVE}"),
        })
    }
}

#[cfg(test)]
mod tests;
