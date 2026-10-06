pub use araphor_data::{TraceRecipeManifestV1, TraceRecipeV1};

use crate::{Result, TraceErrorCodeV1, TraceRequestV1};

impl TraceRequestV1 {
    pub(crate) fn recipe(&self) -> Result<Option<TraceRecipeV1>> {
        let source = &self.source;
        let recipe = TraceRecipeV1::identify(source)?;
        // These exact fault sources collect no host or workload data.
        TraceErrorCodeV1::Unsupported.require(
            recipe.is_some()
                || matches!(
                    source.bytes.as_slice(),
                    b"BEGIN { $i = 0; while ($i < 8192) { @full[$i] = 1; $i++; } } interval:s:2 { exit(); }"
                        | b"interval:hz:10000 { printf(\"bounded diagnostic output\\n\"); }"
                ),
            "trace source has no supported collection capability",
        )?;
        Ok(recipe)
    }
}
