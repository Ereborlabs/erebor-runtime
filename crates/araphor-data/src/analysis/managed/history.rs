use duckdb::params;
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use super::model::{Attempt, ManagedReceipt};
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisSelectionV1, PackageErrorCodeV1 as Code,
    Result,
};

impl AnalysisStore {
    pub fn managed_history(
        &self,
        selection: &AnalysisSelectionV1,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<Vec<ManagedReceipt>> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let instance = Self::managed_instance_from(reader, selection.tenant_id, id)?
                .ok_or_else(|| Code::Missing.error("managed history instance"))?;
            instance.grant.permitted_by(selection)?;
            let head = Self::read_meta_from(reader, &self.root.join("analysis.duckdb"))?.commit_revision;
            let mut statement = reader.prepare(
                "SELECT attempt_id, contract, completed FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? ORDER BY completed, attempt_id"
            ).context(AnalysisDatabaseSnafu { operation: "prepare managed history" })?;
            if instance.generation == 0 || instance.generation > head {
                return Err(Code::Invalid.error("managed history generation"));
            }
            let rows = statement.query_map(params![selection.tenant_id.as_slice(), id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, u64>(2)?))
            }).context(AnalysisDatabaseSnafu { operation: "read managed history" })?;
            let mut history = Vec::new();
            for row in rows {
                control.check()?;
                let (key, bytes, completed) = row.context(AnalysisDatabaseSnafu { operation: "decode managed history row" })?;
                let attempt = Attempt::decode(selection.tenant_id, id, &key, &bytes)?;
                if attempt.capture.generation != instance.generation || attempt.registered == 0 || attempt.registered > head {
                    return Err(Code::Invalid.error("managed history generation"));
                }
                match (attempt.receipt, attempt.terminal) {
                    (Some(receipt), None) => {
                        if receipt.instance != id || receipt.attempt != key
                            || receipt.commit_revision != completed || completed <= attempt.registered || completed > head
                            || receipt.frontier != attempt.request.frontier
                            || receipt.selected.result_id.is_empty() || receipt.selected.commit_revision != completed
                            || receipt.results.iter().any(|(call, reference)| !instance.spec.manifest.calls.contains_key(call)
                                || reference.result_id.is_empty() || reference.commit_revision != completed)
                        {
                            return Err(Code::Invalid.error("managed history receipt"));
                        }
                        history.push(receipt);
                    }
                    (None, Some(terminal)) if terminal.instance == id && terminal.attempt == key
                        && terminal.revision == completed && completed > attempt.registered && completed <= head => {}
                    (None, None) if completed == 0 => {}
                    _ => return Err(Code::Invalid.error("managed history outcome")),
                }
            }
            Ok(history)
        })
    }
}
