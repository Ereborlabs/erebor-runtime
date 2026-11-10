use super::notices::Notice;
use super::*;
use crate::analysis::inputs::{InputChange, InputChanges};

impl DataView {
    pub(in crate::analysis::native) fn input_progress_key(key: &[u8]) -> bool {
        [Processor::PREFIX, ResultRecord::PREFIX, Notice::PREFIX]
            .iter()
            .any(|prefix| key.starts_with(prefix) && key.len() == prefix.len() + 8)
            || key.starts_with(Processor::GAPS) && key.len() == Processor::GAPS.len() + 24
    }

    pub(in crate::analysis::native) fn input_progress(
        &self,
        key: &[u8],
        inputs: &InputChanges,
        position: crate::StorePositionV1,
    ) -> Result<()> {
        if key.starts_with(Processor::PREFIX) || key.starts_with(Processor::GAPS) {
            let prefix = if key.starts_with(Processor::PREFIX) {
                Processor::PREFIX
            } else {
                Processor::GAPS
            };
            let id = NativeStore::number(&key[prefix.len()..prefix.len() + 8])?;
            let bytes = Records::payload(&Processor::key(Processor::PREFIX, id), |key| {
                Records::read(key, &self.snapshot)
            })?
            .ok_or_else(|| Code::Missing.error("input processor state"))?;
            let state: Processor = Records::decode(&bytes)?;
            if state.revision != position.commit_revision || !state.scope.valid() {
                return Err(Code::Invalid.error("input processor revision"));
            }
            inputs.publish(position, InputChange::Processor(&state.scope));
        } else if key.starts_with(ResultRecord::PREFIX) {
            let bytes = Records::payload(key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| Code::Missing.error("input profile record"))?;
            let result: ResultRecord = Records::decode(&bytes)?;
            if result.revision != position.commit_revision || !result.request.scope.valid() {
                return Err(Code::Invalid.error("input profile revision"));
            }
            if result.header.interval_id.is_some() {
                inputs.publish(
                    position,
                    InputChange::Profile {
                        scope: &result.request.scope,
                        result: &result.request.result_id,
                    },
                );
            }
        } else if key.starts_with(Notice::PREFIX) {
            let bytes = Records::payload(key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| Code::Missing.error("input notice record"))?;
            let notice: Notice = Records::decode(&bytes)?;
            if notice.revision != position.commit_revision || !notice.scope.valid() {
                return Err(Code::Invalid.error("input notice revision"));
            }
            inputs.publish(
                position,
                InputChange::Notice {
                    scope: &notice.scope,
                    result: &notice.result.result_id,
                },
            );
        }
        Ok(())
    }
}
