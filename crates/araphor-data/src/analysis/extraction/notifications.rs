mod native;

use super::*;
use crate::{AnalysisContextKeyV1, NotificationObligationV1};

pub(super) use native::NativeNotifications;

pub(super) struct NotificationState {
    pub(super) key: AnalysisContextKeyV1,
    pub(super) revision: u64,
    pub(super) obligation: NotificationObligationV1,
}

impl NotificationState {
    pub(super) fn read(
        store: &AnalysisStore,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<Vec<Self>> {
        let mut states = Vec::new();
        for key in selection.obligations.as_slice() {
            control.check()?;
            let (context, revision) = AnalysisStore::read_context_from(snapshot, &store.root, key)?
                .ok_or_else(|| store.state_error("the selected notification state is absent"))?;
            output.scan(context.body.len())?;
            output.charge(context.body.capacity().saturating_mul(2))?;
            let obligation = NotificationObligationV1::try_from(&context)?;
            output.sink(control).grow(&mut states)?;
            states.push(Self {
                key: context.key,
                revision,
                obligation,
            });
        }
        Ok(states)
    }
}
