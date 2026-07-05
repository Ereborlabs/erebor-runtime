use std::collections::BTreeMap;

use cdp_protocol::{page, runtime::ExecutionContextId, target};
use serde::Serialize;
use serde_json::Value;

use super::{
    BrowserTarget, BrowserTargetId, BrowserTargetKind, BrowserTargetStatus, ExecutionContextState,
    FrameId, FrameState, TargetGraphValue,
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct BrowserTargetGraph {
    targets: BTreeMap<BrowserTargetId, BrowserTarget>,
    frames: BTreeMap<FrameId, FrameState>,
    execution_contexts: BTreeMap<ExecutionContextId, ExecutionContextState>,
}

impl BrowserTargetGraph {
    #[must_use]
    pub fn targets(&self) -> Vec<BrowserTarget> {
        self.targets.values().cloned().collect()
    }

    #[must_use]
    pub fn target(&self, target_id: &BrowserTargetId) -> Option<&BrowserTarget> {
        self.targets.get(target_id)
    }

    #[must_use]
    pub fn target_for_execution_context(
        &self,
        context_id: ExecutionContextId,
    ) -> Option<&BrowserTarget> {
        self.execution_contexts
            .get(&context_id)
            .and_then(|context| self.targets.get(&context.target_id))
    }

    pub fn ensure_page_target(&mut self, target_id: BrowserTargetId) {
        self.targets
            .entry(target_id.clone())
            .or_insert_with(|| BrowserTarget::unknown_page(target_id));
    }

    pub fn record_provisional_navigation(&mut self, target_id: BrowserTargetId, url: &str) {
        let target = self
            .targets
            .entry(target_id.clone())
            .or_insert_with(|| BrowserTarget::unknown_page(target_id));
        target.url = TargetGraphValue::non_empty(url);
        target.status = BrowserTargetStatus::ProvisionalNavigation;
    }

    pub fn record_target_info(&mut self, target_info: &target::TargetInfo) {
        let target_id = BrowserTargetId::new(target_info.target_id.clone());
        let target = self
            .targets
            .entry(target_id.clone())
            .or_insert_with(|| BrowserTarget::new(target_id));
        target.kind = BrowserTargetKind::from_cdp_target_type(&target_info.r#type);
        target.url = TargetGraphValue::non_empty(&target_info.url);
        target.title = TargetGraphValue::non_empty(&target_info.title);
        target.opener = target_info
            .opener_id
            .as_ref()
            .map(|opener_id| BrowserTargetId::new(opener_id.clone()));
        target.attached = target_info.attached;
        target.status = if target.attached {
            BrowserTargetStatus::Attached
        } else {
            BrowserTargetStatus::Created
        };
    }

    pub fn record_target_attached(&mut self, target_info: &target::TargetInfo) {
        self.record_target_info(target_info);
        let target_id = BrowserTargetId::new(target_info.target_id.clone());
        if let Some(target) = self.targets.get_mut(&target_id) {
            target.attached = true;
            target.status = BrowserTargetStatus::Attached;
        }
    }

    pub fn record_target_destroyed(&mut self, target_id: impl Into<String>) {
        let target_id = BrowserTargetId::new(target_id);
        if let Some(target) = self.targets.get_mut(&target_id) {
            target.status = BrowserTargetStatus::Closed;
            target.attached = false;
        }
    }

    pub fn record_target_crashed(&mut self, target_id: impl Into<String>) {
        let target_id = BrowserTargetId::new(target_id);
        if let Some(target) = self.targets.get_mut(&target_id) {
            target.status = BrowserTargetStatus::Crashed;
            target.attached = false;
        }
    }

    pub fn record_frame_tree(&mut self, target_id: BrowserTargetId, frame_tree: &page::FrameTree) {
        self.record_frame_tree_inner(target_id, frame_tree, None, true);
    }

    pub fn record_frame_navigated(&mut self, target_id: BrowserTargetId, frame: &page::Frame) {
        let frame_id = FrameId::new(frame.id.clone());
        let parent_frame_id = frame.parent_id.as_ref().map(|id| FrameId::new(id.clone()));
        self.frames.insert(
            frame_id.clone(),
            FrameState {
                id: frame_id,
                target_id: target_id.clone(),
                parent_frame_id,
                url: TargetGraphValue::non_empty(&frame.url),
            },
        );
        if let Some(target) = self.targets.get_mut(&target_id) {
            target.url = TargetGraphValue::non_empty(&frame.url);
            target.status = BrowserTargetStatus::Active;
        }
    }

    pub fn record_navigated_within_document(
        &mut self,
        target_id: BrowserTargetId,
        frame_id: impl Into<String>,
        url: &str,
    ) {
        let frame_id = FrameId::new(frame_id);
        let frame = self
            .frames
            .entry(frame_id.clone())
            .or_insert_with(|| FrameState {
                id: frame_id,
                target_id: target_id.clone(),
                parent_frame_id: None,
                url: None,
            });
        frame.url = TargetGraphValue::non_empty(url);
        if let Some(target) = self.targets.get_mut(&target_id) {
            target.url = TargetGraphValue::non_empty(url);
            target.status = BrowserTargetStatus::Active;
        }
    }

    pub fn record_execution_context(
        &mut self,
        fallback_target_id: BrowserTargetId,
        context_id: ExecutionContextId,
        origin: Option<String>,
        aux_data: Option<&Value>,
    ) {
        let frame_id = TargetGraphValue::frame_id_from_aux_data(aux_data).map(FrameId::new);
        let target_id = frame_id
            .as_ref()
            .and_then(|frame_id| self.frames.get(frame_id))
            .map_or(fallback_target_id, |frame| frame.target_id.clone());

        self.execution_contexts.insert(
            context_id,
            ExecutionContextState {
                id: context_id,
                target_id,
                frame_id,
                origin,
            },
        );
    }

    fn record_frame_tree_inner(
        &mut self,
        target_id: BrowserTargetId,
        frame_tree: &page::FrameTree,
        parent_frame_id: Option<FrameId>,
        main_frame: bool,
    ) {
        let frame_id = FrameId::new(frame_tree.frame.id.clone());
        self.frames.insert(
            frame_id.clone(),
            FrameState {
                id: frame_id.clone(),
                target_id: target_id.clone(),
                parent_frame_id,
                url: TargetGraphValue::non_empty(&frame_tree.frame.url),
            },
        );

        if main_frame {
            let target = self
                .targets
                .entry(target_id.clone())
                .or_insert_with(|| BrowserTarget::unknown_page(target_id.clone()));
            target.url = TargetGraphValue::non_empty(&frame_tree.frame.url);
            target.status = BrowserTargetStatus::Active;
        }

        if let Some(child_frames) = &frame_tree.child_frames {
            for child_frame in child_frames {
                self.record_frame_tree_inner(
                    target_id.clone(),
                    child_frame,
                    Some(frame_id.clone()),
                    false,
                );
            }
        }
    }
}
