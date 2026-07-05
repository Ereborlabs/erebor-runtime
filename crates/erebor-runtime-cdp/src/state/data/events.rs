use cdp_protocol::{
    page, page::events::NavigatedWithinDocumentEvent, runtime::events::ExecutionContextCreatedEvent,
};

use super::CdpSessionStateData;
use crate::BrowserTargetId;

use crate::state::{projection::SessionStateProjection, PageStatusKind};

impl CdpSessionStateData {
    pub(super) fn record_page_frame_navigated(
        &mut self,
        browser_target_id: Option<BrowserTargetId>,
        frame: &page::Frame,
    ) {
        let page_id = frame
            .parent_id
            .as_ref()
            .and_then(|parent_frame_id| self.frame_to_page.get(parent_frame_id))
            .cloned()
            .unwrap_or_else(|| {
                self.active_page_id
                    .clone()
                    .unwrap_or_else(|| frame.id.clone())
            });
        let page_id = browser_target_id
            .as_ref()
            .map_or(page_id, |target_id| target_id.as_str().to_owned());
        let page = self.page_mut(page_id.clone());
        page.frame_id = Some(frame.id.clone());
        page.url = SessionStateProjection::non_empty(&frame.url);
        page.status = PageStatusKind::Active;
        self.frame_to_page.insert(frame.id.clone(), page_id.clone());
        self.active_page_id = Some(page_id);
        self.target_graph.record_frame_navigated(
            browser_target_id.unwrap_or_else(|| BrowserTargetId::new(frame.id.clone())),
            frame,
        );
    }

    pub(super) fn record_page_navigated_within_document(
        &mut self,
        browser_target_id: Option<BrowserTargetId>,
        event: &NavigatedWithinDocumentEvent,
    ) {
        let page_id = self
            .frame_to_page
            .get(&event.params.frame_id)
            .cloned()
            .unwrap_or_else(|| {
                self.active_page_id
                    .clone()
                    .unwrap_or_else(|| event.params.frame_id.clone())
            });
        let page_id = browser_target_id
            .as_ref()
            .map_or(page_id, |target_id| target_id.as_str().to_owned());
        let page = self.page_mut(page_id.clone());
        page.frame_id = Some(event.params.frame_id.clone());
        page.url = SessionStateProjection::non_empty(&event.params.url);
        page.status = PageStatusKind::Active;
        self.frame_to_page
            .insert(event.params.frame_id.clone(), page_id.clone());
        self.active_page_id = Some(page_id);
        self.target_graph.record_navigated_within_document(
            browser_target_id
                .unwrap_or_else(|| BrowserTargetId::new(event.params.frame_id.clone())),
            event.params.frame_id.clone(),
            &event.params.url,
        );
    }

    pub(super) fn record_execution_context(
        &mut self,
        browser_target_id: Option<BrowserTargetId>,
        event: &ExecutionContextCreatedEvent,
    ) {
        let context = &event.params.context;
        if let Some(frame_id) =
            SessionStateProjection::frame_id_from_aux_data(context.aux_data.as_ref())
        {
            let page_id = self
                .frame_to_page
                .get(&frame_id)
                .cloned()
                .or_else(|| self.active_page_id.clone())
                .unwrap_or_else(|| frame_id.clone());
            self.page_mut(page_id.clone()).frame_id = Some(frame_id.clone());
            self.frame_to_page.insert(frame_id, page_id.clone());
            self.execution_context_to_page.insert(context.id, page_id);
        }
        self.target_graph.record_execution_context(
            browser_target_id.unwrap_or_else(|| {
                self.active_page_id
                    .clone()
                    .map_or_else(|| BrowserTargetId::new("active-page"), BrowserTargetId::new)
            }),
            context.id,
            SessionStateProjection::non_empty(&context.origin),
            context.aux_data.as_ref(),
        );
    }
}
