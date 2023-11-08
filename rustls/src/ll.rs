//! Low-level Connection API

use alloc::collections::VecDeque;

use crate::crypto::cipher::OpaqueMessage;
use crate::msgs::base::Payload;

#[derive(Default)]
pub(crate) struct LlDeferredActions {
    inner: VecDeque<LlDeferredAction>,
}

impl LlDeferredActions {
    pub(crate) fn queue_tls_message(&mut self, m: OpaqueMessage) {
        self.inner
            .push_back(LlDeferredAction::QueueTlsMessage { m });
    }

    pub(crate) fn take_received_plaintext(&mut self, bytes: Payload) {
        self.inner
            .push_back(LlDeferredAction::ReceivedPlainText { bytes });
    }
}

#[allow(dead_code)]
enum LlDeferredAction {
    QueueTlsMessage { m: OpaqueMessage },
    ReceivedPlainText { bytes: Payload },
}
