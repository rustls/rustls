use std::{pin::Pin, future::Future, sync::{Mutex, Arc, atomic::{Ordering, AtomicU64}}, fmt, task::Poll};

use crate::msgs::message::Message;

/// Callback that that would cause this operation to block
/// In order to free this blocking event the future must
/// be polled until completion
pub type WouldBlockCallback = Pin<Box<dyn Future<Output = ()> + Send>>;

static ID_SEED: AtomicU64 = AtomicU64::new(0);

/// The blocking callback cell allows a callback to be passed
/// back to the caller via the result system while being cloned
#[derive(Clone)]
pub struct WouldBlockCell {
    id: u64,
    with_message: Message,
    inner: Arc<Mutex<Option<WouldBlockCallback>>>,
}
impl fmt::Debug
for WouldBlockCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fetch-callback-cell")
    }
}
impl PartialEq for WouldBlockCell {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl WouldBlockCell {
    /// Creates a new cell from a callback
    pub(crate) fn new(callback: WouldBlockCallback, with_message: &Message) -> Self {
        Self {
            id: ID_SEED.fetch_add(1, Ordering::SeqCst),
            with_message: with_message.clone(),
            inner: Arc::new(Mutex::new(Some(callback)))
        }
    }

    /// Get the message that triggered this blocking action
    pub(crate) fn into_msg(self) -> Message {
        self.with_message
    }
}

impl Future
for WouldBlockCell {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(callback) = guard.as_mut() {
            callback.as_mut().poll(cx)
        } else {
            Poll::Ready(())
        }
    }
}
