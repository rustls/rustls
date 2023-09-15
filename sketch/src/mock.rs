use std::sync::atomic::{self, AtomicUsize};

use crate::EncryptError;

pub struct ClientState;

thread_local! {
    static CLIENT_STATE: AtomicUsize = AtomicUsize::new(0);
}

impl ClientState {
    pub fn current(&self) -> usize {
        CLIENT_STATE.with(|client_state| client_state.load(atomic::Ordering::Relaxed))
    }

    pub fn advance(&self) -> usize {
        CLIENT_STATE.with(|client_state| client_state.fetch_add(1, atomic::Ordering::Relaxed))
    }
}

pub fn append(
    num_bytes: usize,
    packet_type: &str,
    outgoing_tls: &mut [u8],
) -> Result<usize, EncryptError> {
    if outgoing_tls.len() < num_bytes {
        Err(EncryptError {
            required_size: num_bytes,
        })
    } else {
        eprintln!("<- wrote {packet_type} packet ({num_bytes}B) to outgoing_tls");
        Ok(num_bytes)
    }
}

pub fn process(num_bytes: usize, packet_type: &str) -> usize {
    eprintln!("-> processed {packet_type} packet ({}B)", num_bytes);
    num_bytes
}
