use core::sync::atomic::{AtomicUsize, Ordering};

pub struct ClientState;

thread_local! {
    static CLIENT_STATE: AtomicUsize = AtomicUsize::new(0);
    static SERVER_STATE: AtomicUsize = AtomicUsize::new(0);
}

impl ClientState {
    pub fn advance(&self) -> usize {
        CLIENT_STATE.with(|state| state.fetch_add(1, Ordering::Relaxed))
    }

    pub fn current(&self) -> usize {
        CLIENT_STATE.with(|state| state.load(Ordering::Relaxed))
    }
}

pub struct ServerState;

impl ServerState {
    pub fn advance(&self) -> usize {
        SERVER_STATE.with(|state| state.fetch_add(1, Ordering::Relaxed))
    }

    pub fn current(&self) -> usize {
        SERVER_STATE.with(|state| state.load(Ordering::Relaxed))
    }
}

pub fn append(num_bytes: usize, packet_type: &str, outgoing_tls: &mut Vec<u8>) {
    outgoing_tls.extend(core::iter::repeat(0).take(num_bytes));
    eprintln!("<- wrote {packet_type} packet ({num_bytes}B) to outgoing_tls");
}

pub fn process(num_bytes: usize, packet_type: &str, incoming_tls_new_end: &mut usize) {
    eprintln!("-> processed {packet_type} packet ({}B)", num_bytes);
    *incoming_tls_new_end += num_bytes;
}
