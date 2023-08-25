/// the flags in this struct must be handled in the following order
/// - `received_early_data`
/// - `received_app_data`
/// - `may_send_early_data`
/// - `may_send_app_data`
/// - `wants_write`
/// - `wants_read`
/// - `may_receive_app_data`
#[derive(Default, Clone, Copy)]
#[must_use]
pub struct Status {
    pub(super) may_receive_app_data: bool,
    pub(super) may_send_app_data: bool,
    pub(super) may_send_early_data: bool,
    pub(super) received_app_data: bool,
    pub(super) received_early_data: bool,
    pub(super) wants_read: bool,
    pub(super) wants_write: bool,
}

impl Status {
    /// Handshake is complete. New TLS data will be application data
    pub fn may_receive_app_data(&self) -> bool {
        self.may_receive_app_data
    }

    /// `encrypt_outgoing` may now be used
    pub fn may_send_app_data(&self) -> bool {
        self.may_send_app_data
    }

    /// `encrypt_early_data` may now be used
    pub fn may_send_early_data(&self) -> bool {
        self.may_send_early_data
    }

    /// `incoming_tls` has application data that `decrypt_incoming` can decrypt
    pub fn received_app_data(&self) -> bool {
        self.received_app_data
    }

    /// `incoming_tls` has early ("0-RTT") data that `decrypt_early_data` can decrypt
    pub fn received_early_data(&self) -> bool {
        self.received_early_data
    }

    /// More TLS data needs to be added to the `incoming_tls` buffer to continue with the
    /// handshake process
    ///
    /// after new data has been appended to `incoming_tls` buffer, `handle_tls_record` must
    /// be called
    pub fn wants_read(&self) -> bool {
        self.wants_read
    }

    /// TLS records related to the handshake has been placed in the `outgoing_tls` buffer and
    /// must be transmitted to continue with the handshake process
    pub fn wants_write(&self) -> bool {
        self.wants_write
    }
}
