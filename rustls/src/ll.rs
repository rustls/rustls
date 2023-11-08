//! Low-level Connection API

use alloc::collections::VecDeque;
use core::num::NonZeroUsize;
use core::{fmt, mem};

use crate::conn::LlConnectionCore;
use crate::crypto::cipher::OpaqueMessage;
use crate::msgs::base::Payload;
use crate::Error;

/// Interface shared by client and server connections.
pub struct LlConnectionCommon<Data> {
    core: LlConnectionCore<Data>,
    wants_write: bool,
}

impl<Data> From<LlConnectionCore<Data>> for LlConnectionCommon<Data> {
    fn from(core: LlConnectionCore<Data>) -> Self {
        Self {
            core,
            wants_write: false,
        }
    }
}

impl<Data> LlConnectionCommon<Data> {
    /// Processes TLS records in the `incoming_tls` buffer
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> Result<LlStatus<'c, 'i, Data>, Error> {
        let mut discard = 0;

        let ll_state = 'outer: loop {
            // process deferred actions that may have been produced by `State::handle` in the
            // last iteration of this loop
            while let Some(action) = self.core.deferred_actions.pop() {
                match action {
                    LlDeferredAction::QueueTlsMessage { m } => {
                        break 'outer MustEncodeTlsData::new(self, m).into()
                    }
                    LlDeferredAction::ReceivedPlainText { bytes } => {
                        break 'outer AppDataAvailable::new(self, incoming_tls, bytes).into();
                    }
                }
            }

            if let Some((new_discard, message)) = self
                .core
                .deframe(&mut incoming_tls[discard..])?
            {
                discard += new_discard;

                let mut state =
                    match mem::replace(&mut self.core.state, Err(Error::HandshakeNotComplete)) {
                        Ok(state) => state,
                        Err(e) => {
                            self.core.state = Err(e.clone());
                            return Err(e);
                        }
                    };

                match self.core.process_msg(message, state) {
                    Ok(new) => state = new,
                    Err(e) => {
                        self.core.state = Err(e.clone());
                        return Err(e);
                    }
                }

                self.core.state = Ok(state);
            } else if self.wants_write {
                let may_send_application_data = self
                    .core
                    .common_state
                    .may_send_application_data;

                break MustTransmitTlsData {
                    conn: self,
                    may_send_application_data,
                }
                .into();
            } else if self
                .core
                .common_state
                .has_received_close_notify
            {
                break LlState::ConnectionClosed;
            } else if self
                .core
                .common_state
                .may_send_application_data
            {
                break LlState::TrafficTransit(MayEncryptAppData { conn: self });
            } else {
                break LlState::NeedsMoreTlsData { num_bytes: None };
            }
        };

        Ok(LlStatus {
            discard,
            state: ll_state,
        })
    }
}

/// The current status of the `LlConnection*`
#[must_use]
pub struct LlStatus<'c, 'i, Data> {
    /// number of bytes that must be discarded from the *front* of `incoming_tls` *after* handling
    /// `state` and *before* the next `process_tls_records` call
    pub discard: usize,

    /// the current state of the handshake process
    pub state: LlState<'c, 'i, Data>,
}

/// The current state of the `LlConnection*`
#[non_exhaustive] // for forwards compatibility; to support caller-side certificate verification
pub enum LlState<'c, 'i, Data> {
    /// One, or more, application data record is available
    AppDataAvailable(AppDataAvailable<'c, 'i, Data>),

    /// A Handshake record must be encoded into the `outgoing_tls` buffer
    MustEncodeTlsData(MustEncodeTlsData<'c, Data>),

    /// TLS records related to the handshake have been placed in the `outgoing_tls` buffer and must
    /// be transmitted to continue with the handshake process
    MustTransmitTlsData(MustTransmitTlsData<'c, Data>),

    /// More TLS data needs to be added to the `incoming_tls` buffer to continue with the handshake
    NeedsMoreTlsData {
        /// number of bytes required to complete a TLS record. `None` indicates that
        /// no information is available
        num_bytes: Option<NonZeroUsize>,
    },

    /// Handshake is complete.
    TrafficTransit(MayEncryptAppData<'c, Data>),

    /// Connection has been closed.
    ConnectionClosed,
}

impl<Data> fmt::Debug for LlState<'_, '_, Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppDataAvailable(..) => f
                .debug_tuple("AppDataAvailable")
                .finish(),
            Self::MustEncodeTlsData(..) => f
                .debug_tuple("MustEncodeTlsData")
                .finish(),
            Self::MustTransmitTlsData(..) => f
                .debug_tuple("MustTransmitTlsData")
                .finish(),
            Self::NeedsMoreTlsData { num_bytes } => f
                .debug_struct("NeedsMoreTlsData")
                .field("num_bytes", num_bytes)
                .finish(),
            Self::TrafficTransit(..) => f.debug_tuple("TrafficTransit").finish(),
            Self::ConnectionClosed => write!(f, "ConnectionClosed"),
        }
    }
}

impl<'c, 'i, Data> From<MustTransmitTlsData<'c, Data>> for LlState<'c, 'i, Data> {
    fn from(v: MustTransmitTlsData<'c, Data>) -> Self {
        Self::MustTransmitTlsData(v)
    }
}

impl<'c, 'i, Data> From<MustEncodeTlsData<'c, Data>> for LlState<'c, 'i, Data> {
    fn from(v: MustEncodeTlsData<'c, Data>) -> Self {
        Self::MustEncodeTlsData(v)
    }
}

impl<'c, 'i, Data> From<AppDataAvailable<'c, 'i, Data>> for LlState<'c, 'i, Data> {
    fn from(v: AppDataAvailable<'c, 'i, Data>) -> Self {
        Self::AppDataAvailable(v)
    }
}

/// Application-data is available
pub struct AppDataAvailable<'c, 'i, Data> {
    _conn: &'c mut LlConnectionCommon<Data>,
    // for forwards compatibility; to support in-place decryption in the future
    _incoming_tls: &'i mut [u8],
    payload: Payload,
    taken: bool,
}

impl<'c, 'i, Data> AppDataAvailable<'c, 'i, Data> {
    fn new(
        _conn: &'c mut LlConnectionCommon<Data>,
        _incoming_tls: &'i mut [u8],
        payload: Payload,
    ) -> Self {
        Self {
            _conn,
            _incoming_tls,
            payload,
            taken: false,
        }
    }

    /// decrypts and returns the next available app-data record
    // TODO deprecate in favor of `Iterator` implementation, which requires in-place decryption
    pub fn next_record(&mut self) -> Option<Result<AppDataRecord, Error>> {
        if self.taken {
            None
        } else {
            self.taken = true;
            Some(Ok(AppDataRecord {
                discard: 0,
                payload: &self.payload.0,
            }))
        }
    }

    /// returns the payload size of the next app-data record *without* decrypting it
    ///
    /// returns `None` if there are no more app-data records
    pub fn peek_len(&self) -> Option<NonZeroUsize> {
        if self.taken {
            None
        } else {
            NonZeroUsize::new(self.payload.0.len())
        }
    }
}

/// A decrypted application-data record
pub struct AppDataRecord<'i> {
    /// Number of additional bytes to discard from the front of `incoming_tls` before the next
    /// call to `process_tls_records`
    pub discard: usize,

    /// The payload of the app-data record
    pub payload: &'i [u8],
}

/// A handshake record must be encoded
pub struct MustEncodeTlsData<'c, Data> {
    conn: &'c mut LlConnectionCommon<Data>,
    message: Option<OpaqueMessage>,
}

impl<'c, Data> MustEncodeTlsData<'c, Data> {
    fn new(conn: &'c mut LlConnectionCommon<Data>, message: OpaqueMessage) -> Self {
        Self {
            conn,
            message: Some(message),
        }
    }

    /// Encodes a handshake record into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encode(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncodeError> {
        let Some(message) = self.message.take() else {
            return Err(EncodeError::AlreadyEncoded);
        };

        let required_size = message.encode_len();

        if required_size > outgoing_tls.len() {
            self.message = Some(message);
            Err(InsufficientSizeError { required_size }.into())
        } else {
            let bytes = message.encode();
            let written = bytes.len();

            debug_assert_eq!(required_size, written);

            outgoing_tls[..written].copy_from_slice(&bytes);

            self.conn.wants_write = true;

            Ok(written)
        }
    }
}

/// Errors that may arise when encoding a handshake record
#[derive(Debug)]
pub enum EncodeError {
    /// Provided buffer was too small
    InsufficientSize(InsufficientSizeError),

    /// The handshake record has already been encoded; do not call `encode` again
    AlreadyEncoded,
}

impl From<InsufficientSizeError> for EncodeError {
    fn from(v: InsufficientSizeError) -> Self {
        Self::InsufficientSize(v)
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSize(InsufficientSizeError { required_size }) => write!(
                f,
                "cannot encode due to insufficient size, {} bytes are required",
                required_size
            ),
            Self::AlreadyEncoded => "cannot encode, data has already been encoded".fmt(f),
        }
    }
}

/// Errors that may arise when encrypting application data
#[derive(Debug)]
pub enum EncryptError {
    /// Provided buffer was too small
    InsufficientSize(InsufficientSizeError),

    /// Encrypter has been exhausted
    EncryptExhausted,
}

impl From<InsufficientSizeError> for EncryptError {
    fn from(v: InsufficientSizeError) -> Self {
        Self::InsufficientSize(v)
    }
}

/// Provided buffer was too small
#[derive(Debug)]
pub struct InsufficientSizeError {
    /// buffer must be at least this size
    pub required_size: usize,
}

impl std::error::Error for EncodeError {}

/// Previously encoded TLS data must be transmitted
pub struct MustTransmitTlsData<'c, Data> {
    conn: &'c mut LlConnectionCommon<Data>,
    may_send_application_data: bool,
}

impl<Data> MustTransmitTlsData<'_, Data> {
    /// signals the `LlConnection*` API that the TLS data has been transmitted
    pub fn done(self) {
        self.conn.wants_write = false;
    }

    /// returns an adapter that allows encrypting app-data before transmitting the already encoded
    /// TLS data
    ///
    /// IF allowed by the protocol
    // XXX unclear if this stage can be reached in practice
    pub fn may_encrypt(&mut self) -> Option<MayEncryptAppData<Data>> {
        if self.may_send_application_data {
            Some(MayEncryptAppData { conn: self.conn })
        } else {
            None
        }
    }
}

/// Allows encrypting app-data
pub struct MayEncryptAppData<'c, Data> {
    conn: &'c mut LlConnectionCommon<Data>,
}

impl<Data> MayEncryptAppData<'_, Data> {
    /// Encrypts `application_data` into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        self.conn
            .core
            .common_state
            .eager_send_some_plaintext(application_data, outgoing_tls)
    }
}

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

    fn pop(&mut self) -> Option<LlDeferredAction> {
        self.inner.pop_front()
    }
}

enum LlDeferredAction {
    QueueTlsMessage { m: OpaqueMessage },
    ReceivedPlainText { bytes: Payload },
}
