use alloc::vec::Vec;
use core::fmt;
use core::mem;
use core::ops::{Deref, DerefMut};

use pki_types::FipsStatus;

use super::split::{Joined, ReceivedPayload, SplitConnection};
use super::{ConnectionCommon, Core, Driven, IoState, SideData, Tcp, TlsInputBuffer};
use crate::common_state::ConnectionOutputs;
use crate::crypto::cipher::{OutboundPlain, Payload};
use crate::error::{ApiMisuse, Error};
use crate::suites::ExtractedSecrets;

/// A buffered TLS connection, for either side.
///
/// This drives a handshake (see [`ClientHandshake`] and [`ServerHandshake`]) to completion
/// as data is received, and then the resulting [`SplitConnection`], behind a single object.
///
/// Encrypt data destined for the peer using [`Self::write()`].
/// Process received data from the peer using [`Self::read_tls()`].
///
/// [`ClientHandshake`]: crate::client::ClientHandshake
/// [`ServerHandshake`]: crate::server::ServerHandshake
pub struct Connection<Side: SideData> {
    state: State<Side>,
}

impl<Side: SideData> Connection<Side> {
    pub(crate) fn new_common(common: ConnectionCommon<Side>) -> Self {
        Self {
            state: State::Handshaking(Core::new(common, ())),
        }
    }

    /// Writes the application data from `plaintext` into TLS records and appends them to `tls`.
    ///
    /// Any data appended to `tls` should be sent to the peer.
    ///
    /// This will fail if either the handshake is not complete yet (because we don't yet have the
    /// keys to encrypt application data) or if the send path has been closed by sending a
    /// `close_notify` alert.
    pub fn write(&mut self, plaintext: OutboundPlain<'_>, tls: &mut Vec<u8>) -> Result<(), Error> {
        let traffic = match &mut self.state {
            State::Handshaking(core) => return core.inner.write(plaintext, tls),
            State::Traffic(traffic) => traffic,
            State::Poisoned => return Err(Error::Unreachable(POISONED)),
        };

        if plaintext.is_empty() {
            return Ok(());
        } else if traffic
            .split
            .send
            .has_sent_close_notify()
        {
            return Err(ApiMisuse::WriteTlsAfterSendPathClosed.into());
        }

        traffic.split.send.write(plaintext, tls);
        Ok(())
    }

    /// Build a [`MessageHandler`] to process messages from the `input` buffer.
    ///
    /// Any data appended to `tls` should be sent to the peer.
    pub fn read_tls<'a, 'm>(
        &'a mut self,
        input: &'m mut dyn TlsInputBuffer,
        tls: &'a mut Vec<u8>,
    ) -> MessageHandler<'a, 'm, Side> {
        MessageHandler {
            conn: self,
            tls,
            input: Input::Free(input),
            done: false,
        }
    }

    /// Sends a TLS1.3 `key_update` message into `tls` to refresh a connection's keys.
    ///
    /// The main reason to call this manually is to roll keys when it is known
    /// a connection will be idle for a long period.
    ///
    /// rustls implicitly and automatically refreshes traffic keys when needed
    /// according to the selected cipher suite's cryptographic constraints.  There
    /// is therefore no need to call this manually to avoid cryptographic keys
    /// "wearing out".
    ///
    /// This call refreshes our encryption keys. Once the peer receives the message,
    /// it refreshes _its_ encryption and decryption keys and sends a response.
    /// Once we receive that response, we refresh our decryption keys to match.
    /// At the end of this process, keys in both directions have been refreshed.
    ///
    /// This fails with [`Error::HandshakeNotComplete`] if called before the initial
    /// handshake is complete, or if a version prior to TLS1.3 is negotiated.
    ///
    /// # Usage advice
    /// Note that other implementations (including rustls) may enforce limits on
    /// the number of `key_update` messages allowed on a given connection to prevent
    /// denial of service.  Therefore, this should be called sparingly.
    ///
    /// rustls only allows one outstanding request at a time; this function succeeds
    /// but sends nothing if a request is already in-flight.
    pub fn refresh_traffic_keys(&mut self, tls: &mut Vec<u8>) -> Result<(), Error> {
        match &mut self.state {
            State::Handshaking(core) => core.inner.refresh_traffic_keys(tls),
            State::Traffic(traffic) => traffic
                .split
                .send
                .refresh_traffic_keys(tls),
            State::Poisoned => Err(Error::Unreachable(POISONED)),
        }
    }

    /// Writes a `close_notify` warning alert into `tls`.
    ///
    /// This informs the peer that the connection is being closed.
    ///
    /// Does nothing if any `close_notify` or fatal alert was already sent.
    pub fn send_close_notify(&mut self, tls: &mut Vec<u8>) {
        match &mut self.state {
            State::Handshaking(core) => core.inner.send_close_notify(tls),
            State::Traffic(traffic) => traffic
                .split
                .send
                .send_close_notify(tls),
            State::Poisoned => {}
        }
    }

    /// Extract secrets, so they can be used when configuring kTLS, for example.
    ///
    /// Should be used with care as it exposes secret key material.
    ///
    /// All TLS data previously written into caller-provided buffers must be sent to the peer before
    /// calling this function.
    ///
    /// This fails with [`ApiMisuse::KernelConnectionWithPendingSendData`] if the
    /// connection has pending data to send, which would otherwise be lost.
    /// Write out that pending data before calling this function.
    pub fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        Ok(self
            .split()?
            .dangerous_into_kernel_connection()?
            .0)
    }

    /// Split a post-handshake connection into a [`SplitConnection`].
    ///
    /// This allows the two directions (transmit and receive) of the connection to be progressed
    /// separately (including by different threads, which would allow dedicating a CPU core for each
    /// direction rather than one per connection; this can dramatically improve performance for
    /// full-duplex protocols).
    ///
    /// It also separates out the [`ConnectionOutputs`] which gives the application direct control
    /// of how long this is kept.
    ///
    /// This fails if:
    ///
    /// - the handshake is not complete. Check with [`Self::is_handshaking()`].
    /// - there is any buffered TLS data to send.  Obtain it first with [`Self::write()`].
    pub fn split(self) -> Result<SplitConnection<Side>, Error> {
        match self.state {
            State::Handshaking(_) => Err(ApiMisuse::SplitDuringHandshake.into()),
            State::Traffic(traffic) => Ok(traffic.split),
            State::Poisoned => Err(Error::Unreachable(POISONED)),
        }
    }

    /// Returns true if the caller should call [`Self::read_tls()`] as soon as possible.
    pub fn wants_read(&self) -> bool {
        match &self.state {
            State::Handshaking(core) => core.inner.wants_read(),
            State::Traffic(traffic) => !traffic
                .split
                .receive
                .has_received_close_notify(),
            State::Poisoned => false,
        }
    }

    /// Returns true if the connection is currently performing the TLS handshake.
    ///
    /// During this time, [`Self::write()`] will return an error.
    pub fn is_handshaking(&self) -> bool {
        matches!(self.state, State::Handshaking(_))
    }

    /// Return the FIPS validation status of the connection.
    ///
    /// This is different from [`CryptoProvider::fips()`][]:
    /// it is concerned only with cryptography, whereas this _also_ covers TLS-level
    /// configuration that NIST recommends, as well as ECH HPKE suites if applicable.
    ///
    /// [`CryptoProvider::fips()`]: crate::crypto::CryptoProvider::fips()
    pub fn fips(&self) -> FipsStatus {
        match &self.state {
            State::Handshaking(core) => core.inner.fips,
            State::Traffic(traffic) => traffic.fips,
            State::Poisoned => FipsStatus::Unvalidated,
        }
    }

    /// Returns data learned during the connection, specific to this side.
    ///
    /// This is [`ClientConnectionData`] for clients and [`ServerConnectionData`] for servers.
    ///
    /// [`ClientConnectionData`]: crate::client::ClientConnectionData
    /// [`ServerConnectionData`]: crate::server::ServerConnectionData
    pub fn side_data(&self) -> &Side::Data {
        match &self.state {
            State::Handshaking(core) => &core.inner.side,
            State::Traffic(traffic) => &traffic.split.side_outputs,
            State::Poisoned => unreachable!("{POISONED}"),
        }
    }

    /// Returns data learned during the connection, specific to this side.
    ///
    /// See [`Self::side_data()`].
    pub fn side_data_mut(&mut self) -> &mut Side::Data {
        match &mut self.state {
            State::Handshaking(core) => &mut core.inner.side,
            State::Traffic(traffic) => &mut traffic.split.side_outputs,
            State::Poisoned => unreachable!("{POISONED}"),
        }
    }

    pub(crate) fn handshaking(&mut self) -> Option<&mut ConnectionCommon<Side>> {
        match &mut self.state {
            State::Handshaking(core) => Some(&mut core.inner),
            _ => None,
        }
    }

    pub(crate) fn tickets_received(&self) -> u32 {
        match &self.state {
            State::Handshaking(core) => {
                core.inner
                    .common
                    .recv
                    .tls13_tickets_received
            }
            State::Traffic(traffic) => {
                traffic
                    .split
                    .receive
                    .recv
                    .tls13_tickets_received
            }
            State::Poisoned => 0,
        }
    }
}

impl<Side: SideData> Deref for Connection<Side> {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        match &self.state {
            State::Handshaking(core) => &core.inner,
            State::Traffic(traffic) => &traffic.split.outputs,
            State::Poisoned => unreachable!("{POISONED}"),
        }
    }
}

impl<Side: SideData> DerefMut for Connection<Side> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.state {
            State::Handshaking(core) => &mut core.inner,
            State::Traffic(traffic) => &mut traffic.split.outputs,
            State::Poisoned => unreachable!("{POISONED}"),
        }
    }
}

impl<Side: SideData> fmt::Debug for Connection<Side> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("handshaking", &self.is_handshaking())
            .finish_non_exhaustive()
    }
}

enum State<Side: SideData> {
    /// The handshake is in progress, or has failed.
    ///
    /// A failed handshake retains its outputs and send path, so that an alert can
    /// still be sent and the error observed.
    Handshaking(Core<Side, Tcp>),

    /// The handshake is complete.
    Traffic(Traffic<Side>),

    /// Placeholder during state transitions.
    Poisoned,
}

struct Traffic<Side: SideData> {
    split: SplitConnection<Side>,
    fips: FipsStatus,
}

impl<Side: SideData> TryFrom<Core<Side, Tcp>> for Traffic<Side> {
    type Error = Error;

    fn try_from(core: Core<Side, Tcp>) -> Result<Self, Error> {
        let fips = core.inner.fips;
        Ok(Self {
            split: SplitConnection::try_from(core.inner)?,
            fips,
        })
    }
}

/// Driver for handling messages from the [`TlsInputBuffer`].
///
/// Must be driven to completion to make progress, by calling either [`Self::handle_all()`] or
/// repeatedly calling [`Self::next_payload()`] until it returns `None`.
///
/// Backpressure is provided by the [`TlsInputBuffer`] implementation. When using a [`VecInput`]
/// buffer, [`VecInput::read()`] will not ingest more data once the internal buffer is full.
///
/// [`VecInput`]: crate::VecInput
/// [`VecInput::read()`]: crate::VecInput::read()
#[must_use]
pub struct MessageHandler<'a, 'm, Side: SideData> {
    conn: &'a mut Connection<Side>,
    tls: &'a mut Vec<u8>,
    input: Input<'m>,
    done: bool,
}

impl<'a, 'm, Side: SideData> MessageHandler<'a, 'm, Side> {
    /// Handles all complete messages from the input buffer.
    ///
    /// Writes any plaintext application data from the input into `buf`, and returns the I/O
    /// state of the connection after processing the last message. If an error is returned,
    /// the connection is in a fatal error state and no further progress can be made. After
    /// an error is received from this function, you should not continue to fill up the buffer.
    ///
    /// However, you may call the other methods on the connection, including
    /// [`Connection::send_close_notify()`]. Any alert produced by the error will have
    /// been appended to the `tls` buffer; most likely you will want to send that data
    /// to the peer and then close the underlying connection.
    pub fn handle_all(mut self, buf: &mut Vec<u8>) -> Result<IoState, Error> {
        while let Some(result) = self.next_payload() {
            buf.extend_from_slice(result?.bytes());
        }

        Ok(self.state())
    }

    /// Yields the first payload of plaintext application data from the input buffer.
    ///
    /// Should be called repeatedly until it returns `None`, at which point the input buffer no
    /// longer contains any complete messages and should be refilled by the application.
    pub fn next_payload(&mut self) -> Option<Result<Payload<'_>, Error>> {
        if self.done {
            return None;
        }

        let input = match mem::replace(&mut self.input, Input::Taken) {
            Input::Free(input) => input,
            Input::Held(payload) => payload.finish(),
            Input::Taken => {
                self.done = true;
                return Some(Err(Error::Unreachable("input was not retained")));
            }
        };

        match self.conn.advance(input, self.tls) {
            Ok(Joined::Payload(payload)) => {
                self.input = Input::Held(payload);
            }
            Ok(Joined::Exhausted(input)) => {
                self.input = Input::Free(input);
                self.done = true;
                return None;
            }
            Err((err, input)) => {
                self.input = Input::Free(input);
                self.done = true;
                return Some(Err(err));
            }
        }

        let Input::Held(payload) = &mut self.input else {
            return Some(Err(Error::Unreachable("payload was not retained")));
        };
        Some(Ok(Payload::Borrowed(payload.data())))
    }

    /// The I/O state of the connection after processing the last message.
    pub fn state(self) -> IoState {
        IoState {
            peer_has_closed: !self.conn.wants_read(),
        }
    }
}

impl<Side: SideData> fmt::Debug for MessageHandler<'_, '_, Side> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageHandler")
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

enum Input<'m> {
    /// The input buffer is available for reading.
    Free(&'m mut dyn TlsInputBuffer),

    /// The input buffer is borrowed by a received payload.
    Held(ReceivedPayload<'m>),

    /// Placeholder during state transitions.
    Taken,
}

impl<Side: SideData> Connection<Side> {
    /// Make progress using `input`, until a payload is available, the input is exhausted,
    /// or an error occurs.
    ///
    /// `input` is returned unless it is borrowed by the returned payload.
    fn advance<'m>(
        &mut self,
        input: &'m mut dyn TlsInputBuffer,
        tls: &mut Vec<u8>,
    ) -> Result<Joined<'m>, (Error, &'m mut dyn TlsInputBuffer)> {
        loop {
            let traffic = match &mut self.state {
                State::Handshaking(_) => {
                    if let Err(err) = self.handshake(&mut *input, tls) {
                        return Err((err, input));
                    }
                    continue;
                }
                State::Traffic(traffic) => traffic,
                State::Poisoned => return Err((Error::Unreachable(POISONED), input)),
            };

            let receive = &mut traffic.split.receive;
            let result = receive.read_joined(input);
            receive.flush(tls);
            return result;
        }
    }

    /// Progress the handshake using `input`.
    ///
    /// On return without error, either the handshake is complete (and `self.state` is
    /// [`State::Traffic`]), or `input` is exhausted.
    fn handshake(
        &mut self,
        input: &mut dyn TlsInputBuffer,
        tls: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let State::Handshaking(core) = mem::replace(&mut self.state, State::Poisoned) else {
            return Err(Error::Unreachable(POISONED));
        };

        let core = match core.process(input, tls) {
            Ok(core) => core,
            Err((core, err)) => {
                self.state = State::Handshaking(core);
                return Err(err);
            }
        };

        let core = match Side::drive(core, tls)? {
            Driven::NeedsInput(core) => {
                let err = core.error().cloned();
                self.state = State::Handshaking(core);
                return err.map_or(Ok(()), Err);
            }
            Driven::Complete(core) => core,
        };

        self.state = State::Traffic(Traffic::try_from(core)?);
        Ok(())
    }
}

const POISONED: &str = "connection state was not restored";
