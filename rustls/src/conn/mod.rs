use alloc::boxed::Box;
use core::fmt::{self, Debug};
use core::mem;
use core::ops::{Deref, DerefMut};
use std::io;

use kernel::KernelConnection;

use crate::common_state::{
    CaptureAppData, CommonState, DEFAULT_BUFFER_LIMIT, Event, EventDisposition, Input, JoinOutput,
    Output, ReceivePath, SplitReceive, State, UnborrowedPayload, maybe_send_fatal_alert,
};
use crate::crypto::cipher::Decrypted;
use crate::error::{AlertDescription, ApiMisuse, Error};
use crate::msgs::{
    AlertLevel, BufferProgress, DeframerVecBuffer, Delocator, Locator, Message, Random,
    TlsInputBuffer,
};
use crate::suites::ExtractedSecrets;
use crate::vecbuf::ChunkVecBuffer;

// pub so that it can be re-exported from the crate root
pub mod kernel;
pub(crate) mod unbuffered;

mod connection {
    use alloc::vec::Vec;
    use core::fmt::Debug;
    use core::ops::{Deref, DerefMut};
    use std::io::{self, BufRead, Read};

    use crate::common_state::ConnectionOutputs;
    use crate::conn::{ConnectionCommon, IoState, KeyingMaterialExporter, SideData};
    use crate::crypto::cipher::OutboundPlain;
    use crate::error::Error;
    use crate::suites::ExtractedSecrets;
    use crate::vecbuf::ChunkVecBuffer;

    /// A trait generalizing over buffered client or server connections.
    pub trait Connection: Debug + Deref<Target = ConnectionOutputs> + DerefMut {
        /// Read TLS content from `rd` into the internal buffer.
        ///
        /// Due to the internal buffering, `rd` can supply TLS messages in arbitrary-sized chunks (like
        /// a socket or pipe might).
        ///
        /// You should call [`process_new_packets()`] each time a call to this function succeeds in order
        /// to empty the incoming TLS data buffer.
        ///
        /// This function returns `Ok(0)` when the underlying `rd` does so. This typically happens when
        /// a socket is cleanly closed, or a file is at EOF. Errors may result from the IO done through
        /// `rd`; additionally, errors of `ErrorKind::Other` are emitted to signal backpressure:
        ///
        /// * In order to empty the incoming TLS data buffer, you should call [`process_new_packets()`]
        ///   each time a call to this function succeeds.
        /// * In order to empty the incoming plaintext data buffer, you should empty it through
        ///   the [`reader()`] after the call to [`process_new_packets()`].
        ///
        /// This function also returns `Ok(0)` once a `close_notify` alert has been successfully
        /// received.  No additional data is ever read in this state.
        ///
        /// [`process_new_packets()`]: Connection::process_new_packets
        /// [`reader()`]: Connection::reader
        fn read_tls(&mut self, rd: &mut dyn Read) -> Result<usize, io::Error>;

        /// Writes TLS messages to `wr`.
        ///
        /// On success, this function returns `Ok(n)` where `n` is a number of bytes written to `wr`
        /// (after encoding and encryption).
        ///
        /// After this function returns, the connection buffer may not yet be fully flushed. The
        /// [`Connection::wants_write()`] function can be used to check if the output buffer is
        /// empty.
        fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error>;

        /// Returns true if the caller should call [`Connection::read_tls`] as soon
        /// as possible.
        ///
        /// If there is pending plaintext data to read with [`Connection::reader`],
        /// this returns false.  If your application respects this mechanism,
        /// only one full TLS message will be buffered by rustls.
        ///
        /// [`Connection::reader`]: crate::Connection::reader
        /// [`Connection::read_tls`]: crate::Connection::read_tls
        fn wants_read(&self) -> bool;

        /// Returns true if the caller should call [`Connection::write_tls`] as soon as possible.
        ///
        /// [`Connection::write_tls`]: crate::Connection::write_tls
        fn wants_write(&self) -> bool;

        /// Returns an object that allows reading plaintext.
        fn reader(&mut self) -> Reader<'_>;

        /// Returns an object that allows writing plaintext.
        fn writer(&mut self) -> Writer<'_>;

        /// Processes any new packets read by a previous call to
        /// [`Connection::read_tls`].
        ///
        /// Errors from this function relate to TLS protocol errors, and
        /// are fatal to the connection.  Future calls after an error will do
        /// no new work and will return the same error. After an error is
        /// received from [`process_new_packets()`], you should not call [`read_tls()`]
        /// any more (it will fill up buffers to no purpose). However, you
        /// may call the other methods on the connection, including `write`,
        /// `send_close_notify`, and `write_tls`. Most likely you will want to
        /// call `write_tls` to send any alerts queued by the error and then
        /// close the underlying connection.
        ///
        /// Success from this function comes with some sundry state data
        /// about the connection.
        ///
        /// [`process_new_packets()`]: Connection::process_new_packets
        /// [`read_tls()`]: Connection::read_tls
        fn process_new_packets(&mut self) -> Result<IoState, Error>;

        /// Returns an object that can derive key material from the agreed connection secrets.
        ///
        /// See [RFC5705][] for more details on what this is for.
        ///
        /// This function can be called at most once per connection.
        ///
        /// This function will error:
        ///
        /// - if called prior to the handshake completing; (check with
        ///   [`Connection::is_handshaking()`] first).
        /// - if called more than once per connection.
        ///
        /// [RFC5705]: https://datatracker.ietf.org/doc/html/rfc5705
        fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error>;

        /// Extract secrets, so they can be used when configuring kTLS, for example.
        ///
        /// Should be used with care as it exposes secret key material.
        fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error>;

        /// Sets a limit on the internal buffers used to buffer
        /// unsent plaintext (prior to completing the TLS handshake)
        /// and unsent TLS records.  This limit acts only on application
        /// data written through [`Connection::writer`].
        ///
        /// By default the limit is 64KB.  The limit can be set
        /// at any time, even if the current buffer use is higher.
        ///
        /// [`None`] means no limit applies, and will mean that written
        /// data is buffered without bound -- it is up to the application
        /// to appropriately schedule its plaintext and TLS writes to bound
        /// memory usage.
        ///
        /// For illustration: `Some(1)` means a limit of one byte applies:
        /// [`Connection::writer`] will accept only one byte, encrypt it and
        /// add a TLS header.  Once this is sent via [`Connection::write_tls`],
        /// another byte may be sent.
        ///
        /// # Internal write-direction buffering
        /// rustls has two buffers whose size are bounded by this setting:
        ///
        /// ## Buffering of unsent plaintext data prior to handshake completion
        ///
        /// Calls to [`Connection::writer`] before or during the handshake
        /// are buffered (up to the limit specified here).  Once the
        /// handshake completes this data is encrypted and the resulting
        /// TLS records are added to the outgoing buffer.
        ///
        /// ## Buffering of outgoing TLS records
        ///
        /// This buffer is used to store TLS records that rustls needs to
        /// send to the peer.  It is used in these two circumstances:
        ///
        /// - by [`Connection::process_new_packets`] when a handshake or alert
        ///   TLS record needs to be sent.
        /// - by [`Connection::writer`] post-handshake: the plaintext is
        ///   encrypted and the resulting TLS record is buffered.
        ///
        /// This buffer is emptied by [`Connection::write_tls`].
        ///
        /// [`Connection::writer`]: crate::Connection::writer
        /// [`Connection::write_tls`]: crate::Connection::write_tls
        /// [`Connection::process_new_packets`]: crate::Connection::process_new_packets
        fn set_buffer_limit(&mut self, limit: Option<usize>);

        /// Sets a limit on the internal buffers used to buffer decoded plaintext.
        ///
        /// See [`Self::set_buffer_limit`] for more information on how limits are applied.
        fn set_plaintext_buffer_limit(&mut self, limit: Option<usize>);

        /// Sends a TLS1.3 `key_update` message to refresh a connection's keys.
        ///
        /// This call refreshes our encryption keys. Once the peer receives the message,
        /// it refreshes _its_ encryption and decryption keys and sends a response.
        /// Once we receive that response, we refresh our decryption keys to match.
        /// At the end of this process, keys in both directions have been refreshed.
        ///
        /// Note that this process does not happen synchronously: this call just
        /// arranges that the `key_update` message will be included in the next
        /// `write_tls` output.
        ///
        /// This fails with `Error::HandshakeNotComplete` if called before the initial
        /// handshake is complete, or if a version prior to TLS1.3 is negotiated.
        ///
        /// # Usage advice
        /// Note that other implementations (including rustls) may enforce limits on
        /// the number of `key_update` messages allowed on a given connection to prevent
        /// denial of service.  Therefore, this should be called sparingly.
        ///
        /// rustls implicitly and automatically refreshes traffic keys when needed
        /// according to the selected cipher suite's cryptographic constraints.  There
        /// is therefore no need to call this manually to avoid cryptographic keys
        /// "wearing out".
        ///
        /// The main reason to call this manually is to roll keys when it is known
        /// a connection will be idle for a long period.
        fn refresh_traffic_keys(&mut self) -> Result<(), Error>;

        /// Queues a `close_notify` warning alert to be sent in the next
        /// [`Connection::write_tls`] call.  This informs the peer that the
        /// connection is being closed.
        ///
        /// Does nothing if any `close_notify` or fatal alert was already sent.
        ///
        /// [`Connection::write_tls`]: crate::Connection::write_tls
        fn send_close_notify(&mut self);

        /// Returns true if the connection is currently performing the TLS handshake.
        ///
        /// During this time plaintext written to the connection is buffered in memory. After
        /// [`Connection::process_new_packets()`] has been called, this might start to return `false`
        /// while the final handshake packets still need to be extracted from the connection's buffers.
        ///
        /// [`Connection::process_new_packets()`]: crate::Connection::process_new_packets
        fn is_handshaking(&self) -> bool;
    }

    /// A structure that implements [`std::io::Read`] for reading plaintext.
    pub struct Reader<'a> {
        pub(super) received_plaintext: &'a mut ChunkVecBuffer,
        pub(super) has_received_close_notify: bool,
        pub(super) has_seen_eof: bool,
    }

    impl<'a> Reader<'a> {
        /// Check the connection's state if no bytes are available for reading.
        fn check_no_bytes_state(&self) -> io::Result<()> {
            match (self.has_received_close_notify, self.has_seen_eof) {
                // cleanly closed; don't care about TCP EOF: express this as Ok(0)
                (true, _) => Ok(()),
                // unclean closure
                (false, true) => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    UNEXPECTED_EOF_MESSAGE,
                )),
                // connection still going, but needs more data: signal `WouldBlock` so that
                // the caller knows this
                (false, false) => Err(io::ErrorKind::WouldBlock.into()),
            }
        }

        /// Obtain a chunk of plaintext data received from the peer over this TLS connection.
        ///
        /// This method consumes `self` so that it can return a slice whose lifetime is bounded by
        /// the [`Connection`] that created this [`Reader`].
        pub fn into_first_chunk(self) -> io::Result<&'a [u8]> {
            match self.received_plaintext.chunk() {
                Some(chunk) => Ok(chunk),
                None => {
                    self.check_no_bytes_state()?;
                    Ok(&[])
                }
            }
        }
    }

    impl Read for Reader<'_> {
        /// Obtain plaintext data received from the peer over this TLS connection.
        ///
        /// If the peer closes the TLS session cleanly, this returns `Ok(0)`  once all
        /// the pending data has been read. No further data can be received on that
        /// connection, so the underlying TCP connection should be half-closed too.
        ///
        /// If the peer closes the TLS session uncleanly (a TCP EOF without sending a
        /// `close_notify` alert) this function returns a `std::io::Error` of type
        /// `ErrorKind::UnexpectedEof` once any pending data has been read.
        ///
        /// Note that support for `close_notify` varies in peer TLS libraries: many do not
        /// support it and uncleanly close the TCP connection (this might be
        /// vulnerable to truncation attacks depending on the application protocol).
        /// This means applications using rustls must both handle EOF
        /// from this function, *and* unexpected EOF of the underlying TCP connection.
        ///
        /// If there are no bytes to read, this returns `Err(ErrorKind::WouldBlock.into())`.
        ///
        /// You may learn the number of bytes available at any time by inspecting
        /// the return of [`Connection::process_new_packets`].
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = self.received_plaintext.read(buf)?;
            if len > 0 || buf.is_empty() {
                return Ok(len);
            }

            self.check_no_bytes_state()
                .map(|()| len)
        }
    }

    impl BufRead for Reader<'_> {
        /// Obtain a chunk of plaintext data received from the peer over this TLS connection.
        /// This reads the same data as [`Reader::read()`], but returns a reference instead of
        /// copying the data.
        ///
        /// The caller should call [`Reader::consume()`] afterward to advance the buffer.
        ///
        /// See [`Reader::into_first_chunk()`] for a version of this function that returns a
        /// buffer with a longer lifetime.
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Reader {
                // reborrow
                received_plaintext: self.received_plaintext,
                ..*self
            }
            .into_first_chunk()
        }

        fn consume(&mut self, amt: usize) {
            self.received_plaintext
                .consume_first_chunk(amt)
        }
    }

    const UNEXPECTED_EOF_MESSAGE: &str = "peer closed connection without sending TLS close_notify: \
https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof";

    /// A structure that implements [`std::io::Write`] for writing plaintext.
    pub struct Writer<'a> {
        sink: &'a mut dyn PlaintextSink,
    }

    impl<'a> Writer<'a> {
        /// Create a new Writer.
        ///
        /// This is not an external interface.  Get one of these objects
        /// from [`Connection::writer`].
        pub(crate) fn new(sink: &'a mut dyn PlaintextSink) -> Self {
            Writer { sink }
        }
    }

    impl io::Write for Writer<'_> {
        /// Send the plaintext `buf` to the peer, encrypting
        /// and authenticating it.  Once this function succeeds
        /// you should call [`Connection::write_tls`] which will output the
        /// corresponding TLS records.
        ///
        /// This function buffers plaintext sent before the
        /// TLS handshake completes, and sends it as soon
        /// as it can.  See [`Connection::set_buffer_limit()`] to control
        /// the size of this buffer.
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.sink.write(buf)
        }

        fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
            self.sink.write_vectored(bufs)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.sink.flush()
        }
    }

    /// Internal trait implemented by the [`ServerConnection`]/[`ClientConnection`]
    /// allowing them to be the subject of a [`Writer`].
    ///
    /// [`ServerConnection`]: crate::ServerConnection
    /// [`ClientConnection`]: crate::ClientConnection
    pub(crate) trait PlaintextSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
        fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize>;
        fn flush(&mut self) -> io::Result<()>;
    }

    impl<Side: SideData> PlaintextSink for ConnectionCommon<Side> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let len = self
                .core
                .common
                .send
                .buffer_plaintext(buf.into(), &mut self.sendable_plaintext);
            self.send.maybe_refresh_traffic_keys();
            Ok(len)
        }

        fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
            let payload_owner: Vec<&[u8]>;
            let payload = match bufs.len() {
                0 => return Ok(0),
                1 => OutboundPlain::Single(bufs[0].deref()),
                _ => {
                    payload_owner = bufs
                        .iter()
                        .map(|io_slice| io_slice.deref())
                        .collect();

                    OutboundPlain::new(&payload_owner)
                }
            };
            let len = self
                .core
                .common
                .send
                .buffer_plaintext(payload, &mut self.sendable_plaintext);
            self.send.maybe_refresh_traffic_keys();
            Ok(len)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

pub use connection::{Connection, Reader, Writer};

/// An object of this type can export keying material.
pub struct KeyingMaterialExporter {
    pub(crate) inner: Box<dyn Exporter>,
}

impl KeyingMaterialExporter {
    /// Derives key material from the agreed connection secrets.
    ///
    /// This function fills in `output` with `output.len()` bytes of key
    /// material derived from a master connection secret using `label`
    /// and `context` for diversification. Ownership of the buffer is taken
    /// by the function and returned via the Ok result to ensure no key
    /// material leaks if the function fails.
    ///
    /// See [RFC5705][] for more details on what this does and is for.  In
    /// other libraries this is often named `SSL_export_keying_material()`
    /// or `SslExportKeyingMaterial()`.
    ///
    /// This function is not meaningful if `output.len()` is zero and will
    /// return an error in that case.
    ///
    /// [RFC5705]: https://datatracker.ietf.org/doc/html/rfc5705
    pub fn derive<T: AsMut<[u8]>>(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        mut output: T,
    ) -> Result<T, Error> {
        if output.as_mut().is_empty() {
            return Err(ApiMisuse::ExporterOutputZeroLength.into());
        }

        self.inner
            .derive(label, context, output.as_mut())
            .map(|_| output)
    }
}

impl Debug for KeyingMaterialExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyingMaterialExporter")
            .finish_non_exhaustive()
    }
}

/// This trait is for any object that can export keying material.
///
/// The terminology comes from [RFC5705](https://datatracker.ietf.org/doc/html/rfc5705)
/// but doesn't really involve "exporting" key material (in the usual meaning of "export"
/// -- of moving an artifact from one domain to another) but is best thought of as key
/// diversification using an existing secret.  That secret is implicit in this interface,
/// so is assumed to be held by `self`. The secret should be zeroized in `drop()`.
///
/// There are several such internal implementations, depending on the context
/// and protocol version.
pub(crate) trait Exporter: Send + Sync {
    /// Fills in `output` with derived keying material.
    ///
    /// This is deterministic depending on a base secret (implicit in `self`),
    /// plus the `label` and `context` values.
    ///
    /// Must fill in `output` entirely, or return an error.
    fn derive(&self, label: &[u8], context: Option<&[u8]>, output: &mut [u8]) -> Result<(), Error>;
}

#[derive(Debug)]
pub(crate) struct ConnectionRandoms {
    pub(crate) client: [u8; 32],
    pub(crate) server: [u8; 32],
}

impl ConnectionRandoms {
    pub(crate) fn new(client: Random, server: Random) -> Self {
        Self {
            client: client.0,
            server: server.0,
        }
    }
}

/// TLS connection state with side-specific data (`Side`).
///
/// This is one of the core abstractions of the rustls API. It represents a single connection
/// to a peer, and holds all the state associated with that connection. Note that it does
/// not hold any IO objects: the application is responsible for reading and writing TLS records.
/// If you want an object that does hold IO objects, see `rustls_util::Stream` and
/// `rustls_util::StreamOwned`.
///
/// This object is generic over the `Side` type parameter, which must implement the marker trait
/// [`SideData`]. This is used to store side-specific data.
pub(crate) struct ConnectionCommon<Side: SideData> {
    pub(crate) core: ConnectionCore<Side>,
    deframer_buffer: DeframerVecBuffer,
    pub(crate) received_plaintext: ChunkVecBuffer,
    pub(crate) sendable_plaintext: ChunkVecBuffer,
    pub(crate) has_seen_eof: bool,
}

impl<Side: SideData> ConnectionCommon<Side> {
    #[inline]
    pub(crate) fn process_new_packets(&mut self) -> Result<IoState, Error> {
        while let Some((payload, mut buffer_progress)) = self
            .core
            .process_new_packets(&mut self.deframer_buffer)?
        {
            let payload = payload.reborrow(&Delocator::new(self.deframer_buffer.slice_mut()));
            self.received_plaintext
                .append(payload.into_vec());
            self.deframer_buffer
                .discard(buffer_progress.take_discard());
        }

        // Release unsent buffered plaintext.
        if self.send.may_send_application_data && !self.sendable_plaintext.is_empty() {
            self.core
                .common
                .send
                .send_buffered_plaintext(&mut self.sendable_plaintext);
        }

        Ok(self.current_io_state())
    }

    pub(crate) fn wants_read(&self) -> bool {
        // We want to read more data all the time, except when we have unprocessed plaintext.
        // This provides back-pressure to the TCP buffers. We also don't want to read more after
        // the peer has sent us a close notification.
        //
        // In the handshake case we don't have readable plaintext before the handshake has
        // completed, but also don't want to read if we still have sendable tls.
        self.received_plaintext.is_empty()
            && !self.recv.has_received_close_notify
            && (self.send.may_send_application_data || self.send.sendable_tls.is_empty())
    }

    pub(crate) fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        self.core.exporter()
    }

    /// Extract secrets, so they can be used when configuring kTLS, for example.
    /// Should be used with care as it exposes secret key material.
    pub(crate) fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        self.core.dangerous_extract_secrets()
    }

    pub(crate) fn set_buffer_limit(&mut self, limit: Option<usize>) {
        self.sendable_plaintext.set_limit(limit);
        self.send.sendable_tls.set_limit(limit);
    }

    pub(crate) fn set_plaintext_buffer_limit(&mut self, limit: Option<usize>) {
        self.received_plaintext.set_limit(limit);
    }

    pub(crate) fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        self.core
            .common
            .send
            .refresh_traffic_keys()
    }

    pub(crate) fn current_io_state(&self) -> IoState {
        let common_state = &self.core.common;
        IoState {
            tls_bytes_to_write: common_state.send.sendable_tls.len(),
            plaintext_bytes_to_read: self.received_plaintext.len(),
            peer_has_closed: common_state
                .recv
                .has_received_close_notify,
        }
    }
}

impl<Side: SideData> ConnectionCommon<Side> {
    /// Returns an object that allows reading plaintext.
    pub(crate) fn reader(&mut self) -> Reader<'_> {
        let common = &mut self.core.common;
        let has_received_close_notify = common.recv.has_received_close_notify;
        Reader {
            received_plaintext: &mut self.received_plaintext,
            // Are we done? i.e., have we processed all received messages, and received a
            // close_notify to indicate that no new messages will arrive?
            has_received_close_notify,
            has_seen_eof: self.has_seen_eof,
        }
    }

    /// Returns an object that allows writing plaintext.
    pub(crate) fn writer(&mut self) -> Writer<'_> {
        Writer::new(self)
    }

    /// Extract the first handshake message.
    ///
    /// This is a shortcut to the `process_new_packets()` -> `process_msg()` ->
    /// `process_handshake_messages()` path, specialized for the first handshake message.
    pub(crate) fn first_handshake_message(&mut self) -> Result<Option<Input<'static>>, Error> {
        let mut buffer_progress = self.recv.hs_deframer.progress();

        let res = self
            .core
            .common
            .recv
            .deframe(self.deframer_buffer.filled_mut(), &mut buffer_progress)
            .map(|opt| opt.map(|pm| Message::try_from(pm.plaintext).map(|m| m.into_owned())));

        match res? {
            Some(Ok(msg)) => {
                self.deframer_buffer
                    .discard(buffer_progress.take_discard());
                Ok(Some(Input {
                    message: msg,
                    aligned_handshake: self.recv.hs_deframer.aligned(),
                }))
            }
            Some(Err(err)) => Err(err.into()),
            None => Ok(None),
        }
    }

    pub(crate) fn replace_state(&mut self, new: Box<dyn State>) {
        self.core.state = Ok(new);
    }

    pub(crate) fn read_tls(&mut self, rd: &mut dyn io::Read) -> Result<usize, io::Error> {
        if self.received_plaintext.is_full() {
            return Err(io::Error::other("received plaintext buffer full"));
        }

        if self.recv.has_received_close_notify {
            return Ok(0);
        }

        let res = self
            .deframer_buffer
            .read(rd, self.recv.hs_deframer.is_active());
        if let Ok(0) = res {
            self.has_seen_eof = true;
        }
        res
    }

    pub(crate) fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.send.sendable_tls.write_to(wr)
    }
}

impl<Side: SideData> Deref for ConnectionCommon<Side> {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.core.common
    }
}

impl<Side: SideData> DerefMut for ConnectionCommon<Side> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core.common
    }
}

impl<Side: SideData> From<ConnectionCore<Side>> for ConnectionCommon<Side> {
    fn from(core: ConnectionCore<Side>) -> Self {
        Self {
            core,
            deframer_buffer: DeframerVecBuffer::default(),
            received_plaintext: ChunkVecBuffer::new(Some(DEFAULT_RECEIVED_PLAINTEXT_LIMIT)),
            sendable_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            has_seen_eof: false,
        }
    }
}

/// Values of this structure are returned from [`Connection::process_new_packets`]
/// and tell the caller the current I/O state of the TLS connection.
///
/// [`Connection::process_new_packets`]: crate::Connection::process_new_packets
#[derive(Debug, Eq, PartialEq)]
pub struct IoState {
    tls_bytes_to_write: usize,
    plaintext_bytes_to_read: usize,
    peer_has_closed: bool,
}

impl IoState {
    /// How many bytes could be written by [`Connection::write_tls`] if called
    /// right now.  A non-zero value implies [`CommonState::wants_write`].
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    pub fn tls_bytes_to_write(&self) -> usize {
        self.tls_bytes_to_write
    }

    /// How many plaintext bytes could be obtained via [`std::io::Read`]
    /// without further I/O.
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }

    /// True if the peer has sent us a close_notify alert.  This is
    /// the TLS mechanism to securely half-close a TLS connection,
    /// and signifies that the peer will not send any further data
    /// on this connection.
    ///
    /// This is also signalled via returning `Ok(0)` from
    /// [`std::io::Read`], after all the received bytes have been
    /// retrieved.
    pub fn peer_has_closed(&self) -> bool {
        self.peer_has_closed
    }
}

pub(crate) fn process_new_packets(
    input: &mut dyn TlsInputBuffer,
    state: &mut Result<Box<dyn State>, Error>,
    recv: &mut ReceivePath,
    output: &mut dyn Output,
) -> Result<Option<(UnborrowedPayload, BufferProgress)>, Error> {
    let mut st = match mem::replace(state, Err(Error::HandshakeNotComplete)) {
        Ok(state) => state,
        Err(e) => {
            *state = Err(e.clone());
            return Err(e);
        }
    };

    let mut plaintext = None;
    let mut buffer_progress = recv.hs_deframer.progress();

    loop {
        let buffer = input.slice_mut();
        let locator = Locator::new(buffer);
        let res = recv.deframe(buffer, &mut buffer_progress);

        let opt_msg = match res {
            Ok(opt_msg) => opt_msg,
            Err(e) => {
                maybe_send_fatal_alert(output, &e);
                if let Error::DecryptError = e {
                    st.handle_decrypt_error();
                }
                *state = Err(e.clone());
                input.discard(buffer_progress.take_discard());
                return Err(e);
            }
        };

        let Some(msg) = opt_msg else {
            break;
        };

        let Decrypted {
            plaintext: msg,
            want_close_before_decrypt,
        } = msg;

        if want_close_before_decrypt {
            output.emit(Event::SendAlert(
                AlertLevel::Warning,
                AlertDescription::CloseNotify,
            ));
        }

        let hs_aligned = recv.hs_deframer.aligned();
        match recv
            .receive_message(msg, hs_aligned, output)
            .and_then(|input| match input {
                Some(input) => st.handle(
                    input,
                    &mut CaptureAppData {
                        data: &mut SplitReceive {
                            recv,
                            other: output,
                        },
                        plaintext_locator: &locator,
                        received_plaintext: &mut plaintext,
                    },
                ),
                None => Ok(st),
            }) {
            Ok(new) => st = new,
            Err(e) => {
                maybe_send_fatal_alert(output, &e);
                *state = Err(e.clone());
                input.discard(buffer_progress.take_discard());
                return Err(e);
            }
        }

        if recv.has_received_close_notify {
            // "Any data received after a closure alert has been received MUST be ignored."
            // -- <https://datatracker.ietf.org/doc/html/rfc8446#section-6.1>
            // This is data that has already been accepted in `read_tls`.
            let entirety = input.slice_mut().len();
            input.discard(entirety);
            break;
        }

        if let Some(payload) = plaintext.take() {
            *state = Ok(st);
            return Ok(Some((payload, buffer_progress)));
        }

        input.discard(buffer_progress.take_discard());
    }

    input.discard(buffer_progress.take_discard());
    *state = Ok(st);
    Ok(None)
}

pub(crate) struct ConnectionCore<Side: SideData> {
    pub(crate) state: Result<Box<dyn State>, Error>,
    pub(crate) side: Side::Data,
    pub(crate) common: CommonState,
}

impl<Side: SideData> ConnectionCore<Side> {
    pub(crate) fn new(state: Box<dyn State>, side: Side::Data, common: CommonState) -> Self {
        Self {
            state: Ok(state),
            side,
            common,
        }
    }

    pub(crate) fn output(&mut self) -> SideCommonOutput<'_> {
        SideCommonOutput {
            side: &mut self.side,
            common: &mut self.common,
        }
    }

    pub(crate) fn process_new_packets(
        &mut self,
        input: &mut dyn TlsInputBuffer,
    ) -> Result<Option<(UnborrowedPayload, BufferProgress)>, Error> {
        process_new_packets(
            input,
            &mut self.state,
            &mut self.common.recv,
            &mut JoinOutput {
                outputs: &mut self.common.outputs,
                protocol: self.common.protocol,
                quic: &mut self.common.quic,
                send: &mut self.common.send,
                side: &mut self.side,
            },
        )
    }

    pub(crate) fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        Ok(self
            .dangerous_into_kernel_connection()?
            .0)
    }

    pub(crate) fn dangerous_into_kernel_connection(
        mut self,
    ) -> Result<(ExtractedSecrets, KernelConnection<Side>), Error> {
        if self.common.is_handshaking() {
            return Err(Error::HandshakeNotComplete);
        }

        if !self.common.send.sendable_tls.is_empty() {
            return Err(ApiMisuse::SecretExtractionWithPendingSendableData.into());
        }

        let state = self.state?;

        let read_seq = self
            .common
            .recv
            .decrypt_state
            .read_seq();
        let write_seq = self
            .common
            .send
            .encrypt_state
            .write_seq();

        let tls13_key_schedule = self
            .common
            .send
            .tls13_key_schedule
            .take();

        let (secrets, state) = state.into_external_state(&tls13_key_schedule)?;
        let secrets = ExtractedSecrets {
            tx: (write_seq, secrets.tx),
            rx: (read_seq, secrets.rx),
        };
        let external = KernelConnection::new(state, self.common, tls13_key_schedule)?;

        Ok((secrets, external))
    }

    pub(crate) fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        match self.common.exporter.take() {
            Some(inner) => Ok(KeyingMaterialExporter { inner }),
            None if self.common.is_handshaking() => Err(Error::HandshakeNotComplete),
            None => Err(ApiMisuse::ExporterAlreadyUsed.into()),
        }
    }

    pub(crate) fn early_exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        match self.common.early_exporter.take() {
            Some(inner) => Ok(KeyingMaterialExporter { inner }),
            None => Err(ApiMisuse::ExporterAlreadyUsed.into()),
        }
    }
}

pub(crate) struct SideCommonOutput<'a> {
    pub(crate) side: &'a mut dyn Output,
    pub(crate) common: &'a mut dyn Output,
}

impl Output for SideCommonOutput<'_> {
    fn emit(&mut self, ev: Event<'_>) {
        match ev.disposition() {
            EventDisposition::SideSpecific => self.side.emit(ev),
            _ => self.common.emit(ev),
        }
    }
}

/// Data specific to the peer's side (client or server).
#[expect(private_bounds)]
pub trait SideData: private::SideData {}

pub(crate) mod private {
    use super::*;

    pub(crate) trait SideData: Debug {
        /// Data storage type.
        type Data: Debug + Output;
    }
}

const DEFAULT_RECEIVED_PLAINTEXT_LIMIT: usize = 16 * 1024;
