//! Implements parts of Datagram TLS (DTLS), specified in [RFC 6347][1] (DTLS
//! 1.2) and [RFC 9147][2] (DTLS 1.3).
//!
//! [1]: https://datatracker.ietf.org/doc/html/rfc6347
//! [2]: https://datatracker.ietf.org/doc/html/rfc9147

use std::boxed::Box;
use std::fmt::Debug;
use std::net::UdpSocket;
use std::sync::Arc;

use pki_types::ServerName;

use crate::client::ClientSide;
use crate::common_state::Protocol;
use crate::conn::ConnectionCore;
use crate::crypto::cipher::OutboundPlain;
use crate::msgs::{ClientExtensionsInput, Delocator, ServerExtensionsInput, SliceInput};
use crate::server::ServerSide;
use crate::vecbuf::ChunkVecBuffer;
use crate::{ClientConfig, ServerConfig, SideData};

/// Errors encountered while sending or receiving data on a `DtlsSocket`.
#[derive(Debug)]
pub enum Error {
    /// Some other error occurred.
    Other(Box<dyn std::error::Error>),
}

/// The client side of a DTLS socket.
pub struct ClientDtlsSocket<SocketLike> {
    inner: DtlsSocket<SocketLike, ClientSide>,
}

impl<SocketLike: UdpSocketLike> ClientDtlsSocket<SocketLike> {
    /// Create a new `ClientDtlsSocket` using the provided DTLS configuration,
    /// wrapping some socket-like primitive.
    pub fn new(
        config: ClientConfig,
        server_name: ServerName<'static>,
        inner: SocketLike,
    ) -> Result<Self, Error> {
        let connection_core = ConnectionCore::for_client(
            Arc::new(config.clone()),
            server_name,
            ClientExtensionsInput::from_alpn(config.alpn_protocols),
            // Never QUIC since this is UDP
            None,
            Protocol::Udp,
        )
        .map_err(|e| Error::Other(e.into()))?;
        Ok(Self {
            inner: DtlsSocket::new(inner, connection_core),
        })
    }

    /// API used by crate clients to send plaintext bytes.
    ///
    /// Under the covers we'll do handshake as needed and also encrypt content
    /// into EncodedMessage.
    ///
    /// Returns number of bytes transmitted, not including DTLS overhead.
    pub fn send<B: AsRef<[u8]>>(&mut self, bytes: B) -> Result<usize, Error> {
        self.inner.send(bytes)
    }

    /// API used by crate clients to receive plaintext bytes.
    ///
    /// Under the covers we'll do handshake as needed and also encrypt content
    /// into EncodedMessage.
    ///
    /// Returns number of bytes transmitted, not including DTLS overhead.
    pub fn recv<B: AsMut<[u8]>>(&mut self, bytes: B) -> Result<usize, Error> {
        self.inner.recv(bytes)
    }
}

/// The server side of a DTLS socket.
pub struct ServerDtlsSocket<SocketLike> {
    inner: DtlsSocket<SocketLike, ServerSide>,
}

impl<SocketLike: UdpSocketLike> ServerDtlsSocket<SocketLike> {
    /// Create a new `ServerDtlsSocket` using the provided DTLS configuration,
    /// wrapping some socket-like primitive.
    pub fn new(config: ServerConfig, inner: SocketLike) -> Result<Self, Error> {
        let connection_core = ConnectionCore::for_server(
            Arc::new(config),
            ServerExtensionsInput {
                // Never set transport parameters, that's only for QUIC
                transport_parameters: None,
            },
            Protocol::Udp,
        )
        .map_err(|e| Error::Other(e.into()))?;
        Ok(Self {
            inner: DtlsSocket::new(inner, connection_core),
        })
    }

    /// API used by crate clients to send plaintext bytes.
    ///
    /// Under the covers we'll do handshake as needed and also encrypt content
    /// into EncodedMessage.
    ///
    /// Returns number of bytes transmitted, not including DTLS overhead.
    pub fn send<B: AsRef<[u8]>>(&mut self, bytes: B) -> Result<usize, Error> {
        self.inner.send(bytes)
    }

    /// API used by crate clients to receive plaintext bytes.
    ///
    /// Under the covers we'll do handshake as needed and also encrypt content
    /// into EncodedMessage.
    ///
    /// Returns number of bytes transmitted, not including DTLS overhead.
    pub fn recv<B: AsMut<[u8]>>(&mut self, bytes: B) -> Result<usize, Error> {
        self.inner.recv(bytes)
    }
}

/// Wraps a [`std::net::UdpSocket`] with the timeout and retransmission logic
/// for handshake messages.
pub(crate) struct DtlsSocket<SocketLike, Side: SideData> {
    /// Inner socket on which messages will be received and sent.
    inner: SocketLike,
    /// Connection internals
    core: ConnectionCore<Side>,
    /// Buffered plaintext waiting for handshakes to complete.
    buffered_plaintext: ChunkVecBuffer,
    /// Plaintext received and decrypted but not yet read.
    received_plaintext: ChunkVecBuffer,
}

impl<SocketLike: UdpSocketLike, Side: SideData> DtlsSocket<SocketLike, Side> {
    fn new(inner: SocketLike, core: ConnectionCore<Side>) -> Self {
        Self {
            inner,
            core,
            buffered_plaintext: ChunkVecBuffer::new(None),
            received_plaintext: ChunkVecBuffer::new(None),
        }
    }

    /// API used by crate clients to send plaintext bytes.
    ///
    /// Under the covers we'll do handshake as needed and also encrypt content
    /// into EncodedMessage.
    ///
    /// Returns number of bytes transmitted, not including DTLS overhead.
    fn send<B: AsRef<[u8]>>(&mut self, bytes: B) -> Result<usize, Error> {
        let sent = self.core.common.send.buffer_plaintext(
            OutboundPlain::Single(bytes.as_ref()),
            &mut self.buffered_plaintext,
        );

        let mut buf = [0u8; 8096];
        self.pending_io(&mut buf)?;

        Ok(sent)
    }

    /// API used by crate clients to receive plaintext bytes.
    ///
    /// Under the covers we'll do handshake as needed and also encrypt content
    /// into EncodedMessage.
    ///
    /// Returns number of bytes transmitted, not including DTLS overhead.
    fn recv<B: AsMut<[u8]>>(&mut self, mut bytes: B) -> Result<usize, Error> {
        let mut receive_buf = bytes.as_mut();
        self.pending_io(&mut receive_buf)?;

        if self.received_plaintext.is_empty() {
            return Ok(0);
        }

        Ok(self
            .received_plaintext
            .write_to(&mut receive_buf)
            .map_err(|e| Error::Other(e.into()))?)
    }

    /// Much like `rustls-util::complete_io`, but doesn't require implemntations of `std::io::{Read,
    /// Write}`.
    fn pending_io(&mut self, mut read_into: &mut [u8]) -> Result<(), Error> {
        // Check if we have any messages to read, possibly to finish handshaking.
        loop {
            let read = self
                .inner
                .recv(&mut read_into)
                .map_err(|e| Error::Other(e.into()))?;
            if read == 0 {
                break;
            }
            if let Some(payload) = self
                .core
                .process_new_packets(&mut SliceInput::new(&mut read_into[..read]), None)
                .map_err(|e| Error::Other(e.into()))?
            {
                let payload = payload.reborrow(&Delocator::new(&mut read_into));
                self.received_plaintext
                    .append(payload.into_vec());
            }
        }

        // If we're now done handshaking, encrypt any buffered plaintext and enqueue into send queue
        if self
            .core
            .common
            .send
            .may_send_application_data
            && !self.buffered_plaintext.is_empty()
        {
            self.core
                .common
                .send
                .send_buffered_plaintext(&mut self.buffered_plaintext);
        }

        // Send any TLS messages we have to send out
        for sendable in self
            .core
            .common
            .send
            .sendable_tls
            .take()
        {
            let _ = self
                .inner
                .send(sendable)
                .map_err(|e| Error::Other(e.into()))?;
        }

        Ok(())
    }
}

/// Something akin to a UDP socket which can send and receive data, but does not
/// implement [`std::io::Write`] or [`std::io::Read`].
pub trait UdpSocketLike {
    /// Errors returned by this `UdpSocketLike`'s methods.
    type Error: std::error::Error + 'static;

    /// Send data.
    fn send<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<usize, Self::Error>;

    /// Receive data.
    fn recv<B: AsMut<[u8]>>(&mut self, buf: B) -> Result<usize, Self::Error>;
}

impl UdpSocketLike for UdpSocket {
    type Error = std::io::Error;

    fn send<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<usize, Self::Error> {
        UdpSocket::send(&self, buf.as_ref())
    }

    fn recv<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<usize, Self::Error> {
        UdpSocket::recv(&self, buf.as_mut())
    }
}

#[cfg(test)]
mod tests {
    use core::hash::Hasher;
    use std::borrow::Cow;
    use std::cmp::min;
    use std::collections::VecDeque;
    use std::fmt::Display;
    use std::sync::{Arc, Mutex};
    use std::vec;
    use std::vec::Vec;

    use crate::client::danger::{ServerIdentity, SignatureVerificationInput};
    use crate::crypto::{Identity, SignatureScheme, TEST_PROVIDER};
    use crate::verify::{HandshakeSignatureValid, PeerVerified, ServerVerifier};

    use pki_types::pem::PemObject;
    use pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;

    #[derive(Debug, Clone)]
    struct InMemoryBuffersError(&'static str);

    impl Display for InMemoryBuffersError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            Display::fmt(self.0, f)
        }
    }

    impl std::error::Error for InMemoryBuffersError {}

    #[derive(Clone, Debug, Default)]
    struct InMemoryBuffers {
        send: Arc<Mutex<VecDeque<Vec<u8>>>>,
        receive: Arc<Mutex<VecDeque<Vec<u8>>>>,
        receive_position: usize,
    }

    impl InMemoryBuffers {
        fn pair() -> (Self, Self) {
            let client_receive = Arc::new(Mutex::new(VecDeque::new()));
            let server_receive = Arc::new(Mutex::new(VecDeque::new()));

            (
                InMemoryBuffers {
                    send: server_receive.clone(),
                    receive: client_receive.clone(),
                    receive_position: 0,
                },
                InMemoryBuffers {
                    send: client_receive,
                    receive: server_receive,
                    receive_position: 0,
                },
            )
        }
    }

    impl UdpSocketLike for InMemoryBuffers {
        type Error = InMemoryBuffersError;

        fn send<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<usize, Self::Error> {
            let slice = buf.as_ref();

            self.send
                .lock()
                .unwrap()
                .push_back(slice.to_vec());

            Ok(slice.len())
        }

        fn recv<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<usize, Self::Error> {
            let read_into = buf.as_mut();

            let mut receive_queue = self.receive.lock().unwrap();

            if let Some(received) = receive_queue.pop_front() {
                let remaining_receive_bytes = received.len() - self.receive_position;
                let bytes_read = min(remaining_receive_bytes, read_into.len());

                read_into[..bytes_read].copy_from_slice(
                    &received[self.receive_position..self.receive_position + bytes_read],
                );

                self.receive_position += bytes_read;

                if self.receive_position == received.len() {
                    self.receive_position = 0;
                } else {
                    // Put buffer back in receive queue for later read
                    receive_queue.push_front(received);
                }

                Ok(bytes_read)
            } else {
                // No buffers in queue
                return Ok(0);
            }
        }
    }

    fn server_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/ecdsa-p256/end.key").as_slice(),
        )
        .unwrap()
    }

    fn server_identity() -> Arc<Identity<'static>> {
        Arc::new(
            Identity::from_cert_chain(vec![
                CertificateDer::from(&include_bytes!("../../../test-ca/ecdsa-p256/end.der")[..]),
                CertificateDer::from(&include_bytes!("../../../test-ca/ecdsa-p256/inter.der")[..]),
            ])
            .unwrap(),
        )
    }

    #[derive(Debug, Clone)]
    struct AcceptsEverythingServerVerifier {}

    impl ServerVerifier for AcceptsEverythingServerVerifier {
        fn verify_identity(&self, _: &ServerIdentity<'_>) -> Result<PeerVerified, crate::Error> {
            Ok(PeerVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &SignatureVerificationInput<'_>,
        ) -> Result<HandshakeSignatureValid, crate::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &SignatureVerificationInput<'_>,
        ) -> Result<HandshakeSignatureValid, crate::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            Vec::from([
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
            ])
        }

        fn request_ocsp_response(&self) -> bool {
            false
        }

        fn hash_config(&self, _: &mut dyn Hasher) {}
    }

    #[test]
    fn in_memory_buffer() {
        let (mut client, mut server) = InMemoryBuffers::pair();

        assert_eq!(
            client
                .send("hello from client")
                .unwrap(),
            17
        );

        let mut buf = [0u8; 1024];
        assert_eq!(server.recv(&mut buf).unwrap(), 17);
        assert_eq!(&buf[..17], b"hello from client");
        assert_eq!(server.recv(&mut buf).unwrap(), 0);

        assert_eq!(
            server
                .send("hello back from server")
                .unwrap(),
            22
        );

        assert_eq!(client.recv(&mut buf).unwrap(), 22);
        assert_eq!(&buf[..22], b"hello back from server");
        assert_eq!(client.recv(&mut buf).unwrap(), 0);

        // queue up multiple messages in server receive buffers
        let messages = [b"message 1", b"message 2"];

        for message in messages {
            assert_eq!(client.send(message).unwrap(), message.len());
        }

        // partial read of a message
        assert_eq!(server.recv(&mut buf[..4]).unwrap(), 4);
        assert_eq!(&buf[..4], b"mess");
        assert_eq!(server.recv(&mut buf[4..]).unwrap(), 5);
        assert_eq!(&buf[..9], messages[0]);
        // read second message
        assert_eq!(server.recv(&mut buf).unwrap(), 9);
        assert_eq!(&buf[..9], messages[1]);
    }

    enum AllowedTlsVersion {
        Dtls12Only,
        Dtls13Only,
        Both,
    }

    /// Construct a DTLS socket pair configured to exchange messages. Only the provided DTLS
    /// version(s) will be supported. Both sockets will be at the start of their respective
    /// handshake state machines. Calling either `send` or `recv` on the client socket will cause it
    /// to send a `ClientHello`, which the server socket will process if and when its own `send` or
    /// `recv` methods are called.
    fn test_setup(
        allowed: AllowedTlsVersion,
    ) -> (
        ClientDtlsSocket<InMemoryBuffers>,
        ServerDtlsSocket<InMemoryBuffers>,
    ) {
        let (client_transport, server_transport) = InMemoryBuffers::pair();

        let mut test_provider = TEST_PROVIDER.clone();
        match allowed {
            AllowedTlsVersion::Dtls12Only => {
                test_provider.tls13_cipher_suites = Cow::Owned(Vec::new());
            }
            AllowedTlsVersion::Dtls13Only => {
                test_provider.tls12_cipher_suites = Cow::Owned(Vec::new());
            }
            // test provider comes with 1.2 and 1.3 ciphersuites by default, so leave it alone
            AllowedTlsVersion::Both => (),
        }

        let client_config = ClientConfig::builder(Arc::new(test_provider.clone()))
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptsEverythingServerVerifier {}))
            .with_no_client_auth()
            .unwrap();

        let client_socket = ClientDtlsSocket::new(
            client_config,
            "example.org".try_into().unwrap(),
            client_transport,
        )
        .unwrap();

        let server_config = ServerConfig::builder(Arc::new(test_provider.clone()))
            .with_no_client_auth()
            .with_single_cert(server_identity(), server_key())
            .unwrap();

        let server_socket = ServerDtlsSocket::new(server_config, server_transport).unwrap();

        (client_socket, server_socket)
    }

    #[test]
    fn full_handshake_and_application_data_dtls_13() {
        let (mut client_socket, mut server_socket) = test_setup(AllowedTlsVersion::Dtls13Only);

        let client_message = b"client sends application data";
        let server_message = b"server sends application data";

        let mut client_sent_message = false;
        let mut server_received_message = false;
        let mut server_sent_message = false;
        let mut client_received_message = false;
        let mut receive_buf = [0; 8096];
        let mut iters = 0;
        let mut server_saw_handshake = false;

        loop {
            assert!(iters < 10);
            if !client_sent_message {
                let sent = client_socket
                    .send(client_message)
                    .unwrap();
                assert_eq!(sent, client_message.len());
                client_sent_message = true;
            }

            if !server_sent_message && server_received_message {
                let sent = server_socket
                    .send(server_message)
                    .unwrap();
                assert_eq!(sent, server_message.len());

                server_sent_message = true;
            }

            {
                // Peek at message received by server so we can verify its encoding
                let server_recv = server_socket
                    .inner
                    .inner
                    .receive
                    .lock()
                    .unwrap();

                if let Some(peek_server_recv) = server_recv.back() {
                    std::println!("server recv: {peek_server_recv:?}");

                    if server_saw_handshake {
                        // This is DTLS 1.3, so message should have a unified header on it, whose
                        // first byte is not a TLS content type but instead a bitmask describing the
                        // unified header.
                        assert!((32u8..63).contains(&peek_server_recv[0]));
                    } else {
                        // The first handshake message is an unencrypted handshake message and does not
                        // get a unified header.
                        assert_eq!(peek_server_recv[0], 22);
                        server_saw_handshake = true;
                    }
                } else {
                    std::println!("empty server recv");
                }
            }

            {
                // Peek at message received by server so we can verify its encoding. By the time we
                // get here, the client will already have handled the server hello via a call to
                // pending_io, so we'll never see the unencrypted server hello here.
                let client_recv = client_socket
                    .inner
                    .inner
                    .receive
                    .lock()
                    .unwrap();

                if let Some(peek_client_recv) = client_recv.back() {
                    std::println!("client recv: {peek_client_recv:?}");

                    // This is DTLS 1.3, so message should have a unified header on it, whose first byte
                    // is not a TLS content type but instead a bitmask describing the unified header.
                    assert!((32u8..63).contains(&peek_client_recv[0]));
                } else {
                    std::println!("empty client recv");
                }
            }

            // Call recv on server and client sockets at each iteration to drive the handshake and
            // packet processing machine until application data comes through
            let server_recvd = server_socket
                .recv(&mut receive_buf)
                .unwrap();
            if client_sent_message
                && !server_received_message
                && server_recvd == client_message.len()
            {
                server_received_message = true;
                assert_eq!(&receive_buf[..client_message.len()], client_message);
            } else {
                assert_eq!(server_recvd, 0);
            }

            let client_recvd = client_socket
                .recv(&mut receive_buf)
                .unwrap();
            if server_sent_message && client_recvd == server_message.len() {
                client_received_message = true;
                assert_eq!(&receive_buf[..server_message.len()], server_message);
            } else {
                assert_eq!(client_recvd, 0);
            }

            if server_received_message
                && client_received_message
                && client_sent_message
                && server_sent_message
            {
                break;
            }

            iters += 1;
        }
    }

    #[test]
    fn full_handshake_and_application_data_dtls_12() {
        let (mut client_socket, mut server_socket) = test_setup(AllowedTlsVersion::Dtls12Only);

        let client_message = b"client sends application data";
        let server_message = b"server sends application data";

        let mut client_sent_message = false;
        let mut server_received_message = false;
        let mut server_sent_message = false;
        let mut client_received_message = false;
        let mut receive_buf = [0; 8096];
        let mut iters = 0;
        loop {
            assert!(iters < 10);
            if !client_sent_message {
                let sent = client_socket
                    .send(client_message)
                    .unwrap();
                assert_eq!(sent, client_message.len());
                std::println!("client sent message");
                client_sent_message = true;
            }

            if !server_sent_message && server_received_message {
                let sent = server_socket
                    .send(server_message)
                    .unwrap();
                assert_eq!(sent, server_message.len());
                std::println!("server sent message");

                server_sent_message = true;
            }

            {
                // Peek at message received by server
                let server_recv = server_socket
                    .inner
                    .inner
                    .receive
                    .lock()
                    .unwrap();
                let peek_server_recv = server_recv.back();

                std::println!("server recv: {peek_server_recv:?}");
            }

            {
                // Peek at message received by client
                let client_recv = client_socket
                    .inner
                    .inner
                    .receive
                    .lock()
                    .unwrap();
                let peek_client_recv = client_recv.back();

                std::println!("client recv: {peek_client_recv:?}");
            }

            // Call recv on server and client sockets at each iteration to drive the handshake and
            // packet processing machine until application data comes through
            let server_recvd = server_socket
                .recv(&mut receive_buf)
                .unwrap();

            std::println!("server recv {server_recvd}");
            if client_sent_message
                && !server_received_message
                && server_recvd == client_message.len()
            {
                std::println!("server recv something");
                server_received_message = true;
                assert_eq!(&receive_buf[..client_message.len()], client_message);
            } else {
                std::println!("server recv 0");
                assert_eq!(server_recvd, 0);
            }

            let client_recvd = client_socket
                .recv(&mut receive_buf)
                .unwrap();
            if server_sent_message && client_recvd == server_message.len() {
                client_received_message = true;
                assert_eq!(&receive_buf[..server_message.len()], server_message);
            } else {
                assert_eq!(client_recvd, 0);
            }

            if server_received_message
                && client_received_message
                && client_sent_message
                && server_sent_message
            {
                break;
            }

            iters += 1;
        }
    }

    #[test]
    fn anti_replay_dtls_12() {
        // We should maintain a sliding window of seen TLS record sequence
        // numbers, per epoch(?). Replayed sequence numbers should be rejected.
        // Replayed sequence numbers outside the replay window will get through.
        // <https://datatracker.ietf.org/doc/html/rfc9147#section-4.5.1>
        let (mut client_socket, mut server_socket) = test_setup(AllowedTlsVersion::Dtls12Only);

        let client_message = b"client sends application data";
        let server_message = b"server sends application data";
        let mut receive_buf = [0; 8096];

        // Client send: send client hello, buffer plaintext
        assert_eq!(
            client_socket
                .send(client_message)
                .unwrap(),
            client_message.len()
        );

        // Server recv: process client hello, send server hello
        assert_eq!(
            server_socket
                .recv(&mut receive_buf)
                .unwrap(),
            0,
        );

        // Client recv: process server hello
        assert_eq!(
            client_socket
                .recv(&mut receive_buf)
                .unwrap(),
            0
        );

        // Server recv: process client finished, become ready for traffic
        assert_eq!(
            server_socket
                .recv(&mut receive_buf)
                .unwrap(),
            0,
        );

        // Client recv: process server finished, become ready for traffic, encrypt buffered
        // plaintext and send it
        assert_eq!(
            client_socket
                .recv(&mut receive_buf)
                .unwrap(),
            0
        );

        // Peek at application data message received by server
        let replayed = server_socket
            .inner
            .inner
            .receive
            .lock()
            .unwrap()
            .back()
            .unwrap()
            .clone();
        std::println!("server recv: {replayed:?}");
        // Make sure the record is application data as expected
        assert_eq!(replayed[0], 23);

        // Server recv: receive client message
        assert_eq!(
            server_socket
                .recv(&mut receive_buf)
                .unwrap(),
            client_message.len()
        );
        assert_eq!(&receive_buf[..client_message.len()], client_message);

        // Replay the record into the server's transport and it should get rejected.
        assert_eq!(
            client_socket
                .inner
                .inner
                .send(&replayed)
                .unwrap(),
            replayed.len()
        );

        // Server recv: should reject replayed message. This doesn't yield an
        // error all the way up here, so we check the receive path's replay
        // counter.
        assert_eq!(
            server_socket
                .recv(&mut receive_buf)
                .unwrap(),
            0
        );

        assert_eq!(
            server_socket
                .inner
                .core
                .common
                .recv
                .discarded_replayed_records,
            1
        );
    }

    fn hex_dump<B: AsRef<[u8]>>(buf: B) {
        let slice = buf.as_ref();
        for (idx, byte) in slice.iter().enumerate() {
            if idx % 8 == 0 {
                std::print!("\n");
            }
            std::print!("{byte:02x} ");
        }
        std::println!("");
    }
}
