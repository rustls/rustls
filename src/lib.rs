//! # Rustls - a modern TLS library
//! Rustls is a TLS library that aims to provide a good level of cryptographic security,
//! requires no configuration to achieve that security, and provides no unsafe features or
//! obsolete cryptography.
//!
//! ## Current features
//!
//! * TLS1.2 and TLS1.3 (draft 23) only.
//! * ECDSA or RSA server authentication by clients.
//! * ECDSA or RSA server authentication by servers.
//! * Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
//! * AES128-GCM and AES256-GCM bulk encryption, with safe nonces.
//! * Chacha20Poly1305 bulk encryption.
//! * ALPN support.
//! * SNI support.
//! * Tunable MTU to make TLS messages match size of underlying transport.
//! * Optional use of vectored IO to minimise system calls.
//! * TLS1.2 session resumption.
//! * TLS1.2 resumption via tickets (RFC5077).
//! * TLS1.3 resumption via tickets or session storage.
//! * Client authentication by clients.
//! * Client authentication by servers.
//! * Extended master secret support (RFC7627).
//! * Exporters (RFC5705).
//! * OCSP stapling by servers.
//! * SCT stapling by servers.
//! * SCT verification by clients.
//!
//! ## Possible future features
//!
//! * PSK support.
//! * OCSP verification by clients.
//! * Certificate pinning.
//!
//! ## Non-features
//!
//! The following things are broken, obsolete, badly designed, underspecified,
//! dangerous and/or insane. Rustls does not support:
//!
//! * SSL1, SSL2, SSL3, TLS1 or TLS1.1.
//! * RC4.
//! * DES or triple DES.
//! * EXPORT ciphersuites.
//! * MAC-then-encrypt ciphersuites.
//! * Ciphersuites without forward secrecy.
//! * Renegotiation.
//! * Kerberos.
//! * Compression.
//! * Discrete-log Diffie-Hellman.
//! * Automatic protocol version downgrade.
//! * AES-GCM with unsafe nonces.
//!
//! There are plenty of other libraries that provide these features should you
//! need them.
//!
//! ## Design Overview
//! ### Rustls does not take care of network IO
//! It doesn't make or accept TCP connections, or do DNS, or read or write files.
//!
//! There's example client and server code which uses mio to do all needed network
//! IO.
//!
//! ### Rustls provides encrypted pipes
//! These are the `ServerSession` and `ClientSession` types.  You supply raw TLS traffic
//! on the left (via the `read_tls()` and `write_tls()` methods) and then read/write the
//! plaintext on the right:
//!
//! ```text
//!          TLS                                   Plaintext
//!          ===                                   =========
//!     read_tls()      +-----------------------+      io::Read
//!                     |                       |
//!           +--------->     ClientSession     +--------->
//!                     |          or           |
//!           <---------+     ServerSession     <---------+
//!                     |                       |
//!     write_tls()     +-----------------------+      io::Write
//! ```
//!
//! ### Rustls takes care of server certificate verification
//! You do not need to provide anything other than a set of root certificates to trust.
//! Certificate verification cannot be turned off or disabled in the main API.
//!
//! ## Getting started
//! This is the minimum you need to do to make a TLS client connection.
//!
//! First, we make a `ClientConfig`.  You're likely to make one of these per process,
//! and use it for all connections made by that process.
//!
//! ```
//! let mut config = rustls::ClientConfig::new();
//! ```
//!
//! Next we load some root certificates.  These are used to authenticate the server.
//! The recommended way is to depend on the `webpki_roots` crate which contains
//! the Mozilla set of root certificates.
//!
//! ```rust,ignore
//! config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
//! ```
//!
//! Now we can make a session.  You need to provide the server's hostname so we
//! know what to expect to find in the server's certificate.
//!
//! ```no_run
//! # extern crate rustls;
//! # extern crate webpki;
//! # use std::sync::Arc;
//! # let mut config = rustls::ClientConfig::new();
//! let rc_config = Arc::new(config);
//! let example_com = webpki::DNSNameRef::try_from_ascii_str("example.com").unwrap();
//! let mut client = rustls::ClientSession::new(&rc_config, example_com);
//! ```
//!
//! Now you should do appropriate IO for the `client` object.  If `client.wants_read()` yields
//! true, you should call `client.read_tls()` when the underlying connection has data.
//! Likewise, if `client.wants_write()` yields true, you should call `client.write_tls()`
//! when the underlying connection is able to send data.  You should continue doing this
//! as long as the connection is valid.
//!
//! The return types of `read_tls()` and `write_tls()` only tell you if the IO worked.  No
//! parsing or processing of the TLS messages is done.  After each `read_tls()` you should
//! therefore call `client.process_new_packets()` which parses and processes the messages.
//! Any error returned from `process_new_packets` is fatal to the session, and will tell you
//! why.  For example, if the server's certificate is expired `process_new_packets` will
//! return `Err(WebPKIError(CertExpired))`.  From this point on, `process_new_packets` will
//! not do any new work and will return that error continually.
//!
//! You can extract newly received data by calling `client.read()` (via the `io::Read`
//! trait).  You can send data to the peer by calling `client.write()` (via the `io::Write`
//! trait).  Note that `client.write()` buffers data you send if the TLS session is not
//! yet established: this is useful for writing (say) a HTTP request, but don't write huge
//! amounts of data.
//!
//! The following code uses a fictional socket IO API for illustration, and does not handle
//! errors.
//!
//! ```text
//! use std::io;
//!
//! client.write(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! let mut socket = connect("example.com", 443);
//! loop {
//!   if client.wants_read() && socket.ready_for_read() {
//!     client.read_tls(&mut socket).unwrap();
//!     client.process_new_packets().unwrap();
//!
//!     let mut plaintext = Vec::new();
//!     client.read_to_end(&mut plaintext).unwrap();
//!     io::stdout().write(&plaintext).unwrap();
//!   }
//!
//!   if client.wants_write() && socket.ready_for_write() {
//!     client.write_tls(&mut socket).unwrap();
//!   }
//!
//!   socket.wait_for_something_to_happen();
//! }
//! ```
//!
//! # Examples
//! `tlsserver` and `tlsclient` are full worked examples.  These both use mio.
//!
//! # Crate features
//! Here's a list of what features are exposed by the rustls crate and what
//! they mean.
//!
//! - `logging`: this makes the rustls crate depend on the `log` crate.
//!   rustls outputs interesting protocol-level messages at `trace!` and `debug!`
//!   level, and protocol-level errors at `warn!` and `error!` level.  The log
//!   messages do not contain secret key data, and so are safe to archive without
//!   affecting session security.  This feature is in the default set.
//!
//! - `dangerous_configuration`: this feature enables a `dangerous()` method on
//!   `ClientConfig` and `ServerConfig` that allows setting inadvisable options,
//!   such as replacing the certificate verification process.  Applications
//!   requesting this feature should be reviewed carefully.
//!
//! - `quic`: this feature exposes additional constructors and functions
//!   for using rustls as a TLS library for QUIC.  See the `quic` module for
//!   details of these.  You will only need this if you're writing a QUIC
//!   implementation.
//!

// Require docs for public APIs, deny unsafe code, etc.
#![forbid(unsafe_code,
          unstable_features)]
#![deny(trivial_casts,
        trivial_numeric_casts,
        missing_docs,
        unused_import_braces,
        unused_extern_crates,
        unused_qualifications)]

// Relax these clippy lints:
// - needless_pass_by_value: this is unhelpful for trait implementations
//   which need to match the trait.
#![cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
// - ptr_arg: this triggers on references to type aliases that are Vec
//   underneath.
#![cfg_attr(feature = "cargo-clippy", allow(ptr_arg))]

// Our dependencies:

// webpki for certificate verification.
extern crate webpki;

// *ring* for cryptography.
extern crate ring;

// untrusted for feeding ring and webpki.
extern crate untrusted;

// sct for validation of stapled certificate transparency SCTs.
extern crate sct;

// rust-base64 for pemfile module.
extern crate base64;

// log for logging (optional).
#[cfg(feature = "logging")]
#[macro_use]
extern crate log;

#[cfg(not(feature = "logging"))]
#[macro_use]
mod compile_out_log {
    macro_rules! trace    ( ($($tt:tt)*) => {{}} );
    macro_rules! debug    ( ($($tt:tt)*) => {{}} );
    macro_rules! info     ( ($($tt:tt)*) => {{}} );
    macro_rules! warn     ( ($($tt:tt)*) => {{}} );
    macro_rules! error    ( ($($tt:tt)*) => {{}} );
}

mod util;
#[allow(missing_docs)]
#[macro_use]
mod msgs;
mod error;
mod rand;
mod hash_hs;
mod vecbuf;
mod prf;
mod cipher;
mod key_schedule;
mod session;
mod stream;
mod pemfile;
mod x509;
mod anchors;
mod verify;
#[cfg(test)]
mod verifybench;
mod handshake;
mod suites;
mod ticketer;
mod server;
mod client;
mod key;
mod bs_debug;
mod keylog;

/// Internal classes which may be useful outside the library.
/// The contents of this section DO NOT form part of the stable interface.
pub mod internal {
    /// Functions for parsing PEM files containing certificates/keys.
    pub mod pemfile {
        pub use pemfile::{certs, rsa_private_keys, pkcs8_private_keys};
    }

    /// Low-level TLS message parsing and encoding functions.
    pub mod msgs {
        pub use msgs::*;
    }
}

// The public interface is:
pub use msgs::enums::ProtocolVersion;
pub use msgs::enums::SignatureScheme;
pub use msgs::enums::CipherSuite;
pub use error::TLSError;
pub use session::Session;
pub use stream::{Stream, StreamOwned};
pub use anchors::{DistinguishedNames, RootCertStore};
pub use client::StoresClientSessions;
pub use client::handy::{NoClientSessionStorage, ClientSessionMemoryCache};
pub use client::{ClientConfig, ClientSession};
pub use client::ResolvesClientCert;
pub use server::StoresServerSessions;
pub use server::handy::{NoServerSessionStorage, ServerSessionMemoryCache};
pub use server::{ServerConfig, ServerSession};
pub use server::handy::ResolvesServerCertUsingSNI;
pub use server::ResolvesServerCert;
pub use server::ProducesTickets;
pub use ticketer::Ticketer;
pub use verify::{NoClientAuth, AllowAnyAuthenticatedClient,
                 AllowAnyAnonymousOrAuthenticatedClient};
pub use suites::{ALL_CIPHERSUITES, BulkAlgorithm, SupportedCipherSuite};
pub use key::{Certificate, PrivateKey};
pub use keylog::{KeyLog, NoKeyLog, KeyLogFile};
pub use vecbuf::WriteV;

/// Message signing interfaces and implementations.
pub mod sign;

#[cfg(feature = "quic")]
/// APIs for implementing QUIC TLS
pub mod quic;

#[cfg(not(feature = "quic"))]
// If QUIC support is disabled, just define a private module with an empty
// trait to allow Session having QuicExt as a trait bound.
mod quic {
    pub trait QuicExt {}
    impl QuicExt for super::ClientSession {}
    impl QuicExt for super::ServerSession {}
}

#[cfg(feature = "dangerous_configuration")]
pub use verify::{ServerCertVerifier, ServerCertVerified,
    ClientCertVerifier, ClientCertVerified};
#[cfg(feature = "dangerous_configuration")]
pub use client::danger::DangerousClientConfig;

