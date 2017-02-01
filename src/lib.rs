//! # Rustls - a modern TLS library
//! Rustls is a TLS library that aims to provide a good level of cryptographic security,
//! requires no configuration to achieve that security, and provides no unsafe features or
//! obsolete cryptography.
//!
//! ## Current features
//!
//! * TLS1.2 only.
//! * ECDSA or RSA server authentication by clients.
//! * RSA server authentication by servers.
//! * Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
//! * AES128-GCM and AES256-GCM bulk encryption, with safe nonces.
//! * Chacha20Poly1305 bulk encryption.
//! * ALPN support.
//! * SNI support.
//! * Tunable MTU to make TLS messages match size of underlying transport.
//! * Resumption.
//! * Resumption via tickets (RFC5077).
//! * Client authentication by clients.
//! * Client authentication by servers.
//!
//! ## Possible future features
//!
//! * ECDSA server authentication by servers.
//! * PSK support.
//! * TLS1.3.
//! * OCSP stapling.
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
//! These objects are not `Send` or `Sync`, so exist in one thread unless you make
//! your own arrangements.
//!
//! ### Rustls takes care of server certificate verification
//! You do not need to provide anything other than a set of root certificates to trust.
//! Certificate verification cannot be turned off or disabled.
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
//! config.root_store.add_trust_anchors(&webpki_roots::ROOTS);
//! ```
//!
//! Now we can make a session.  You need to provide the server's hostname so we
//! know what to expect to find in the server's certificate.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # let mut config = rustls::ClientConfig::new();
//! let rc_config = Arc::new(config);
//! let mut client = rustls::ClientSession::new(&rc_config, "example.com");
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
//! return `Err(WebPKIError(CertExpired))`.
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

/* Our dependencies: */

/* webpki for certificate verification. */
extern crate webpki;

/* *ring* for cryptography. */
extern crate ring;

/* time for feeding webpki the time. */
extern crate time;

/* untrusted for feeding ring and webpki. */
extern crate untrusted;

/* rust-base64 for pemfile module. */
extern crate base64;

/* log for logging (optional). */
#[cfg(feature = "logging")]
#[macro_use]
extern crate log;

extern crate crossbeam;
extern crate rayon;

#[cfg(not(feature = "logging"))]
#[macro_use]
mod compile_out_log {
  macro_rules! debug    ( ($($tt:tt)*) => {{}} );
  macro_rules! info     ( ($($tt:tt)*) => {{}} );
  macro_rules! warn     ( ($($tt:tt)*) => {{}} );
  macro_rules! error    ( ($($tt:tt)*) => {{}} );
}

mod util;
#[macro_use]
mod msgs;
mod error;
mod rand;
mod hash_hs;
mod vecbuf;
mod prf;
mod cipher;
mod session;
mod pemfile;
mod x509;
mod sign;
mod verify;
mod handshake;
mod server_hs;
mod client_hs;
mod suites;
mod ticketer;
mod server;
mod client;
mod key;
/// Internal classes which may be useful outside the library.
/// The contents of this section DO NOT form part of the stable interface.
pub mod internal {
  /// Functions for parsing PEM files containing certificates/keys.
  pub mod pemfile {
    pub use pemfile::{certs, rsa_private_keys};
  }

  /// Low-level TLS message parsing and encoding functions.
  pub mod msgs {
    pub use msgs::*;
  }
}

/* The public interface is: */
pub use error::TLSError;
pub use session::Session;
pub use verify::{RootCertStore, verify_server_cert, parallel_verify_server_cert};
pub use client::{StoresClientSessions, ClientSessionMemoryCache, ClientConfig, ClientSession};
pub use server::{StoresServerSessions, ServerSessionMemoryCache, ServerConfig, ServerSession};
pub use server::ProducesTickets;
pub use ticketer::Ticketer;
pub use suites::{ALL_CIPHERSUITES, SupportedCipherSuite};
pub use key::{Certificate, PrivateKey};
