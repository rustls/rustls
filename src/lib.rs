extern crate webpki;
extern crate ring;
extern crate rustc_serialize;
#[macro_use]
extern crate log;

mod msgs;
mod error;
mod rand;
mod hash_hs;
mod prf;
mod session;
mod pemfile;
mod sign;
mod verify;
mod handshake;
mod server_hs;
mod client_hs;
mod suites;
mod server;
mod client;

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
pub use client::{StoresClientSessions, ClientConfig, ClientSession};
pub use verify::{RootCertStore};
pub use server::{ServerConfig, ServerSession};
pub use suites::{ALL_CIPHERSUITES, SupportedCipherSuite};
