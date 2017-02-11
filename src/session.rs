use ring;
use msgs::enums::ProtocolVersion;
use error::TLSError;
use key;
use prf;
use rand;

use std::io;
use std::io::{Read, Write};

/// Generalises `ClientSession` and `ServerSession`
pub trait Session: Read + Write + Send {
    /// Read TLS content from `rd`.  This method does internal
    /// buffering, so `rd` can supply TLS messages in arbitrary-
    /// sized chunks (like a socket or pipe might).
    ///
    /// You should call `process_new_packets` each time a call to
    /// this function succeeds.
    ///
    /// The returned error only relates to IO on `rd`.  TLS-level
    /// errors are emitted from `process_new_packets`.
    ///
    /// This function returns `Ok(0)` when the underlying `rd` does
    /// so.  This typically happens when a socket is cleanly closed,
    /// or a file is at EOF.
    fn read_tls(&mut self, rd: &mut Read) -> Result<usize, io::Error>;

    /// Writes TLS messages to `wr`.
    fn write_tls(&mut self, wr: &mut Write) -> Result<usize, io::Error>;

    /// Processes any new packets read by a previous call to `read_tls`.
    /// Errors from this function relate to TLS protocol errors, and
    /// are fatal to the session.  Future calls after an error will do
    /// no new work and will return the same error.
    ///
    /// Success from this function can mean new plaintext is available:
    /// obtain it using `read`.
    fn process_new_packets(&mut self) -> Result<(), TLSError>;

    /// Returns true if the caller should call `read_tls` as soon
    /// as possible.
    fn wants_read(&self) -> bool;

    /// Returns true if the caller should call `write_tls` as soon
    /// as possible.
    fn wants_write(&self) -> bool;

    /// Returns true if the session is currently perform the TLS
    /// handshake.  During this time plaintext written to the
    /// session is buffered in memory.
    fn is_handshaking(&self) -> bool;

    /// Queues a close_notify fatal alert to be sent in the next
    /// `write_tls` call.  This informs the peer that the
    /// connection is being closed.
    fn send_close_notify(&mut self);

    /// Retrieves the certificate chain used by the peer to authenticate.
    ///
    /// For clients, this is the certificate chain of the server.
    ///
    /// For servers, this is the certificate chain of the client,
    /// if client authentication was completed.
    ///
    /// The return value is None until this value is available.
    fn get_peer_certificates(&self) -> Option<Vec<key::Certificate>>;

    /// Retrieves the protocol agreed with the peer via ALPN.
    ///
    /// A return value of None after handshake completion
    /// means no protocol was agreed (because no protocols
    /// were offered or accepted by the peer).
    fn get_alpn_protocol(&self) -> Option<String>;

    /// Retrieves the protocol version agreed with the peer.
    ///
    /// This returns None until the version is agreed.
    fn get_protocol_version(&self) -> Option<ProtocolVersion>;
}

#[derive(Clone, Debug)]
pub struct SessionRandoms {
    pub we_are_client: bool,
    pub client: [u8; 32],
    pub server: [u8; 32],
}

impl SessionRandoms {
    pub fn for_server() -> SessionRandoms {
        let mut ret = SessionRandoms {
            we_are_client: false,
            client: [0u8; 32],
            server: [0u8; 32],
        };

        rand::fill_random(&mut ret.server);
        ret
    }

    pub fn for_client() -> SessionRandoms {
        let mut ret = SessionRandoms {
            we_are_client: true,
            client: [0u8; 32],
            server: [0u8; 32],
        };

        rand::fill_random(&mut ret.client);
        ret
    }
}

fn join_randoms(first: &[u8], second: &[u8]) -> [u8; 64] {
    let mut randoms = [0u8; 64];
    randoms.as_mut().write_all(first).unwrap();
    randoms[32..].as_mut().write_all(second).unwrap();
    randoms
}

pub struct SessionSecrets {
    pub randoms: SessionRandoms,
    hash: &'static ring::digest::Algorithm,
    master_secret: [u8; 48],
}

impl SessionSecrets {
    pub fn new(randoms: &SessionRandoms,
               hashalg: &'static ring::digest::Algorithm,
               pms: &[u8])
               -> SessionSecrets {
        let mut ret = SessionSecrets {
            randoms: randoms.clone(),
            hash: hashalg,
            master_secret: [0u8; 48],
        };

        let randoms = join_randoms(&ret.randoms.client, &ret.randoms.server);
        prf::prf(&mut ret.master_secret,
                 ret.hash,
                 pms,
                 b"master secret",
                 &randoms);
        ret
    }

    pub fn new_ems(randoms: &SessionRandoms,
                   hs_hash: &[u8],
                   hashalg: &'static ring::digest::Algorithm,
                   pms: &[u8]) -> SessionSecrets {
        let mut ret = SessionSecrets {
            randoms: randoms.clone(),
            hash: hashalg,
            master_secret: [0u8; 48]
        };

        prf::prf(&mut ret.master_secret,
                 ret.hash,
                 pms,
                 b"extended master secret",
                 hs_hash);
        ret
    }

    pub fn new_resume(randoms: &SessionRandoms,
                      hashalg: &'static ring::digest::Algorithm,
                      master_secret: &[u8])
                      -> SessionSecrets {
        let mut ret = SessionSecrets {
            randoms: randoms.clone(),
            hash: hashalg,
            master_secret: [0u8; 48],
        };
        ret.master_secret.as_mut().write_all(master_secret).unwrap();
        ret
    }

    pub fn make_key_block(&self, len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.resize(len, 0u8);

        // NOTE: opposite order to above for no good reason.
        // Don't design security protocols on drugs, kids.
        let randoms = join_randoms(&self.randoms.server, &self.randoms.client);
        prf::prf(&mut out,
                 self.hash,
                 &self.master_secret,
                 b"key expansion",
                 &randoms);

        out
    }

    pub fn get_master_secret(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        ret.extend_from_slice(&self.master_secret);
        ret
    }

    pub fn make_verify_data(&self, handshake_hash: &[u8], label: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.resize(12, 0u8);

        prf::prf(&mut out,
                 self.hash,
                 &self.master_secret,
                 label,
                 handshake_hash);
        out
    }

    pub fn client_verify_data(&self, handshake_hash: &[u8]) -> Vec<u8> {
        self.make_verify_data(handshake_hash, b"client finished")
    }

    pub fn server_verify_data(&self, handshake_hash: &[u8]) -> Vec<u8> {
        self.make_verify_data(handshake_hash, b"server finished")
    }
}

