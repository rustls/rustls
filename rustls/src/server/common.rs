use crate::hash_hs;
use crate::key;
use crate::kx;
use crate::msgs::handshake::{ServerExtension, SessionID};

use ring::digest;
use std::mem;

pub struct HandshakeDetails {
    pub transcript: hash_hs::HandshakeHash,
    pub hash_at_server_fin: Option<digest::Digest>,
    pub session_id: SessionID,
    pub extra_exts: Vec<ServerExtension>,
}

impl HandshakeDetails {
    pub fn new(extra_exts: Vec<ServerExtension>) -> HandshakeDetails {
        HandshakeDetails {
            transcript: hash_hs::HandshakeHash::new(),
            hash_at_server_fin: None,
            session_id: SessionID::empty(),
            extra_exts,
        }
    }
}

pub struct ServerKXDetails {
    pub kx: kx::KeyExchange,
}

impl ServerKXDetails {
    pub fn new(kx: kx::KeyExchange) -> ServerKXDetails {
        ServerKXDetails { kx }
    }
}

pub struct ClientCertDetails {
    pub cert_chain: Vec<key::Certificate>,
}

impl ClientCertDetails {
    pub fn new(chain: Vec<key::Certificate>) -> ClientCertDetails {
        ClientCertDetails { cert_chain: chain }
    }

    pub fn take_chain(&mut self) -> Vec<key::Certificate> {
        mem::replace(&mut self.cert_chain, Vec::new())
    }
}
