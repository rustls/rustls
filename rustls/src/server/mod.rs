use alloc::vec::Vec;

use pki_types::{DnsName, UnixTime};

use crate::crypto::cipher::Payload;
use crate::crypto::{CipherSuite, Identity};
use crate::enums::{ApplicationProtocol, ProtocolVersion};
use crate::error::InvalidMessage;
use crate::msgs::{Codec, MaybeEmpty, Reader, SessionId, SizedPayload};
pub use crate::verify::NoClientAuth;
#[cfg(feature = "webpki")]
pub use crate::webpki::{
    ClientVerifierBuilder, ParsedCertificate, VerifierBuilderError, WebPkiClientVerifier,
};

pub(crate) mod config;
pub use config::{
    ClientHello, InvalidSniPolicy, ServerConfig, ServerCredentialResolver, StoresServerSessions,
    WantsServerCert,
};

mod connection;
pub use connection::{
    Accepted, AcceptedAlert, Acceptor, ReadEarlyData, ServerConnection, ServerSide,
};

pub(crate) mod handy;
#[cfg(feature = "webpki")]
pub use handy::ServerNameResolver;
pub use handy::{NoServerSessionStorage, ServerSessionMemoryCache};

mod hs;
pub(crate) use hs::ServerHandler;

mod state;
pub use state::{
    AwaitClientFlight, ChooseConfig, ReceiveEarlyData, SendHalfRttTraffic, SendServerFlight,
    ServerOutputs, ServerState, ServerTraffic,
};

mod tls12;
pub(crate) use tls12::TLS12_HANDLER;
use tls12::Tls12ServerSessionValue;

mod tls13;
pub(crate) use tls13::TLS13_HANDLER;
use tls13::Tls13ServerSessionValue;

/// Dangerous configuration that should be audited and used with extreme care.
pub mod danger {
    pub use crate::verify::{
        ClientIdentity, ClientVerifier, PeerVerified, SignatureVerificationInput,
    };
}

#[cfg(test)]
mod test;

#[derive(Debug)]
pub(crate) enum ServerSessionValue<'a> {
    Tls12(Tls12ServerSessionValue<'a>),
    Tls13(Tls13ServerSessionValue<'a>),
}

impl<'a> Codec<'a> for ServerSessionValue<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Tls12(value) => {
                ProtocolVersion::TLSv1_2.encode(bytes);
                value.encode(bytes);
            }
            Self::Tls13(value) => {
                ProtocolVersion::TLSv1_3.encode(bytes);
                value.encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        match ProtocolVersion::read(r)? {
            ProtocolVersion::TLSv1_2 => Ok(Self::Tls12(Tls12ServerSessionValue::read(r)?)),
            ProtocolVersion::TLSv1_3 => Ok(Self::Tls13(Tls13ServerSessionValue::read(r)?)),
            _ => Err(InvalidMessage::UnknownProtocolVersion),
        }
    }
}

#[derive(Debug)]
pub(crate) struct CommonServerSessionValue<'a> {
    pub(crate) creation_time_sec: u64,
    pub(crate) sni: Option<DnsName<'a>>,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) peer_identity: Option<Identity<'a>>,
    pub(crate) alpn: Option<ApplicationProtocol<'a>>,
    pub(crate) application_data: SizedPayload<'a, u16, MaybeEmpty>,
}

impl<'a> CommonServerSessionValue<'a> {
    pub(crate) fn new(
        sni: Option<&DnsName<'a>>,
        cipher_suite: CipherSuite,
        peer_identity: Option<Identity<'a>>,
        alpn: Option<ApplicationProtocol<'a>>,
        application_data: Vec<u8>,
        creation_time: UnixTime,
    ) -> Self {
        Self {
            creation_time_sec: creation_time.as_secs(),
            sni: sni.map(|s| s.to_owned()),
            cipher_suite,
            peer_identity,
            alpn,
            application_data: SizedPayload::from(Payload::new(application_data)),
        }
    }

    fn into_owned(self) -> CommonServerSessionValue<'static> {
        CommonServerSessionValue {
            creation_time_sec: self.creation_time_sec,
            sni: self.sni.map(|s| s.to_owned()),
            cipher_suite: self.cipher_suite,
            peer_identity: self
                .peer_identity
                .map(|i| i.into_owned()),
            alpn: self.alpn.map(|a| a.to_owned()),
            application_data: self.application_data.into_owned(),
        }
    }

    pub(crate) fn can_resume(&self, suite: CipherSuite, sni: Option<&DnsName<'_>>) -> bool {
        // The RFCs underspecify what happens if we try to resume to
        // an unoffered/varying suite.  We merely don't resume in weird cases.
        //
        // RFC 6066 says "A server that implements this extension MUST NOT accept
        // the request to resume the session if the server_name extension contains
        // a different name. Instead, it proceeds with a full handshake to
        // establish a new session."
        //
        // RFC 8446: "The server MUST ensure that it selects
        // a compatible PSK (if any) and cipher suite."
        self.cipher_suite == suite && self.sni.as_ref() == sni
    }
}

impl Codec<'_> for CommonServerSessionValue<'_> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.creation_time_sec.encode(bytes);
        if let Some(sni) = &self.sni {
            1u8.encode(bytes);
            let sni_bytes: &str = sni.as_ref();
            SizedPayload::<u8, MaybeEmpty>::from(Payload::Borrowed(sni_bytes.as_bytes()))
                .encode(bytes);
        } else {
            0u8.encode(bytes);
        }
        self.cipher_suite.encode(bytes);
        if let Some(identity) = &self.peer_identity {
            1u8.encode(bytes);
            identity.encode(bytes);
        } else {
            0u8.encode(bytes);
        }
        if let Some(alpn) = &self.alpn {
            1u8.encode(bytes);
            alpn.encode(bytes);
        } else {
            0u8.encode(bytes);
        }
        self.application_data.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let creation_time_sec = u64::read(r)?;
        let sni = match u8::read(r)? {
            1 => {
                let dns_name = SizedPayload::<u8, MaybeEmpty>::read(r)?;
                let dns_name = match DnsName::try_from(dns_name.bytes()) {
                    Ok(dns_name) => dns_name.to_owned(),
                    Err(_) => return Err(InvalidMessage::InvalidServerName),
                };

                Some(dns_name)
            }
            _ => None,
        };

        Ok(Self {
            creation_time_sec,
            sni,
            cipher_suite: CipherSuite::read(r)?,
            peer_identity: match u8::read(r)? {
                1 => Some(Identity::read(r)?.into_owned()),
                _ => None,
            },
            alpn: match u8::read(r)? {
                1 => Some(ApplicationProtocol::read(r)?.to_owned()),
                _ => None,
            },
            application_data: SizedPayload::read(r)?.into_owned(),
        })
    }
}

/// A key that identifies a server-side resumable session.
pub struct ServerSessionKey<'a> {
    inner: &'a [u8],
}

impl<'a> ServerSessionKey<'a> {
    pub(crate) fn new(inner: &'a [u8]) -> Self {
        Self { inner }
    }
}

impl<'a> From<&'a SessionId> for ServerSessionKey<'a> {
    fn from(session_id: &'a SessionId) -> Self {
        Self::new(session_id.as_ref())
    }
}

impl AsRef<[u8]> for ServerSessionKey<'_> {
    fn as_ref(&self) -> &[u8] {
        self.inner
    }
}
