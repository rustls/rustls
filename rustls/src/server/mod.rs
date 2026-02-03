use alloc::vec::Vec;

use pki_types::{DnsName, UnixTime};
use zeroize::Zeroizing;

use crate::crypto::cipher::Payload;
use crate::crypto::{CipherSuite, Identity};
use crate::enums::{ApplicationProtocol, ProtocolVersion};
use crate::error::InvalidMessage;
use crate::msgs::{Codec, MaybeEmpty, Reader, SizedPayload};
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
#[cfg(feature = "std")]
pub use connection::{Accepted, AcceptedAlert, Acceptor, ReadEarlyData, ServerConnection};
pub use connection::{ServerConnectionData, UnbufferedServerConnection};

pub(crate) mod handy;
pub use handy::NoServerSessionStorage;
#[cfg(all(any(feature = "std", feature = "hashbrown"), feature = "webpki"))]
pub use handy::ServerNameResolver;
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use handy::ServerSessionMemoryCache;

mod hs;
pub(crate) use hs::ServerHandler;

mod tls12;
pub(crate) use tls12::TLS12_HANDLER;

mod tls13;
pub(crate) use tls13::TLS13_HANDLER;

/// Dangerous configuration that should be audited and used with extreme care.
pub mod danger {
    pub use crate::verify::{
        ClientIdentity, ClientVerifier, PeerVerified, SignatureVerificationInput,
    };
}

#[cfg(test)]
mod test;

#[derive(Debug)]
pub(crate) enum ServerSessionValue {
    Tls12(Tls12ServerSessionValue),
    Tls13(Tls13ServerSessionValue),
}

impl Codec<'_> for ServerSessionValue {
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

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match ProtocolVersion::read(r)? {
            ProtocolVersion::TLSv1_2 => Ok(Self::Tls12(Tls12ServerSessionValue::read(r)?)),
            ProtocolVersion::TLSv1_3 => Ok(Self::Tls13(Tls13ServerSessionValue::read(r)?)),
            _ => Err(InvalidMessage::UnknownProtocolVersion),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Tls12ServerSessionValue {
    pub(crate) common: CommonServerSessionValue,
    pub(crate) master_secret: Zeroizing<[u8; 48]>,
    pub(crate) extended_ms: bool,
}

impl Tls12ServerSessionValue {
    pub(crate) fn new(
        common: CommonServerSessionValue,
        master_secret: &[u8; 48],
        extended_ms: bool,
    ) -> Self {
        Self {
            common,
            master_secret: Zeroizing::new(*master_secret),
            extended_ms,
        }
    }
}

impl Codec<'_> for Tls12ServerSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.common.encode(bytes);
        bytes.extend_from_slice(self.master_secret.as_ref());
        (self.extended_ms as u8).encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            common: CommonServerSessionValue::read(r)?,
            master_secret: Zeroizing::new(
                match r
                    .take(48)
                    .and_then(|slice| slice.try_into().ok())
                {
                    Some(array) => array,
                    None => return Err(InvalidMessage::MessageTooShort),
                },
            ),
            extended_ms: matches!(u8::read(r)?, 1),
        })
    }
}

impl From<Tls12ServerSessionValue> for ServerSessionValue {
    fn from(value: Tls12ServerSessionValue) -> Self {
        Self::Tls12(value)
    }
}

#[derive(Debug)]
pub(crate) struct Tls13ServerSessionValue {
    pub(crate) common: CommonServerSessionValue,
    pub(crate) secret: Zeroizing<SizedPayload<'static, u8>>,
    pub(crate) age_obfuscation_offset: u32,

    // not encoded vv
    freshness: Option<bool>,
}

impl Tls13ServerSessionValue {
    pub(crate) fn new(
        common: CommonServerSessionValue,
        secret: &[u8],
        age_obfuscation_offset: u32,
    ) -> Self {
        Self {
            common,
            secret: Zeroizing::new(secret.to_vec().into()),
            age_obfuscation_offset,
            freshness: None,
        }
    }

    pub(crate) fn set_freshness(
        mut self,
        obfuscated_client_age_ms: u32,
        time_now: UnixTime,
    ) -> Self {
        let client_age_ms = obfuscated_client_age_ms.wrapping_sub(self.age_obfuscation_offset);
        let server_age_ms = (time_now
            .as_secs()
            .saturating_sub(self.common.creation_time_sec) as u32)
            .saturating_mul(1000);

        let age_difference = server_age_ms.abs_diff(client_age_ms);

        self.freshness = Some(age_difference <= MAX_FRESHNESS_SKEW_MS);
        self
    }

    pub(crate) fn is_fresh(&self) -> bool {
        self.freshness.unwrap_or_default()
    }
}

impl Codec<'_> for Tls13ServerSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.common.encode(bytes);
        self.secret.encode(bytes);
        self.age_obfuscation_offset
            .encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            common: CommonServerSessionValue::read(r)?,
            secret: Zeroizing::new(SizedPayload::read(r)?.into_owned()),
            age_obfuscation_offset: u32::read(r)?,
            freshness: None,
        })
    }
}

impl From<Tls13ServerSessionValue> for ServerSessionValue {
    fn from(value: Tls13ServerSessionValue) -> Self {
        Self::Tls13(value)
    }
}

#[derive(Debug)]
pub(crate) struct CommonServerSessionValue {
    pub(crate) creation_time_sec: u64,
    pub(crate) sni: Option<DnsName<'static>>,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) peer_identity: Option<Identity<'static>>,
    pub(crate) alpn: Option<ApplicationProtocol<'static>>,
    pub(crate) application_data: SizedPayload<'static, u16, MaybeEmpty>,
}

impl CommonServerSessionValue {
    pub(crate) fn new(
        sni: Option<&DnsName<'_>>,
        cipher_suite: CipherSuite,
        peer_identity: Option<Identity<'static>>,
        alpn: Option<ApplicationProtocol<'static>>,
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

impl Codec<'_> for CommonServerSessionValue {
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

/// This is the maximum allowed skew between server and client clocks, over
/// the maximum ticket lifetime period.  This encompasses TCP retransmission
/// times in case packet loss occurs when the client sends the ClientHello
/// or receives the NewSessionTicket, _and_ actual clock skew over this period.
static MAX_FRESHNESS_SKEW_MS: u32 = 60 * 1000;
