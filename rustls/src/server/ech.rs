#[cfg(feature = "std")]
use crate::common_state::{Context, State};
#[cfg(feature = "std")]
use crate::conn::ConnectionCore;
use crate::crypto::hpke::{EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey};
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{
    ClientExtension, ClientHelloPayload, EchConfigPayload, EncryptedClientHello,
    EncryptedClientHelloOuter, HpkeSymmetricCipherSuite,
};
#[cfg(feature = "std")]
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
#[cfg(feature = "std")]
use crate::msgs::message::{Message, MessagePayload, PlainMessage};
use crate::server::hs::ServerContext;
#[cfg(feature = "std")]
use crate::server::ClientHello;
use crate::server::ServerConnectionData;
#[cfg(feature = "std")]
use crate::vecbuf::ChunkVecBuffer;
#[cfg(feature = "std")]
use crate::ServerConnection;
use crate::{
    AlertDescription, ConnectionCommon, Error, InvalidMessage, PeerMisbehaved, ProtocolVersion,
};
#[cfg(feature = "std")]
use crate::{CommonState, HandshakeType, Side, SignatureScheme};
#[cfg(feature = "std")]
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::{Debug, Formatter};
use pki_types::DnsName;

pub struct EchConfig {
    pub private_key: HpkePrivateKey,
    pub config: EchConfigPayload,
    pub is_retry: bool,
}

impl EchConfig {
    // TODO this is copied. move into EchConfigPayload?
    pub(crate) fn hpke_info(&self) -> Vec<u8> {
        let mut info = Vec::with_capacity(128);
        // "tls ech" || 0x00 || ECHConfig
        info.extend_from_slice(b"tls ech\0");
        self.config.encode(&mut info);
        info
    }
}

pub(crate) struct DecodeContext {
    opener: Box<dyn HpkeOpener>,
    config_id: u8,
    cipher_suite: HpkeSymmetricCipherSuite,
    public_name: DnsName<'static>,
    inner_hello: ClientHelloPayload,
}

pub(crate) fn parse_ech_ext_outer_and_sni<'a>(
    cx: &mut ServerContext<'_>,
    ech_extension: Option<&'a EncryptedClientHello>,
) -> Result<Option<(&'a EncryptedClientHelloOuter, DnsName<'static>)>, Error> {
    match (ech_extension, cx.data.sni.clone()) {
        (Some(EncryptedClientHello::Outer(ech_ext_outer)), Some(sni)) => {
            Ok(Some((ech_ext_outer, sni)))
        }
        (Some(EncryptedClientHello::Outer(_)), None) => Err(cx
            .common
            .missing_extension(PeerMisbehaved::MissingSni)),
        (Some(EncryptedClientHello::Inner), _) => Err(cx.common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::OfferedIncorrectEchType,
        )),
        (None, _) => Ok(None),
    }
}

pub(crate) fn handle_ech_outer(
    ech_configs: &[EchConfig],
    hpke_suites: &[&'static dyn Hpke],
    cx: &mut ServerContext<'_>,
    outer_hello: &ClientHelloPayload,
    ech_ext_outer: &EncryptedClientHelloOuter,
    sni: &DnsName<'_>,
) -> Result<Option<DecodeContext>, Error> {
    let matching_configs = find_matching_ech_configs(ech_configs, hpke_suites, ech_ext_outer);
    let aad = compute_ech_aad(outer_hello.clone());

    // TODO: should it support the "strategy" where you try against every single config?
    let mut decode_context = None;
    for (hpke, ech_config, public_name) in matching_configs {
        if let Ok(mut opener) = hpke.setup_opener(
            &EncapsulatedSecret(ech_ext_outer.enc.0.clone()),
            &ech_config.hpke_info(),
            &ech_config.private_key,
        ) {
            if let Ok(plaintext) = opener.open(&aad, &ech_ext_outer.payload.0) {
                if sni != public_name {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::MismatchedSniAndEchConfigPublicName,
                    ));
                }

                let mut reader = Reader::init(&plaintext);
                // TODO: this code is inspired from ::read(), can it be refactored?
                let decode_result =
                    ClientHelloPayload::payload_decode(&mut reader, true).and_then(|r| {
                        reader.expect_empty("read_bytes")?;
                        Ok(r)
                    });

                match decode_result {
                    Ok(decoded_hello) => {
                        decode_context = Some(DecodeContext {
                            opener,
                            config_id: ech_ext_outer.config_id,
                            cipher_suite: ech_ext_outer.cipher_suite,
                            public_name: public_name.to_owned(),
                            inner_hello: decoded_hello,
                        });
                        break;
                    }
                    Err(InvalidMessage::TrailingData(_)) => {
                        return Err(cx.common.send_fatal_alert(
                            AlertDescription::IllegalParameter,
                            PeerMisbehaved::NonZeroClientHelloInnerPadding,
                        ))
                    }
                    _ => {
                        // TODO: if we fail to read the decrypted CH, does that mean it failed to decrypt
                        // and it should move on to the next configuration, or should it abort?
                    }
                }
            }
        }
    }

    if let Some(mut decode_context) = decode_context {
        validate_inner_hello(cx, outer_hello, &mut decode_context.inner_hello)?;
        return Ok(Some(decode_context));
    }

    Ok(None)
}

fn find_matching_ech_configs<'a>(
    ech_configs: &'a [EchConfig],
    hpke_suites: &[&'static dyn Hpke],
    ech_ext_outer: &EncryptedClientHelloOuter,
) -> Vec<(&'static dyn Hpke, &'a EchConfig, &'a DnsName<'static>)> {
    ech_configs
        .iter()
        .filter_map(|ech_config| {
            // TODO: we're supposed to check if the ECH version matches.
            // but that's also the codepoint of the ech extension.
            // can we even handle multiple versions?
            match &ech_config.config {
                EchConfigPayload::V18(contents) => {
                    if contents.key_config.config_id != ech_ext_outer.config_id {
                        return None;
                    }

                    let hs = contents
                        .key_config
                        .symmetric_cipher_suites
                        .iter()
                        .find(|hs| **hs == ech_ext_outer.cipher_suite)?;
                    let hpke = hpke_suites
                        .iter()
                        .find(|hpke| {
                            hpke.suite().kem == contents.key_config.kem_id
                                && hpke.suite().sym == *hs
                        })
                        .copied()?;

                    Some((hpke, ech_config, &contents.public_name))
                }
                // TODO: can we avoid this beforehand?
                EchConfigPayload::Unknown { .. } => None,
            }
        })
        // TODO: is avoiding collect() possible?
        .collect()
}

fn compute_ech_aad(mut client_hello: ClientHelloPayload) -> Vec<u8> {
    // Safety: already know ECH Outer extension is present
    // TODO: do I pull the unwrap out of the function?
    let ech_outer = client_hello
        .extensions
        .iter_mut()
        .find_map(|ext| match ext {
            ClientExtension::EncryptedClientHello(EncryptedClientHello::Outer(ech_outer)) => {
                Some(ech_outer)
            }
            _ => None,
        })
        .unwrap();
    ech_outer.payload = PayloadU16::new(vec![0; ech_outer.payload.0.len()]);
    client_hello.get_encoding()
}

fn maybe_process_ech_outer_exts(
    cx: &mut ServerContext<'_>,
    outer_hello: &ClientHelloPayload,
    inner_hello: &mut ClientHelloPayload,
) -> Result<(), Error> {
    let ech_outer_exts = inner_hello
        .extensions
        .iter()
        .enumerate()
        .find_map(|(idx, ext)| {
            if let ClientExtension::EncryptedClientHelloOuterExtensions(extension_types) = ext {
                return Some((idx, extension_types.clone()));
            }

            None
        });

    if let Some((ech_outer_exts_idx, ech_outer_ext_types)) = ech_outer_exts {
        // recommended linear time algorithm
        // TODO: can this be more rust-like?
        let mut i = 0;
        let n = outer_hello.extensions.len();
        let mut decompressed = Vec::with_capacity(n);
        for extension_type in ech_outer_ext_types {
            if matches!(extension_type, ExtensionType::EncryptedClientHello) {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::IllegalEchExtensionInEchOuterExtensions,
                ));
            }

            while i < n && outer_hello.extensions[i].ext_type() != extension_type {
                i += 1;
            }

            if i == n {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::MismatchedEchOuterExtensions,
                ));
            }

            decompressed.push(outer_hello.extensions[i].clone());
            i += 1;
        }

        inner_hello
            .extensions
            .splice(ech_outer_exts_idx..ech_outer_exts_idx + 1, decompressed);
    }

    Ok(())
}

fn validate_inner_hello(
    cx: &mut ServerContext<'_>,
    outer_hello: &ClientHelloPayload,
    inner_hello: &mut ClientHelloPayload,
) -> Result<(), Error> {
    maybe_process_ech_outer_exts(cx, outer_hello, inner_hello)?;

    if inner_hello
        .ech_extension()
        .map(|ext| match ext {
            EncryptedClientHello::Outer(_) => None,
            EncryptedClientHello::Inner => Some(()),
        })
        .is_none()
    {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::OfferedIncorrectEchType,
        ));
    }

    let bad_tls_ver = inner_hello
        .versions_extension()
        .map(|versions| {
            versions.iter().any(|version| {
                matches!(
                    *version,
                    // TODO: this is ugly but we need a way to check if it's <TLS1.3. can't just check for non-1.3 ver bc of GREASE
                    // TODO: need to care about dtls?
                    ProtocolVersion::SSLv2
                        | ProtocolVersion::SSLv3
                        | ProtocolVersion::TLSv1_0
                        | ProtocolVersion::TLSv1_1
                        | ProtocolVersion::TLSv1_2
                )
            })
        })
        .unwrap_or(true);
    if bad_tls_ver {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::OfferedEchWithOldProtocolVersion,
        ));
    }

    inner_hello.session_id = outer_hello.session_id;

    Ok(())
}

#[cfg(feature = "std")]
pub enum EchStatus {
    Accepted(EchAccepted),
    Rejected(ServerConnection),
}

// TODO: this is copied from AcceptedAlert
#[cfg(feature = "std")]
pub struct EchAlert<'a>(&'a mut ChunkVecBuffer);

#[cfg(feature = "std")]
impl<'a> EchAlert<'a> {
    pub fn write(&mut self, wr: &mut dyn std::io::Write) -> Result<usize, std::io::Error> {
        self.0.write_to(wr)
    }

    pub fn write_all(&mut self, wr: &mut dyn std::io::Write) -> Result<(), std::io::Error> {
        while self.write(wr)? != 0 {}
        Ok(())
    }
}

#[cfg(feature = "std")]
impl<'a> From<&'a mut ConnectionCommon<ServerConnectionData>> for EchAlert<'a> {
    fn from(conn: &'a mut ConnectionCommon<ServerConnectionData>) -> Self {
        Self(&mut conn.core.common_state.sendable_tls)
    }
}

#[cfg(feature = "std")]
impl<'a> Debug for EchAlert<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EchAlert").finish()
    }
}

#[cfg(feature = "std")]
pub struct EchAccepted {
    decode_context: DecodeContext,
    frontend_connection: ConnectionCommon<ServerConnectionData>,
    backend_connection: ConnectionCommon<()>,
    backend_buf: ChunkVecBuffer,
    sig_schemes: Vec<SignatureScheme>,
    received_backend_message: bool,
    done: bool,
}

#[cfg(feature = "std")]
impl EchAccepted {
    pub(crate) fn new(
        decode_context: DecodeContext,
        frontend_connection: ConnectionCommon<ServerConnectionData>,
        sig_schemes: Vec<SignatureScheme>,
    ) -> Self {
        let mut backend_buf = ChunkVecBuffer::new(None);
        let encoded = Self::serialize_hello(decode_context.inner_hello.clone(), false);
        backend_buf.append(encoded);

        Self {
            decode_context,
            frontend_connection,
            backend_connection: ConnectionCommon::from(ConnectionCore::new(
                Box::new(Dummy),
                (),
                CommonState::new(Side::Client),
            )),
            backend_buf,
            sig_schemes,
            received_backend_message: false,
            done: false,
        }
    }

    pub fn done(&self) -> bool {
        self.done
    }

    pub fn read_frontend_tls(
        &mut self,
        rd: &mut dyn std::io::Read,
    ) -> Result<usize, std::io::Error> {
        self.frontend_connection.read_tls(rd)
    }

    pub fn wants_backend_write(&self) -> bool {
        !self.backend_buf.is_empty()
    }

    pub fn write_backend_tls(
        &mut self,
        wr: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        self.backend_buf.write_to(wr)
    }

    pub fn wants_backend_copy(&self) -> bool {
        !self.received_backend_message
    }

    pub fn copy_backend_tls(&mut self, rd: &[u8]) -> Result<usize, std::io::Error> {
        self.backend_connection
            .read_tls(&mut std::io::Cursor::new(rd))
    }

    pub fn process_io(&mut self) -> Result<(), Error> {
        if !self.received_backend_message {
            match self
                .backend_connection
                .first_handshake_message()
            {
                Ok(Some(Message {
                    payload:
                        MessagePayload::Handshake {
                            parsed:
                                HandshakeMessagePayload {
                                    typ: HandshakeType::ServerHello,
                                    ..
                                },
                            ..
                        },
                    ..
                })) => {
                    self.done = true;
                    self.received_backend_message = true;
                }
                Ok(Some(Message {
                    payload:
                        MessagePayload::Handshake {
                            parsed:
                                HandshakeMessagePayload {
                                    typ: HandshakeType::HelloRetryRequest,
                                    ..
                                },
                            ..
                        },
                    ..
                })) => {
                    self.received_backend_message = true;
                }
                Err(_) => {
                    return Err(self
                        .frontend_connection
                        .core
                        .common_state
                        .send_fatal_alert(
                            AlertDescription::InternalError,
                            // TODO: what to put?
                            Error::General("todo".to_owned()),
                        ));
                }
                _ => {}
            }
        }

        if self.done || !self.received_backend_message {
            // TODO: sufficient?
            self.backend_buf.append(
                self.frontend_connection
                    .deframer_buffer
                    .filled()
                    .to_owned(),
            );

            return Ok(());
        };

        loop {
            let message = match self
                .frontend_connection
                .first_handshake_message()
            {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(_) => {
                    return Err(self
                        .frontend_connection
                        .core
                        .common_state
                        .send_fatal_alert(
                            AlertDescription::InternalError,
                            // TODO: what to put?
                            Error::General("todo".to_owned()),
                        ));
                }
            };

            match &message {
                Message {
                    payload:
                        MessagePayload::Handshake {
                            parsed:
                                HandshakeMessagePayload {
                                    payload: HandshakePayload::ClientHello(outer_hello),
                                    ..
                                },
                            ..
                        },
                    ..
                } => {
                    let mut cx = Context::from(&mut self.frontend_connection);
                    let _ = crate::server::hs::process_client_hello(&message, true, &mut cx)?;

                    let (ech_ext_outer, sni) =
                        parse_ech_ext_outer_and_sni(&mut cx, outer_hello.ech_extension())?
                            .ok_or_else(|| {
                                cx.common
                                    .missing_extension(PeerMisbehaved::MissingEch)
                            })?;

                    if ech_ext_outer.config_id != self.decode_context.config_id
                        || ech_ext_outer.cipher_suite != self.decode_context.cipher_suite
                        || !ech_ext_outer.enc.0.is_empty()
                    {
                        return Err(cx.common.send_fatal_alert(
                            AlertDescription::IllegalParameter,
                            PeerMisbehaved::InvalidEchExtensionInEchOuterAfterRetry,
                        ));
                    }

                    let aad = compute_ech_aad(outer_hello.clone());
                    let mut inner_hello = self
                        .decode_context
                        .opener
                        .open(&aad, &ech_ext_outer.payload.0)
                        .and_then(|plaintext| {
                            let mut reader = Reader::init(&plaintext);
                            ClientHelloPayload::payload_decode(&mut reader, true)
                                .and_then(|r| {
                                    reader.expect_empty("read_bytes")?;
                                    Ok(r)
                                })
                                .map_err(|e| e.into())
                        })
                        .map_err(|_| {
                            cx.common.send_fatal_alert(
                                AlertDescription::DecryptError,
                                PeerMisbehaved::InvalidSecondEch,
                            )
                        })?;

                    if sni != self.decode_context.public_name {
                        return Err(cx.common.send_fatal_alert(
                            AlertDescription::IllegalParameter,
                            PeerMisbehaved::MismatchedSniAndEchConfigPublicName,
                        ));
                    }

                    validate_inner_hello(&mut cx, outer_hello, &mut inner_hello)?;

                    let encoded = Self::serialize_hello(inner_hello.clone(), true);
                    self.backend_buf.append(encoded);
                    self.done = true;
                }
                _ => {
                    let encoded = PlainMessage::from(message)
                        .into_unencrypted_opaque()
                        .encode();
                    self.backend_buf.append(encoded);
                }
            }
        }

        Ok(())
    }

    // TODO: this doesn't seem ideal
    pub fn as_alert(&mut self) -> EchAlert<'_> {
        EchAlert::from(&mut self.frontend_connection)
    }

    pub fn initial_hello(&self) -> ClientHello<'_> {
        ClientHello::new(
            &self.frontend_connection.core.data.sni,
            &self.sig_schemes,
            self.decode_context
                .inner_hello
                .alpn_extension(),
            &self
                .decode_context
                .inner_hello
                .cipher_suites,
        )
    }

    fn serialize_hello(chp: ClientHelloPayload, second: bool) -> Vec<u8> {
        let message = Message {
            version: if second {
                ProtocolVersion::TLSv1_2
            } else {
                ProtocolVersion::TLSv1_0
            },
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientHello,
                payload: HandshakePayload::ClientHello(chp),
            }),
        };

        let plain = PlainMessage::from(message);
        plain.into_unencrypted_opaque().encode()
    }
}

// TODO: shares a lot with Accepting
#[cfg(feature = "std")]
struct Dummy;

#[cfg(feature = "std")]
impl State<()> for Dummy {
    fn handle<'m>(
        self: Box<Self>,
        _cx: &mut Context<'_, ()>,
        _m: Message<'m>,
    ) -> Result<Box<dyn State<()> + 'm>, Error>
    where
        Self: 'm,
    {
        Err(Error::General("unreachable state".into()))
    }

    fn into_owned(self: Box<Self>) -> Box<dyn State<()> + 'static> {
        self
    }
}
