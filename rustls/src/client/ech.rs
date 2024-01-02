#![allow(dead_code)] // TODO(@cpu): remove in subsequent commit.
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use pki_types::{DnsName, ServerName};
use subtle::ConstantTimeEq;

use crate::client::EchConfig;
use crate::crypto::hash::Hash;
use crate::crypto::hpke::{EncapsulatedSecret, HpkeProvider, HpkePublicKey, HpkeSealer, HpkeSuite};
use crate::crypto::SecureRandom;
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::base::{Payload, PayloadU16};
use crate::msgs::codec::Codec;
use crate::msgs::enums::{EchVersion, ExtensionType, HpkeAead, HpkeKdf, HpkeKem};
use crate::msgs::handshake::{
    ClientExtension, ClientHelloPayload, EchConfig as EchConfigMsg, EchConfigContents, Encoding,
    EncryptedClientHello, EncryptedClientHelloOuter, HandshakeMessagePayload, HandshakePayload,
    HelloRetryRequest, HpkeKeyConfig, HpkeSymmetricCipherSuite, Random, ServerHelloPayload,
    SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::tls13::key_schedule::{server_ech_hrr_confirmation_secret, KeyScheduleHandshakeStart};
use crate::{
    AlertDescription, CommonState, Error, HandshakeType, PeerIncompatible, PeerMisbehaved,
    ProtocolVersion, Tls13CipherSuite,
};

/// An enum representing ECH offer status.
pub(crate) enum Status {
    /// ECH was not offered - it is a normal TLS handshake.
    NotOffered,
    /// ECH was offered and the server accepted.
    Accepted,
    /// ECH was offered and the server rejected.
    Rejected,
}

/// Contextual data for a TLS client handshake that has offered encrypted client hello (ECH).
pub(crate) struct EchState {
    // The public DNS name from the ECH configuration we've chosen - this is included as the SNI
    // value for the "outer" client hello. It can only be a DnsName, not an IP address.
    pub(crate) outer_name: DnsName<'static>,
    // An HPKE sealer context that can be used for encrypting ECH data.
    sender: Box<dyn HpkeSealer>,
    // The ID of the ECH configuration we've chosen - this is included in the outer ECH extension.
    config_id: u8,
    // The private server name we'll use for the inner protected hello.
    inner_name: ServerName<'static>,
    // The advertised maximum name length from the ECH configuration we've chosen - this is used
    // for padding calculations.
    maximum_name_length: u8,
    // A supported symmetric cipher suite from the ECH configuration we've chosen - this is
    // included in the outer ECH extension.
    cipher_suite: HpkeSymmetricCipherSuite,
    // A secret encapsulated to the public key of the remote server. This is included in the
    // outer ECH extension for non-retry outer hello messages.
    enc: EncapsulatedSecret,
    // A random value we use for the inner hello.
    inner_hello_random: Random,
    // A transcript buffer maintained for the inner hello. Once ECH is confirmed we switch to
    // using this transcript for the handshake.
    inner_hello_transcript: HandshakeHashBuffer,
}

impl EchState {
    pub(crate) fn new(
        config: &EchConfig,
        inner_name: ServerName<'static>,
        client_auth_enabled: bool,
        secure_random: &dyn SecureRandom,
    ) -> Result<Self, Error> {
        let config_contents = &config.config.contents;
        let key_config = &config_contents.key_config;

        // Encapsulate a secret for the server's public key, and set up a sender context
        // we can use to seal messages.
        let (enc, sender) = config
            .hpke_provider
            .start(&config.suite)?
            .setup_sealer(
                &config.hpke_info(),
                &HpkePublicKey(key_config.public_key.0.clone()),
            )?;

        // Start a new transcript buffer for the inner hello.
        let mut inner_hello_transcript = HandshakeHashBuffer::new();
        if client_auth_enabled {
            inner_hello_transcript.set_client_auth_enabled();
        }

        Ok(Self {
            sender,
            config_id: key_config.config_id,
            inner_name,
            outer_name: config_contents.public_name.clone(),
            maximum_name_length: config_contents.maximum_name_length,
            cipher_suite: config.suite.sym,
            enc,
            inner_hello_random: Random::new(secure_random)?,
            inner_hello_transcript,
        })
    }

    /// Confirm whether an ECH offer was accepted based on examining the server hello.
    pub(crate) fn confirm_acceptance(
        self,
        ks: &mut KeyScheduleHandshakeStart,
        server_hello: &ServerHelloPayload,
        hash: &'static dyn Hash,
    ) -> Result<Option<(HandshakeHash, Random)>, Error> {
        // Star the inner transcript hash now that we know the hash algorithm to use.
        let inner_transcript = self
            .inner_hello_transcript
            .start_hash(hash);

        // Fork the transcript that we've started with the inner hello to use for a confirmation step.
        // We need to preserve the original inner_transcript to use if this confirmation succeeds.
        let mut confirmation_transcript = inner_transcript.clone();

        // Add the server hello confirmation - this differs from the standard server hello encoding.
        confirmation_transcript.add_message(&Self::server_hello_conf(server_hello));

        // Derive a confirmation secret from the inner hello random and the confirmation transcript.
        let derived = ks.server_ech_confirmation_secret(
            self.inner_hello_random.0.as_ref(),
            confirmation_transcript.current_hash(),
        );

        // Check that first 8 digits of the derived secret match the last 8 digits of the original
        // server random. This match signals that the server accepted the ECH offer.
        // Indexing safety: Random is [0; 32] by construction.
        Ok(
            match ConstantTimeEq::ct_eq(derived.as_ref(), server_hello.random.0[24..].as_ref())
                .into()
            {
                true => {
                    trace!("ECH accepted by server");
                    Some((inner_transcript, self.inner_hello_random))
                }
                false => {
                    trace!("ECH rejected by server");
                    None
                }
            },
        )
    }

    /// Construct a ClientHelloPayload offering ECH.
    ///
    /// An outer hello, with a protected inner hello for the `inner_name` will be returned, and the
    /// ECH context will be updated to reflect the inner hello that was offered.
    ///
    /// If `retry_req` is `Some`, then the outer hello will be constructed for a hello retry request.
    pub(crate) fn ech_hello(
        &mut self,
        mut outer_hello: ClientHelloPayload,
        retry_req: Option<&HelloRetryRequest>,
    ) -> Result<ClientHelloPayload, Error> {
        trace!(
            "Preparing ECH offer {}",
            if retry_req.is_some() { "for retry" } else { "" }
        );

        // Construct the encoded inner hello and message.
        let (encoded_inner_hello, inner_hello_msg) =
            self.encode_inner_hello(&outer_hello, retry_req);

        // Update the inner transcript buffer with the inner hello message.
        self.inner_hello_transcript
            .add_message(&inner_hello_msg.into_owned());

        // Complete the ClientHelloOuterAAD with an ech extension, the payload should be a placeholder
        // of size L, all zeroes. L == length of encrypting encoded client hello inner w/ the selected
        // HPKE AEAD. (sum of plaintext + tag length, typically).
        let payload_len =
            encoded_inner_hello.len() + Self::aead_tag_len(self.cipher_suite.aead_id)?;

        // Outer hello's created in response to a hello retry request omit the enc value.
        let enc = match retry_req.is_some() {
            true => Vec::default(),
            false => self.enc.0.clone(),
        };

        fn outer_hello_ext(ctx: &EchState, enc: Vec<u8>, payload: Vec<u8>) -> ClientExtension {
            ClientExtension::EncryptedClientHello(EncryptedClientHello::Outer(
                EncryptedClientHelloOuter {
                    cipher_suite: ctx.cipher_suite,
                    config_id: ctx.config_id,
                    enc: PayloadU16::new(enc),
                    payload: PayloadU16::new(payload),
                },
            ))
        }

        // To compute the encoded AAD we add a placeholder extension with an empty payload.
        outer_hello
            .extensions
            .push(outer_hello_ext(self, enc.clone(), vec![0; payload_len]));

        // Next we compute the proper extension payload.
        let payload = self
            .sender
            .seal(&outer_hello.get_encoding(), &encoded_inner_hello)?;

        // And then we replace the placeholder extension with the real one.
        outer_hello.extensions.pop();
        outer_hello
            .extensions
            .push(outer_hello_ext(self, enc, payload));

        Ok(outer_hello)
    }

    pub(crate) fn confirm_hrr_acceptance(
        &self,
        hrr: &HelloRetryRequest,
        cs: &Tls13CipherSuite,
        common: &mut CommonState,
    ) -> Result<(), Error> {
        // The client checks for the "encrypted_client_hello" extension.
        let ech_conf = match hrr.ech_retry_request() {
            // If none is found, the server has rejected ECH and there are no retry
            // configs to offer. Abort with an ech required alert and return an err.
            None => return Err(fatal_alert_required(None, common)),
            // Otherwise, if it has a length other than 8, the client aborts the
            // handshake with a "decode_error" alert.
            Some(ech_conf) if ech_conf.len() != 8 => {
                return Err({
                    common.send_fatal_alert(
                        AlertDescription::DecodeError,
                        PeerMisbehaved::IllegalHelloRetryRequestWithInvalidEch,
                    )
                })
            }
            Some(ech_conf) => ech_conf,
        };

        // Otherwise the client computes hrr_accept_confirmation as described in Section
        // 7.2.1
        let confirmation_transcript = self.inner_hello_transcript.clone();
        let mut confirmation_transcript =
            confirmation_transcript.start_hash(cs.common.hash_provider);
        confirmation_transcript.rollup_for_hrr();
        confirmation_transcript.add_message(&Self::hello_retry_request_conf(hrr));

        let derived = server_ech_hrr_confirmation_secret(
            cs.hkdf_provider,
            &self.inner_hello_random.0,
            confirmation_transcript.current_hash(),
        );

        match ConstantTimeEq::ct_eq(derived.as_ref(), ech_conf).into() {
            true => {
                trace!("ECH accepted by server in hello retry request");
                Ok(())
            }
            false => {
                trace!("ECH rejected by server in hello retry request");
                // Abort with the ech_required alert. There are no retry configs to offer.
                Err(fatal_alert_required(None, common))
            }
        }
    }

    pub(crate) fn grease_ech_ext(
        hpke_provider: &'static dyn HpkeProvider,
        secure_random: &'static dyn SecureRandom,
        inner_name: ServerName<'static>,
        outer_hello: &ClientHelloPayload,
    ) -> Result<ClientExtension, Error> {
        trace!("Preparing GREASE ECH extension");

        // Pick a random config id.
        let mut config_id: [u8; 1] = [0; 1];
        secure_random.fill(&mut config_id[..])?;

        // Decide on a supported HPKE suite:
        //  "The selection SHOULD vary to exercise all supported configurations, but MAY be held
        //   constant for successive connections to the same server in the same session."
        // TODO(XXX): Consider picking at random.
        let cipher_suite = HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_128_GCM,
        };
        let suite = HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: cipher_suite,
        };
        let cipher_suites = vec![cipher_suite];

        // Construct a dummy ECH state - we don't have a real ECH config from a server since
        // this is for GREASE.
        let grease_state = Self::new(
            &EchConfig {
                hpke_provider,
                config: EchConfigMsg {
                    version: EchVersion::V14,
                    contents: EchConfigContents {
                        key_config: HpkeKeyConfig {
                            config_id: 0,
                            kem_id: HpkeKem::DHKEM_P256_HKDF_SHA256,
                            public_key: PayloadU16(DUMMY_25519_PUBKEY.to_vec()),
                            symmetric_cipher_suites: cipher_suites,
                        },
                        maximum_name_length: 0,
                        public_name: DnsName::try_from("filler").unwrap(),
                        extensions: Vec::default(),
                    },
                },
                suite,
            },
            inner_name,
            false,
            secure_random,
        )?;

        // Construct an inner hello using the outer hello - this allows us to know the size of
        // dummy payload we should use for the GREASE extension.
        let (encoded_inner_hello, _) = grease_state.encode_inner_hello(outer_hello, None);

        // Generate a payload of random data equivalent in length to a real inner hello.
        let payload_len = encoded_inner_hello.len() + Self::aead_tag_len(cipher_suite.aead_id)?;
        let mut payload = vec![0; payload_len];
        secure_random.fill(&mut payload)?;

        // Return the GREASE extension.
        Ok(ClientExtension::EncryptedClientHello(
            EncryptedClientHello::Outer(EncryptedClientHelloOuter {
                cipher_suite,
                config_id: config_id[0],
                enc: PayloadU16(grease_state.enc.0),
                payload: PayloadU16::new(payload),
            }),
        ))
    }

    /// Update the ECH context inner hello transcript based on a received hello retry request message.
    ///
    /// This will start the in-progress transcript using the given `hash`, convert it into an HRR
    /// buffer, and then add the hello retry message `m`.
    pub(crate) fn transcript_hrr_update(&mut self, hash: &'static dyn Hash, m: &Message) {
        trace!("Updating ECH inner transcript for HRR");

        let inner_transcript = self
            .inner_hello_transcript
            .clone()
            .start_hash(hash);

        let mut inner_transcript_buffer = inner_transcript.into_hrr_buffer();
        inner_transcript_buffer.add_message(m);
        self.inner_hello_transcript = inner_transcript_buffer;
    }

    pub(crate) fn aead_tag_len(aead: HpkeAead) -> Result<usize, Error> {
        match aead {
            HpkeAead::AES_128_GCM | HpkeAead::AES_256_GCM | HpkeAead::CHACHA20_POLY_1305 => Ok(16),
            _ => Err(Error::General("unsupported AEAD".into())),
        }
    }

    fn encode_inner_hello(
        &self,
        outer_hello: &ClientHelloPayload,
        retryreq: Option<&HelloRetryRequest>,
    ) -> (Vec<u8>, Message) {
        // Start building an inner hello by cloning the initial outer hello.
        let mut inner_hello = outer_hello.clone();

        // Remove the outer SNI that was copied into the inner hello.
        if let Some(index) = inner_hello
            .extensions
            .iter()
            .position(|ext| ext.ext_type() == ExtensionType::ServerName)
        {
            inner_hello.extensions.remove(index);
        };

        // Add the correct inner SNI - we only do this when the inner name is a DnsName. IP
        // addresses should not appear in SNI.
        if let ServerName::DnsName(inner_name) = &self.inner_name {
            inner_hello
                .extensions
                .insert(0, ClientExtension::make_sni(&inner_name.borrow()));
        }

        // Add the inner variant extension to the inner hello.
        // Section 6.1 rule 4.
        inner_hello
            .extensions
            .push(ClientExtension::EncryptedClientHello(
                EncryptedClientHello::Inner,
            ));

        // Set the inner hello random to the one we generated when creating the ECH state.
        // We hold on to the inner_hello_random in the ECH state to use later for confirming
        // whether ECH was accepted or not.
        inner_hello.random = self.inner_hello_random;

        // 5.1 "Encoding the ClientHelloInner"

        // Setting the legacy_session_id field to the empty string.
        // Preserve these for reuse
        let original_session_id = inner_hello.session_id;

        // SessionID is required to be empty in the EncodedClientHelloInner.
        inner_hello.session_id = SessionId::empty();

        // Repeating large extensions between ClientHelloInner and ClientHelloOuter can lead to excessive
        // size. To reduce the size impact, the client MAY substitute extensions which it knows will be
        // duplicated in ClientHelloOuter.

        // TODO(@cpu): Extension compression would be handled here-ish.

        // Encode the inner hello with the empty session ID.
        let mut encoded_hello = inner_hello.get_encoding();

        // Restore session ID.
        inner_hello.session_id = original_session_id;

        // Calculate padding
        // max_name_len = L
        let max_name_len = self.maximum_name_length;
        let max_name_len = if max_name_len > 0 { max_name_len } else { 255 };

        let padding_len = match &self.inner_name {
            ServerName::DnsName(name) => {
                // name.len() = D
                // max(0, L - D)
                core::cmp::max(0_u8, max_name_len - name.as_ref().len() as u8)
            }
            _ => {
                // L + 9
                // "This is the length of a "server_name" extension with an L-byte name."
                max_name_len + 9
            }
        };

        // Let L be the length of the EncodedClientHelloInner with all the padding computed so far
        // Let N = 31 - ((L - 1) % 32) and add N bytes of padding.
        let padding_len = 31 - ((encoded_hello.len() + (padding_len as usize) - 1) % 32);
        encoded_hello.extend(vec![0; padding_len]);

        // Construct the inner hello message that will be used for the transcript.
        let inner_hello_msg = Message {
            version: match retryreq {
                // <https://datatracker.ietf.org/doc/html/rfc8446#section-5.1>:
                // "This value MUST be set to 0x0303 for all records generated
                //  by a TLS 1.3 implementation ..."
                Some(_) => ProtocolVersion::TLSv1_2,
                // "... other than an initial ClientHello (i.e., one not
                // generated after a HelloRetryRequest), where it MAY also be
                // 0x0301 for compatibility purposes"
                //
                // (retryreq == None means we're in the "initial ClientHello" case)
                None => ProtocolVersion::TLSv1_0,
            },
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientHello,
                payload: HandshakePayload::ClientHello(inner_hello),
            }),
        };

        (encoded_hello, inner_hello_msg)
    }

    fn server_hello_conf(server_hello: &ServerHelloPayload) -> Message {
        Self::ech_conf_message(HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(server_hello.clone()),
        })
    }

    fn hello_retry_request_conf(retry_req: &HelloRetryRequest) -> Message {
        Self::ech_conf_message(HandshakeMessagePayload {
            typ: HandshakeType::HelloRetryRequest,
            payload: HandshakePayload::HelloRetryRequest(retry_req.clone()),
        })
    }

    fn ech_conf_message(hmp: HandshakeMessagePayload) -> Message {
        let mut hmp_encoded = Vec::new();
        hmp.payload_encode(&mut hmp_encoded, Encoding::EchConfirmation);
        Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake {
                encoded: Payload::new(hmp_encoded),
                parsed: hmp,
            },
        }
    }
}

pub(crate) fn fatal_alert_required(
    retry_configs: Option<Vec<EchConfigMsg>>,
    common: &mut CommonState,
) -> Error {
    common.send_fatal_alert(
        AlertDescription::EncryptedClientHelloRequired,
        PeerIncompatible::ServerRejectedEncryptedClientHello(retry_configs),
    )
}

/// Randomly generated X25519 public key to use for GREASE ECH HPKE.
const DUMMY_25519_PUBKEY: &[u8] = &[
    0x67, 0x35, 0xCA, 0x50, 0x21, 0xFC, 0x4F, 0xE6, 0x29, 0x3B, 0x31, 0x2C, 0xB5, 0xE0, 0x97, 0xD8,
    0xD0, 0x58, 0x97, 0xCF, 0x5C, 0x15, 0x12, 0x79, 0x4B, 0xEF, 0x1D, 0x98, 0x52, 0x74, 0xDC, 0x5E,
];
