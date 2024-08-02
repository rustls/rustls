use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

use pki_types::{CertificateDer, ServerName, UnixTime};

use crate::enums::SignatureScheme;
use crate::error::{Error, InvalidMessage};
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::DistinguishedName;

// Marker types.  These are used to bind the fact some verification
// (certificate chain or handshake signature) has taken place into
// protocol states.  We use this to have the compiler check that there
// are no 'goto fail'-style elisions of important checks before we
// reach the traffic stage.
//
// These types are public, but cannot be directly constructed.  This
// means their origins can be precisely determined by looking
// for their `assertion` constructors.

/// Zero-sized marker type representing verification of a signature.
#[derive(Debug)]
pub struct HandshakeSignatureValid(());

impl HandshakeSignatureValid {
    /// Make a `HandshakeSignatureValid`
    pub fn assertion() -> Self {
        Self(())
    }
}

#[derive(Debug)]
pub(crate) struct FinishedMessageVerified(());

impl FinishedMessageVerified {
    pub(crate) fn assertion() -> Self {
        Self(())
    }
}

/// Zero-sized marker type representing verification of a server cert chain.
pub type ServerCertVerified = PeerCertVerified;

/// Zero-sized marker type representing verification of a client cert chain.
pub type ClientCertVerified = PeerCertVerified;

/// Zero-sized marker type representing verification of the peer's cert chain.
#[allow(unreachable_pub)]
#[derive(Debug)]
pub struct PeerCertVerified(());

#[allow(unreachable_pub)]
impl PeerCertVerified {
    /// Make a `PeerCertVerified`
    pub fn assertion() -> Self {
        Self(())
    }
}

/// Something that can verify a server certificate chain, and verify
/// signatures made by certificates.
#[allow(unreachable_pub)]
pub trait ServerCertVerifier: Debug + Send + Sync {
    /// XXX: start incremental verification process
    /// XXX: receiver would ideally be &Arc<Self>, requires `arbitrary_self_types`
    fn start(&self, verifier: &Arc<dyn ServerCertVerifier>) -> Box<dyn IncrementalVerifier> {
        Box::new(StoringServerVerifier::new(verifier.clone()))
    }

    /// Verify the end-entity certificate `end_entity` is valid for the
    /// hostname `dns_name` and chains to at least one trust anchor.
    ///
    /// `intermediates` contains all certificates other than `end_entity` that
    /// were sent as part of the server's [Certificate] message. It is in the
    /// same order that the server sent them and may be empty.
    ///
    /// Note that none of the certificates have been parsed yet, so it is the responsibility of
    /// the implementer to handle invalid data. It is recommended that the implementer returns
    /// [`Error::InvalidCertificate(CertificateError::BadEncoding)`] when these cases are encountered.
    ///
    /// [Certificate]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error>;

    /// Verify a signature allegedly by the given server certificate.
    ///
    /// `message` is not hashed, and needs hashing during the verification.
    /// The signature and algorithm are within `dss`.  `cert` contains the
    /// public key to use.
    ///
    /// `cert` has already been validated by [`ServerCertVerifier::verify_server_cert`].
    ///
    /// If and only if the signature is valid, return `Ok(HandshakeSignatureValid)`.
    /// Otherwise, return an error -- rustls will send an alert and abort the
    /// connection.
    ///
    /// This method is only called for TLS1.2 handshakes.  Note that, in TLS1.2,
    /// SignatureSchemes such as `SignatureScheme::ECDSA_NISTP256_SHA256` are not
    /// in fact bound to the specific curve implied in their name.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// Verify a signature allegedly by the given server certificate.
    ///
    /// This method is only called for TLS1.3 handshakes.
    ///
    /// This method is very similar to `verify_tls12_signature`: but note the
    /// tighter ECDSA SignatureScheme semantics -- e.g. `SignatureScheme::ECDSA_NISTP256_SHA256`
    /// must only validate signatures using public keys on the right curve --
    /// rustls does not enforce this requirement for you.
    ///
    /// `cert` has already been validated by [`ServerCertVerifier::verify_server_cert`].
    ///
    /// If and only if the signature is valid, return `Ok(HandshakeSignatureValid)`.
    /// Otherwise, return an error -- rustls will send an alert and abort the
    /// connection.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// Return the list of SignatureSchemes that this verifier will handle,
    /// in `verify_tls12_signature` and `verify_tls13_signature` calls.
    ///
    /// This should be in priority order, with the most preferred first.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;
}

pub trait IncrementalVerifier: Debug + Send + Sync {
    fn add_peer_certificate(
        &mut self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    );
    fn add_server_name(&mut self, server_name: &ServerName<'_>);
    fn add_ocsp_response(&mut self, ocsp_response: &[u8]);
    fn add_tls12_signature(&mut self, message: &[u8], dss: &DigitallySignedStruct);
    fn add_tls13_signature(&mut self, message: &[u8], dss: &DigitallySignedStruct);

    /// Should return:
    ///
    /// - `Ok(PeerCertVerified)` to finish successfully.
    /// - `Ok(None)` to keep waiting.
    /// - `Err(_)` to fail.
    ///
    fn take_cert_verified(&mut self) -> Result<Option<PeerCertVerified>, Error>;

    fn take_signature_verified(&mut self) -> Result<Option<HandshakeSignatureValid>, Error>;
}

/// Something that can verify a client certificate chain
#[allow(unreachable_pub)]
pub trait ClientCertVerifier: Debug + Send + Sync {
    /// Returns `true` to enable the server to request a client certificate and
    /// `false` to skip requesting a client certificate. Defaults to `true`.
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// Return `true` to require a client certificate and `false` to make
    /// client authentication optional.
    /// Defaults to `self.offer_client_auth()`.
    fn client_auth_mandatory(&self) -> bool {
        self.offer_client_auth()
    }

    /// Returns the [`DistinguishedName`] [subjects] that the server will hint to clients to
    /// identify acceptable authentication trust anchors.
    ///
    /// These hint values help the client pick a client certificate it believes the server will
    /// accept. The hints must be DER-encoded X.500 distinguished names, per [RFC 5280 A.1]. They
    /// are sent in the [`certificate_authorities`] extension of a [`CertificateRequest`] message
    /// when [ClientCertVerifier::offer_client_auth] is true. When an empty list is sent the client
    /// should always provide a client certificate if it has one.
    ///
    /// Generally this list should contain the [`DistinguishedName`] of each root trust
    /// anchor in the root cert store that the server is configured to use for authenticating
    /// presented client certificates.
    ///
    /// In some circumstances this list may be customized to include [`DistinguishedName`] entries
    /// that do not correspond to a trust anchor in the server's root cert store. For example,
    /// the server may be configured to trust a root CA that cross-signed an issuer certificate
    /// that the client considers a trust anchor. From the server's perspective the cross-signed
    /// certificate is an intermediate, and not present in the server's root cert store. The client
    /// may have the cross-signed certificate configured as a trust anchor, and be unaware of the
    /// root CA that cross-signed it. If the server's hints list only contained the subjects of the
    /// server's root store the client would consider a client certificate issued by the cross-signed
    /// issuer unacceptable, since its subject was not hinted. To avoid this circumstance the server
    /// should customize the hints list to include the subject of the cross-signed issuer in addition
    /// to the subjects from the root cert store.
    ///
    /// [subjects]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.6
    /// [RFC 5280 A.1]: https://www.rfc-editor.org/rfc/rfc5280#appendix-A.1
    /// [`CertificateRequest`]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
    /// [`certificate_authorities`]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.4
    fn root_hint_subjects(&self) -> &[DistinguishedName];

    /// Verify the end-entity certificate `end_entity` is valid, acceptable,
    /// and chains to at least one of the trust anchors trusted by
    /// this verifier.
    ///
    /// `intermediates` contains the intermediate certificates the
    /// client sent along with the end-entity certificate; it is in the same
    /// order that the peer sent them and may be empty.
    ///
    /// Note that none of the certificates have been parsed yet, so it is the responsibility of
    /// the implementer to handle invalid data. It is recommended that the implementer returns
    /// an [InvalidCertificate] error with the [BadEncoding] variant when these cases are encountered.
    ///
    /// [InvalidCertificate]: Error#variant.InvalidCertificate
    /// [BadEncoding]: crate::CertificateError#variant.BadEncoding
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error>;

    /// Verify a signature allegedly by the given client certificate.
    ///
    /// `message` is not hashed, and needs hashing during the verification.
    /// The signature and algorithm are within `dss`.  `cert` contains the
    /// public key to use.
    ///
    /// `cert` has already been validated by [`ClientCertVerifier::verify_client_cert`].
    ///
    /// If and only if the signature is valid, return `Ok(HandshakeSignatureValid)`.
    /// Otherwise, return an error -- rustls will send an alert and abort the
    /// connection.
    ///
    /// This method is only called for TLS1.2 handshakes.  Note that, in TLS1.2,
    /// SignatureSchemes such as `SignatureScheme::ECDSA_NISTP256_SHA256` are not
    /// in fact bound to the specific curve implied in their name.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// Verify a signature allegedly by the given client certificate.
    ///
    /// This method is only called for TLS1.3 handshakes.
    ///
    /// This method is very similar to `verify_tls12_signature`, but note the
    /// tighter ECDSA SignatureScheme semantics in TLS 1.3. For example,
    /// `SignatureScheme::ECDSA_NISTP256_SHA256`
    /// must only validate signatures using public keys on the right curve --
    /// rustls does not enforce this requirement for you.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// Return the list of SignatureSchemes that this verifier will handle,
    /// in `verify_tls12_signature` and `verify_tls13_signature` calls.
    ///
    /// This should be in priority order, with the most preferred first.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;
}

/// Turns off client authentication. In contrast to using
/// `WebPkiClientVerifier::builder(roots).allow_unauthenticated().build()`, the `NoClientAuth`
/// `ClientCertVerifier` will not offer client authentication at all, vs offering but not
/// requiring it.
#[derive(Debug)]
pub struct NoClientAuth;

impl ClientCertVerifier for NoClientAuth {
    fn offer_client_auth(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        unimplemented!();
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        unimplemented!();
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        unimplemented!();
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        unimplemented!();
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        unimplemented!();
    }
}

/// This type combines a [`SignatureScheme`] and a signature payload produced with that scheme.
#[derive(Debug, Clone)]
pub struct DigitallySignedStruct {
    /// The [`SignatureScheme`] used to produce the signature.
    pub scheme: SignatureScheme,
    sig: PayloadU16,
}

impl DigitallySignedStruct {
    pub(crate) fn new(scheme: SignatureScheme, sig: Vec<u8>) -> Self {
        Self {
            scheme,
            sig: PayloadU16::new(sig),
        }
    }

    /// Get the signature.
    pub fn signature(&self) -> &[u8] {
        &self.sig.0
    }
}

impl Codec<'_> for DigitallySignedStruct {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.scheme.encode(bytes);
        self.sig.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let scheme = SignatureScheme::read(r)?;
        let sig = PayloadU16::read(r)?;

        Ok(Self { scheme, sig })
    }
}

#[derive(Debug)]
pub struct StoringServerVerifier {
    parent: Arc<dyn ServerCertVerifier>,

    // collected input
    cert: Option<CertificateDer<'static>>,
    intermediates: Option<Vec<CertificateDer<'static>>>,
    server_name: Option<ServerName<'static>>,
    ocsp_response: Option<Vec<u8>>,
    current_time: Option<UnixTime>,

    // pending output
    signature_result: Option<Result<HandshakeSignatureValid, Error>>,
}

impl StoringServerVerifier {
    pub fn new(parent: Arc<dyn ServerCertVerifier>) -> Self {
        Self {
            parent,
            cert: None,
            intermediates: None,
            server_name: None,
            ocsp_response: None,
            current_time: None,
            signature_result: None,
        }
    }
}

impl IncrementalVerifier for StoringServerVerifier {
    fn add_peer_certificate(
        &mut self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) {
        self.cert = Some(end_entity.clone().into_owned());
        self.intermediates = Some(
            intermediates
                .into_iter()
                .map(|c| c.clone().into_owned())
                .collect(),
        );
        self.current_time = Some(now);
    }

    fn add_server_name(&mut self, server_name: &ServerName<'_>) {
        self.server_name = Some(server_name.clone().to_owned());
    }

    fn add_ocsp_response(&mut self, ocsp_response: &[u8]) {
        self.ocsp_response = Some(ocsp_response.to_vec());
    }

    fn add_tls12_signature(&mut self, message: &[u8], dss: &DigitallySignedStruct) {
        self.signature_result = Some(self.parent.verify_tls12_signature(
            message,
            self.cert.as_ref().unwrap(),
            dss,
        ));
    }

    fn add_tls13_signature(&mut self, message: &[u8], dss: &DigitallySignedStruct) {
        self.signature_result = Some(self.parent.verify_tls13_signature(
            message,
            self.cert.as_ref().unwrap(),
            dss,
        ));
    }

    fn take_cert_verified(&mut self) -> Result<Option<PeerCertVerified>, Error> {
        self.parent
            .verify_server_cert(
                self.cert.as_ref().unwrap(),
                self.intermediates.as_ref().unwrap(),
                self.server_name.as_ref().unwrap(),
                self.ocsp_response
                    .as_deref()
                    .unwrap_or_default(),
                self.current_time.clone().unwrap(),
            )
            .map(Some)
    }

    fn take_signature_verified(&mut self) -> Result<Option<HandshakeSignatureValid>, Error> {
        self.signature_result.take().transpose()
    }
}

#[test]
fn assertions_are_debug() {
    use std::format;

    assert_eq!(
        format!("{:?}", ClientCertVerified::assertion()),
        "PeerCertVerified(())"
    );
    assert_eq!(
        format!("{:?}", HandshakeSignatureValid::assertion()),
        "HandshakeSignatureValid(())"
    );
    assert_eq!(
        format!("{:?}", FinishedMessageVerified::assertion()),
        "FinishedMessageVerified(())"
    );
    assert_eq!(
        format!("{:?}", ServerCertVerified::assertion()),
        "PeerCertVerified(())"
    );
}
