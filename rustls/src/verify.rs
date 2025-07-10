use alloc::vec::Vec;
use core::fmt::Debug;

use pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};

use crate::PeerIncompatible;
use crate::enums::{CertificateType, SignatureScheme};
use crate::error::{Error, InvalidMessage};
use crate::identity::{Identity, TlsIdentityEntries, X509Identity};
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::{CertificateExtensions, DistinguishedName, IdentityEntry};
use crate::sync::Arc;

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

/// Zero-sized marker type representing verification of a server identity.
#[allow(unreachable_pub)]
#[derive(Debug)]
pub struct ServerIdVerified(());

/// Please use [`ServerIdVerified`] instead.
#[allow(dead_code)]
pub type ServerCertVerified = ServerIdVerified;

#[allow(unreachable_pub)]
impl ServerIdVerified {
    /// Make a `ServerIdVerified`
    pub fn assertion() -> Self {
        Self(())
    }
}

/// Zero-sized marker type representing verification of a client identity.
#[derive(Debug)]
pub struct ClientIdVerified(());

/// Please use [`ClientIdVerified`] instead.
#[allow(dead_code)]
pub type ClientCertVerified = ClientIdVerified;

impl ClientIdVerified {
    /// Make a `ClientIdVerified`
    pub fn assertion() -> Self {
        Self(())
    }
}

/// Something that can verify a server certificate chain, and verify
/// signatures made by certificates.
#[allow(unreachable_pub)]
pub trait ServerCertVerifier: Debug + Send + Sync {
    /// Verify the end-entity certificate `end_entity` is valid for the
    /// hostname `dns_name` and chains to at least one trust anchor.
    ///
    /// `intermediates` contains all certificates other than `end_entity` that
    /// were sent as part of the server's [Certificate] message. It is in the
    /// same order that the server sent them and may be empty.
    ///
    /// `ocsp_response` is empty if no OCSP response was received, and that also
    /// covers the case where `request_ocsp_response()` returns false.
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
    ) -> Result<ServerIdVerified, Error>;

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

    /// Return true if this verifier will process stapled OCSP responses.
    ///
    /// This controls whether a client will ask the server for a stapled OCSP response.
    /// There is no guarantee the server will provide one.
    fn request_ocsp_response(&self) -> bool;

    /// Return the [`DistinguishedName`]s of certificate authorities that this verifier trusts.
    ///
    /// If specified, will be sent as the [`certificate_authorities`] extension in ClientHello.
    /// Note that this is only applicable to TLS 1.3.
    ///
    /// [`certificate_authorities`]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.4
    fn root_hint_subjects(&self) -> Option<Arc<[DistinguishedName]>> {
        None
    }
}

pub trait ServerIdVerifier: Debug + Send + Sync {
    fn parse_tls13_payload(
        &self,
        id_type: CertificateType,
        payload: TlsIdentityEntries<'_>,
    ) -> Result<Identity, Error>;

    fn verify_identity(
        &self,
        server_id: &Identity,
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<ServerIdVerified, Error>;

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _server_id: &Identity,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        server_id: &Identity,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;

    fn supported_certificate_types(&self) -> &[CertificateType];
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        None
    }
}

#[derive(Debug)]
pub(crate) struct ServerCertVerifierCompat(Arc<dyn ServerCertVerifier>);

fn get_certs(id: &Identity) -> Result<(&CertificateDer<'_>, &[CertificateDer<'_>]), Error> {
    Ok(id
        .as_certificates()
        .ok_or(Error::UnsupportedIdentityType)?
        .split_first()
        .ok_or(Error::NoCertificatesPresented)?)
}

impl From<Arc<dyn ServerCertVerifier>> for ServerCertVerifierCompat {
    fn from(value: Arc<dyn ServerCertVerifier>) -> Self {
        Self(value)
    }
}

impl<T: ServerCertVerifier + 'static> From<Arc<T>> for ServerCertVerifierCompat {
    fn from(value: Arc<T>) -> Self {
        Self(value)
    }
}

impl<T: ServerCertVerifier + 'static> From<T> for ServerCertVerifierCompat {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}

fn parse_tls13_cert<'a>(
    id_type: CertificateType,
    payloads: impl Iterator<Item = IdentityEntry<'a>>,
) -> Result<Identity, Error> {
    if id_type != CertificateType::X509 {
        return Err(Error::UnsupportedIdentityType);
    }
    let mut ocsp_response = None;
    let mut certs = Vec::default();

    for (num, entry) in payloads.into_iter().enumerate() {
        let cert = CertificateDer::from(entry.payload.into_vec());
        let extensions = CertificateExtensions::try_from(entry.extensions.bytes())?;
        if num == 0 {
            ocsp_response = extensions
                .status
                .map(|s| s.ocsp_response.0.into_vec());
        }
        certs.push(cert);
    }

    let identity = X509Identity::new(certs, ocsp_response);
    Ok(identity.into())
}

impl ServerIdVerifier for ServerCertVerifierCompat {
    fn parse_tls13_payload(
        &self,
        id_type: CertificateType,
        payload: TlsIdentityEntries<'_>,
    ) -> Result<Identity, Error> {
        parse_tls13_cert(id_type, payload.into_iter())
    }

    fn verify_identity(
        &self,
        server_id: &Identity,
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<ServerIdVerified, Error> {
        let (end_entity, intermediates) = get_certs(server_id)?;
        let ocsp_response = server_id
            .as_any()
            .downcast_ref::<X509Identity>()
            .map(|cd| cd.ocsp_response.as_slice())
            .unwrap_or_else(|| &[]);

        self.0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        server_id: &Identity,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let (end_entity, _) = get_certs(server_id)?;
        self.0
            .verify_tls12_signature(message, end_entity, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        server_id: &Identity,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let (end_entity, _) = get_certs(server_id)?;
        self.0
            .verify_tls13_signature(message, end_entity, dss)
    }

    fn supported_certificate_types(&self) -> &[CertificateType] {
        &[CertificateType::X509]
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.0.root_hint_subjects()
    }
}

pub trait ServerRpkVerifier: Debug + Send + Sync {
    fn verify_server_rpk(
        &self,
        public_key: &SubjectPublicKeyInfoDer<'_>,
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<ServerIdVerified, Error>;

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        public_key: &SubjectPublicKeyInfoDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        None
    }
}

#[derive(Debug)]
pub(crate) struct ServerRpkVerifierWrapper(Arc<dyn ServerRpkVerifier>);

fn get_public_key(id: &Identity) -> Result<&SubjectPublicKeyInfoDer<'_>, Error> {
    id.as_public_key()
        .ok_or(Error::UnsupportedIdentityType)
}

impl From<Arc<dyn ServerRpkVerifier>> for ServerRpkVerifierWrapper {
    fn from(value: Arc<dyn ServerRpkVerifier>) -> Self {
        Self(value)
    }
}

impl<T: ServerRpkVerifier + 'static> From<Arc<T>> for ServerRpkVerifierWrapper {
    fn from(value: Arc<T>) -> Self {
        Self(value)
    }
}

impl<T: ServerRpkVerifier + 'static> From<T> for ServerRpkVerifierWrapper {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}

fn parse_tls13_rpk<'a>(
    id_type: CertificateType,
    payloads: impl Iterator<Item = IdentityEntry<'a>>,
) -> Result<Identity, Error> {
    if id_type != CertificateType::RawPublicKey {
        return Err(Error::UnsupportedIdentityType);
    }

    let entries = payloads.into_iter().collect::<Vec<_>>();
    if entries.len() != 1 {
        // todo: needs proper error
        return Err(Error::General(
            "RPK certificate payloads need to have exactly 1 entry".into(),
        ));
    }
    Ok(SubjectPublicKeyInfoDer::from(
        entries
            .into_iter()
            .next()
            .expect("entry to be there")
            .payload
            .into_vec(),
    )
    .into())
}

impl ServerIdVerifier for ServerRpkVerifierWrapper {
    fn parse_tls13_payload(
        &self,
        id_type: CertificateType,
        payload: TlsIdentityEntries<'_>,
    ) -> Result<Identity, Error> {
        parse_tls13_rpk(id_type, payload.into_iter())
    }

    fn verify_identity(
        &self,
        server_id: &Identity,
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<ServerIdVerified, Error> {
        self.0
            .verify_server_rpk(get_public_key(server_id)?, server_name, now)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        server_id: &Identity,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0
            .verify_tls13_signature(message, get_public_key(server_id)?, dss)
    }

    fn supported_certificate_types(&self) -> &[CertificateType] {
        &[CertificateType::RawPublicKey]
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.0.root_hint_subjects()
    }
}

pub trait ClientIdVerifier: Debug + Send + Sync {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        self.offer_client_auth()
    }
    fn negotiate_certificate_type(&self, offered: &[CertificateType]) -> Option<CertificateType> {
        self.supported_certificate_types()
            .iter()
            .find(|c| offered.contains(*c))
            .map(|c| *c)
    }

    fn supported_certificate_types(&self) -> &[CertificateType];
    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]>;

    fn parse_tls13_payload(
        &self,
        id_type: CertificateType,
        payload: TlsIdentityEntries<'_>,
    ) -> Result<Identity, Error>;

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;

    fn verify_client_identity(
        &self,
        client_id: &Identity,
        now: UnixTime,
    ) -> Result<ClientIdVerified, Error>;

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _client_id: &Identity,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        client_id: &Identity,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;
}

#[derive(Debug)]
pub(crate) struct ClientCertVerifierCompat(Arc<dyn ClientCertVerifier>);

impl From<Arc<dyn ClientCertVerifier>> for ClientCertVerifierCompat {
    fn from(value: Arc<dyn ClientCertVerifier>) -> Self {
        Self(value)
    }
}

impl<T: ClientCertVerifier + 'static> From<Arc<T>> for ClientCertVerifierCompat {
    fn from(value: Arc<T>) -> Self {
        Self(value)
    }
}

impl<T: ClientCertVerifier + 'static> From<T> for ClientCertVerifierCompat {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}

impl ClientIdVerifier for ClientCertVerifierCompat {
    fn offer_client_auth(&self) -> bool {
        self.0.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.0.client_auth_mandatory()
    }

    fn supported_certificate_types(&self) -> &[CertificateType] {
        &[CertificateType::X509]
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        let hints = self.0.root_hint_subjects();
        if hints.is_empty() { None } else { Some(hints) }
    }

    fn parse_tls13_payload(
        &self,
        id_type: CertificateType,
        payload: TlsIdentityEntries<'_>,
    ) -> Result<Identity, Error> {
        parse_tls13_cert(id_type, payload.into_iter())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }

    fn verify_client_identity(
        &self,
        client_id: &Identity,
        now: UnixTime,
    ) -> Result<ClientIdVerified, Error> {
        let (end_entity, intermediates) = get_certs(client_id)?;
        self.0
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        client_id: &Identity,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let (end_entity, _) = get_certs(client_id)?;
        self.0
            .verify_tls12_signature(message, end_entity, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        client_id: &Identity,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let (end_entity, _) = get_certs(client_id)?;
        self.0
            .verify_tls13_signature(message, end_entity, dss)
    }
}

pub trait ClientRpkVerifier: Debug + Send + Sync {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        self.offer_client_auth()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;

    fn verify_client_rpk(
        &self,
        client_rpk: &SubjectPublicKeyInfoDer<'_>,
        now: UnixTime,
    ) -> Result<ClientIdVerified, Error>;

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        client_rpk: &SubjectPublicKeyInfoDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>;
}

#[derive(Debug)]
pub(crate) struct ClientRpkVerifierWrapper(Arc<dyn ClientRpkVerifier>);

impl From<Arc<dyn ClientRpkVerifier>> for ClientRpkVerifierWrapper {
    fn from(value: Arc<dyn ClientRpkVerifier>) -> Self {
        Self(value)
    }
}

impl<T: ClientRpkVerifier + 'static> From<Arc<T>> for ClientRpkVerifierWrapper {
    fn from(value: Arc<T>) -> Self {
        Self(value)
    }
}

impl<T: ClientRpkVerifier + 'static> From<T> for ClientRpkVerifierWrapper {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}

impl ClientIdVerifier for ClientRpkVerifierWrapper {
    fn offer_client_auth(&self) -> bool {
        self.0.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.0.client_auth_mandatory()
    }

    fn supported_certificate_types(&self) -> &[CertificateType] {
        &[CertificateType::RawPublicKey]
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        let hints = self.0.root_hint_subjects();
        if hints.is_empty() { None } else { Some(hints) }
    }

    fn parse_tls13_payload(
        &self,
        id_type: CertificateType,
        payload: TlsIdentityEntries<'_>,
    ) -> Result<Identity, Error> {
        parse_tls13_rpk(id_type, payload.into_iter())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }

    fn verify_client_identity(
        &self,
        client_id: &Identity,
        now: UnixTime,
    ) -> Result<ClientIdVerified, Error> {
        let rpk = get_public_key(client_id)?;
        self.0.verify_client_rpk(rpk, now)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        client_id: &Identity,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let rpk = get_public_key(client_id)?;
        self.0
            .verify_tls13_signature(message, rpk, dss)
    }
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
    fn root_hint_subjects(&self) -> Arc<[DistinguishedName]>;

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
    ) -> Result<ClientIdVerified, Error>;

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

/// Turns off client authentication.
///
/// In contrast to using
/// `WebPkiClientVerifier::builder(roots).allow_unauthenticated().build()`, the `NoClientAuth`
/// `ClientCertVerifier` will not offer client authentication at all, vs offering but not
/// requiring it.
#[derive(Debug)]
pub struct NoClientAuth;

impl ClientCertVerifier for NoClientAuth {
    fn offer_client_auth(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> Arc<[DistinguishedName]> {
        unimplemented!();
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientIdVerified, Error> {
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

#[test]
fn assertions_are_debug() {
    use std::format;

    assert_eq!(
        format!("{:?}", ClientIdVerified::assertion()),
        "ClientIdVerified(())"
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
        format!("{:?}", ServerIdVerified::assertion()),
        "ServerIdVerified(())"
    );
}
