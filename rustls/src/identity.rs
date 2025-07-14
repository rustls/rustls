use alloc::boxed::Box;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::Debug;
use core::iter;

use pki_types::{CertificateDer, SubjectPublicKeyInfoDer};

use crate::enums::CertificateType;
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::handshake;
use crate::msgs::handshake::{
    CertificateChain, IdentityPayloadTls13, CertificateStatus, IdentityEntry,
};
use crate::sign::{CertifiedKey, KeyPair, SigningKey};
use crate::sync::Arc;

#[derive(Debug, Clone)]
pub struct Identity(Arc<dyn TlsIdentity>);

impl Default for Identity {
    fn default() -> Self {
        X509Identity::new([], None::<&[u8]>).into()
    }
}

impl Identity {
    pub fn as_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.as_any()
            .downcast_ref::<X509Identity>()
            .map(|cd| cd.cert_chain.as_ref())
    }

    pub fn as_public_key(&self) -> Option<&SubjectPublicKeyInfoDer<'static>> {
        self.as_any()
            .downcast_ref::<SubjectPublicKeyInfoDer<'static>>()
    }

    pub fn as_any(&self) -> &dyn Any {
        self.0.as_any()
    }

    pub fn certificate_type(&self) -> CertificateType {
        self.0.certificate_type()
    }

    pub(crate) fn to_wire_format(&self) -> TlsIdentityEntries<'_> {
        self.0.to_wire_format()
    }
}

pub type TlsIdentityEntries<'a> = Vec<IdentityEntry<'a>>;

impl<'a> From<TlsIdentityEntries<'a>> for IdentityPayloadTls13<'a> {
    fn from(value: TlsIdentityEntries<'a>) -> Self {
        Self {
            context: PayloadU8::empty(),
            entries: value,
        }
    }
}

impl<'a> From<IdentityPayloadTls13<'a>> for TlsIdentityEntries<'a> {
    fn from(value: IdentityPayloadTls13<'a>) -> Self {
        value.entries
    }
}

pub(crate) trait IntoOwned {
    type R<'a>;
    fn into_owned(self) -> Self::R<'static>;
}

impl IntoOwned for TlsIdentityEntries<'_> {
    type R<'a> = TlsIdentityEntries<'a>;

    fn into_owned(self) -> Self::R<'static> {
        self.into_iter()
            .map(|e| e.into_owned())
            .collect()
    }
}

impl From<CertificateChain<'static>> for Identity {
    fn from(value: CertificateChain<'static>) -> Self {
        X509Identity::new(value.0, None::<&[u8]>).into()
    }
}

impl<T: TlsIdentity + 'static> From<T> for Identity {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}

pub trait TlsIdentity: Debug + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn certificate_type(&self) -> CertificateType;
    fn to_wire_format(&self) -> TlsIdentityEntries<'_>;
}

#[derive(Debug)]
pub(crate) struct X509Identity {
    pub(crate) cert_chain: CertificateChain<'static>,
    pub(crate) ocsp_response: Vec<u8>,
}

impl X509Identity {
    pub(crate) fn new<'a>(
        cert_chain: impl IntoIterator<Item = CertificateDer<'a>>,
        ocsp_response: impl Into<Payload<'a>>,
    ) -> Self {
        Self {
            cert_chain: CertificateChain::from_certs(cert_chain.into_iter()).into_owned(),
            ocsp_response: ocsp_response.into().into_vec(),
        }
    }
}

impl TlsIdentity for X509Identity {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn certificate_type(&self) -> CertificateType {
        CertificateType::X509
    }

    fn to_wire_format(&self) -> TlsIdentityEntries<'_> {
        self.cert_chain
            .iter()
            // zip certificate iterator with `ocsp_response` followed by
            // an infinite-length iterator of `None`.
            .zip(
                [&self.ocsp_response]
                    .into_iter()
                    .filter_map(|o| {
                        let mut exts = handshake::CertificateExtensions::default();
                        if !o.is_empty() {
                            exts.status = Some(CertificateStatus::new(o));
                            let mut out = Vec::new();
                            exts.encode_payload(&mut out);
                            Some(Some(out))
                        } else {
                            None
                        }
                    })
                    .chain(iter::repeat(None)),
            )
            .map(|(cert, ocsp)| {
                if let Some(ocsp) = ocsp {
                    IdentityEntry::new_with_extensions(cert.as_ref(), ocsp)
                } else {
                    IdentityEntry::new(cert.as_ref())
                }
            })
            .collect()
    }
}

impl TlsIdentity for SubjectPublicKeyInfoDer<'static> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn certificate_type(&self) -> CertificateType {
        CertificateType::RawPublicKey
    }

    fn to_wire_format(&self) -> TlsIdentityEntries<'_> {
        [IdentityEntry::new(self.as_ref())].into()
    }
}

#[derive(Clone, Debug)]
pub struct SigningIdentity(Arc<dyn IdentitySigner>, Identity);

impl SigningIdentity {
    pub fn id(&self) -> &Identity {
        &self.1
    }

    pub(crate) fn signing_key(&self) -> &dyn SigningKey {
        self.0.signing_key()
    }

    pub fn as_certified_key(&self) -> Option<&CertifiedKey> {
        self.as_any()
            .downcast_ref::<CertifiedKey>()
    }

    pub fn as_key_pair(&self) -> Option<&KeyPair> {
        self.as_any().downcast_ref::<KeyPair>()
    }

    pub fn as_any(&self) -> &dyn Any {
        self.0.as_any()
    }
}

impl<T: IdentitySigner + 'static> From<T> for SigningIdentity {
    fn from(value: T) -> Self {
        Arc::new(value).into()
    }
}

impl<T: IdentitySigner + 'static> From<Arc<T>> for SigningIdentity {
    fn from(value: Arc<T>) -> Self {
        let id: Arc<dyn TlsIdentity> = Arc::from(value.id());
        Self(value, Identity(id))
    }
}

pub trait IdentitySigner: Debug + Send + Sync {
    fn id(&self) -> Box<dyn TlsIdentity>;

    fn signing_key(&self) -> &dyn SigningKey;

    fn as_any(&self) -> &dyn Any;
}
