use ecdsa::{
    elliptic_curve::{
        generic_array::ArrayLength, ops::Invert, pkcs8, pkcs8::DecodePrivateKey, subtle::CtOption,
        CurveArithmetic, FieldBytesSize, Scalar,
    },
    hazmat::{DigestPrimitive, SignPrimitive},
    PrimeCurve, SignatureSize,
};
use rustls::{
    sign::{Signer, SigningKey},
    Error, SignatureAlgorithm, SignatureScheme,
};
use signature::{RandomizedSigner, SignatureEncoding};
use std::{marker::PhantomData, ops::Add, sync::Arc};
use webpki::types::PrivateKeyDer;

pub struct EcdsaSigningKey<C> {
    key: Arc<C>,
    scheme: SignatureScheme,
}

impl TryFrom<PrivateKeyDer<'_>> for EcdsaSigningKey<p256::ecdsa::SigningKey> {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyDer) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(key) => {
                p256::ecdsa::SigningKey::from_pkcs8_der(key.secret_pkcs8_der()).map(|kp| Self {
                    key: Arc::new(kp),
                    scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
                })
            }
            _ => todo!(),
        }
    }
}

impl<C> SigningKey for EcdsaSigningKey<ecdsa::SigningKey<C>>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    ecdsa::der::MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<ecdsa::der::MaxOverhead> + ArrayLength<u8>,
{
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(GenericRandomizedSigner::<
                ecdsa::der::Signature<C>,
                _,
            > {
                _marker: Default::default(),
                key: self.key.clone(),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

pub struct GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding,
    T: RandomizedSigner<S>,
{
    _marker: PhantomData<S>,
    key: Arc<T>,
    scheme: SignatureScheme,
}

impl<T, S> Signer for GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding + Send + Sync,
    T: RandomizedSigner<S> + Send + Sync,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key
            .try_sign_with_rng(&mut rand_core::OsRng, message)
            .map_err(|_| rustls::Error::General("signing failed".into()))
            .map(|sig: S| sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
