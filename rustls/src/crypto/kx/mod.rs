use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::ops::Deref;

use zeroize::Zeroize;

use super::NamedGroup;
use crate::enums::ProtocolVersion;
use crate::error::Error;

pub mod ffdhe;
use ffdhe::FfdheGroup;

/// A supported key exchange group.
///
/// This type carries both configuration and implementation. Specifically,
/// it has a TLS-level name expressed using the [`NamedGroup`] enum, and
/// a function which produces a [`ActiveKeyExchange`].
///
/// Compare with [`NamedGroup`], which carries solely a protocol identifier.
pub trait SupportedKxGroup: Send + Sync + Debug {
    /// Start a key exchange.
    ///
    /// This will prepare an ephemeral secret key in the supported group, and a corresponding
    /// public key. The key exchange can be completed by calling [`ActiveKeyExchange::complete()`]
    /// or discarded.
    ///
    /// Most implementations will want to return the `StartedKeyExchange::Single(_)` variant.
    /// Hybrid key exchange algorithms, which are constructed from two underlying algorithms,
    /// may wish to return `StartedKeyExchange::Hybrid(_)` variant which additionally allows
    /// one part of the key exchange to be completed separately.  See the documentation
    /// on [`HybridKeyExchange`] for more detail.
    ///
    /// # Errors
    ///
    /// This can fail if the random source fails during ephemeral key generation.
    fn start(&self) -> Result<StartedKeyExchange, Error>;

    /// Start and complete a key exchange, in one operation.
    ///
    /// The default implementation for this calls `start()` and then calls
    /// `complete()` on the result.  This is suitable for Diffie-Hellman-like
    /// key exchange algorithms, where there is not a data dependency between
    /// our key share (named "pub_key" in this API) and the peer's (`peer_pub_key`).
    ///
    /// If there is such a data dependency (like key encapsulation mechanisms), this
    /// function should be implemented.
    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let kx = self.start()?.into_single();

        Ok(CompletedKeyExchange {
            group: kx.group(),
            pub_key: kx.pub_key().to_vec(),
            secret: kx.complete(peer_pub_key)?,
        })
    }

    /// FFDHE group the `SupportedKxGroup` operates in, if any.
    ///
    /// The default implementation returns `None`, so non-FFDHE groups (the
    /// most common) do not need to do anything.
    ///
    /// FFDHE groups must implement this. [`ffdhe`] contains suitable values to return, for
    /// example [`ffdhe::FFDHE2048`].
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    /// Named group the SupportedKxGroup operates in.
    ///
    /// If the `NamedGroup` enum does not have a name for the algorithm you are implementing,
    /// you can use [`NamedGroup::Unknown`].
    fn name(&self) -> NamedGroup;

    /// Return `true` if this is backed by a FIPS-approved implementation.
    fn fips(&self) -> bool {
        false
    }
}

/// Return value from [`SupportedKxGroup::start()`].
#[non_exhaustive]
pub enum StartedKeyExchange {
    /// A single [`ActiveKeyExchange`].
    Single(Box<dyn ActiveKeyExchange>),
    /// A [`HybridKeyExchange`] that can potentially be split.
    Hybrid(Box<dyn HybridKeyExchange>),
}

impl StartedKeyExchange {
    /// Collapses this object into its underlying [`ActiveKeyExchange`].
    ///
    /// This removes the ability to do the hybrid key exchange optimization,
    /// but still allows the key exchange as a whole to be completed.
    pub fn into_single(self) -> Box<dyn ActiveKeyExchange> {
        match self {
            Self::Single(s) => s,
            Self::Hybrid(h) => h.into_key_exchange(),
        }
    }

    /// Accesses the [`HybridKeyExchange`], and checks it was also usable separately.
    ///
    /// Returns:
    ///
    /// - the [`HybridKeyExchange`]
    /// - the stand-alone `SupportedKxGroup` for the hybrid's component group.
    ///
    /// This returns `None` for:
    ///
    /// - non-hybrid groups,
    /// - if the hybrid component group is not present in `supported`
    /// - if the hybrid component group is not usable with `version`
    pub(crate) fn as_hybrid_checked(
        &self,
        supported: &[&'static dyn SupportedKxGroup],
        version: ProtocolVersion,
    ) -> Option<(&dyn HybridKeyExchange, &'static dyn SupportedKxGroup)> {
        let Self::Hybrid(hybrid) = self else {
            return None;
        };

        let component_group = hybrid.component().0;
        if !component_group.usable_for_version(version) {
            return None;
        }

        supported
            .iter()
            .find(|g| g.name() == component_group)
            .copied()
            .map(|g| (hybrid.as_ref(), g))
    }
}

impl Deref for StartedKeyExchange {
    type Target = dyn ActiveKeyExchange;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Single(s) => s.as_ref(),
            Self::Hybrid(h) => h.as_key_exchange(),
        }
    }
}

/// An in-progress key exchange originating from a [`SupportedKxGroup`].
pub trait ActiveKeyExchange: Send + Sync {
    /// Completes the key exchange, given the peer's public key.
    ///
    /// This method must return an error if `peer_pub_key` is invalid: either
    /// misencoded, or an invalid public key (such as, but not limited to, being
    /// in a small order subgroup).
    ///
    /// If the key exchange algorithm is FFDHE, the result must be left-padded with zeros,
    /// as required by [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-7.4.1)
    /// (see [`complete_for_tls_version()`](Self::complete_for_tls_version) for more details).
    ///
    /// The shared secret is returned as a [`SharedSecret`] which can be constructed
    /// from a `&[u8]`.
    ///
    /// This consumes and so terminates the [`ActiveKeyExchange`].
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error>;

    /// Completes the key exchange for the given TLS version, given the peer's public key.
    ///
    /// Note that finite-field Diffie–Hellman key exchange has different requirements for the derived
    /// shared secret in TLS 1.2 and TLS 1.3 (ECDHE key exchange is the same in TLS 1.2 and TLS 1.3):
    ///
    /// In TLS 1.2, the calculated secret is required to be stripped of leading zeros
    /// [(RFC 5246)](https://www.rfc-editor.org/rfc/rfc5246#section-8.1.2).
    ///
    /// In TLS 1.3, the calculated secret is required to be padded with leading zeros to be the same
    /// byte-length as the group modulus [(RFC 8446)](https://www.rfc-editor.org/rfc/rfc8446#section-7.4.1).
    ///
    /// The default implementation of this method delegates to [`complete()`](Self::complete) assuming it is
    /// implemented for TLS 1.3 (i.e., for FFDHE KX, removes padding as needed). Implementers of this trait
    /// are encouraged to just implement [`complete()`](Self::complete) assuming TLS 1.3, and let the default
    /// implementation of this method handle TLS 1.2-specific requirements.
    ///
    /// This method must return an error if `peer_pub_key` is invalid: either
    /// misencoded, or an invalid public key (such as, but not limited to, being
    /// in a small order subgroup).
    ///
    /// The shared secret is returned as a [`SharedSecret`] which can be constructed
    /// from a `&[u8]`.
    ///
    /// This consumes and so terminates the [`ActiveKeyExchange`].
    fn complete_for_tls_version(
        self: Box<Self>,
        peer_pub_key: &[u8],
        tls_version: ProtocolVersion,
    ) -> Result<SharedSecret, Error> {
        if tls_version == ProtocolVersion::TLSv1_3 {
            return self.complete(peer_pub_key);
        }

        let group = self.group();
        let mut complete_res = self.complete(peer_pub_key)?;
        if group.key_exchange_algorithm() == KeyExchangeAlgorithm::DHE {
            complete_res.strip_leading_zeros();
        }
        Ok(complete_res)
    }

    /// Return the public key being used.
    ///
    /// For ECDHE, the encoding required is defined in
    /// [RFC8446 section 4.2.8.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2).
    ///
    /// For FFDHE, the encoding required is defined in
    /// [RFC8446 section 4.2.8.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.1).
    fn pub_key(&self) -> &[u8];

    /// FFDHE group the `ActiveKeyExchange` is operating in.
    ///
    /// The default implementation returns `None`, so non-FFDHE groups (the
    /// most common) do not need to do anything.
    ///
    /// FFDHE groups must implement this. [`ffdhe`] contains suitable values to return, for
    /// example [`ffdhe::FFDHE2048`].
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    /// Return the group being used.
    fn group(&self) -> NamedGroup;
}

/// An in-progress hybrid key exchange originating from a [`SupportedKxGroup`].
///
/// "Hybrid" means a key exchange algorithm which is constructed from two
/// (or more) independent component algorithms. Usually one is post-quantum-secure,
/// and the other is "classical".  See
/// <https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/11/>
///
/// There is no requirement for a hybrid scheme (or any other!) to implement
/// `HybridKeyExchange` if it is not desirable for it to be "split" like this.
/// It only enables an optimization; described below.
///
/// # Background
/// Rustls always sends a presumptive key share in its `ClientHello`, using
/// (absent any other information) the first item in
/// [`CryptoProvider::kx_groups`][super::CryptoProvider::kx_groups].
/// If the server accepts the client's selection, it can complete the handshake
/// using that key share.  If not, the server sends a `HelloRetryRequest` instructing
/// the client to send a different key share instead.
///
/// This request costs an extra round trip, and wastes the key exchange computation
/// (in [`SupportedKxGroup::start()`]) the client already did.  We would
/// like to avoid those wastes if possible.
///
/// It is early days for post-quantum-secure hybrid key exchange deployment.
/// This means (commonly) continuing to offer both the hybrid and classical
/// key exchanges, so the handshake can be completed without a `HelloRetryRequest`
/// for servers that support the offered hybrid or classical schemes.
///
/// Implementing `HybridKeyExchange` enables two optimizations:
///
/// 1. Sending both the hybrid and classical key shares in the `ClientHello`.
///
/// 2. Performing the classical key exchange setup only once.  This is important
///    because the classical key exchange setup is relatively expensive.
///    This optimization is permitted and described in
///    <https://www.ietf.org/archive/id/draft-ietf-tls-hybrid-design-11.html#section-3.2>
///
/// Both of these only happen if the classical algorithm appears separately in
/// the client's [`CryptoProvider::kx_groups`][super::CryptoProvider::kx_groups],
/// and if the hybrid algorithm appears first in that list.
///
/// # How it works
/// This function is only called by rustls for clients.  It is called when
/// constructing the initial `ClientHello`.  rustls follows these steps:
///
/// 1. If the return value is `None`, nothing further happens.
/// 2. If the given [`NamedGroup`] does not appear in
///    [`CryptoProvider::kx_groups`][super::CryptoProvider::kx_groups], nothing further happens.
/// 3. The given key share is added to the `ClientHello`, after the hybrid entry.
///
/// Then, one of three things may happen when the server replies to the `ClientHello`:
///
/// 1. The server sends a `HelloRetryRequest`.  Everything is thrown away and
///    we start again.
/// 2. The server agrees to our hybrid key exchange: rustls calls
///    [`ActiveKeyExchange::complete()`] consuming `self`.
/// 3. The server agrees to our classical key exchange: rustls calls
///    [`HybridKeyExchange::complete_component()`] which
///    discards the hybrid key data, and completes just the classical key exchange.
pub trait HybridKeyExchange: ActiveKeyExchange {
    /// Returns the [`NamedGroup`] and public key "share" for the component.
    fn component(&self) -> (NamedGroup, &[u8]);

    /// Completes the classical component of the key exchange, given the peer's public key.
    ///
    /// This method must return an error if `peer_pub_key` is invalid: either
    /// misencoded, or an invalid public key (such as, but not limited to, being
    /// in a small order subgroup).
    ///
    /// The shared secret is returned as a [`SharedSecret`] which can be constructed
    /// from a `&[u8]`.
    ///
    /// See the documentation on [`HybridKeyExchange`] for explanation.
    fn complete_component(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error>;

    /// Obtain the value as a `dyn ActiveKeyExchange`
    fn as_key_exchange(&self) -> &(dyn ActiveKeyExchange + 'static);

    /// Remove the ability to do hybrid key exchange on this object.
    fn into_key_exchange(self: Box<Self>) -> Box<dyn ActiveKeyExchange>;
}

/// The result from [`SupportedKxGroup::start_and_complete()`].
#[expect(clippy::exhaustive_structs)]
pub struct CompletedKeyExchange {
    /// Which group was used.
    pub group: NamedGroup,

    /// Our key share (sometimes a public key).
    pub pub_key: Vec<u8>,

    /// The computed shared secret.
    pub secret: SharedSecret,
}

/// The result from [`ActiveKeyExchange::complete()`] or [`HybridKeyExchange::complete_component()`].
pub struct SharedSecret {
    buf: Vec<u8>,
    offset: usize,
}

impl SharedSecret {
    /// Returns the shared secret as a slice of bytes.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.buf[self.offset..]
    }

    /// Removes leading zeros from `secret_bytes()` by adjusting the `offset`.
    ///
    /// This function does not re-allocate.
    fn strip_leading_zeros(&mut self) {
        let start = self
            .secret_bytes()
            .iter()
            .enumerate()
            .find(|(_i, x)| **x != 0)
            .map(|(i, _x)| i)
            .unwrap_or_else(|| self.secret_bytes().len());
        self.offset += start;
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl From<&[u8]> for SharedSecret {
    fn from(source: &[u8]) -> Self {
        Self {
            buf: source.to_vec(),
            offset: 0,
        }
    }
}

impl From<Vec<u8>> for SharedSecret {
    fn from(buf: Vec<u8>) -> Self {
        Self { buf, offset: 0 }
    }
}

/// Describes supported key exchange mechanisms.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum KeyExchangeAlgorithm {
    /// Diffie-Hellman Key exchange (with only known parameters as defined in [RFC 7919]).
    ///
    /// [RFC 7919]: https://datatracker.ietf.org/doc/html/rfc7919
    DHE,
    /// Key exchange performed via elliptic curve Diffie-Hellman.
    ECDHE,
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::SharedSecret;

    #[test]
    fn test_shared_secret_strip_leading_zeros() {
        let test_cases = [
            (vec![0, 1], vec![1]),
            (vec![1], vec![1]),
            (vec![1, 0, 2], vec![1, 0, 2]),
            (vec![0, 0, 1, 2], vec![1, 2]),
            (vec![0, 0, 0], vec![]),
            (vec![], vec![]),
        ];
        for (buf, expected) in test_cases {
            let mut secret = SharedSecret::from(&buf[..]);
            assert_eq!(secret.secret_bytes(), buf);
            secret.strip_leading_zeros();
            assert_eq!(secret.secret_bytes(), expected);
        }
    }
}
